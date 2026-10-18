package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Harsette/ralx/internal/runner"
	"github.com/Harsette/ralx/internal/store"
)

// "Connect" for real CLIs: RalX runs the CLI's own browser/device login as
// the RalX account, in RalX's private home, so the token lands where agents
// can't read it and is never shown on screen. RalX then moves the token
// into the vault and injects it per call.

type cliLoginSpec struct {
	tool       string
	argv       func(configDir string) []string
	url        *regexp.Regexp
	credential string
	label      string
	// harvest reads the token the CLI saved, returns vault fields + meta,
	// and deletes the CLI's own copy.
	harvest func(s *Server, configDir string) (map[string]string, map[string]any, error)
}

var cliLogins = map[string]cliLoginSpec{
	"vercel": {
		tool:       "vercel",
		argv:       func(dir string) []string { return []string{"login", "--global-config", dir} },
		url:        regexp.MustCompile(`https://vercel\.com/oauth/device\?user_code=[A-Z0-9-]+`),
		credential: "vercel",
		label:      "Vercel",
		harvest: func(s *Server, dir string) (map[string]string, map[string]any, error) {
			p := filepath.Join(dir, "auth.json")
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, nil, fmt.Errorf("vercel didn't save a login: %w", err)
			}
			var a struct {
				Token string `json:"token"`
			}
			if err := json.Unmarshal(b, &a); err != nil || a.Token == "" {
				return nil, nil, errors.New("vercel login file has no token")
			}
			_ = os.Remove(p)
			return map[string]string{"token": a.Token}, map[string]any{"connected_at": time.Now().Unix()}, nil
		},
	},
}

type cliSession struct {
	ID      string `json:"id"`
	Tool    string `json:"tool"`
	URL     string `json:"url"`
	Status  string `json:"status"` // waiting | connected | error
	Error   string `json:"error,omitempty"`
	Agent   string `json:"-"`
	sess    *runner.Session
	created time.Time
}

type cliSessions struct {
	mu sync.Mutex
	m  map[string]*cliSession
}

var cliSess = &cliSessions{m: map[string]*cliSession{}}

func (s *Server) startCLILogin(tool, agent string, allowReplace bool) (*cliSession, error) {
	spec, ok := cliLogins[tool]
	if !ok {
		return nil, fmt.Errorf("no connect flow for %q (try: vercel)", tool)
	}
	if _, err := s.store.GetCredential(spec.credential); err == nil && !allowReplace {
		return nil, fmt.Errorf("%s is already connected; the owner can reconnect it from the RalX app", spec.label)
	}
	dir := filepath.Join(s.run.Home(), "login", tool)
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	rs, err := s.run.StartLogin(spec.tool, spec.argv(dir), map[string]string{"VERCEL_TELEMETRY_DISABLED": "1"}, spec.url, 15*time.Minute)
	if err != nil {
		return nil, err
	}
	cs := &cliSession{ID: store.NewID("cli_"), Tool: tool, URL: rs.URL(), Status: "waiting", Agent: agent, sess: rs, created: time.Now()}
	if cs.URL == "" {
		rs.Stop()
		return nil, errors.New(spec.label + " login didn't start: " + s.red.String(lastLines(rs.Output(), 3)))
	}
	cliSess.mu.Lock()
	cliSess.m[cs.ID] = cs
	cliSess.mu.Unlock()
	s.store.Audit(agent, tool+".connect", "started", 0, "")
	go s.finishCLILogin(cs, spec, dir)
	return cs, nil
}

func (s *Server) finishCLILogin(cs *cliSession, spec cliLoginSpec, dir string) {
	done, err := cs.sess.Wait(15 * time.Minute)
	set := func(status, msg string) {
		cliSess.mu.Lock()
		cs.Status, cs.Error = status, msg
		cliSess.mu.Unlock()
	}
	if !done {
		cs.sess.Stop()
		set("error", "timed out waiting for the browser approval")
		return
	}
	if err != nil {
		set("error", s.red.String(lastLines(cs.sess.Output(), 3)))
		s.store.Audit(cs.Agent, spec.tool+".connect", "error", 0, cs.Error)
		return
	}
	if err := s.saveCLILogin(cs.Agent, spec, dir); err != nil {
		set("error", err.Error())
		return
	}
	set("connected", "")
	s.store.Audit(cs.Agent, spec.tool+".connect", "ok", 0, spec.label+" connected")
}

// saveCLILogin moves the token the CLI saved into the vault.
func (s *Server) saveCLILogin(agent string, spec cliLoginSpec, dir string) error {
	fields, meta, err := spec.harvest(s, dir)
	if err != nil {
		return err
	}
	_ = os.RemoveAll(dir)
	if _, err := s.store.PutCredential(spec.credential, "token", spec.credential, spec.label, meta, fields); err != nil {
		return err
	}
	// Marks the replacement so refusals of calls made with the old login stop counting.
	s.store.Audit(agent, "credential.put", "ok", 0, spec.credential+" via "+spec.tool+".connect")
	for k, v := range fields {
		s.red.Add(spec.credential+":"+k, v)
	}
	return nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " / ")
}

func (s *Server) handleCLIConnect(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	cs, err := s.startCLILogin(r.PathValue("tool"), agent.Name, false)
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	s.writeJSONAgent(w, 200, cs)
}

func (s *Server) handleCLISession(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	cliSess.mu.Lock()
	cs, ok := cliSess.m[r.PathValue("id")]
	var cp cliSession
	if ok {
		cp = *cs
	}
	cliSess.mu.Unlock()
	if !ok || cp.Agent != agent.Name {
		s.fail(w, 404, "no such connect session")
		return
	}
	// Through the agent-bound choke point: a failed login's captured output (cp.Error)
	// could carry an encoded stored credential, and a plain writeJSON would skip the
	// fail-closed deep check entirely (Astra7 self-review CLI poll bypass).
	s.writeJSONAgent(w, 200, cp)
}

func (s *Server) handleAdminCLIConnect(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	cs, err := s.startCLILogin(r.PathValue("tool"), "owner", true)
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, cs)
}
