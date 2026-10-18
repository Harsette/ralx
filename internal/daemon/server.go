// Package daemon is the RalX vault and broker process. It is the only place
// real credentials exist in plaintext, and only in its memory.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/browserlogin"
	"github.com/Harsette/ralx/internal/google"
	"github.com/Harsette/ralx/internal/redact"
	"github.com/Harsette/ralx/internal/runner"
	"github.com/Harsette/ralx/internal/secretbox"
	"github.com/Harsette/ralx/internal/social"
	"github.com/Harsette/ralx/internal/store"
	"github.com/Harsette/ralx/internal/upstream"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir             string
	Addr                string // loopback listen address, e.g. 127.0.0.1:7317
	Dev                 bool   // running as the interactive user (no account boundary)
	ManagedSandboxTools bool   // explicit trust of a managed read-only Linux root; dev only
	AdminPipe           string // Windows named pipe or unix socket for elevated admin
	ServiceSID          string
	Version             string
}

type Server struct {
	cfg     Config
	hub     HubConfig
	oauth   *oauthServer
	up      *upstream.Manager
	ext     *http.Client // outbound client for http.request (SSRF-guarded; overridable in tests)
	store   *store.Store
	reg     *actions.Registry
	red     *redact.Redactor
	run     *runner.Runner
	google  *google.Broker
	social  *social.Client
	admin   *adminAuth
	staging *staging
	browser *browserlogin.Manager
	enroll  *enrollments
	logger  *log.Logger
	origin  string
	port    string
	started time.Time
}

func New(cfg Config, logger *log.Logger) (*Server, error) {
	if cfg.ManagedSandboxTools && !cfg.Dev {
		return nil, errors.New("managed sandbox tool paths require --dev")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	key, err := secretbox.LoadOrCreateKey(filepath.Join(cfg.DataDir, "vault.key"))
	if err != nil {
		return nil, err
	}
	box, err := secretbox.New(key)
	for i := range key {
		key[i] = 0
	}
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "ralx.db"), box)
	if err != nil {
		return nil, err
	}
	_, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("bad listen address %q: %w", cfg.Addr, err)
	}
	s := &Server{cfg: cfg, store: st, reg: actions.NewRegistry(), red: redact.New(), logger: logger,
		origin: "http://localhost:" + port, port: port, started: time.Now(), enroll: newEnrollments()}
	if all, err := st.AllSecretValues(); err == nil {
		s.red.Replace(all)
	}
	if cfg.ServiceSID != "" {
		runner.TrustSID(cfg.ServiceSID)
	}
	tools, prefix := s.loadTools()
	s.run = &runner.Runner{Tools: tools, Prefix: prefix, HomeDir: filepath.Join(cfg.DataDir, "home")}
	s.google = google.NewBroker(st, s.red, "http://127.0.0.1:"+port+"/oauth/google/callback")
	s.google.OnEvent = func(actor, action, outcome, detail string) { st.Audit(actor, action, outcome, 0, detail) }
	s.social = social.New(st, s.red)
	s.staging = newStaging(filepath.Join(cfg.DataDir, "home", "staging"))
	if s.hub, err = loadHubConfig(cfg.DataDir); err != nil {
		return nil, err
	}
	if s.admin, err = newAdminAuth(st, s.allOrigins()); err != nil {
		return nil, err
	}
	s.oauth = newOAuthServer(s)
	if err := s.reg.LoadBuiltin(); err != nil {
		return nil, err
	}
	if err := s.reg.LoadDir(filepath.Join(cfg.DataDir, "actions.d")); err != nil {
		s.logger.Printf("custom actions: %v", err)
	}
	for _, a := range s.google.Actions() {
		if err := s.reg.Add(a); err != nil {
			return nil, err
		}
	}
	for _, a := range s.social.Actions() {
		if err := s.reg.Add(a); err != nil {
			return nil, err
		}
	}
	s.ext = safeHTTPClient()
	if err := s.registerBrowserLogins(); err != nil {
		return nil, err
	}
	if err := s.reg.Add(s.httpRequestAction()); err != nil {
		return nil, err
	}
	s.up = upstream.NewManager(st, s.red, s.reg, "http://127.0.0.1:"+port+"/oauth/mcp/callback")
	s.up.Logf = logger.Printf
	return s, nil
}

func (s *Server) Close() error {
	if s.browser != nil {
		s.browser.Close()
	}
	if s.up != nil {
		s.up.Close()
	}
	return s.store.Close()
}

// loadTools reads tools.yaml (name: path, or name: [interpreter, script])
// and keeps only tools whose every file non-admins cannot replace.
func (s *Server) loadTools() (map[string]string, map[string][]string) {
	specs := map[string][]string{}
	if data, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "tools.yaml")); err == nil {
		raw := map[string]any{}
		_ = yaml.Unmarshal(data, &raw)
		for k, v := range raw {
			switch x := v.(type) {
			case string:
				specs[k] = []string{x}
			case []any:
				for _, e := range x {
					if str, ok := e.(string); ok {
						specs[k] = append(specs[k], str)
					}
				}
			}
		}
	}
	for name, def := range defaultToolPaths() {
		if _, ok := specs[name]; ok {
			continue
		}
		present := true
		for _, p := range def {
			if _, err := os.Stat(p); err != nil {
				present = false
			}
		}
		if present {
			specs[name] = def
		}
	}
	tools, prefix := map[string]string{}, map[string][]string{}
	for name, spec := range specs {
		if len(spec) == 0 {
			continue
		}
		// VerifyToolPath returns the verified canonical path; store exactly that
		// and run it, so there is no second resolution to race and no fall-back to
		// an unverified original path (Astra N8/R11).
		ok := true
		canon := make([]string, 0, len(spec))
		for _, p := range spec {
			verify := runner.VerifyToolPath
			if s.cfg.ManagedSandboxTools {
				verify = runner.VerifyToolPathInManagedSandbox
			}
			cp, err := verify(p)
			if err != nil {
				if s.cfg.Dev {
					s.logger.Printf("tool %s: %v (allowed in dev mode only)", name, err)
					canon = append(canon, p)
					continue
				}
				s.logger.Printf("tool %s disabled: %v", name, err)
				ok = false
				break
			}
			canon = append(canon, cp)
		}
		if ok {
			tools[name] = canon[0]
			if len(canon) > 1 {
				prefix[name] = canon[1:]
			}
		}
	}
	return tools, prefix
}

// ---------- HTTP plumbing ----------

type ctxKey int

const (
	ctxPipeAdmin ctxKey = 1
	// ctxGrantFamily carries the OAuth refresh-token family of the request's
	// bearer token, so a queued approval can be bound to it (Astra N9).
	ctxGrantFamily ctxKey = 2
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// agentScrub is the single fail-closed exit for agent-bound bytes: it redacts in
// place, then returns withheld=true if the SCRUBBED bytes still reconstruct a
// registered credential under any recognised transform (an encoded/percent/split
// form red.Bytes can't rewrite). Every agent-facing writer - success, error,
// readback, MCP result, streamed metadata - goes through this one check, so a new
// path can't reintroduce a leak by writing bytes directly (Astra7 choke point).
func (s *Server) agentScrub(b []byte, actor ...string) (out []byte, withheld bool) {
	clean, bad := s.vaultScrub(b)
	if bad || s.browser == nil {
		return clean, bad
	}
	return s.browser.ScrubOutput(clean, actor...)
}

// Protected session files must still refuse vault credentials while retaining
// the cookies/tokens they exist to export. Conversation output checks both.
func (s *Server) vaultScrub(b []byte) (out []byte, withheld bool) {
	if s.red.ShortLiteral(string(b)) {
		return nil, true
	}
	scrubbed := s.red.Bytes(b)
	if s.red.DeepContainsSecret(string(scrubbed)) {
		return nil, true
	}
	return scrubbed, false
}

// fail writes an agent/admin-facing error through the same fail-closed check: an
// error string that still reconstructs a credential after in-place redaction (e.g.
// a percent-encoded stored key echoed in a provider error) is withheld, not sent.
// This closes the error path - fail() backs every handler's error exit, including
// the Drive download stream error - alongside the result path in execute() and the
// readback path in writeJSONAgent (Astra7 F1 error-body bypass).
func (s *Server) fail(w http.ResponseWriter, code int, msg string) {
	scrubbed, withheld := s.agentScrub([]byte(msg))
	if withheld {
		scrubbed = []byte("error withheld - it reconstructs a credential")
	}
	writeJSON(w, code, map[string]any{"error": string(scrubbed)})
}

// writeJSONAgent writes an agent-facing JSON response through the redactor, so
// provider metadata (e.g. a Google upload result, connection status, a flow or
// approval readback) that contains a known secret is scrubbed before it reaches
// the agent (Astra R3). It redacts in place, then - if the SCRUBBED bytes still
// reconstruct a credential under any recognised transform (an encoded/percent/
// split form red.Bytes can't rewrite) - withholds the whole response (Daru6 run6:
// upload results / metadata / errors must all pass a final deep check).
func (s *Server) writeJSONAgent(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		writeJSON(w, code, map[string]any{"error": "encoding error"})
		return
	}
	scrubbed, withheld := s.agentScrub(b)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if withheld {
		_, _ = w.Write([]byte(`{"status":"withheld","error":"response withheld - it reconstructs a credential"}`))
		return
	}
	_, _ = w.Write(scrubbed)
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	dec.UseNumber()
	return dec.Decode(v)
}

// hostGuard blocks DNS-rebinding and cross-site browser requests: only
// loopback Host headers are accepted on the TCP listener.
func (s *Server) hostGuard(next http.Handler) http.Handler {
	allowed := map[string]bool{
		"127.0.0.1:" + s.port: true, "localhost:" + s.port: true, "[::1]:" + s.port: true,
	}
	for _, h := range s.publicHosts() {
		allowed[h] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed[strings.ToLower(r.Host)] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		// Owner-only admin successes include deliberate credential reveal. Public
		// protocol, callback, agent, download and SDK exits share the final boundary.
		p := r.URL.Path
		if strings.HasPrefix(p, "/v1/") || p == "/mcp" || strings.HasPrefix(p, "/oauth/") || strings.HasPrefix(p, "/.well-known/") || strings.HasPrefix(p, "/drop/") || p == "/healthz" || p == "/admin/api/session" || strings.HasPrefix(p, "/admin/api/setup/") || strings.HasPrefix(p, "/admin/api/login/") {
			s.agentOutput(next).ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes(mux *http.ServeMux) {
	// Agent API (bearer agent key)
	mux.HandleFunc("GET /v1/whoami", s.agentOnly(s.handleWhoami))
	mux.HandleFunc("GET /v1/actions", s.agentOnly(s.handleListActions))
	mux.HandleFunc("POST /v1/actions/{name}", s.agentOnly(s.handleCallAction))
	mux.HandleFunc("GET /v1/approvals/{id}", s.agentOnly(s.handleGetApproval))
	mux.HandleFunc("GET /v1/connections", s.agentOnly(s.handleConnections))
	mux.HandleFunc("POST /v1/connect/google", s.agentOnly(s.handleConnectGoogle))
	mux.HandleFunc("GET /v1/connect/flows/{id}", s.agentOnly(s.handleGetFlow))
	mux.HandleFunc("POST /v1/connect/cli/{tool}", s.agentOnly(s.handleCLIConnect))
	mux.HandleFunc("GET /v1/connect/cli/sessions/{id}", s.agentOnly(s.handleCLISession))
	mux.HandleFunc("POST /admin/api/connect/cli/{tool}", s.localAdminOnly(s.handleAdminCLIConnect))
	mux.HandleFunc("POST /v1/uploads", s.agentOnly(s.handleStartUpload))
	mux.HandleFunc("PUT /v1/uploads/{id}", s.agentOnly(s.handlePutChunk))
	mux.HandleFunc("GET /v1/uploads/{id}", s.agentOnly(s.handleUploadStatus))
	mux.HandleFunc("GET /v1/drive/files/{id}/content", s.agentOnly(s.handleDriveDownload))
	mux.HandleFunc("GET /v1/leakscan/fingerprints", s.agentOnly(s.handleFingerprints))

	// OAuth redirect targets (browser)
	mux.HandleFunc("GET /oauth/google/callback", s.google.HandleCallback)
	mux.HandleFunc("GET /oauth/mcp/callback", s.up.HandleCallback)
	mux.HandleFunc("POST /admin/api/upstreams/oauth", s.localAdminOnly(s.handleUpstreamOAuth))
	mux.HandleFunc("POST /admin/api/upstreams/header", s.localAdminOnly(s.handleUpstreamHeader))
	mux.HandleFunc("POST /admin/api/upstreams/reload", s.localAdminOnly(s.handleUpstreamReload))
	mux.HandleFunc("POST /admin/api/upstreams/notion-page-edits", s.localAdminOnly(s.handleNotionPageEdits))
	mux.HandleFunc("POST /admin/api/upstreams/policy", s.localAdminOnly(s.handleUpstreamPolicy))

	// Remote MCP (the main door for cloud agents) and the OAuth 2.1
	// authorization server that chat connectors sign in through.
	s.mcpRoutes(mux)
	s.oauth.routes(mux)

	// Admin API (passkey session, or the elevated admin pipe)
	s.adminRoutes(mux)

	// UI
	mux.Handle("/", s.uiHandler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "version": s.cfg.Version})
	})
}

// Serve runs the loopback HTTP listener and the admin pipe until ctx ends.
func (s *Server) Serve(ctx context.Context) error {
	mux := http.NewServeMux()
	s.routes(mux)
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: s.hostGuard(mux), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- srv.Serve(ln) }()
	// Private-network listeners (e.g. the Tailscale IP). The interface may
	// come up after the service starts, so keep retrying.
	for _, addr := range s.hub.PrivateListen {
		addr := addr
		go func() {
			for ctx.Err() == nil {
				pl, err := net.Listen("tcp", addr)
				if err != nil {
					time.Sleep(10 * time.Second)
					continue
				}
				s.logger.Printf("also listening on private address %s", addr)
				_ = srv.Serve(pl)
				return
			}
		}()
	}

	var pipeSrv *http.Server
	if s.cfg.AdminPipe != "" {
		pl, err := listenAdmin(s.cfg.AdminPipe, s.cfg.Dev)
		if err != nil {
			s.logger.Printf("admin pipe unavailable: %v", err)
		} else {
			pmux := http.NewServeMux()
			s.routes(pmux)
			pipeSrv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pmux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxPipeAdmin, true)))
			}), ReadHeaderTimeout: 10 * time.Second}
			go func() { errc <- pipeSrv.Serve(pl) }()
		}
	}
	s.logger.Printf("RalX %s listening on http://localhost:%s (dev=%v)", s.cfg.Version, s.port, s.cfg.Dev)
	go func() {
		// At boot the service can start before the network is up; keep retrying
		// upstreams that failed for that kind of reason instead of leaving them dead.
		failed := s.up.LoadAll(ctx)
		s.up.RetryFailed(ctx, failed, []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute})
	}()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	if pipeSrv != nil {
		_ = pipeSrv.Shutdown(sctx)
	}
	return nil
}
