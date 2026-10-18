package daemon

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Harsette/ralx/internal/store"
)

// Agent enrollment by pasted prompt. The owner mints a one-time code (only its
// hash is kept, in memory, for 15 minutes) and pastes a prompt carrying it into
// an agent. The agent redeems the code into a pending request and polls with a
// request secret only it holds. The owner approves with a passkey bound to that
// request; the agent's next poll creates the agent and hands over its key once.
// No key exists before that poll and none is stored in plaintext.

const (
	enrollCodeTTL     = 15 * time.Minute
	enrollRequestTTL  = 15 * time.Minute
	enrollPickupTTL   = 10 * time.Minute
	enrollMaxFailures = 5
	enrollFailWindow  = time.Minute
	enrollCodeChars   = "23456789ABCDEFGHJKMNPQRSTVWXYZ" // no 0/O, 1/I/L, U
)

var enrollNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,40}$`)

type enrollCode struct {
	id      string
	hash    string
	expires time.Time
}

type enrollRequest struct {
	ID          string `json:"id"`
	CodeID      string `json:"code_id"`
	Name        string `json:"name"`
	Client      string `json:"client"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"` // pending | approved | denied | delivered | expired
	CreatedAt   int64  `json:"created_at"`
	secretHash  []byte
	expires     time.Time
}

type enrollments struct {
	now func() time.Time

	mu    sync.Mutex
	code  *enrollCode // at most one live code; minting a new one replaces it
	reqs  map[string]*enrollRequest
	fails []time.Time
}

func newEnrollments() *enrollments {
	return &enrollments{now: time.Now, reqs: map[string]*enrollRequest{}}
}

func normalizeEnrollCode(c string) string {
	c = strings.ToUpper(c)
	c = strings.NewReplacer("-", "", " ", "").Replace(c)
	return c
}

func randEnrollCode() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	out := make([]byte, 0, 9)
	for i, x := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, enrollCodeChars[int(x)%len(enrollCodeChars)])
	}
	return string(out)
}

// sweep expires stale codes and requests. Callers hold mu.
func (e *enrollments) sweep(now time.Time) {
	if e.code != nil && !now.Before(e.code.expires) {
		e.code = nil
	}
	for id, r := range e.reqs {
		if (r.Status == "pending" || r.Status == "approved") && !now.Before(r.expires) {
			r.Status = "expired"
		}
		// Keep finished requests for a while so a late poll gets a clear answer.
		if r.Status != "pending" && r.Status != "approved" && now.Sub(time.Unix(r.CreatedAt, 0)) > time.Hour {
			delete(e.reqs, id)
		}
	}
	keep := e.fails[:0]
	for _, t := range e.fails {
		if now.Sub(t) < enrollFailWindow {
			keep = append(keep, t)
		}
	}
	e.fails = keep
}

func (e *enrollments) mint() (code string, id string, expires time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	code = randEnrollCode()
	c := &enrollCode{id: store.NewID("enc_"), hash: store.HashToken(normalizeEnrollCode(code)), expires: now.Add(enrollCodeTTL)}
	e.code = c
	return code, c.id, c.expires
}

var (
	errEnrollLimited = errors.New("too many wrong codes; wait a minute and try again")
	errEnrollCode    = errors.New("that code is wrong, already used or expired; ask the owner for a new one in RalX")
)

// redeem consumes the live code and opens a pending request. A wrong code
// counts towards the guessing limit; while limited, every code is refused.
func (e *enrollments) redeem(code, name, client string) (*enrollRequest, string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	e.sweep(now)
	if len(e.fails) >= enrollMaxFailures {
		return nil, "", errEnrollLimited
	}
	got := store.HashToken(normalizeEnrollCode(code))
	if e.code == nil || subtle.ConstantTimeCompare([]byte(got), []byte(e.code.hash)) != 1 {
		e.fails = append(e.fails, now)
		return nil, "", errEnrollCode
	}
	codeID := e.code.id
	e.code = nil
	secret := randID(32)
	h := sha256.Sum256([]byte(secret))
	fp := make([]byte, 0, 9)
	for i, x := range h[:8] {
		if i == 4 {
			fp = append(fp, '-')
		}
		fp = append(fp, enrollCodeChars[int(x)%len(enrollCodeChars)])
	}
	r := &enrollRequest{ID: store.NewID("enr_"), CodeID: codeID, Name: name, Client: client,
		Fingerprint: string(fp), Status: "pending", CreatedAt: now.Unix(),
		secretHash: h[:], expires: now.Add(enrollRequestTTL)}
	e.reqs[r.ID] = r
	cp := *r // the handler reads it unlocked while the owner may decide
	return &cp, secret, nil
}

// lookup finds a request by id and secret. A wrong secret looks like no request.
func (e *enrollments) lookup(id, secret string) *enrollRequest {
	r := e.reqs[id]
	if r == nil {
		return nil
	}
	h := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(h[:], r.secretHash) != 1 {
		return nil
	}
	return r
}

func (e *enrollments) decide(id, status string) (*enrollRequest, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	e.sweep(now)
	r := e.reqs[id]
	if r == nil || r.Status != "pending" {
		return nil, errors.New("this request is not waiting (already decided or expired)")
	}
	r.Status = status
	if status == "approved" {
		r.expires = now.Add(enrollPickupTTL)
	}
	cp := *r
	return &cp, nil
}

func (e *enrollments) pending() []*enrollRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sweep(e.now())
	var out []*enrollRequest
	for _, r := range e.reqs {
		if r.Status == "pending" {
			cp := *r
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

// ---------- HTTP ----------

func (s *Server) enrollRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /admin/api/enroll/code", s.localAdminOnly(s.handleEnrollCode))
	mux.HandleFunc("POST /admin/api/enroll/{id}/approve", s.localAdminOnly(s.handleEnrollApprove))
	mux.HandleFunc("POST /admin/api/enroll/{id}/deny", s.localAdminOnly(s.handleEnrollDeny))
	mux.HandleFunc("POST /v1/enroll", s.localOnly(s.handleEnrollRedeem))
	mux.HandleFunc("GET /v1/enroll/{id}", s.localOnly(s.handleEnrollPoll))
}

// localOnly admits only agents on this computer: no browser (a web page can
// POST text/plain cross-origin and would burn the guessing limit), a loopback
// peer and Host, and none of the internet-origin or funnel signals.
func (s *Server) localOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
			s.fail(w, http.StatusForbidden, "browser requests are not accepted for agent enrollment")
			return
		}
		if !isPipe(r) && (!remoteIsLoopback(r) || !isLoopbackHostPort(r.Host) ||
			s.isInternetOrigin(r) || funneled(r)) {
			s.fail(w, http.StatusForbidden, "agents connect from RalX's own computer, not over the network")
			return
		}
		h(w, r)
	}
}

// remoteIsLoopback reports whether the immediate peer is this computer.
func remoteIsLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) handleEnrollCode(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	code, id, exp := s.enroll.mint()
	s.store.Audit("owner", "agent.enroll.code", "ok", 0, id+" via "+ac.via)
	writeJSON(w, 200, map[string]any{"code": code, "code_id": id, "expires_at": exp.Unix(), "prompt": s.enrollPrompt(code, exp)})
}

// enrollPrompt is the text the owner pastes into an agent. It carries only the
// one-time code; the agent key is created later, on the agent's own machine.
func (s *Server) enrollPrompt(code string, exp time.Time) string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = `C:\Program Files\RalX\ralx.exe`
	}
	url := ""
	if s.port != "7317" {
		url = " --url http://127.0.0.1:" + s.port
	}
	owner := strings.TrimSpace(os.Getenv("RALX_OWNER_NAME"))
	if owner == "" {
		owner = "the owner"
	}
	return fmt.Sprintf(`Connect yourself to RalX, the account plug on this computer. Through it you can use the connected accounts (Gmail, Drive, GitHub, Notion and more) without ever seeing a password or token.

1. Pick a short lowercase name for yourself (like claude-code-ralveto) and run this, with --client claude-code or --client codex (in PowerShell put & in front):
   "%[1]s" enroll %[2]s --name <your-name> --client <claude-code|codex>%[3]s
2. It prints a fingerprint. Tell %[5]s: "Approve <your-name> in RalX, fingerprint XXXX-XXXX." Run the same command again until it says approved.
3. Once approved it saves your agent key and adds the RalX MCP server to your client. Never open, print or copy the key file.
4. Check it works:
   "%[1]s" --agent <your-name> status
   "%[1]s" --agent <your-name> gmail search --max 1

The code works once and expires at %[4]s. Anything that sends, posts, deletes, deploys or pays still waits for approval from %[5]s.`,
		exe, code, url, exp.Local().Format("15:04"), owner)
}

func (s *Server) handleEnrollRedeem(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		s.fail(w, 400, "bad JSON")
		return
	}
	name := strings.TrimSpace(rawString(body, "name"))
	client := rawString(body, "client")
	if !enrollNameRe.MatchString(name) {
		s.fail(w, 400, "name must be lowercase letters, numbers, dots or dashes (up to 41)")
		return
	}
	if client != "claude-code" && client != "codex" {
		client = "other"
	}
	if _, err := s.store.GetAgentByName(name); err == nil {
		s.fail(w, 409, "an agent called "+name+" already exists; pick another name")
		return
	}
	req, secret, err := s.enroll.redeem(rawString(body, "code"), name, client)
	if err != nil {
		code := 403
		if errors.Is(err, errEnrollLimited) {
			code = 429
		}
		s.store.Audit("agent:"+name, "agent.enroll", "rejected", 0, err.Error())
		s.fail(w, code, err.Error())
		return
	}
	s.store.Audit("agent:"+name, "agent.enroll", "held", 0, req.ID+" "+client+" fingerprint "+req.Fingerprint)
	writeJSON(w, 201, map[string]any{"request_id": req.ID, "secret": secret, "fingerprint": req.Fingerprint,
		"status": req.Status, "expires_at": req.expires.Unix()})
}

func (s *Server) handleEnrollPoll(w http.ResponseWriter, r *http.Request) {
	e := s.enroll
	e.mu.Lock()
	e.sweep(e.now())
	req := e.lookup(r.PathValue("id"), r.Header.Get("X-RalX-Enroll-Secret"))
	if req == nil {
		e.mu.Unlock()
		s.fail(w, 404, "no such request")
		return
	}
	if req.Status != "approved" {
		st := req.Status
		e.mu.Unlock()
		writeJSON(w, 200, map[string]any{"status": st})
		return
	}
	// Approved: this poll is the one pickup. Mark it first so a parallel poll
	// can't also take a key.
	req.Status = "delivered"
	name := req.Name
	e.mu.Unlock()
	a, key, err := s.store.CreateAgent(name, store.Policy{})
	if err != nil {
		s.fail(w, 409, err.Error())
		return
	}
	s.store.Audit("owner", "agent.create", "ok", 0, name+" via enrollment "+req.ID)
	writeJSON(w, 200, map[string]any{"status": "approved", "agent": a.Name, "key": key})
}

func (s *Server) handleEnrollApprove(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	id := r.PathValue("id")
	body, _ := readBody(r)
	// Same bar as creating an agent: a passkey bound to this request, or the
	// elevated admin pipe.
	if err := s.stepUp(ac, "enroll.approve:"+id, body, true); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	req, err := s.enroll.decide(id, "approved")
	if err != nil {
		s.fail(w, 409, err.Error())
		return
	}
	s.store.Audit("owner", "agent.enroll", "approved", 0, req.Name+" "+req.ID+" via "+ac.via)
	writeJSON(w, 200, map[string]any{"ok": true, "status": "approved", "name": req.Name})
}

func (s *Server) handleEnrollDeny(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	req, err := s.enroll.decide(r.PathValue("id"), "denied")
	if err != nil {
		s.fail(w, 409, err.Error())
		return
	}
	s.store.Audit("owner", "agent.enroll", "denied", 0, req.Name+" "+req.ID+" via "+ac.via)
	writeJSON(w, 200, map[string]any{"ok": true, "status": "denied"})
}
