package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/actions"
)

const testSecret = "sk-test-SUPERSECRETVALUE-1234567890abcdef"

type harness struct {
	t      *testing.T
	s      *Server
	h      http.Handler
	cookie *http.Cookie
	csrf   string
	authn  *softAuthn
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	s, err := New(Config{DataDir: dir, Addr: "127.0.0.1:7399", Dev: true, Version: "test"}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	// Test actions: a read that leaks its secret (to prove redaction) and a
	// gated one.
	if err := s.reg.Add(&actions.Action{Name: "test.leak", Risk: actions.Read, Description: "leaks",
		Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
			f, err := env.Secret("demo")
			if err != nil {
				return nil, err
			}
			return map[string]any{"oops": "the key is " + f["token"]}, nil
		}}); err != nil {
		t.Fatal(err)
	}
	if err := s.reg.Add(&actions.Action{Name: "test.danger", Risk: actions.Gated, GateReason: "deletes", Description: "dangerous",
		SummaryTemplate: "Delete {thing}",
		Params:          []actions.Param{{Name: "thing", Type: "string", Required: true, Pattern: "[a-z]+"}},
		Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
			return map[string]any{"deleted": args["thing"]}, nil
		}}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.routes(mux)
	return &harness{t: t, s: s, h: s.hostGuard(mux), authn: newSoftAuthn(t, "http://localhost:7399")}
}

type resp struct {
	code int
	body map[string]any
	raw  []byte
	hdr  http.Header
}

func (h *harness) do(method, path string, body any, hdr map[string]string, pipe bool) resp {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, "http://localhost:7399"+path, rd)
	// Local by default (httptest's default RemoteAddr is a public TEST-NET
	// address); tests that exercise a remote peer set RemoteAddr themselves.
	req.RemoteAddr = "127.0.0.1:54321"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if h.cookie != nil {
		req.AddCookie(h.cookie)
	}
	if pipe {
		req = req.WithContext(context.WithValue(req.Context(), ctxPipeAdmin, true))
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	out := resp{code: rec.Code, raw: rec.Body.Bytes(), hdr: rec.Header()}
	_ = json.Unmarshal(out.raw, &out.body)
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			if c.MaxAge < 0 {
				h.cookie = nil
			} else {
				h.cookie = c
			}
		}
	}
	return out
}

func (h *harness) agent(name string) string {
	h.t.Helper()
	r := h.do("POST", "/admin/api/agents", map[string]any{"name": name}, nil, true)
	if r.code != 200 {
		h.t.Fatalf("create agent: %d %s", r.code, r.raw)
	}
	return r.body["key"].(string)
}

func bearer(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} }

func (h *harness) browser() map[string]string {
	return map[string]string{"Origin": "http://localhost:7399", "X-RalX-CSRF": h.csrfOr("x")}
}

func (h *harness) csrfOr(d string) string {
	if h.csrf != "" {
		return h.csrf
	}
	return d
}

// setupPasskey registers the soft passkey through the real setup-link flow
// and leaves the harness signed in.
func (h *harness) setupPasskey() {
	h.t.Helper()
	r := h.do("POST", "/admin/api/setup-link", map[string]any{}, nil, true)
	u, _ := r.body["url"].(string)
	tok := u[strings.Index(u, "#setup=")+7:]
	r = h.do("POST", "/admin/api/setup/begin", map[string]any{"token": tok}, h.browser(), false)
	if r.code != 200 {
		h.t.Fatalf("setup begin: %d %s", r.code, r.raw)
	}
	cred := h.authn.register(h.t, r.raw)
	r = h.do("POST", "/admin/api/setup/finish", map[string]any{"token": tok, "name": "test", "credential": cred}, h.browser(), false)
	if r.code != 200 {
		h.t.Fatalf("setup finish: %d %s", r.code, r.raw)
	}
	h.csrf, _ = r.body["csrf"].(string)
	// the token is single-use
	r = h.do("POST", "/admin/api/setup/begin", map[string]any{"token": tok}, h.browser(), false)
	if r.code != 403 {
		h.t.Fatalf("setup token reusable: %d", r.code)
	}
}

func (h *harness) stepUp(op string) json.RawMessage {
	h.t.Helper()
	r := h.do("POST", "/admin/api/stepup/begin", map[string]any{"op": op}, h.browser(), false)
	if r.code != 200 {
		h.t.Fatalf("stepup begin: %d %s", r.code, r.raw)
	}
	return h.authn.assert(h.t, r.raw)
}

func TestAgentAuthAndRevoke(t *testing.T) {
	h := newHarness(t)
	key := h.agent("a1")
	if r := h.do("GET", "/v1/whoami", nil, bearer(key), false); r.code != 200 || r.body["agent"] != "a1" {
		t.Fatalf("whoami: %d %s", r.code, r.raw)
	}
	if r := h.do("GET", "/v1/whoami", nil, bearer(key+"x"), false); r.code != 401 {
		t.Fatalf("tampered key accepted: %d", r.code)
	}
	if r := h.do("POST", "/admin/api/agents/a1/revoke", nil, nil, true); r.code != 200 {
		t.Fatalf("revoke: %d %s", r.code, r.raw)
	}
	r := h.do("GET", "/v1/whoami", nil, bearer(key), false)
	if r.code != 401 || !strings.Contains(r.body["error"].(string), "revoked") {
		t.Fatalf("revoked agent still works: %d %s", r.code, r.raw)
	}
}

func TestAgentAPIRefusesBrowsers(t *testing.T) {
	h := newHarness(t)
	key := h.agent("a1")
	hdr := bearer(key)
	hdr["Origin"] = "https://evil.example"
	if r := h.do("GET", "/v1/whoami", nil, hdr, false); r.code != 403 {
		t.Fatalf("browser request accepted: %d", r.code)
	}
}

func TestHostGuard(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest("GET", "http://evil.example:7399/healthz", nil)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("rebinding host accepted: %d", rec.Code)
	}
}

func TestValidation(t *testing.T) {
	h := newHarness(t)
	key := h.agent("a1")
	cases := []map[string]any{
		{"thing": "-rf"},
		{"thing": "abc; rm -rf /"},
		{"thing": "abc", "extra": 1},
		{},
	}
	for _, args := range cases {
		r := h.do("POST", "/v1/actions/test.danger", map[string]any{"args": args}, bearer(key), false)
		if r.code != 400 {
			t.Fatalf("args %v accepted: %d %s", args, r.code, r.raw)
		}
	}
	if r := h.do("POST", "/v1/actions/shell.exec", map[string]any{"args": map[string]any{}}, bearer(key), false); r.code != 404 {
		t.Fatalf("unknown action: %d", r.code)
	}
}

func TestRedaction(t *testing.T) {
	h := newHarness(t)
	if r := h.do("POST", "/admin/api/credentials", map[string]any{"name": "demo", "fields": map[string]string{"token": testSecret}}, nil, true); r.code != 200 {
		t.Fatalf("put: %d %s", r.code, r.raw)
	}
	key := h.agent("a1")
	r := h.do("POST", "/v1/actions/test.leak", map[string]any{"args": map[string]any{}}, bearer(key), false)
	if r.code != 200 {
		t.Fatalf("leak call: %d %s", r.code, r.raw)
	}
	if bytes.Contains(r.raw, []byte(testSecret)) || !bytes.Contains(r.raw, []byte("REDACTED")) {
		t.Fatalf("secret not redacted: %s", r.raw)
	}
	// credential listings never include values
	for _, path := range []string{"/v1/connections"} {
		if r := h.do("GET", path, nil, bearer(key), false); bytes.Contains(r.raw, []byte(testSecret)) {
			t.Fatalf("%s leaked secret", path)
		}
	}
	st := h.do("GET", "/admin/api/state", nil, nil, true)
	if bytes.Contains(st.raw, []byte(testSecret)) {
		t.Fatalf("admin state leaked the value")
	}
	// audit log holds no secret
	audit, _ := h.s.store.ListAudit(100)
	for _, e := range audit {
		if strings.Contains(e.Detail, testSecret) {
			t.Fatalf("audit leaked secret: %s", e.Detail)
		}
	}
	// the vault file on disk holds no plaintext
	if bytesInDir(t, h.s.cfg.DataDir, testSecret) {
		t.Fatalf("plaintext secret found in data dir")
	}
}

func TestApprovalRequiresPasskey(t *testing.T) {
	h := newHarness(t)
	key := h.agent("a1")
	other := h.agent("a2")
	r := h.do("POST", "/v1/actions/test.danger", map[string]any{"args": map[string]any{"thing": "repo"}}, bearer(key), false)
	if r.code != 202 || r.body["status"] != "held" {
		t.Fatalf("not held: %d %s", r.code, r.raw)
	}
	id := r.body["approval_id"].(string)

	// another agent can't see it
	if r := h.do("GET", "/v1/approvals/"+id, nil, bearer(other), false); r.code != 404 {
		t.Fatalf("cross-agent approval visible: %d", r.code)
	}
	// the elevated admin pipe can't approve
	if r := h.do("POST", "/admin/api/approvals/"+id+"/approve", map[string]any{}, nil, true); r.code != 403 {
		t.Fatalf("pipe approved: %d %s", r.code, r.raw)
	}
	// no session: refused
	if r := h.do("POST", "/admin/api/approvals/"+id+"/approve", map[string]any{}, h.browser(), false); r.code != 401 {
		t.Fatalf("anonymous approve: %d", r.code)
	}
	h.setupPasskey()
	// session but no passkey assertion: refused
	if r := h.do("POST", "/admin/api/approvals/"+id+"/approve", map[string]any{}, h.browser(), false); r.code != 403 {
		t.Fatalf("approve without assertion: %d %s", r.code, r.raw)
	}
	// session without CSRF header: refused
	if r := h.do("POST", "/admin/api/approvals/"+id+"/approve", map[string]any{}, map[string]string{"Origin": "http://localhost:7399"}, false); r.code != 403 {
		t.Fatalf("approve without csrf: %d", r.code)
	}
	// an assertion made for a different operation doesn't count
	wrong := h.stepUp("reveal:demo")
	if r := h.do("POST", "/admin/api/approvals/"+id+"/approve", map[string]any{"assertion": wrong}, h.browser(), false); r.code != 403 {
		t.Fatalf("assertion for another op accepted: %d %s", r.code, r.raw)
	}
	// a passkey without user verification doesn't count
	h.authn.uv = false
	noUV := h.stepUp("approve:" + id)
	if r := h.do("POST", "/admin/api/approvals/"+id+"/approve", map[string]any{"assertion": noUV}, h.browser(), false); r.code != 403 {
		t.Fatalf("assertion without UV accepted: %d %s", r.code, r.raw)
	}
	h.authn.uv = true
	// the real thing
	good := h.stepUp("approve:" + id)
	if r := h.do("POST", "/admin/api/approvals/"+id+"/approve", map[string]any{"assertion": good}, h.browser(), false); r.code != 200 {
		t.Fatalf("approve: %d %s", r.code, r.raw)
	}
	// replay of the same assertion fails
	if r := h.do("POST", "/admin/api/approvals/"+id+"/approve", map[string]any{"assertion": good}, h.browser(), false); r.code == 200 {
		t.Fatalf("assertion replay accepted")
	}
	var final resp
	for i := 0; i < 50; i++ {
		final = h.do("GET", "/v1/approvals/"+id, nil, bearer(key), false)
		if final.body["status"] == "executed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if final.body["status"] != "executed" || !bytes.Contains(final.raw, []byte(`"deleted":"repo"`)) {
		t.Fatalf("approval did not execute: %s", final.raw)
	}
}

func TestRevokedAgentApprovalDoesNotRun(t *testing.T) {
	h := newHarness(t)
	key := h.agent("a1")
	r := h.do("POST", "/v1/actions/test.danger", map[string]any{"args": map[string]any{"thing": "x"}}, bearer(key), false)
	id := r.body["approval_id"].(string)
	h.do("POST", "/admin/api/agents/a1/revoke", nil, nil, true)
	h.setupPasskey()
	good := h.stepUp("approve:" + id)
	h.do("POST", "/admin/api/approvals/"+id+"/approve", map[string]any{"assertion": good}, h.browser(), false)
	time.Sleep(100 * time.Millisecond)
	a, _ := h.s.store.GetApproval(id)
	if a.Status != "failed" || !strings.Contains(a.Error, "revoked") {
		t.Fatalf("revoked agent's approval ran: %+v", a)
	}
}

func TestRevealRequiresPasskey(t *testing.T) {
	h := newHarness(t)
	h.do("POST", "/admin/api/credentials", map[string]any{"name": "demo", "fields": map[string]string{"token": testSecret}}, nil, true)
	if r := h.do("POST", "/admin/api/credentials/reveal", map[string]any{"name": "demo"}, nil, true); r.code != 403 {
		t.Fatalf("pipe reveal: %d", r.code)
	}
	h.setupPasskey()
	if r := h.do("POST", "/admin/api/credentials/reveal", map[string]any{"name": "demo"}, h.browser(), false); r.code != 403 {
		t.Fatalf("reveal without assertion: %d", r.code)
	}
	a := h.stepUp("reveal:demo")
	r := h.do("POST", "/admin/api/credentials/reveal", map[string]any{"name": "demo", "assertion": a}, h.browser(), false)
	if r.code != 200 || !bytes.Contains(r.raw, []byte(testSecret)) {
		t.Fatalf("reveal: %d %s", r.code, r.raw)
	}
}

func TestLoginAndLogout(t *testing.T) {
	h := newHarness(t)
	h.setupPasskey()
	h.do("POST", "/admin/api/logout", nil, h.browser(), false)
	if r := h.do("GET", "/admin/api/state", nil, nil, false); r.code != 401 {
		t.Fatalf("state after logout: %d", r.code)
	}
	r := h.do("POST", "/admin/api/login/begin", nil, h.browser(), false)
	opts, _ := json.Marshal(r.body["options"])
	cred := h.authn.assert(t, opts)
	r = h.do("POST", "/admin/api/login/finish", map[string]any{"ceremony": r.body["ceremony"], "credential": cred}, h.browser(), false)
	if r.code != 200 {
		t.Fatalf("login: %d %s", r.code, r.raw)
	}
	h.csrf, _ = r.body["csrf"].(string)
	if r := h.do("GET", "/admin/api/state", nil, nil, false); r.code != 200 {
		t.Fatalf("state after login: %d", r.code)
	}
}

func TestFingerprintsAreHashesOnly(t *testing.T) {
	h := newHarness(t)
	h.do("POST", "/admin/api/credentials", map[string]any{"name": "demo", "fields": map[string]string{"token": testSecret}}, nil, true)
	key := h.agent("a1")
	r := h.do("GET", "/v1/leakscan/fingerprints", nil, bearer(key), false)
	if r.code != 200 || bytes.Contains(r.raw, []byte(testSecret[:16])) || bytes.Contains(r.raw, []byte("SUPERSECRET")) {
		t.Fatalf("fingerprints leak: %s", r.raw)
	}
}
