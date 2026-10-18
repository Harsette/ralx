package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/store"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeResp(r *http.Request, code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

// seedGoogle wires a fake Google (token endpoint + API) and a default
// connected account, so Drive/YouTube broker calls work offline.
func seedGoogle(t *testing.T, h *harness, api func(*http.Request) (*http.Response, error)) {
	t.Helper()
	// Swap ONLY the broker's transport, keeping the real NewBroker client (and its
	// no-redirect CheckRedirect), so the R9 redirect-replay test actually proves
	// NewBroker's policy — reverting it leaves the test red.
	h.s.google.HTTP.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "oauth2.googleapis.com" {
			return fakeResp(r, 200, `{"access_token":"ya29.test","expires_in":3600}`), nil
		}
		return api(r)
	})
	// Most tests use fixture upload hosts (upload.example, etc.); accept them.
	// Tests that must prove the googleapis host binding (R10) turn this off.
	h.s.google.TrustAnyUploadHost = true
	if _, err := h.s.store.PutCredential("google-oauth-client", "oauth_client", "google", "", map[string]any{"client_id": "cid"}, map[string]string{"client_id": "cid", "client_secret": "sec"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.store.PutCredential("google:test@x", "oauth_token", "google", "test@x",
		map[string]any{"email": "test@x", "default": true, "default_for": []any{"drive", "youtube", "gmail"}, "status": "ok"},
		map[string]string{"refresh_token": "rt"}); err != nil {
		t.Fatal(err)
	}
}

// mcpDo drives the /mcp endpoint through the full handler, like the Astra probe.
func mcpDo(h *harness, key, origin, session string, initialize bool) *httptest.ResponseRecorder {
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	if !initialize {
		body = `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	}
	r := httptest.NewRequest("POST", "http://localhost:7399/mcp", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if session != "" {
		r.Header.Set("Mcp-Session-Id", session)
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, r)
	return w
}

// Astra 1 (JSON-escaping half): escaped forms of a normal-length secret are
// redacted in a native result. (Short secrets remain un-fingerprintable; see
// threat-model known issues.)
func TestFixJSONEscapedRedaction(t *testing.T) {
	h := newHarness(t)
	key := h.agent("a1")
	for _, value := range []string{"fixture<&>credential-long", "fixture\"credential-long", "fixture\\credential-long"} {
		if r := h.do("POST", "/admin/api/credentials", map[string]any{"name": "demo", "fields": map[string]string{"token": value}}, nil, true); r.code != 200 {
			t.Fatal("fixture failed")
		}
		r := h.do("POST", "/v1/actions/test.leak", map[string]any{"args": map[string]any{}}, bearer(key), false)
		if strings.Contains(string(r.raw), value) {
			t.Fatalf("escaped secret %q leaked: %s", value, r.raw)
		}
		if !strings.Contains(string(r.raw), "REDACTED") {
			t.Fatalf("value %q not redacted: %s", value, r.raw)
		}
	}
}

// Astra 2: a foreign browser Origin is refused on /mcp; a cross-agent session
// stays refused.
func TestFixMCPForeignOriginRejected(t *testing.T) {
	h := newHarness(t)
	key := h.agent("a1")
	if w := mcpDo(h, key, "https://untrusted.example", "", true); w.Code != 403 {
		t.Fatalf("foreign Origin accepted on /mcp: %d", w.Code)
	}
	// no Origin (server-to-server) still works
	w := mcpDo(h, key, "", "", true)
	if w.Code != 200 {
		t.Fatalf("no-Origin initialize rejected: %d", w.Code)
	}
	sid := w.Header().Get("Mcp-Session-Id")
	other := h.agent("other")
	if w := mcpDo(h, other, "", sid, false); w.Code == 200 {
		t.Fatal("cross-agent session accepted")
	}
}

// Astra 3 & 11: a token minted for another origin is refused on /mcp and REST.
func TestFixOAuthAudienceRejected(t *testing.T) {
	h := newHarness(t)
	a, _, _ := h.s.store.CreateAgent("aud", store.Policy{})
	at, _, _ := h.s.store.IssueTokens(a.ID, "c", "", "https://other-origin.example/mcp", "ralx", time.Hour, time.Hour)
	if w := mcpDo(h, at, "", "", true); w.Code == 200 {
		t.Fatalf("foreign-audience token accepted on /mcp: %d", w.Code)
	}
	if r := h.do("GET", "/v1/whoami", nil, bearer(at), false); r.code == 200 {
		t.Fatalf("foreign-audience token accepted on REST: %d", r.code)
	}
}

// Astra 4/10 (broken path): the old policy-skipping /v1/uploads youtube target
// is gone; YouTube uploads go through the gated youtube.upload action.
func TestFixYouTubeUploadTargetRemoved(t *testing.T) {
	h := newHarness(t)
	key := h.agent("a1")
	r := h.do("POST", "/v1/uploads", map[string]any{"target": "youtube", "title": "x", "privacy": "public", "size": 1}, bearer(key), false)
	if r.code == 200 || r.code == 202 {
		t.Fatalf("youtube upload target still served: %d %s", r.code, r.raw)
	}
}

// Astra 5: an approval whose agent policy was narrowed to forbid the action
// does not execute.
func TestFixApprovalRechecksPolicy(t *testing.T) {
	h := newHarness(t)
	key := h.agent("a1")
	r := h.do("POST", "/v1/actions/test.danger", map[string]any{"args": map[string]any{"thing": "repo"}}, bearer(key), false)
	id := r.body["approval_id"].(string)
	a, _, _, _, _ := h.s.authenticateBearer(key)
	if err := h.s.store.SetAgentPolicy(a.ID, store.Policy{Deny: []string{"test.danger"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.s.store.DecideApproval(id, "approved", "test"); err != nil {
		t.Fatal(err)
	}
	h.s.runApproval(id)
	ap, _ := h.s.store.GetApproval(id)
	if ap.Status != "failed" {
		t.Fatalf("narrowed-policy approval executed: %s", ap.Status)
	}
}

// Astra 6: after a policy change, a new MCP session advertises only the
// permitted tools.
func TestFixMCPCatalogReflectsPolicy(t *testing.T) {
	h := newHarness(t)
	key := h.agent("a1")
	a, _, _, _, _ := h.s.authenticateBearer(key)
	if err := h.s.store.SetAgentPolicy(a.ID, store.Policy{Allow: []string{"gh.repo.list"}}); err != nil {
		t.Fatal(err)
	}
	w := mcpDo(h, key, "", "", true)
	sid := w.Header().Get("Mcp-Session-Id")
	w = mcpDo(h, key, "", sid, false)
	if strings.Contains(w.Body.String(), "gh_repo_delete") {
		t.Fatalf("forbidden tool still advertised: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "gh_repo_list") {
		t.Fatal("permitted tool missing")
	}
}

// Astra 7: a client can only revoke its own grant.
func TestFixRevokeOnlyOwnClient(t *testing.T) {
	h := newHarness(t)
	a, _, _ := h.s.store.CreateAgent("rv", store.Policy{})
	c1, _, _ := h.s.store.RegisterOAuthClient("one", []string{"https://one.example/cb"}, nil, false)
	c2, _, _ := h.s.store.RegisterOAuthClient("two", []string{"https://two.example/cb"}, nil, false)
	at, rt, _ := h.s.store.IssueTokens(a.ID, c1.ID, "", "https://x/mcp", "ralx", time.Hour, time.Hour)
	// c2 tries to revoke c1's refresh token
	form := "client_id=" + c2.ID + "&token=" + rt
	req := httptest.NewRequest("POST", "http://localhost:7399/oauth/revoke", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("revoke status %d", rec.Code)
	}
	if _, _, err := h.s.store.AuthenticateAccessToken(at); err != nil {
		t.Fatal("another client revoked this grant")
	}
	// the owning client can revoke it
	form = "client_id=" + c1.ID + "&token=" + rt
	req = httptest.NewRequest("POST", "http://localhost:7399/oauth/revoke", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.h.ServeHTTP(httptest.NewRecorder(), req)
	if _, _, err := h.s.store.AuthenticateAccessToken(at); err == nil {
		t.Fatal("owning client's revoke did not take effect")
	}
}

// Astra 8 (ceremony expiry): a pending passkey ceremony older than its TTL is
// refused server-side, regardless of the browser/authenticator timeout.
func TestFixCeremonyExpiry(t *testing.T) {
	h := newHarness(t)
	h.setupPasskey()
	if _, err := h.s.admin.beginAssertion("op:test:reveal:demo", "localhost"); err != nil {
		t.Fatal(err)
	}
	// fresh ceremony is usable
	h.s.admin.mu.Lock()
	for k, p := range h.s.admin.pending {
		p.created = time.Now().Add(-ceremonyTTL - time.Second)
		h.s.admin.pending[k] = p
	}
	keys := make([]string, 0, len(h.s.admin.pending))
	for k := range h.s.admin.pending {
		keys = append(keys, k)
	}
	h.s.admin.mu.Unlock()
	if len(keys) == 0 {
		t.Fatal("no pending ceremony")
	}
	if _, ok := h.s.admin.takePending(keys[0], "localhost"); ok {
		t.Fatal("expired ceremony was accepted")
	}
}

// Astra 8 (consent binding): the passkey is bound to the chosen agent and
// access, so an assertion signed for one can't approve a different one.
func TestFixConsentBindsAgentAccess(t *testing.T) {
	h := newHarness(t)
	h.setupPasskey()
	c, _, _ := h.s.store.RegisterOAuthClient("fix", []string{"https://fix.example/cb"}, nil, false)
	id := "consent-fix"
	h.s.oauth.mu.Lock()
	h.s.oauth.requests[id] = &authRequest{ID: id, ClientID: c.ID, ClientName: c.Name, RedirectURI: c.RedirectURIs[0], Origin: h.s.origin, Resource: h.s.origin + "/mcp", Created: time.Now()}
	h.s.oauth.mu.Unlock()
	// Sign for agent "alpha", full access…
	assertion := h.stepUp("oauth.approve:" + id + ":alpha:full")
	// …but try to approve as "beta": refused.
	r := h.do("POST", "/oauth/approve", map[string]any{"id": id, "agent": "beta", "access": "full", "assertion": assertion}, h.browser(), false)
	if r.code == 200 {
		t.Fatal("consent for one agent approved a different agent")
	}
	// Sign for read access but try to approve full access: refused too (the op is
	// bound to the access level, not just the agent).
	readAssertion := h.stepUp("oauth.approve:" + id + ":alpha:read")
	r = h.do("POST", "/oauth/approve", map[string]any{"id": id, "agent": "alpha", "access": "full", "assertion": readAssertion}, h.browser(), false)
	if r.code == 200 {
		t.Fatal("consent signed for read access approved full access")
	}
	// the matching approval succeeds
	assertion = h.stepUp("oauth.approve:" + id + ":alpha:full")
	r = h.do("POST", "/oauth/approve", map[string]any{"id": id, "agent": "alpha", "access": "full", "assertion": assertion}, h.browser(), false)
	if r.code != 200 {
		t.Fatalf("matching consent rejected: %d %s", r.code, r.raw)
	}
}

// Astra 11: a completed final chunk reports Done with the full offset, not a
// stale pre-absorb snapshot.
func TestFixUploadSnapshotAfterAbsorb(t *testing.T) {
	h := newHarness(t)
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" { // resumable session init
			resp := fakeResp(r, 200, "")
			resp.Header.Set("Location", "https://upload.googleapis.test/session/xyz")
			return resp, nil
		}
		return fakeResp(r, 200, `{"id":"file1"}`), nil // final PUT
	})
	key := h.agent("a1")
	r := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "name": "f", "size": 1}, bearer(key), false)
	id, _ := r.body["upload_id"].(string)
	if id == "" {
		t.Fatalf("no upload id: %s", r.raw)
	}
	u, err := h.s.google.PutChunk(reqCtx(), id, "a1", 0, 1, strings.NewReader("A"))
	if err != nil {
		t.Fatal(err)
	}
	if !u.Done || u.Offset != 1 {
		t.Fatalf("final chunk returned stale snapshot: done=%v offset=%d", u.Done, u.Offset)
	}
}

func reqCtx() context.Context { return httptest.NewRequest("GET", "/", nil).Context() }
