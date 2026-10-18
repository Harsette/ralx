package daemon

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/store"
)

// Astra3 probes, inverted: each asserts the FIX. All outbound requests use fake
// transports, and the actual inbound routes use Recorders with no sockets.
func TestAstra3ReproMCPApprovalSurvivesGrantRevocation(t *testing.T) {
	h := newHarness(t)
	a, _, err := h.s.store.CreateAgent("astra3-mcp-grant", store.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	at, rt, err := h.s.store.IssueTokens(a.ID, "synthetic-client", "", h.s.origin+"/mcp", "ralx", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	init := mcpDo(h, at, "", "", true)
	if init.Code != 200 {
		t.Fatalf("initialize: %d %s", init.Code, init.Body.String())
	}
	req := httptest.NewRequest("POST", h.s.origin+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"test_danger","arguments":{"thing":"repo"}}}`))
	req.Header.Set("Authorization", "Bearer "+at)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", init.Header().Get("Mcp-Session-Id"))
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "HELD") {
		t.Fatalf("tool call: %d %s", w.Code, w.Body.String())
	}
	aps, err := h.s.store.ListApprovals("pending", 10)
	if err != nil || len(aps) != 1 {
		t.Fatalf("approvals: %v %v", aps, err)
	}
	ap := aps[0]
	// Fixed: an /mcp tool call binds the grant family, and after the grant is
	// revoked its queued action is refused at run time.
	if ap.GrantFamily == "" {
		t.Fatal("MCP approval has no grant family")
	}
	h.s.store.RevokeToken(rt)
	if got := mcpDo(h, at, "", "", true); got.Code != 401 {
		t.Fatalf("revoked MCP auth: %d", got.Code)
	}
	// Fixed: revoke cancels the pending /mcp approval.
	if a2, _ := h.s.store.GetApproval(ap.ID); a2.Status != "denied" {
		t.Fatalf("revoke should have cancelled the /mcp approval, got %s", a2.Status)
	}
	if err := h.s.store.DecideApproval(ap.ID, "approved", "synthetic owner"); err == nil {
		t.Fatal("a cancelled /mcp approval was approvable")
	}
	h.s.runApproval(ap.ID)
	ap, err = h.s.store.GetApproval(ap.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ap.Status == "executed" {
		t.Fatalf("revoked grant's /mcp action still executed: %s", ap.Status)
	}
}

func TestAstra3ReproSharedDriveMissingGrantAndRecipientBinding(t *testing.T) {
	h := newHarness(t)
	lookups, uploads := 0, 0
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		switch r.Method {
		case "GET":
			if strings.Contains(r.URL.Path, "/permissions") {
				lookups++ // count permissions.list (the real audience source)
				return fakeResp(r, 200, `{"permissions":[{"type":"user","role":"reader","emailAddress":"initial@example.invalid"}]}`), nil
			}
			return fakeResp(r, 200, `{"name":"F","shared":true,"ownedByMe":true}`), nil
		case "POST":
			res := fakeResp(r, 200, "")
			res.Header.Set("Location", "https://upload.example/session/astra3-synthetic")
			return res, nil
		case "PUT":
			data, _ := io.ReadAll(r.Body)
			if string(data) != "GOOD" {
				t.Fatalf("unexpected data %q", data)
			}
			uploads++
			return fakeResp(r, 200, `{"id":"synthetic-file"}`), nil
		}
		t.Fatalf("unexpected request %s", r.Method)
		return nil, nil
	})
	a, key, err := h.s.store.CreateAgent("astra3-drive-grant", store.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	at, rt, err := h.s.store.IssueTokens(a.ID, "synthetic-client", "", h.s.origin+"/mcp", "ralx", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f, err := h.s.staging.start(a.ID, "approved.txt", "text/plain", 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.staging.put(f.ID, a.ID, 0, 4, strings.NewReader("GOOD")); err != nil {
		t.Fatal(err)
	}
	r := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "media_upload_id": f.ID, "parent_id": "sharedfolder123", "account": "test@x"}, bearer(at), false)
	if r.code != 202 || lookups != 1 {
		t.Fatalf("queue upload: %d lookups=%d %s", r.code, lookups, r.raw)
	}
	id := r.body["approval_id"].(string)
	ap, err := h.s.store.GetApproval(id)
	if err != nil {
		t.Fatal(err)
	}
	// Fixed: the shared-Drive approval carries the grant family.
	if ap.GrantFamily == "" {
		t.Fatal("shared-Drive approval has no grant family")
	}
	h.s.store.RevokeToken(rt)
	if got := h.do("GET", "/v1/whoami", nil, bearer(at), false); got.code != 401 {
		t.Fatalf("revoked auth: %d", got.code)
	}
	// Fixed: revoking the grant cancels the pending shared-Drive approval, so it
	// can't be approved or finished — not even with another live key for the
	// same agent.
	if a2, _ := h.s.store.GetApproval(id); a2.Status != "denied" {
		t.Fatalf("revoke should have cancelled the Drive approval, got %s", a2.Status)
	}
	if err := h.s.store.DecideApproval(id, "approved", "synthetic owner"); err == nil {
		t.Fatal("a cancelled Drive approval was approvable")
	}
	done := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "approval_id": id}, bearer(key), false)
	if done.code == 200 {
		t.Fatalf("revoked grant's upload was finished: %s", done.raw)
	}
	if uploads != 0 {
		t.Fatalf("bytes were uploaded after revoke: %d", uploads)
	}
}

func TestAstra3ReproSharedDriveDefaultAccountChangesAfterApproval(t *testing.T) {
	h := newHarness(t)
	var used []string
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		used = append(used, r.Method+" "+r.Header.Get("Authorization"))
		switch r.Method {
		case "GET":
			return fakeResp(r, 200, `{"shared":true,"ownedByMe":true,"permissions":[{"type":"anyone"}]}`), nil
		case "POST":
			res := fakeResp(r, 200, "")
			res.Header.Set("Location", "https://upload.example/session/astra3-other-account")
			return res, nil
		case "PUT":
			return fakeResp(r, 200, `{"id":"synthetic-file"}`), nil
		}
		t.Fatalf("unexpected request: %s", r.Method)
		return nil, nil
	})
	base := h.s.google.HTTP.Transport
	h.s.google.HTTP.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "oauth2.googleapis.com" {
			_ = r.ParseForm()
			if r.Form.Get("refresh_token") == "synthetic-other-refresh" {
				return fakeResp(r, 200, `{"access_token":"synthetic-account-b-access","expires_in":3600}`), nil
			}
			return fakeResp(r, 200, `{"access_token":"synthetic-account-a-access","expires_in":3600}`), nil
		}
		return base.RoundTrip(r)
	})
	if _, err := h.s.store.PutCredential("google:other@x", "oauth_token", "google", "other@x", map[string]any{"email": "other@x", "status": "ok"}, map[string]string{"refresh_token": "synthetic-other-refresh"}); err != nil {
		t.Fatal(err)
	}
	key := h.agent("astra3-account")
	a := mustAgent(t, h, "astra3-account")
	f, err := h.s.staging.start(a.ID, "approved.txt", "text/plain", 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.staging.put(f.ID, a.ID, 0, 4, strings.NewReader("GOOD")); err != nil {
		t.Fatal(err)
	}
	r := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "media_upload_id": f.ID, "parent_id": "sharedfolder123"}, bearer(key), false)
	if r.code != 202 {
		t.Fatalf("queue upload: %d %s", r.code, r.raw)
	}
	id := r.body["approval_id"].(string)
	if err := h.s.store.DecideApproval(id, "approved", "synthetic owner"); err != nil {
		t.Fatal(err)
	}
	if err := h.s.google.SetDefaultFor("other@x", []string{"drive"}); err != nil {
		t.Fatal(err)
	}
	done := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "approval_id": id}, bearer(key), false)
	if done.code != 200 {
		t.Fatalf("finish: %d %s", done.code, done.raw)
	}
	joined := strings.Join(used, ";")
	// Fixed: the approval resolved and stored account A, so the server-side upload
	// uses A even after the default changed to B.
	if strings.Contains(joined, "Bearer synthetic-account-b-access") {
		t.Fatalf("approved upload used the changed default account B: %s", joined)
	}
	if !strings.Contains(joined, "POST Bearer synthetic-account-a-access") {
		t.Fatalf("approved upload did not use the resolved account A: %s", joined)
	}
}
