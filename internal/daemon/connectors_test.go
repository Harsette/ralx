package daemon

// The owner home screen: every connector this build supports, its real status,
// and a connect flow per connector. Synthetic values, fake Google; no sockets.
import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/store"
	"github.com/Harsette/ralx/internal/upstream"
)

func connectorsByID(t *testing.T, r resp) map[string]map[string]any {
	t.Helper()
	if r.code != 200 {
		t.Fatalf("connectors: %d %s", r.code, r.raw)
	}
	list, _ := r.body["connectors"].([]any)
	out := map[string]map[string]any{}
	for _, x := range list {
		c := x.(map[string]any)
		out[c["id"].(string)] = c
	}
	return out
}

func accountsOf(c map[string]any) []map[string]any {
	var out []map[string]any
	for _, x := range c["accounts"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

func TestConnectorsHomeIsOwnerOnly(t *testing.T) {
	h := newHarness(t)
	const synthetic = "ghp_SyntheticConnectorsHomeToken0123456789"
	if _, err := h.s.store.PutCredential("github", "api_key", "github", "GitHub (fixture)", nil, map[string]string{"token": synthetic}); err != nil {
		t.Fatal(err)
	}
	if r := h.do("GET", "/admin/api/connectors", nil, nil, false); r.code != 401 {
		t.Fatalf("signed-out browser got the connectors list: %d %s", r.code, r.raw)
	}
	key := h.agent("connectors-agent")
	if r := h.do("GET", "/admin/api/connectors", nil, bearer(key), false); r.code != 401 {
		t.Fatalf("agent key got the owner connectors list: %d %s", r.code, r.raw)
	}
	h.setupPasskey()
	r := h.do("GET", "/admin/api/connectors", nil, h.browser(), false)
	if r.code != 200 {
		t.Fatalf("signed-in owner: %d %s", r.code, r.raw)
	}
	if strings.Contains(string(r.raw), synthetic) {
		t.Fatal("connectors list carried a stored secret value")
	}
	// A signed-in session from a public internet peer is refused, like the rest
	// of the credential surface.
	req := httptest.NewRequest("GET", "http://localhost:7399/admin/api/connectors", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("public peer with a session got the list: %d", rec.Code)
	}
}

func TestConnectorsListEverySupportedService(t *testing.T) {
	h := newHarness(t)
	got := connectorsByID(t, h.do("GET", "/admin/api/connectors", nil, nil, true))
	for _, id := range []string{"google", "github", "vercel", "cloudflare", "uploadpost", "notion"} {
		c, ok := got[id]
		if !ok {
			t.Fatalf("connector %s missing from the home screen: %v", id, got)
		}
		if c["status"] != "not_connected" && c["status"] != "setup_needed" {
			t.Fatalf("%s should start not connected, got %v", id, c["status"])
		}
		switch c["connect"] {
		case "google", "key", "cli", "mcp_oauth":
		default:
			t.Fatalf("%s has no connect flow: %v", id, c["connect"])
		}
	}
	// Every credential a built-in action needs must have a row, so a new
	// catalog can't silently be missing from the home screen.
	creds := map[string]bool{}
	for _, c := range got {
		if s, _ := c["credential"].(string); s != "" {
			creds[s] = true
		}
	}
	for _, a := range h.s.reg.List() {
		for _, req := range a.Requires {
			if req == "google" || strings.HasPrefix(req, "mcp:") || strings.HasPrefix(a.Name, "test.") {
				continue
			}
			if !creds[req] {
				t.Fatalf("action %s needs credential %q but no connector offers it", a.Name, req)
			}
		}
	}
}

func TestConnectorsShowRealStatus(t *testing.T) {
	h := newHarness(t)
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) { return fakeResp(r, 200, "{}"), nil })
	if _, err := h.s.store.PutCredential("google:second@example.com", "oauth_token", "google", "second@example.com",
		map[string]any{"email": "second@example.com", "status": "reconnect_needed", "services": []any{"gmail"}},
		map[string]string{"refresh_token": "synthetic-second-refresh-0123456789"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.store.PutCredential("github", "api_key", "github", "GitHub (fixture)", nil, map[string]string{"token": "ghp_SyntheticStatusToken0123456789abc"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.store.PutCredential("uploadpost", "api_key", "uploadpost", "Upload-Post", nil, map[string]string{"api_key": "SyntheticUploadPostKey0123456789"}); err != nil {
		t.Fatal(err)
	}
	notionErr := `calling "initialize": rejected by transport: notion sign-in expired (token endpoint returned 400 invalid_grant); reconnect it in RalX`
	if _, err := h.s.store.PutCredential("mcp:notion", "mcp_server", "mcp", "notion (MCP)",
		map[string]any{"url": "https://mcp.notion.com/mcp", "auth": "oauth", "status": "error", "error": notionErr},
		map[string]string{"access_token": "SyntheticNotionAccess0123456789", "refresh_token": "SyntheticNotionRefresh0123456789", "expires_at": "0"}); err != nil {
		t.Fatal(err)
	}
	got := connectorsByID(t, h.do("GET", "/admin/api/connectors", nil, nil, true))

	g := got["google"]
	accts := accountsOf(g)
	if len(accts) != 2 {
		t.Fatalf("both Google accounts should show: %v", accts)
	}
	status := map[string]string{}
	for _, a := range accts {
		status[a["label"].(string)] = a["status"].(string)
	}
	if status["test@x"] != "ok" || status["second@example.com"] != "error" {
		t.Fatalf("per-account Google status wrong: %v", status)
	}
	if g["status"] != "error" {
		t.Fatalf("a Google account needing reconnect should flag the row: %v", g["status"])
	}
	if got["github"]["status"] != "connected" || len(accountsOf(got["github"])) != 1 {
		t.Fatalf("github: %v", got["github"])
	}
	if got["cloudflare"]["status"] != "not_connected" || got["vercel"]["status"] != "not_connected" {
		t.Fatalf("unconnected services shown as connected: %v %v", got["cloudflare"], got["vercel"])
	}
	if up := got["uploadpost"]; up["status"] != "error" || !strings.Contains(up["reason"].(string), "profile") {
		t.Fatalf("Upload-Post without a profile can't post and should say so: %v", up)
	}
	n := got["notion"]
	if n["status"] != "error" || !strings.Contains(n["reason"].(string), "expired") || !strings.Contains(n["detail"].(string), "invalid_grant") {
		t.Fatalf("notion error not explained: %v", n)
	}
	if n["url"] != "https://mcp.notion.com/mcp" {
		t.Fatalf("notion reconnect needs its server URL: %v", n["url"])
	}
}

func TestGoogleConnectOffersAccountChooser(t *testing.T) {
	h := newHarness(t)
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) { return fakeResp(r, 200, "{}"), nil })
	h.setupPasskey()
	r := h.do("POST", "/admin/api/connect/google", map[string]any{"services": []string{"gmail", "drive", "youtube"}}, h.browser(), false)
	if r.code != 200 {
		t.Fatalf("connect google: %d %s", r.code, r.raw)
	}
	u, err := url.Parse(r.body["auth_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "accounts.google.com" || q.Get("prompt") != "select_account consent" || q.Get("login_hint") != "" {
		t.Fatalf("add-another-account URL must open Google's account chooser: %s", u)
	}
	if !strings.HasSuffix(q.Get("redirect_uri"), "/oauth/google/callback") || q.Get("access_type") != "offline" {
		t.Fatalf("consent URL lost its callback/offline access: %s", u)
	}
	// Reconnecting a named account goes straight to that account.
	r = h.do("POST", "/admin/api/connect/google", map[string]any{"login_hint": "test@x"}, h.browser(), false)
	u, _ = url.Parse(r.body["auth_url"].(string))
	if u.Query().Get("login_hint") != "test@x" || u.Query().Get("prompt") != "consent" {
		t.Fatalf("reconnect URL should target the named account: %s", u)
	}
}

func syntheticIDToken(email string) string {
	enc := base64.RawURLEncoding.EncodeToString
	payload, _ := json.Marshal(map[string]any{"email": email})
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(payload) + ".sig"
}

func TestSecondGoogleAccountConnectsAndSearchesByAccount(t *testing.T) {
	h := newHarness(t)
	accessFor := map[string]string{ // refresh token -> access token
		"rt":                                  "synthetic-access-first-0123456789",
		"synthetic-refresh-second-0123456789": "synthetic-access-second-0123456789",
	}
	subjectFor := map[string]string{
		"Bearer synthetic-access-first-0123456789":  "subject-first",
		"Bearer synthetic-access-second-0123456789": "subject-second",
	}
	seedGoogle(t, h, nil)
	h.s.google.HTTP.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "oauth2.googleapis.com" {
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			switch r.Form.Get("grant_type") {
			case "authorization_code":
				if r.Form.Get("code") != "synthetic-code-second" {
					return fakeResp(r, 400, `{"error":"invalid_grant"}`), nil
				}
				return fakeResp(r, 200, `{"access_token":"synthetic-access-second-0123456789","expires_in":3600,"refresh_token":"synthetic-refresh-second-0123456789",`+
					`"scope":"openid email https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.compose","id_token":"`+syntheticIDToken("second@example.com")+`"}`), nil
			case "refresh_token":
				if a, ok := accessFor[r.Form.Get("refresh_token")]; ok {
					return fakeResp(r, 200, `{"access_token":"`+a+`","expires_in":3600}`), nil
				}
				return fakeResp(r, 400, `{"error":"invalid_grant"}`), nil
			}
		}
		if r.URL.Host == "gmail.googleapis.com" {
			subject, ok := subjectFor[r.Header.Get("Authorization")]
			if !ok {
				return fakeResp(r, 401, `{}`), nil
			}
			if strings.HasSuffix(r.URL.Path, "/messages") {
				return fakeResp(r, 200, `{"messages":[{"id":"fixturemsg01","threadId":"fixturethread01"}],"resultSizeEstimate":1}`), nil
			}
			return fakeResp(r, 200, `{"id":"fixturemsg01","threadId":"fixturethread01","snippet":"s","payload":{"headers":[{"name":"Subject","value":"`+subject+`"}]}}`), nil
		}
		t.Fatalf("unexpected request %s", r.URL)
		return nil, nil
	})

	h.setupPasskey()
	start := h.do("POST", "/admin/api/connect/google", map[string]any{}, h.browser(), false)
	if start.code != 200 {
		t.Fatalf("start: %d %s", start.code, start.raw)
	}
	u, _ := url.Parse(start.body["auth_url"].(string))
	state := u.Query().Get("state")
	cb := h.do("GET", "/oauth/google/callback?state="+url.QueryEscape(state)+"&code=synthetic-code-second", nil, nil, false)
	if cb.code != 200 || !strings.Contains(string(cb.raw), "Google is connected") {
		t.Fatalf("callback: %d %s", cb.code, cb.raw)
	}

	got := connectorsByID(t, h.do("GET", "/admin/api/connectors", nil, h.browser(), false))
	labels := map[string]bool{}
	for _, a := range accountsOf(got["google"]) {
		labels[a["label"].(string)] = true
	}
	if !labels["test@x"] || !labels["second@example.com"] {
		t.Fatalf("both Google accounts should appear after the second Allow: %v", labels)
	}

	key := h.agent("claude-code")
	search := func(account string) string {
		args := map[string]any{"q": "in:inbox", "max": 1}
		if account != "" {
			args["account"] = account
		}
		r := h.do("POST", "/v1/actions/gmail.search", map[string]any{"args": args}, bearer(key), false)
		if r.code != 200 {
			t.Fatalf("gmail.search %q: %d %s", account, r.code, r.raw)
		}
		return string(r.raw)
	}
	if out := search("second@example.com"); !strings.Contains(out, "subject-second") {
		t.Fatalf("second account search used the wrong mailbox: %s", out)
	}
	if out := search("test@x"); !strings.Contains(out, "subject-first") {
		t.Fatalf("first account search used the wrong mailbox: %s", out)
	}
	if out := search(""); !strings.Contains(out, "subject-first") {
		t.Fatalf("default account changed after adding a second one: %s", out)
	}
}

// After a refused Vercel call the owner reconnects through Vercel's own login;
// the old refusal, and any failed connect attempt, must not keep the row saying
// the login looks expired (R3).
func TestVercelReconnectClearsOldRefusal(t *testing.T) {
	h := newHarness(t)
	if h.s.run.Tools == nil {
		h.s.run.Tools = map[string]string{}
	}
	h.s.run.Tools["vercel"] = filepath.Join(t.TempDir(), "vercel.exe")
	if _, err := h.s.store.PutCredential("vercel", "token", "vercel", "Vercel", nil, map[string]string{"token": "synthetic-vercel-old-0123456789"}); err != nil {
		t.Fatal(err)
	}
	h.s.store.Audit("fixture-agent", "vercel.projects.list", "error", 0, "vercel: HTTP 401: invalid token")
	if g := connectorsByID(t, h.do("GET", "/admin/api/connectors", nil, nil, true))["vercel"]; g["status"] != "error" {
		t.Fatalf("a refused last call should flag the row: %v", g)
	}
	spec := cliLogins["vercel"]
	spec.harvest = func(*Server, string) (map[string]string, map[string]any, error) {
		return map[string]string{"token": "synthetic-vercel-new-0123456789"}, map[string]any{}, nil
	}
	if err := h.s.saveCLILogin("hamza", spec, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if g := connectorsByID(t, h.do("GET", "/admin/api/connectors", nil, nil, true))["vercel"]; g["status"] != "connected" {
		t.Fatalf("a refusal from before the Vercel reconnect still flags the row: %v", g)
	}
	h.s.store.Audit("hamza", "vercel.connect", "error", 0, "unauthorized: device code expired")
	if g := connectorsByID(t, h.do("GET", "/admin/api/connectors", nil, nil, true))["vercel"]; g["status"] != "connected" {
		t.Fatalf("a failed connect attempt flagged the saved login: %v", g)
	}
}

// R4: only RalX's own login events are skipped. An upstream tool that happens
// to be called "connect" is an ordinary call, and its refusal flags the row.
func TestUpstreamConnectToolRefusalFlagsRow(t *testing.T) {
	h := newHarness(t)
	putHeaderUpstream(t, h, "demo", nil)
	h.s.store.Audit("fixture-agent", "demo.connect", "error", 0, "demo: HTTP 401: invalid token")
	if g := connectorsByID(t, h.do("GET", "/admin/api/connectors", nil, nil, true))["mcp:demo"]; g["status"] != "error" {
		t.Fatalf("a refused upstream tool named connect left the row connected: %v", g)
	}
}

// RalX audits its own "upstream.connect" events, so no upstream may be named
// "upstream", or its "connect" tool would be mistaken for one.
func TestUpstreamNameCannotShadowLoginEvents(t *testing.T) {
	for _, n := range []string{"upstream", "credential", "vercel", "google"} {
		if !upstream.ReservedName(n) {
			t.Errorf("%q is a RalX audit namespace but an upstream may take it", n)
		}
	}
}
// After a refused GitHub call the owner pastes a new key; the old refusal must
// not keep the row saying the login looks expired.
func TestConnectorReplacedKeyClearsOldRefusal(t *testing.T) {
	h := newHarness(t)
	if _, err := h.s.store.PutCredential("github", "api_key", "github", "GitHub token", nil, map[string]string{"token": "ghp_SyntheticRefusedToken0123456789abc"}); err != nil {
		t.Fatal(err)
	}
	h.s.store.Audit("fixture-agent", "gh.repo.list", "error", 0, "gh: HTTP 401: Bad credentials")
	if g := connectorsByID(t, h.do("GET", "/admin/api/connectors", nil, nil, true))["github"]; g["status"] != "error" {
		t.Fatalf("a refused last call should flag the row: %v", g)
	}
	r := h.do("POST", "/admin/api/credentials", map[string]any{"name": "github", "kind": "api_key", "provider": "github", "label": "GitHub token",
		"meta": map[string]any{}, "fields": map[string]string{"token": "ghp_SyntheticReplacedToken0123456789ab"}}, nil, true)
	if r.code != 200 {
		t.Fatalf("replace: %d %s", r.code, r.raw)
	}
	if g := connectorsByID(t, h.do("GET", "/admin/api/connectors", nil, nil, true))["github"]; g["status"] != "connected" {
		t.Fatalf("a refusal from before the key was replaced still flags the row: %v", g)
	}
}

// Replacing a key from the home screen keeps the owner's settings on it (e.g.
// the hosts it may be sent to); only the key itself and its bookkeeping change.
func TestConnectorKeyReplaceKeepsSettings(t *testing.T) {
	h := newHarness(t)
	if _, err := h.s.store.PutCredential("github", "api_key", "github", "GitHub token",
		map[string]any{"allowed_hosts": []string{"api.github.com"}, "status": "error"},
		map[string]string{"token": "ghp_SyntheticOldToken0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}
	r := h.do("POST", "/admin/api/credentials", map[string]any{"name": "github", "kind": "api_key", "provider": "github", "label": "GitHub token",
		"meta": map[string]any{}, "keep_meta": true, "fields": map[string]string{"token": "ghp_SyntheticNewToken0123456789abcdef"}}, nil, true)
	if r.code != 200 {
		t.Fatalf("replace: %d %s", r.code, r.raw)
	}
	c, _ := h.s.store.GetCredential("github")
	if hosts := metaStrings(c.Meta, "allowed_hosts"); len(hosts) != 1 || hosts[0] != "api.github.com" {
		t.Fatalf("replacing the key dropped its allowed hosts: %v", c.Meta)
	}
	if _, ok := c.Meta["status"]; ok {
		t.Fatalf("the old key's status carried over to the new key: %v", c.Meta)
	}
}

// R2-1: a home-screen key replacement merges the stored settings; if the owner
// tightens allowed_hosts in between, the replacement must not write back the
// earlier, wider allow-list.
func TestConnectorKeyReplaceDoesNotRestoreStaleSettings(t *testing.T) {
	h := newHarness(t)
	if _, err := h.s.store.PutCredential("github", "api_key", "github", "GitHub token",
		map[string]any{"allowed_hosts": []string{"api.github.com", "uploads.github.com"}},
		map[string]string{"token": "ghp_SyntheticOldToken0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}
	fired := false
	testHookKeepMetaMerged = func() {
		if fired {
			return
		}
		fired = true
		if _, err := h.s.store.PutCredential("github", "api_key", "github", "GitHub token",
			map[string]any{"allowed_hosts": []string{"api.github.com"}},
			map[string]string{"token": "ghp_SyntheticOldToken0123456789abcdef"}); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { testHookKeepMetaMerged = nil })
	r := h.do("POST", "/admin/api/credentials", map[string]any{"name": "github", "kind": "api_key", "provider": "github", "label": "GitHub token",
		"meta": map[string]any{}, "keep_meta": true, "fields": map[string]string{"token": "ghp_SyntheticNewToken0123456789abcdef"}}, nil, true)
	if r.code != 200 {
		t.Fatalf("replace: %d %s", r.code, r.raw)
	}
	if !fired {
		t.Fatal("hook never ran")
	}
	c, _ := h.s.store.GetCredential("github")
	if hosts := metaStrings(c.Meta, "allowed_hosts"); len(hosts) != 1 || hosts[0] != "api.github.com" {
		t.Fatalf("replacement restored the obsolete allow-list: %v", c.Meta["allowed_hosts"])
	}
	if f, _ := h.s.store.Secret("github"); f["token"] != "ghp_SyntheticNewToken0123456789abcdef" {
		t.Fatal("the replacement key was not stored")
	}
}

// R2-3: a call that started on the old key and finished (refused) after the
// owner saved a new one tried the old login; it must not flag the new key.
func TestConnectorSlowOldKeyRefusalAfterReplace(t *testing.T) {
	h := newHarness(t)
	if _, err := h.s.store.PutCredential("github", "api_key", "github", "GitHub token", nil, map[string]string{"token": "ghp_SyntheticRefusedToken0123456789abc"}); err != nil {
		t.Fatal(err)
	}
	r := h.do("POST", "/admin/api/credentials", map[string]any{"name": "github", "kind": "api_key", "provider": "github", "label": "GitHub token",
		"meta": map[string]any{}, "keep_meta": true, "fields": map[string]string{"token": "ghp_SyntheticReplacedToken0123456789ab"}}, nil, true)
	if r.code != 200 {
		t.Fatalf("replace: %d %s", r.code, r.raw)
	}
	// The old-key call began 5s ago, before the save, and is audited only now.
	h.s.store.Audit("fixture-agent", "gh.repo.list", "error", 5*time.Second, "gh: HTTP 401: Bad credentials")
	if g := connectorsByID(t, h.do("GET", "/admin/api/connectors", nil, nil, true))["github"]; g["status"] != "connected" {
		t.Fatalf("an old-key call that finished after the save flags the new key: %v", g)
	}
}

// A refusal of a call that started after the save is the new key's own and
// still flags the row; one that may have started in the save's second does not.
func TestLastCallRefusedUsesCallStart(t *testing.T) {
	put := &store.AuditEntry{ID: 1, TS: 100, Action: "credential.put", Outcome: "ok", Detail: "github via passkey"}
	refused := func(id, ts, durMS int64) *store.AuditEntry {
		return &store.AuditEntry{ID: id, TS: ts, Action: "gh.repo.list", Outcome: "error", DurationMS: durMS, Detail: "gh: HTTP 401: Bad credentials"}
	}
	pre := &store.AuditEntry{ID: 0, TS: 99, Action: "gh.repo.list", Outcome: "error", Detail: "gh: HTTP 401: Bad credentials"}
	cases := []struct {
		name  string
		audit []*store.AuditEntry
		want  bool
	}{
		{"refused before the save", []*store.AuditEntry{put, pre}, false},
		{"started after the save", []*store.AuditEntry{refused(2, 103, 500), put, pre}, true},
		{"started before the save", []*store.AuditEntry{refused(2, 103, 4000), put, pre}, false},
		{"started in the save's second", []*store.AuditEntry{refused(2, 100, 0), put, pre}, false},
		{"old-key refusal hides nothing newer", []*store.AuditEntry{refused(3, 104, 9000), refused(2, 103, 500), put}, true},
		{"never saved", []*store.AuditEntry{pre}, true},
	}
	for _, tc := range cases {
		if got := lastCallRefused(tc.audit, []string{"gh."}, "github"); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}
