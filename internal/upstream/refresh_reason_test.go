package upstream

// A refused refresh must say why (the provider's OAuth error code), so the owner
// screen can tell "sign-in expired" from a network or config problem. Synthetic
// values, fake transport; no sockets.
import (
	"net/http"
	"strings"
	"testing"
)

// Only the provider refusing the refresh token means the sign-in is dead. A rate
// limit, an outage or a garbled reply must stay retryable and keep the status.
func TestRefreshOnlyRefusalMarksReconnect(t *testing.T) {
	cases := []struct {
		status  int
		body    string
		refused bool
	}{
		{400, `{"error":"invalid_grant"}`, true},
		{401, `{"error":"invalid_client"}`, true},
		{400, `{"error":"unauthorized_client"}`, true},
		{403, `{}`, true},
		{429, `{"error":"rate_limited"}`, false},
		{500, `{"error":"server_error"}`, false},
		{503, `<html>down</html>`, false},
		{200, `not json`, false},
		{200, `{}`, false},
		{400, `{"error":"temporarily_unavailable"}`, false},
	}
	for _, tc := range cases {
		m := astra2Manager(t)
		meta := map[string]any{"url": "https://first.example/mcp", "auth": "oauth", "gen": "generation-a", "client_id": "synthetic-a", "token_endpoint": "https://first.example/token", "resource": "https://first.example/mcp", "status": "ok"}
		if _, err := m.Store.PutCredential("mcp:demo", "mcp_server", "mcp", "fixture", meta, map[string]string{"access_token": "SyntheticExpiredCredential0123456789", "refresh_token": "SyntheticRefreshCredential012345", "expires_at": "0"}); err != nil {
			t.Fatal(err)
		}
		m.Transport = astra2RT(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/token" {
				return astra2Response(r, tc.status, tc.body), nil
			}
			t.Fatalf("request reached %s without a token", r.URL)
			return nil, nil
		})
		c, _ := m.Store.GetCredential("mcp:demo")
		f, _ := m.Store.Secret("mcp:demo")
		rt := &authRT{m: m, name: "demo", conf: confOf(c), genfp: connGen(c, f)}
		req, _ := http.NewRequest("POST", "https://first.example/mcp", strings.NewReader("{}"))
		res, err := rt.RoundTrip(req)
		if res != nil {
			res.Body.Close()
		}
		after, _ := m.Store.GetCredential("mcp:demo")
		gotRefused := err != nil && strings.Contains(err.Error(), signInRefused)
		if err == nil || gotRefused != tc.refused || (after.Meta["status"] == "reconnect_needed") != tc.refused {
			t.Errorf("%d %s: refused=%v want %v, status=%v, err=%v", tc.status, tc.body, gotRefused, tc.refused, after.Meta["status"], err)
		}
	}
}

func TestRefreshRefusalKeepsProviderReason(t *testing.T) {
	m := astra2Manager(t)
	const refresh = "SyntheticRefusedRefreshCredential012345"
	meta := map[string]any{"url": "https://first.example/mcp", "auth": "oauth", "gen": "generation-a", "client_id": "synthetic-a", "token_endpoint": "https://first.example/token", "resource": "https://first.example/mcp"}
	if _, err := m.Store.PutCredential("mcp:demo", "mcp_server", "mcp", "fixture", meta, map[string]string{"access_token": "SyntheticExpiredCredential0123456789", "refresh_token": refresh, "expires_at": "0"}); err != nil {
		t.Fatal(err)
	}
	m.Transport = astra2RT(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			return astra2Response(r, 400, `{"error":"invalid_grant"}`), nil
		}
		t.Fatalf("request reached %s without a token", r.URL)
		return nil, nil
	})
	c, _ := m.Store.GetCredential("mcp:demo")
	f, _ := m.Store.Secret("mcp:demo")
	rt := &authRT{m: m, name: "demo", conf: confOf(c), genfp: connGen(c, f)}
	req, _ := http.NewRequest("POST", "https://first.example/mcp", strings.NewReader("{}"))
	res, err := rt.RoundTrip(req)
	if res != nil {
		res.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") || !strings.Contains(err.Error(), "reconnect") {
		t.Fatalf("refusal reason lost: %v", err)
	}
	if strings.Contains(err.Error(), refresh) {
		t.Fatal("error carried the refresh token")
	}
	after, _ := m.Store.GetCredential("mcp:demo")
	if after.Meta["status"] != "reconnect_needed" {
		t.Fatalf("status = %v", after.Meta["status"])
	}
}

// R4: a refresh on the old refresh token that is refused after the owner
// reconnected must not flag the new sign-in.
func TestStaleRefreshRefusalKeepsReconnectedStatus(t *testing.T) {
	m := astra2Manager(t)
	put := func(gen, refresh string) {
		meta := map[string]any{"url": "https://first.example/mcp", "auth": "oauth", "gen": gen, "client_id": "synthetic-a", "token_endpoint": "https://first.example/token", "resource": "https://first.example/mcp", "status": "ok"}
		if _, err := m.Store.PutCredential("mcp:demo", "mcp_server", "mcp", "fixture", meta, map[string]string{"access_token": "SyntheticExpiredCredential0123456789", "refresh_token": refresh, "expires_at": "0"}); err != nil {
			t.Fatal(err)
		}
	}
	put("generation-a", "SyntheticRefreshCredentialOld0123")
	m.Transport = astra2RT(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			put("generation-b", "SyntheticRefreshCredentialNew0123") // the owner reconnects meanwhile
			return astra2Response(r, 400, `{"error":"invalid_grant"}`), nil
		}
		t.Fatalf("request reached %s without a token", r.URL)
		return nil, nil
	})
	c, _ := m.Store.GetCredential("mcp:demo")
	f, _ := m.Store.Secret("mcp:demo")
	rt := &authRT{m: m, name: "demo", conf: confOf(c), genfp: connGen(c, f)}
	req, _ := http.NewRequest("POST", "https://first.example/mcp", strings.NewReader("{}"))
	if res, _ := rt.RoundTrip(req); res != nil {
		res.Body.Close()
	}
	if after, _ := m.Store.GetCredential("mcp:demo"); after.Meta["status"] != "ok" {
		t.Fatalf("an old refresh's refusal flagged the reconnected sign-in: %v", after.Meta["status"])
	}
}
