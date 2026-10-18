package upstream

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestAstra8HeldOAuthRereadRejectsReplacement(t *testing.T) {
	m := astra2Manager(t)
	meta := map[string]any{"url": "https://first.example/mcp", "auth": "oauth", "gen": "synthetic-a", "client_id": "fixture", "token_endpoint": "https://first.example/token"}
	if _, err := m.Store.PutCredential("mcp:demo", "mcp_server", "mcp", "fixture", meta, map[string]string{"access_token": "SyntheticExpiredAccess0123456789", "refresh_token": "SyntheticRefreshA0123456789", "expires_at": "0"}); err != nil {
		t.Fatal(err)
	}
	c, f, err := m.Store.SecretWithMeta("mcp:demo")
	if err != nil {
		t.Fatal(err)
	}
	oldGen := connGen(c, f)
	meta["gen"], meta["url"] = "synthetic-b", "https://second.example/mcp"
	if _, err := m.Store.PutCredential("mcp:demo", "mcp_server", "mcp", "fixture", meta, map[string]string{"access_token": "SyntheticReplacementAccess9876543210", "expires_at": fmt.Sprint(time.Now().Add(time.Hour).Unix())}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	m.Transport = astra2RT(func(r *http.Request) (*http.Response, error) { calls++; return astra2Response(r, 200, "{}"), nil })
	if tok, err := m.accessToken(context.Background(), "demo", f, oldGen); err == nil || tok != "" {
		t.Fatal("replacement token returned for old generation")
	}
	if calls != 0 {
		t.Fatalf("unexpected transport calls: %d", calls)
	}
	t.Log("expired snapshot followed by replacement: lock-time reread refuses replacement, zero transport calls")
}
