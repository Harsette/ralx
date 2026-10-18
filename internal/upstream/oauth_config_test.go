package upstream

// R2-2: an OAuth upstream whose stored token endpoint can never work is a config
// problem, not a network one, so boot must not retry it forever. Synthetic values,
// fake transport; no sockets.
import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestLoadRejectsUnusableTokenEndpoint(t *testing.T) {
	for _, endpoint := range []string{"", "http://first.example/token", "https://127.0.0.1/token"} {
		m := astra2Manager(t)
		meta := map[string]any{"url": "https://first.example/mcp", "auth": "oauth", "gen": "generation-a", "client_id": "synthetic-a", "token_endpoint": endpoint, "resource": "https://first.example/mcp"}
		if _, err := m.Store.PutCredential("mcp:demo", "mcp_server", "mcp", "fixture", meta, map[string]string{"access_token": "SyntheticExpiredCredential0123456789", "refresh_token": "SyntheticRefreshCredential012345", "expires_at": "0"}); err != nil {
			t.Fatal(err)
		}
		m.Transport = astra2RT(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("fixture: no network")
		})
		err := m.Load(context.Background(), "demo")
		if err == nil || retryable(err) {
			t.Errorf("token_endpoint %q: want a non-retryable config error, got %v", endpoint, err)
		}
		if c, _ := m.Store.GetCredential("mcp:demo"); c.Meta["status"] != "error" {
			t.Errorf("token_endpoint %q: status = %v", endpoint, c.Meta["status"])
		}
	}
}
