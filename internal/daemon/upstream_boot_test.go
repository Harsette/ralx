package daemon

// Notion showed "sign-in expired" for days because the hub refreshed its
// sign-in at boot, before the network was up, called that an expiry, and never
// tried again. A network failure must say so and be retried; a real refusal
// still asks for a reconnect. Synthetic values; local fixture server only.
import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type flakyTransport struct {
	base *url.URL
	down *atomic.Bool
}

func (f flakyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.down.Load() {
		return nil, errors.New("dial tcp: lookup mcp.notion.com: no such host")
	}
	return notionFixtureTransport{base: f.base}.RoundTrip(r)
}

func bootFixture(t *testing.T, tokenStatus int) (*harness, *atomic.Bool) {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	srv.AddTool(&mcp.Tool{Name: "notion-search", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "fixture"}}}, nil
	})
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{DisableLocalhostProtection: true}))
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if tokenStatus != 200 {
			w.WriteHeader(tokenStatus)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"SyntheticBootAccess0123456789","expires_in":3600}`))
	})
	up := httptest.NewServer(mux)
	t.Cleanup(func() { up.CloseClientConnections(); up.Close() })
	h := newHarness(t)
	h.s.up.AllowHTTP = true
	u, _ := url.Parse(up.URL)
	down := &atomic.Bool{}
	down.Store(true)
	h.s.up.Transport = flakyTransport{base: u, down: down}
	meta := map[string]any{"url": "https://mcp.notion.com/mcp", "auth": "oauth", "prefix": "notion", "client_id": "synthetic-client",
		"token_endpoint": "https://mcp.notion.com/token", "resource": "https://mcp.notion.com/mcp"}
	if _, err := h.s.store.PutCredential("mcp:notion", "mcp_server", "mcp", "notion (MCP)", meta,
		map[string]string{"access_token": "SyntheticStaleAccess0123456789", "refresh_token": "SyntheticBootRefresh0123456789", "expires_at": "0"}); err != nil {
		t.Fatal(err)
	}
	return h, down
}

func TestUpstreamLoadRetriesAfterBootNetworkFailure(t *testing.T) {
	h, down := bootFixture(t, 200)
	failed := h.s.up.LoadAll(context.Background())
	c, _ := h.s.store.GetCredential("mcp:notion")
	detail, _ := c.Meta["error"].(string)
	if len(failed) != 1 || strings.Contains(detail, "sign-in expired") || c.Meta["status"] == "reconnect_needed" {
		t.Fatalf("a network failure at boot was reported as an expired sign-in: failed=%v status=%v error=%q", failed, c.Meta["status"], detail)
	}
	n := connectorsByID(t, h.do("GET", "/admin/api/connectors", nil, nil, true))["notion"]
	if n["status"] != "error" || !strings.Contains(n["reason"].(string), "couldn't reach") {
		t.Fatalf("home screen should say RalX couldn't reach Notion: %v", n)
	}
	down.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	h.s.up.RetryFailed(ctx, failed, []time.Duration{10 * time.Millisecond})
	c, _ = h.s.store.GetCredential("mcp:notion")
	if _, ok := h.s.reg.Get("notion.notion_search"); c.Meta["status"] != "ok" || !ok {
		t.Fatalf("upstream not loaded after the network came back: status=%v error=%v", c.Meta["status"], c.Meta["error"])
	}
}

func TestUpstreamRefusedSignInIsNotRetried(t *testing.T) {
	h, down := bootFixture(t, 400)
	down.Store(false)
	failed := h.s.up.LoadAll(context.Background())
	if len(failed) != 0 {
		t.Fatalf("a refused sign-in can't fix itself and must not be retried: %v", failed)
	}
	c, _ := h.s.store.GetCredential("mcp:notion")
	if detail, _ := c.Meta["error"].(string); !strings.Contains(detail, "sign-in expired") || !strings.Contains(detail, "invalid_grant") {
		t.Fatalf("refusal should ask for a reconnect with the provider's reason: %q", detail)
	}
}
