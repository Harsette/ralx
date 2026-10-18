package daemon

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Dotted display titles duplicate the underscore tool names. A real SDK list
// of 260 otherwise small tools used to exceed the 512-distinct-fragment cap
// solely because it advertised both spellings. Names and schemas must arrive
// through the actual negotiated HTTP session without increasing that cap.
func TestCatalogSDKOmitsRedundantActionTitles(t *testing.T) {
	l := newLiveHub(t)
	l.s.red.Add("fixture", "SyntheticCatalogSDKCredential0123456789")
	for i := 0; i < 260; i++ {
		if err := l.s.reg.Add(&actions.Action{
			Name: fmt.Sprintf("catalog.inspect%03d", i), Risk: actions.Read,
			Native: func(context.Context, actions.Env, map[string]any) (any, error) { return nil, nil },
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, key, err := l.s.store.CreateAgent("catalog-sdk", store.Policy{Allow: []string{"catalog.*"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "synthetic-catalog-proof", Version: "1"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: l.ip + "/mcp", HTTPClient: &http.Client{Transport: bearerRT{tok: key}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	listed, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 262 || listed.NextCursor != "" {
		t.Fatalf("tools=%d, want262 with no remaining page", len(listed.Tools))
	}
	seen := make(map[string]bool)
	for _, tool := range listed.Tools {
		seen[tool.Name] = true
		if tool.InputSchema == nil {
			t.Fatalf("missing schema for %s", tool.Name)
		}
	}
	for i := 0; i < 260; i++ {
		if !seen[fmt.Sprintf("catalog_inspect%03d", i)] {
			t.Fatalf("missing tool %d", i)
		}
	}
}

func TestMCPCORSHeadersRequireBrowserOrigin(t *testing.T) {
	h := newHarness(t)
	key := h.agent("cors-catalog")
	want := map[string]string{
		"Access-Control-Allow-Origin":   "*",
		"Access-Control-Allow-Methods":  "GET, POST, DELETE, OPTIONS",
		"Access-Control-Allow-Headers":  "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID",
		"Access-Control-Expose-Headers": "Mcp-Session-Id, WWW-Authenticate",
	}
	for _, origin := range []string{"", "http://localhost:6274"} {
		for _, method := range []string{"POST", "OPTIONS"} {
			t.Run(method+"/"+origin, func(t *testing.T) {
				var headers http.Header
				if method == "POST" {
					response := mcpDo(h, key, origin, "", true)
					if response.Code != http.StatusOK {
						t.Fatalf("initialize status=%d", response.Code)
					}
					headers = response.Header()
				} else {
					response := h.do(method, "/mcp", nil, map[string]string{"Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "Authorization, Content-Type"}, false)
					if response.code != http.StatusNoContent {
						t.Fatalf("preflight status=%d", response.code)
					}
					headers = response.hdr
				}
				for name, value := range want {
					if origin == "" {
						value = ""
					}
					if got := headers.Get(name); got != value {
						t.Fatalf("%s=%q, want %q", name, got, value)
					}
				}
			})
		}
	}
}
