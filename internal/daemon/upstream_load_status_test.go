package daemon

// A load that connects but can't list or accept the tools must not leave the
// previous "ok" behind (the home screen said connected with no tools, and the
// boot retry skipped it). A config or catalog problem a retry can't fix must not
// be retried. Synthetic values; local fixture server only.
import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// listFailTransport fails every tools/list request while down is set.
type listFailTransport struct {
	base *url.URL
	down *atomic.Bool
}

func (f listFailTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil && f.down.Load() {
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if bytes.Contains(b, []byte(`"tools/list"`)) {
			return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(nil)), Request: r}, nil
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
	}
	return notionFixtureTransport{base: f.base}.RoundTrip(r)
}

func headerFixture(t *testing.T, tools ...string) (*harness, *url.URL) {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	for _, n := range tools {
		srv.AddTool(&mcp.Tool{Name: n, InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "fixture"}}}, nil
		})
	}
	up := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{DisableLocalhostProtection: true}))
	t.Cleanup(func() { up.CloseClientConnections(); up.Close() })
	h := newHarness(t)
	h.s.up.AllowHTTP = true
	u, _ := url.Parse(up.URL)
	h.s.up.Transport = notionFixtureTransport{base: u}
	return h, u
}

func putHeaderUpstream(t *testing.T, h *harness, name string, meta map[string]any) {
	t.Helper()
	m := map[string]any{"url": "https://mcp.example.com/mcp", "auth": "header", "header": "X-Fixture-Key", "status": "ok", "tools": 3}
	for k, v := range meta {
		m[k] = v
	}
	if _, err := h.s.store.PutCredential("mcp:"+name, "mcp_server", "mcp", name+" (MCP)", m, map[string]string{"value": "SyntheticHeaderValue0123456789"}); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamListToolsFailureIsRecordedAndRetried(t *testing.T) {
	h, u := headerFixture(t, "search")
	down := &atomic.Bool{}
	down.Store(true)
	h.s.up.Transport = listFailTransport{base: u, down: down}
	putHeaderUpstream(t, h, "demo", nil) // a previous run left status ok
	failed := h.s.up.LoadAll(context.Background())
	if len(failed) != 1 {
		t.Fatalf("a tools/list failure should be retried: %v", failed)
	}
	c, _ := h.s.store.GetCredential("mcp:demo")
	if c.Meta["status"] == "ok" {
		t.Fatalf("a failed load kept the old ok status: %v", c.Meta)
	}
	if n := connectorsByID(t, h.do("GET", "/admin/api/connectors", nil, nil, true))["mcp:demo"]; n["status"] != "error" {
		t.Fatalf("home screen says %v for an upstream with no tools loaded", n["status"])
	}
	down.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	h.s.up.RetryFailed(ctx, failed, []time.Duration{10 * time.Millisecond})
	if _, ok := h.s.reg.Get("demo.search"); !ok {
		t.Fatal("upstream not loaded on retry after tools/list recovered")
	}
}

func TestUpstreamConfigErrorsAreNotRetried(t *testing.T) {
	h, _ := headerFixture(t, "a-b", "a_b") // two tools that collide as demo.a_b
	putHeaderUpstream(t, h, "demo", nil)
	putHeaderUpstream(t, h, "reserved", map[string]any{"prefix": "gh"})
	failed := h.s.up.LoadAll(context.Background())
	if len(failed) != 0 {
		t.Fatalf("a collision or reserved prefix can't fix itself and must not be retried: %v", failed)
	}
	for _, n := range []string{"mcp:demo", "mcp:reserved"} {
		if c, _ := h.s.store.GetCredential(n); c.Meta["status"] != "error" {
			t.Fatalf("%s status = %v", n, c.Meta["status"])
		}
	}
	// Even if one is handed to the retry loop, it gives up instead of looping.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		h.s.up.RetryFailed(ctx, []string{"demo", "reserved"}, []time.Duration{time.Millisecond})
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("RetryFailed kept retrying a config error")
	}
}
