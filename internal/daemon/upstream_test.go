package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Harsette/ralx/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const upstreamKey = "upstream-secret-key-0123456789abcdef"

// fakeUpstream is an MCP server that only answers with the right key.
func fakeUpstream(t *testing.T) *httptest.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake-notion", Version: "1"}, nil)
	yes := true
	srv.AddTool(&mcp.Tool{Name: "search", Description: "search pages", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}},
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "found: roadmap"}}}, nil
		})
	srv.AddTool(&mcp.Tool{Name: "delete-page", Description: "delete a page", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{DestructiveHint: &yes}},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "deleted"}}}, nil
		})
	srv.AddTool(&mcp.Tool{Name: "create-page", Description: "create a page", InputSchema: map[string]any{"type": "object"}},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "created"}}}, nil
		})
	srv.AddTool(&mcp.Tool{Name: "create-comment", Description: "comment on a page", InputSchema: map[string]any{"type": "object"}},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "commented"}}}, nil
		})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{DisableLocalhostProtection: true})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != upstreamKey {
			http.Error(w, "unauthorized", 401)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { ts.CloseClientConnections(); ts.Close() })
	return ts
}

func TestUpstreamAggregation(t *testing.T) {
	up := fakeUpstream(t)
	h := newHarness(t)
	h.s.up.AllowHTTP = true
	if err := h.s.up.AddHeaderServer("notion", up.URL, "X-Api-Key", upstreamKey); err != nil {
		t.Fatal(err)
	}
	// A downstream server is treated as hostile: every tool defaults to gated,
	// regardless of its name or a read-only hint (Astra N3).
	for _, n := range []string{"notion.search", "notion.delete_page", "notion.create_page", "notion.create_comment"} {
		a, ok := h.s.reg.Get(n)
		if !ok || string(a.Risk) != "gated" {
			t.Fatalf("%s should default to gated: ok=%v", n, ok)
		}
	}
	// Only an owner-maintained override lowers specific tools.
	// Overrides are keyed by the upstream's raw tool name (as it ships it).
	if err := h.s.store.UpdateMeta("mcp:notion", map[string]any{"risk_overrides": map[string]any{"search": "read", "create-page": "write"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.s.up.Load(context.Background(), "notion"); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"notion.search": "read", "notion.delete_page": "gated", "notion.create_page": "write", "notion.create_comment": "gated"}
	for name, risk := range want {
		a, ok := h.s.reg.Get(name)
		if !ok || string(a.Risk) != risk {
			t.Fatalf("%s: present=%v want %s", name, ok, risk)
		}
	}
	key := h.agent("a1")
	// A read-overridden tool runs now.
	r := h.do("POST", "/v1/actions/notion.search", map[string]any{"args": map[string]any{"q": "roadmap"}}, bearer(key), false)
	if r.code != 200 || !strings.Contains(string(r.raw), "found: roadmap") {
		t.Fatalf("search: %d %s", r.code, r.raw)
	}
	// An un-overridden tool is held, even though its name looks harmless.
	if rr := h.do("POST", "/v1/actions/notion.create_comment", map[string]any{"args": map[string]any{}}, bearer(key), false); rr.code != 202 {
		t.Fatalf("create_comment should be held: %d %s", rr.code, rr.raw)
	}
	r = h.do("POST", "/v1/actions/notion.delete_page", map[string]any{"args": map[string]any{"page": "x"}}, bearer(key), false)
	if r.code != 202 {
		t.Fatalf("delete not held: %d %s", r.code, r.raw)
	}
	// the upstream key is never shown to the agent
	for _, path := range []string{"/v1/connections", "/v1/actions"} {
		if rr := h.do("GET", path, nil, bearer(key), false); strings.Contains(string(rr.raw), upstreamKey) {
			t.Fatalf("%s leaked the upstream key", path)
		}
	}
	c, _ := h.s.store.GetCredential("mcp:notion")
	if c.Meta["status"] != "ok" {
		t.Fatalf("status: %v", c.Meta)
	}
	_ = store.ErrNotFound
}

// A paste link (how Hamza pastes a key from his phone, no chat, no terminal)
// can provision a downstream MCP server (Composio): pasting the key connects
// it live, its tools register with the right risk, and the key never reaches
// the agent.
func TestDropProvisionsUpstreamMCP(t *testing.T) {
	up := fakeUpstream(t) // requires X-Api-Key == upstreamKey
	h := newHarness(t)
	h.s.up.AllowHTTP = true

	// Mint the mcp_server paste link (owner, over the admin pipe).
	r := h.do("POST", "/admin/api/drop", map[string]any{
		"name": "composio", "kind": "mcp_server", "label": "Composio MCP",
		"meta": map[string]any{"url": up.URL, "header": "X-Api-Key"},
	}, nil, true)
	if r.code != 200 {
		t.Fatalf("mint: %d %s", r.code, r.raw)
	}
	link, _ := r.body["url"].(string)
	i := strings.Index(link, "#drop=")
	if i < 0 {
		t.Fatalf("no drop token in %q", link)
	}
	tok := link[i+6:]

	// The paste page can read the link's label.
	if ri := h.do("GET", "/drop/"+tok, nil, nil, false); ri.code != 200 {
		t.Fatalf("drop info: %d %s", ri.code, ri.raw)
	}

	// Pasting the key provisions and connects the upstream.
	rs := h.do("POST", "/drop/submit", map[string]any{"token": tok, "value": upstreamKey}, nil, false)
	if rs.code != 200 {
		t.Fatalf("submit: %d %s", rs.code, rs.raw)
	}

	// Its tools register, and default to gated (a downstream server is hostile),
	// so nothing from Composio runs without Hamza's approval (Astra N3 / delta).
	for _, n := range []string{"composio.search", "composio.delete_page"} {
		if a, ok := h.s.reg.Get(n); !ok || string(a.Risk) != "gated" {
			t.Fatalf("%s should default to gated: ok=%v", n, ok)
		}
	}

	// An agent calling an upstream tool is held, not executed, and the key the
	// agent never sees is not leaked anywhere agent-facing.
	key := h.agent("a1")
	rc := h.do("POST", "/v1/actions/composio.search", map[string]any{"args": map[string]any{"q": "roadmap"}}, bearer(key), false)
	if rc.code != 202 {
		t.Fatalf("composio.search should be held: %d %s", rc.code, rc.raw)
	}
	for _, p := range []string{"/v1/connections", "/v1/actions"} {
		if rr := h.do("GET", p, nil, bearer(key), false); strings.Contains(string(rr.raw), upstreamKey) {
			t.Fatalf("%s leaked the upstream key", p)
		}
	}

	// A single-use link can't be replayed.
	if rr := h.do("POST", "/drop/submit", map[string]any{"token": tok, "value": upstreamKey}, nil, false); rr.code != 404 {
		t.Fatalf("paste link reusable: %d", rr.code)
	}

	// Minting an mcp_server link without an https url/header is refused.
	if rb := h.do("POST", "/admin/api/drop", map[string]any{"name": "composio2", "kind": "mcp_server", "meta": map[string]any{}}, nil, true); rb.code != 400 {
		t.Fatalf("mcp_server link without url/header should 400: %d %s", rb.code, rb.raw)
	}
}
