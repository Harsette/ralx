package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type notionFixtureTransport struct{ base *url.URL }

func (n notionFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	u := *r.URL
	u.Scheme, u.Host = n.base.Scheme, n.base.Host
	clone.URL = &u
	return http.DefaultTransport.RoundTrip(clone)
}

func TestNotionPageEditsThroughHub(t *testing.T) {
	var calls atomic.Int64
	srv := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	pageSchema := map[string]any{"type": "object", "required": []string{"page_id", "command"}, "properties": map[string]any{
		"page_id":    map[string]any{"type": "string"},
		"command":    map[string]any{"type": "string", "enum": []string{"update_properties", "insert_content", "update_content", "replace_content"}},
		"content":    map[string]any{"type": "string"},
		"properties": map[string]any{"type": "object"},
		"position":   map[string]any{"type": "object", "required": []string{"type"}, "additionalProperties": false, "properties": map[string]any{"type": map[string]any{"type": "string", "enum": []string{"start", "end"}}}},
	}}
	srv.AddTool(&mcp.Tool{Name: "notion-update-page", InputSchema: pageSchema}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		calls.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "fixture edited"}}}, nil
	})
	srv.AddTool(&mcp.Tool{Name: "shell", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Error("held shell dispatched")
		return nil, nil
	})
	up := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{DisableLocalhostProtection: true}))
	t.Cleanup(func() { up.CloseClientConnections(); up.Close() })
	h := newHarness(t)
	h.s.up.AllowHTTP = true // fixture transport below makes no external requests
	u, _ := url.Parse(up.URL)
	h.s.up.Transport = notionFixtureTransport{base: u}
	_, err := h.s.store.PutCredential("mcp:notion", "mcp_server", "mcp", "fixture", map[string]any{"url": "https://mcp.notion.com/mcp", "auth": "header", "header": "X-Fixture-Key"}, map[string]string{"value": upstreamKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.s.up.Load(context.Background(), "notion"); err != nil {
		t.Fatal(err)
	}
	key := h.agent("page-editor")
	policy := map[string]any{"name": "notion", "tool": "notion-update-page", "enabled": true}
	if r := h.do("POST", "/admin/api/upstreams/notion-page-edits", policy, bearer(key), false); r.code != 401 && r.code != 403 {
		t.Fatalf("agent could change the rule: %d", r.code)
	}
	if r := h.do("POST", "/admin/api/upstreams/notion-page-edits", policy, nil, true); r.code != 200 {
		t.Fatalf("admin rule: %d %s", r.code, r.raw)
	}
	generic := map[string]any{"name": "notion", "tool": "notion-update-page", "risk": "notion-page-edits"}
	if r := h.do("POST", "/admin/api/upstreams/policy", generic, bearer(key), false); r.code != 401 && r.code != 403 {
		t.Fatalf("agent changed generic policy: %d", r.code)
	}
	for _, bad := range []map[string]any{
		{"name": "notion", "tool": "notion-update-page", "risk": "approve-everything"},
		{"name": "notion", "tool": "notion_update_page", "risk": "read"},
		{"name": "notion", "tool": "unknown", "risk": "read"},
		{"name": "notion", "tool": "shell", "risk": "write"},
	} {
		if r := h.do("POST", "/admin/api/upstreams/policy", bad, nil, true); r.code != 400 {
			t.Fatalf("bad policy: %d %s", r.code, r.raw)
		}
	}
	for _, args := range []map[string]any{
		{"page_id": "fixture", "command": "update_properties", "properties": map[string]any{"Status": "Done"}},
		{"page_id": "fixture", "command": "insert_content", "content": "verified", "position": map[string]any{"type": "end"}},
	} {
		r := h.do("POST", "/v1/actions/notion.notion_update_page", map[string]any{"args": args}, bearer(key), false)
		if r.code != 200 || !strings.Contains(string(r.raw), "fixture edited") {
			t.Fatalf("edit: %d %s", r.code, r.raw)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls=%d", calls.Load())
	}
	for _, args := range []map[string]any{
		{"page_id": "fixture", "command": "update_content", "new_str": "delete old content"},
		{"page_id": "fixture", "command": "insert_content", "content": "x", "allow_deleting_content": true},
		{"page_id": "fixture", "command": "unexpected"},
	} {
		if r := h.do("POST", "/v1/actions/notion.notion_update_page", map[string]any{"args": args}, bearer(key), false); r.code != 202 {
			t.Fatalf("unsafe edit not held: %d %s", r.code, r.raw)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("held call reached the upstream")
	}
	// Bind a real held approval to the current definition, then change policy.
	old := h.do("POST", "/v1/actions/notion.notion_update_page", map[string]any{"args": map[string]any{"page_id": "fixture", "command": "replace_content", "content": "replacement"}}, bearer(key), false)
	if old.code != 202 {
		t.Fatalf("original hold: %d", old.code)
	}
	oldID, _ := old.body["approval_id"].(string)
	generic["risk"] = "deletes"
	if r := h.do("POST", "/admin/api/upstreams/policy", generic, nil, true); r.code != 200 {
		t.Fatalf("generic admin: %d %s", r.code, r.raw)
	}
	if err := h.s.store.DecideApproval(oldID, "approved", "fixture"); err != nil {
		t.Fatal(err)
	}
	h.s.runApproval(oldID)
	oldApproval, err := h.s.store.GetApproval(oldID)
	if err != nil || oldApproval.Status != "failed" || oldApproval.Error == "" || calls.Load() != 2 {
		t.Fatalf("stale approval executed: %+v %v, calls=%d", oldApproval, err, calls.Load())
	}
	policy["enabled"] = false
	if r := h.do("POST", "/admin/api/upstreams/notion-page-edits", policy, nil, true); r.code != 200 {
		t.Fatalf("disable: %d %s", r.code, r.raw)
	}
	if r := h.do("POST", "/v1/actions/notion.notion_update_page", map[string]any{"args": map[string]any{"page_id": "fixture", "command": "insert_content", "content": "x"}}, bearer(key), false); r.code != 202 {
		t.Fatalf("disabled rule still ran: %d", r.code)
	}
}

func TestManagedSandboxToolsRequireDev(t *testing.T) {
	if _, err := New(Config{ManagedSandboxTools: true}, nil); err == nil {
		t.Fatal("production accepted sandbox root trust")
	}
}
