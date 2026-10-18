package upstream

import (
	"testing"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/redact"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNotionPageEditPolicy(t *testing.T) {
	m := &Manager{Red: redact.New()}
	tool := &mcp.Tool{Name: "notion-update-page", InputSchema: map[string]any{"type": "object"}}
	sc := serverConf{Name: "notion", Prefix: "notion", URL: "https://mcp.notion.com/mcp"}
	baseline := m.toAction("notion", sc, "fixture", tool)
	if !baseline.IsGated(map[string]any{"command": "update_properties"}) {
		t.Fatal("upstream gained permission without a reviewed rule")
	}
	sc.Overrides = map[string]string{tool.Name: "notion-page-edits"}
	a := m.toAction("notion", sc, "fixture", tool)
	if a.Risk != actions.Write || a.DefDigest == baseline.DefDigest {
		t.Fatal("rule is not a private write bound into the tool definition")
	}
	for _, tc := range []struct {
		name string
		args map[string]any
		held bool
	}{
		{"status", map[string]any{"page_id": "fixture", "command": "update_properties", "properties": map[string]any{"Status": "Done"}}, false},
		{"append", map[string]any{"page_id": "fixture", "command": "insert_content", "content": "proof", "position": map[string]any{"type": "end"}}, false},
		{"bad position", map[string]any{"page_id": "fixture", "command": "insert_content", "content": "proof", "position": "end"}, true},
		{"extra position", map[string]any{"page_id": "fixture", "command": "insert_content", "content": "proof", "position": map[string]any{"type": "end", "replace": true}}, true},
		{"replace", map[string]any{"page_id": "fixture", "command": "update_content", "new_str": "replacement"}, true},
		{"deletion flag", map[string]any{"page_id": "fixture", "command": "insert_content", "content": "x", "allow_deleting_content": true}, true},
		{"archive flag", map[string]any{"page_id": "fixture", "command": "update_properties", "properties": map[string]any{"Status": "Done"}, "archived": true}, true},
		{"missing command", map[string]any{"page_id": "fixture"}, true},
		{"unknown command", map[string]any{"page_id": "fixture", "command": "delete_page"}, true},
		{"bad properties", map[string]any{"page_id": "fixture", "command": "update_properties", "properties": "oops"}, true},
		{"missing id", map[string]any{"command": "insert_content", "content": "x"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if a.IsGated(tc.args) != tc.held {
				t.Fatalf("held=%v, want %v", a.IsGated(tc.args), tc.held)
			}
		})
	}
	for _, endpoint := range []string{"http://mcp.notion.com/mcp", "https://evil.example/mcp", "https://mcp.notion.com.evil.example/mcp", "https://mcp.notion.com/mcp?other=1", "https://user@mcp.notion.com/mcp", "https://mcp.notion.com:443/mcp"} {
		sc.URL = endpoint
		if got := m.toAction("notion", sc, "fixture", tool); got.Risk != actions.Gated {
			t.Fatalf("rule applied to unreviewed endpoint %s", endpoint)
		}
	}
}
