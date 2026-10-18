package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Inverted: an old approval must NOT execute a changed raw downstream tool.
func TestAstra3ReproApprovalFollowsNormalizedToolReplacement(t *testing.T) {
	h := newHarness(t)
	calls := 0
	var invoked string
	setTool := func(raw string) {
		base := astra2MCPTransport([]map[string]any{{"name": raw, "inputSchema": map[string]any{"type": "object"}}}, &calls)
		h.s.up.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
			if r.Body != nil {
				b, _ := io.ReadAll(r.Body)
				var msg struct {
					Method string `json:"method"`
					Params struct {
						Name string `json:"name"`
					} `json:"params"`
				}
				_ = json.Unmarshal(b, &msg)
				if msg.Method == "tools/call" {
					invoked = msg.Params.Name
				}
				r.Body = io.NopCloser(bytes.NewReader(b))
			}
			return base.RoundTrip(r)
		})
	}
	setTool("dispatch-job")
	if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", "synthetic-definition-key-0123456789"); err != nil {
		t.Fatal(err)
	}
	r := h.do("POST", "/v1/actions/demo.dispatch_job", map[string]any{"args": map[string]any{"record": "fixture"}}, bearer(h.agent("definition")), false)
	if r.code != 202 {
		t.Fatalf("not held: %d", r.code)
	}
	id := r.body["approval_id"].(string)
	ap, _ := h.s.store.GetApproval(id)
	if !strings.Contains(ap.Summary, "dispatch-job") {
		t.Fatal("approval did not reference original raw tool")
	}
	if err := h.s.store.DecideApproval(id, "approved", "synthetic owner"); err != nil {
		t.Fatal(err)
	}
	setTool("dispatch_job")
	if err := h.s.up.Load(context.Background(), "demo"); err != nil {
		t.Fatal(err)
	}
	h.s.runApproval(id)
	ap, _ = h.s.store.GetApproval(id)
	// Fixed: the approval is pinned to the original definition's digest, so after
	// a reload swaps the raw tool under the same normalized name it is refused,
	// not executed.
	if ap.Status == "executed" {
		t.Fatalf("approval ran a changed definition: status=%s tool=%q", ap.Status, invoked)
	}
	if invoked == "dispatch_job" {
		t.Fatal("the replacement raw tool was invoked")
	}
}
