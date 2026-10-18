package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/store"
)

func TestAstra4ReproApprovalChangesUpstreamOrigin(t *testing.T) {
	h := newHarness(t)
	calls := 0
	base := astra2MCPTransport([]map[string]any{{"name": "dispatch", "inputSchema": map[string]any{"type": "object"}}}, &calls)
	var calledHost string
	h.s.up.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		before := calls
		res, err := base.RoundTrip(r)
		if calls > before {
			calledHost = r.URL.Host
		}
		return res, err
	})
	if err := h.s.up.AddHeaderServer("demo", "https://first.example/mcp", "X-Key", "synthetic-definition-key-0123456789"); err != nil {
		t.Fatal(err)
	}
	r := h.do("POST", "/v1/actions/demo.dispatch", map[string]any{"args": map[string]any{"record": "approved"}}, bearer(h.agent("origin-swap")), false)
	if r.code != 202 {
		t.Fatalf("queue: %d", r.code)
	}
	id := r.body["approval_id"].(string)
	ap, _ := h.s.store.GetApproval(id)
	if ap.DefDigest == "" {
		t.Fatal("missing baseline digest")
	}
	if err := h.s.store.DecideApproval(id, "approved", "synthetic owner"); err != nil {
		t.Fatal(err)
	}
	if err := h.s.store.UpdateMeta("mcp:demo", map[string]any{"url": "https://second.example/mcp"}); err != nil {
		t.Fatal(err)
	}
	if err := h.s.up.Load(context.Background(), "demo"); err != nil {
		t.Fatal(err)
	}
	// Fixed: the digest includes the endpoint origin, so swapping the URL changes
	// it and the old approval is refused — second.example is never called.
	a, _ := h.s.reg.Get("demo.dispatch")
	if a.DefDigest == ap.DefDigest {
		t.Fatal("origin swap did not change the definition digest")
	}
	h.s.runApproval(id)
	ap, _ = h.s.store.GetApproval(id)
	if ap.Status == "executed" || calledHost == "second.example" || calls != 0 {
		t.Fatalf("old approval ran against the swapped origin: status=%s host=%s calls=%d", ap.Status, calledHost, calls)
	}
}

func TestAstra4ReproLegacyApprovalEmptyDigest(t *testing.T) {
	h := newHarness(t)
	calls := 0
	setTool := func(raw string) {
		h.s.up.Transport = astra2MCPTransport([]map[string]any{{"name": raw, "inputSchema": map[string]any{"type": "object"}}}, &calls)
	}
	setTool("dispatch-job")
	if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", "synthetic-legacy-key-0123456789"); err != nil {
		t.Fatal(err)
	}
	_, _, err := h.s.store.CreateAgent("legacy", store.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	agent := mustAgent(t, h, "legacy")
	// Pre-fix database approvals acquire def_digest='' during the migration.
	ap := &store.Approval{AgentID: agent.ID, AgentName: agent.Name, Action: "demo.dispatch_job", Summary: "demo: dispatch-job", GateReason: "sensitive", Origin: "key", Args: json.RawMessage(`{"record":"original"}`)}
	if err := h.s.store.CreateApproval(ap); err != nil {
		t.Fatal(err)
	}
	if err := h.s.store.DecideApproval(ap.ID, "approved", "synthetic owner"); err != nil {
		t.Fatal(err)
	}
	setTool("dispatch_job")
	if err := h.s.up.Load(context.Background(), "demo"); err != nil {
		t.Fatal(err)
	}
	h.s.runApproval(ap.ID)
	got, _ := h.s.store.GetApproval(ap.ID)
	// Fixed: the action now carries a digest, so an approval with an empty
	// (legacy) digest is refused rather than executing the changed tool.
	if got.Status == "executed" || calls != 0 {
		t.Fatalf("legacy empty-digest approval executed the changed tool: status=%s calls=%d", got.Status, calls)
	}
}

func TestAstra4ReproLegacyApprovalSurvivesGrantRevocation(t *testing.T) {
	h := newHarness(t)
	agent, _, err := h.s.store.CreateAgent("legacy-grant", store.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	at, rt, err := h.s.store.IssueTokens(agent.ID, "synthetic-client", "", h.s.origin+"/mcp", "ralx", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Model the record emitted by pre-fix OAuth /mcp: grant_family was empty.
	ap := &store.Approval{AgentID: agent.ID, AgentName: agent.Name, Action: "test.danger", Summary: "Delete repo", GateReason: "deletes", Args: json.RawMessage(`{"thing":"repo"}`)}
	if err := h.s.store.CreateApproval(ap); err != nil {
		t.Fatal(err)
	}
	h.s.store.RevokeToken(rt)
	if got := h.do("GET", "/v1/whoami", nil, bearer(at), false); got.code != 401 {
		t.Fatalf("revocation not active: %d", got.code)
	}
	// Fixed: revoking the grant cancels the agent's pending approvals, including
	// a legacy one with an empty grant_family, so it can't be approved or run.
	if g, _ := h.s.store.GetApproval(ap.ID); g.Status != "denied" {
		t.Fatalf("revoke should have cancelled the legacy approval, got %s", g.Status)
	}
	if err := h.s.store.DecideApproval(ap.ID, "approved", "synthetic owner"); err == nil {
		t.Fatal("a cancelled legacy approval was approvable")
	}
	h.s.runApproval(ap.ID)
	if got, _ := h.s.store.GetApproval(ap.ID); got.Status == "executed" {
		t.Fatalf("legacy empty-family approval executed after revoke: %s", got.Status)
	}
}
