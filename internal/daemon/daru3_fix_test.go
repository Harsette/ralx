package daemon

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Daru review of 88d4c4a, inverted: N9 must hold on the /mcp path too (the path
// ChatGPT/Claude connectors use), not just REST. An action queued over /mcp by
// an OAuth grant carries that grant's family, so revoking the grant cancels its
// queued work.
func TestFixMCPApprovalRevokedGrantRefused(t *testing.T) {
	l := newLiveHub(t)
	a, _, err := l.s.store.CreateAgent("mcpgrant", store.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	at, rt, err := l.s.store.IssueTokens(a.ID, "synthetic-client", "", "", "ralx", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "1"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: l.ip + "/mcp", HTTPClient: &http.Client{Transport: bearerRT{tok: at}}}, nil)
	if err != nil {
		t.Fatalf("mcp connect: %v", err)
	}
	defer sess.Close()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "test_danger", Arguments: map[string]any{"thing": "repo"}})
	if err != nil || !strings.Contains(textOf(res), "HELD") {
		t.Fatalf("not held: %v %s", err, textOf(res))
	}
	pend, err := l.s.store.ListApprovals("pending", 10)
	if err != nil || len(pend) != 1 {
		t.Fatalf("pending approvals: %v %d", err, len(pend))
	}
	id := pend[0].ID
	// Fixed: the /mcp-queued approval carries the grant family.
	if pend[0].GrantFamily == "" {
		t.Fatal("approval queued over /mcp has no grant family")
	}
	l.s.store.RevokeToken(rt)
	if _, _, _, _, err := l.s.authenticateBearer(at); err == nil {
		t.Fatal("revoked grant still authenticates")
	}
	// Fixed: revoke cancels the pending /mcp approval; it can't be approved or run.
	if ap, _ := l.s.store.GetApproval(id); ap.Status != "denied" {
		t.Fatalf("revoke should have cancelled the /mcp approval, got %s", ap.Status)
	}
	if err := l.s.store.DecideApproval(id, "approved", "synthetic owner"); err == nil {
		t.Fatal("a cancelled /mcp approval was approvable")
	}
	l.s.runApproval(id)
	ap, _ := l.s.store.GetApproval(id)
	if ap.Status == "executed" {
		t.Fatalf("revoked grant's /mcp-queued action still executed (grant_family=%q)", ap.GrantFamily)
	}
}
