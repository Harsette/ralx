package daemon

// Astra 7 self-review regressions (inverted). Synthetic values, fake transports.
import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A successful owner reconnect of the SAME tool to a NEW host+key replaces the
// definition; an approval pinned to the old account/definition must be refused and the
// new host must never receive the call (blocker: approval reuse after account change).
// This is a sequential control, not concurrent replacement proof. The retained
// Astra8HeldCallDuringReconnect fixture pauses discovery during a real goroutine.
func TestAstra7SelfReviewReconnectToNewAccountRefused(t *testing.T) {
	h := newHarness(t)
	const keyA = "SyntheticAccountACredential0123456789"
	const keyB = "SyntheticAccountBCredential9876543210"
	calls := 0
	used, host := "", ""
	base := astra2MCPTransport([]map[string]any{{"name": "dispatch", "inputSchema": map[string]any{"type": "object"}}}, &calls)
	h.s.up.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		before := calls
		res, err := base.RoundTrip(r)
		if calls > before {
			used = r.Header.Get("X-Key")
			host = r.URL.Host
		}
		return res, err
	})
	if err := h.s.up.AddHeaderServer("demo", "https://first.example/mcp", "X-Key", keyA); err != nil {
		t.Fatal(err)
	}
	id := astra6Approve(t, h, h.agent("a7-reconnect-ok"), "demo.dispatch", map[string]any{})
	if err := h.s.up.AddHeaderServer("demo", "https://second.example/mcp", "X-Key", keyB); err != nil {
		t.Fatal(err)
	}
	h.s.runApproval(id)
	ap, _ := h.s.store.GetApproval(id)
	if ap.Status == "executed" || calls != 0 || used == keyB || host == "second.example" {
		t.Fatalf("defect reproduced: A's approval ran after reconnect to B (status=%s calls=%d newKey=%t newHost=%t)", ap.Status, calls, used == keyB, host == "second.example")
	}
}

// The CLI connect-session poll routes through the agent-bound choke point, so a failed
// login whose captured output embeds an encoded stored credential is withheld, not
// returned by plain writeJSON (blocker: an agent-bound path skipping the choke point).
func TestAstra7SelfReviewCLIPollWithheld(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticCLILoginCredential0123456789"
	putHostCred(t, h, "svc", secret, nil)
	key := h.agent("a7-cli")
	agent := mustAgent(t, h, "a7-cli")
	cs := &cliSession{ID: "cli_fixture", Tool: "vercel", Status: "error", Error: a5Percent(secret), Agent: agent.Name}
	cliSess.mu.Lock()
	cliSess.m[cs.ID] = cs
	cliSess.mu.Unlock()
	r := h.do("GET", "/v1/connect/cli/sessions/cli_fixture", nil, bearer(key), false)
	decoded, _ := url.QueryUnescape(string(r.raw))
	if strings.Contains(decoded, secret) || strings.Contains(string(r.raw), a5Percent(secret)) {
		t.Fatal("defect reproduced: CLI session poll released the stored credential")
	}
}

// A credential split as decimal-byte NUMBER arrays across two tools must be withheld —
// the whole-catalog cross-check decodes numeric arrays and drops the upstream's tools.
func TestAstra7SelfReviewNumericCrossToolWithheld(t *testing.T) {
	h := newHarness(t)
	const secret = "ABCDWXYZ1234pqrs"
	b := []byte(secret)
	toNums := func(bb []byte) []any {
		out := make([]any, 0, len(bb))
		for _, c := range bb {
			out = append(out, float64(c))
		}
		return out
	}
	tools := []map[string]any{
		{"name": "inspectone", "inputSchema": map[string]any{"type": "object", "x-data": toNums(b[:8])}},
		{"name": "inspecttwo", "inputSchema": map[string]any{"type": "object", "x-data": toNums(b[8:])}},
	}
	calls := 0
	h.s.up.Transport = astra2MCPTransport(tools, &calls)
	if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", secret); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.s.reg.Get("demo.inspectone"); ok {
		t.Fatal("defect reproduced: a numeric-array cross-tool split tool was advertised")
	}
	if _, ok := h.s.reg.Get("demo.inspecttwo"); ok {
		t.Fatal("defect reproduced: a numeric-array cross-tool split tool was advertised")
	}
}

// A Drive download with a secret split between the X-RalX-Filename header and the body
// must withhold BOTH (the two halves pass independent checks but the agent concatenates).
func TestAstra7SelfReviewDriveFilenameBodySplitWithheld(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticSplitCredentialABCDwxyz"
	putHostCred(t, h, "svc", secret, nil)
	half1, half2 := secret[:len(secret)/2], secret[len(secret)/2:]
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("alt") == "media" {
			return fakeResp(r, 200, half2), nil
		}
		return fakeResp(r, 200, `{"name":"`+half1+`","mimeType":"text/plain"}`), nil
	})
	r := h.do("GET", "/v1/drive/files/abcdefghijk/content", nil, bearer(h.agent("a7-split")), false)
	if r.code != 200 {
		t.Fatalf("status %d", r.code)
	}
	if r.hdr.Get("X-RalX-Filename") != "withheld" || r.hdr.Get("X-RalX-Withheld") != "credential" {
		t.Fatalf("defect reproduced: filename/body split not withheld (name=%q withheld=%q)", r.hdr.Get("X-RalX-Filename"), r.hdr.Get("X-RalX-Withheld"))
	}
	if strings.Contains(string(r.raw), half2) {
		t.Fatal("defect reproduced: the body half was released")
	}
}

// An owner credential write for an upstream MCP server — even one that re-submits the
// SAME url and SAME key (the OAuth-account-replacement analog, where only tokens change)
// — bumps the connection generation, so a pending approval pinned to the old generation
// is refused at dispatch.
func TestAstra7SelfReviewAdminWriteBumpsGen(t *testing.T) {
	h := newHarness(t)
	const key = "SyntheticSameConfigCredential0123456789"
	calls := 0
	used := ""
	base := astra2MCPTransport([]map[string]any{{"name": "dispatch", "inputSchema": map[string]any{"type": "object"}}}, &calls)
	h.s.up.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		before := calls
		res, err := base.RoundTrip(r)
		if calls > before {
			used = r.Header.Get("X-Key")
		}
		return res, err
	})
	if err := h.s.up.AddHeaderServer("demo", "https://first.example/mcp", "X-Key", key); err != nil {
		t.Fatal(err)
	}
	id := astra6Approve(t, h, h.agent("a7-samecfg"), "demo.dispatch", map[string]any{})
	cred, err := h.s.store.GetCredential("mcp:demo")
	if err != nil {
		t.Fatal(err)
	}
	// Re-write the SAME url and SAME key: only meta.gen is bumped by the handler.
	r := h.do("POST", "/admin/api/credentials", map[string]any{"name": "mcp:demo", "kind": "mcp_server", "provider": "mcp", "meta": cred.Meta, "fields": map[string]string{"value": key}}, nil, true)
	if r.code != 200 {
		t.Fatalf("owner write: %d %s", r.code, r.raw)
	}
	h.s.runApproval(id)
	ap, _ := h.s.store.GetApproval(id)
	if ap.Status == "executed" || calls != 0 || used == key {
		t.Fatalf("defect reproduced: same-config write kept the generation; stale approval ran (status=%s calls=%d)", ap.Status, calls)
	}
}
