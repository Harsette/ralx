package daemon

// Astra 7 probes, inverted (Fix*). Synthetic values, fake transports; no sockets.
import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func astra7MCPCall(t *testing.T, h *harness, key, tool string, args map[string]any) string {
	t.Helper()
	init := mcpDo(h, key, "", "", true)
	if init.Code != 200 {
		t.Fatalf("initialize: %d", init.Code)
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	req := httptest.NewRequest("POST", "http://localhost:7399/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", init.Header().Get("Mcp-Session-Id"))
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("MCP call: %d %s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

// Inverted ReproCatalogTwoTools: a key split across TWO tools' schema property names
// is withheld from both the REST catalog and remote MCP tools/list (all the server's
// tools are dropped), zero tool calls.
func TestAstra7FixCatalogTwoToolsWithheld(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticCrossToolCredential0123456789"
	halves := []string{secret[:18], secret[18:]}
	calls := 0
	tools := []map[string]any{}
	for i, name := range []string{"inspectone", "inspecttwo"} {
		tools = append(tools, map[string]any{"name": name, "inputSchema": map[string]any{"type": "object", "properties": map[string]any{halves[i]: map[string]any{"type": "string"}}}})
	}
	h.s.up.Transport = astra2MCPTransport(tools, &calls)
	if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", secret); err != nil {
		t.Fatal(err)
	}
	key := h.agent("a7-catalog")
	rest := h.do("GET", "/v1/actions", nil, bearer(key), false)
	init := mcpDo(h, key, "", "", true)
	remote := mcpDo(h, key, "", init.Header().Get("Mcp-Session-Id"), false)
	if rest.code != 200 || init.Code != 200 || remote.Code != 200 || calls != 0 {
		t.Fatalf("REST=%d MCP=%d/%d calls=%d", rest.code, init.Code, remote.Code, calls)
	}
	for _, half := range halves {
		if bytes.Contains(rest.raw, []byte(half)) || strings.Contains(remote.Body.String(), half) {
			t.Fatal("defect reproduced: a credential half reached the agent-facing catalog across two tools")
		}
	}
}

// Inverted ReproCatalogPairCap: one tool whose schema pads the split with 260 ordinary
// strings no longer bypasses the pairwise cap — the tool is dropped (fail closed).
func TestAstra7FixCatalogPairCapWithheld(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticPairCapCredential0123456789"
	halves := []string{secret[:18], secret[18:]}
	parts := make([]any, 260)
	for i := range parts {
		parts[i] = "ordinary"
	}
	parts = append(parts, halves[0], "separator", halves[1])
	calls := 0
	h.s.up.Transport = astra2MCPTransport([]map[string]any{{"name": "inspect", "inputSchema": map[string]any{"type": "object", "x-parts": parts}}}, &calls)
	if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", secret); err != nil {
		t.Fatal(err)
	}
	r := h.do("GET", "/v1/actions", nil, bearer(h.agent("a7-cap")), false)
	if r.code != 200 || calls != 0 {
		t.Fatalf("catalog=%d calls=%d", r.code, calls)
	}
	for _, half := range halves {
		if bytes.Contains(r.raw, []byte(half)) {
			t.Fatal("defect reproduced: a key half bypassed the pairwise cap and reached the catalog")
		}
	}
}

// Inverted ReproPunctuationFramedUpstreamResult: an approved upstream result that is a
// prose-prefixed, period-suffixed base64(gzip(secret)) is withheld at the upstream
// choke point; the recoverable blob never reaches the agent through REST readback.
func TestAstra7FixPunctuationFramedUpstreamResultWithheld(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticFramedCredential0123456789"
	token := base64.StdEncoding.EncodeToString(a5Gzip(strings.Repeat(secret, 64)))
	payload := "metadataisordinary " + token + "."
	calls := 0
	base := astra2MCPTransport([]map[string]any{{"name": "inspect", "inputSchema": map[string]any{"type": "object"}}}, &calls)
	h.s.up.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		res, err := base.RoundTrip(r)
		if err != nil || res.StatusCode != 200 {
			return res, err
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		var msg map[string]any
		_ = json.Unmarshal(b, &msg)
		if result, ok := msg["result"].(map[string]any); ok {
			if _, ok := result["content"]; ok {
				result["content"] = []any{map[string]any{"type": "text", "text": payload}}
			}
		}
		b, _ = json.Marshal(msg)
		res.Body = io.NopCloser(bytes.NewReader(b))
		return res, nil
	})
	if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", secret); err != nil {
		t.Fatal(err)
	}
	key := h.agent("a7-framing")
	id := astra6Approve(t, h, key, "demo.inspect", map[string]any{})
	h.s.runApproval(id)
	result := h.do("GET", "/v1/approvals/"+id, nil, bearer(key), false)
	ap, _ := h.s.store.GetApproval(id)
	if result.code != 200 || calls != 1 || ap.Status != "executed" {
		t.Fatalf("poll=%d calls=%d status=%s", result.code, calls, ap.Status)
	}
	if bytes.Contains(result.raw, []byte(token)) {
		t.Fatal("defect reproduced: recoverable base64-gzip upstream result reached the agent")
	}
}

// Inverted ReproDriveErrorBypassesWithhold: an unapproved Drive download whose provider
// error embeds a percent-encoded stored key is withheld at fail() — 502, no secret.
func TestAstra7FixDriveErrorWithheld(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticDriveErrorCredential0123456789"
	putHostCred(t, h, "svc", secret, nil)
	calls := 0
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		calls++
		return fakeResp(r, 403, `{"error":{"message":"`+a5Percent(secret)+`"}}`), nil
	})
	r := h.do("GET", "/v1/drive/files/abcdefghijk/content", nil, bearer(h.agent("a7-error")), false)
	decoded, _ := url.QueryUnescape(string(r.raw))
	if r.code != 502 || calls != 1 {
		t.Fatalf("status=%d calls=%d", r.code, calls)
	}
	if strings.Contains(decoded, secret) || strings.Contains(string(r.raw), a5Percent(secret)) {
		t.Fatal("defect reproduced: Drive download error leaked the stored credential")
	}
}

// Inverted ReproMCPApprovalBypassesWithhold: an approved upload result holding a
// percent-encoded stored key is withheld on completion, REST poll AND remote MCP
// ralx_approval — the MCP readback no longer bypasses the choke point.
func TestAstra7FixMCPApprovalWithheld(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticUploadResultCredential0123456789"
	putHostCred(t, h, "svc", secret, nil)
	gets, uploads := 0, 0
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		switch r.Method {
		case "GET":
			gets++
			if strings.HasSuffix(r.URL.Path, "/permissions") {
				return fakeResp(r, 200, `{"permissions":[{"id":"synthetic-recipient","type":"user","role":"reader","emailAddress":"recipient@example.invalid"}]}`), nil
			}
			return fakeResp(r, 200, `{"ownedByMe":true,"shared":true}`), nil
		case "POST":
			res := fakeResp(r, 200, "")
			res.Header.Set("Location", "https://www.googleapis.com/upload/session/fixture")
			return res, nil
		case "PUT":
			uploads++
			_, _ = io.ReadAll(r.Body)
			return fakeResp(r, 200, `{"id":"fixture-id","name":"`+a5Percent(secret)+`"}`), nil
		}
		t.Fatalf("unexpected provider method %s", r.Method)
		return nil, nil
	})
	key := h.agent("a7-upload")
	agent := mustAgent(t, h, "a7-upload")
	f, err := h.s.staging.start(agent.ID, "fixture.txt", "text/plain", 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.s.staging.put(f.ID, agent.ID, 0, 4, strings.NewReader("GOOD")); err != nil {
		t.Fatal(err)
	}
	q := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "parent_id": "fixturefolder123", "media_upload_id": f.ID}, bearer(key), false)
	if q.code != 202 {
		t.Fatalf("queue=%d %s", q.code, q.raw)
	}
	id := q.body["approval_id"].(string)
	if err = h.s.store.DecideApproval(id, "approved", "synthetic fixture"); err != nil {
		t.Fatal(err)
	}
	done := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "approval_id": id}, bearer(key), false)
	if done.body["status"] != "withheld" || uploads != 1 || gets != 4 {
		t.Fatalf("completion status=%v uploads=%d gets=%d", done.body["status"], uploads, gets)
	}
	poll := h.do("GET", "/v1/approvals/"+id, nil, bearer(key), false)
	if poll.body["status"] != "withheld" {
		t.Fatal("REST readback control not withheld")
	}
	remote := astra7MCPCall(t, h, key, "ralx_approval", map[string]any{"approval_id": id})
	decoded, _ := url.QueryUnescape(remote)
	if strings.Contains(decoded, secret) || strings.Contains(remote, a5Percent(secret)) {
		t.Fatal("defect reproduced: MCP ralx_approval released the stored credential")
	}
}

// Inverted ReproGenericUpstreamReplacementSameGeneration: a generic owner credential
// replacement (new host + new key, stored gen token unchanged) is refused at dispatch
// by the content-derived generation; the old approval never sends the new key.
func TestAstra7FixGenericUpstreamReplacementRefused(t *testing.T) {
	h := newHarness(t)
	const oldKey = "SyntheticOldConnectionCredential0123456789"
	const newKey = "SyntheticReplacementCredential9876543210"
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
	if err := h.s.up.AddHeaderServer("demo", "https://first.example/mcp", "X-Key", oldKey); err != nil {
		t.Fatal(err)
	}
	id := astra6Approve(t, h, h.agent("a7-replace"), "demo.dispatch", map[string]any{})
	cred, err := h.s.store.GetCredential("mcp:demo")
	if err != nil {
		t.Fatal(err)
	}
	cred.Meta["url"] = "https://second.example/mcp"
	r := h.do("POST", "/admin/api/credentials", map[string]any{"name": "mcp:demo", "kind": "mcp_server", "provider": "mcp", "meta": cred.Meta, "fields": map[string]string{"value": newKey}}, nil, true)
	if r.code != 200 {
		t.Fatalf("owner replacement: %d %s", r.code, r.raw)
	}
	h.s.runApproval(id)
	ap, _ := h.s.store.GetApproval(id)
	if ap.Status == "executed" || calls != 0 || used == newKey || host == "first.example" {
		t.Fatalf("defect reproduced: status=%s calls=%d newKey=%t oldHost=%t", ap.Status, calls, used == newKey, host == "first.example")
	}
}
