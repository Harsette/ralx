package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// These fixtures put known synthetic secrets in metadata to prove which HTTP
// writers skip withholding. They do not claim an agent can create secret metadata.
func TestAstra8FixUnguardedAgentJSON(t *testing.T) {
	t.Run("whoami", func(t *testing.T) {
		h := newHarness(t)
		const secret = "SyntheticWhoamiCredential0123456789"
		key := h.agent(secret)
		putHostCred(t, h, "fixture", secret, nil)
		r := h.do("GET", "/v1/whoami", nil, bearer(key), false)
		if r.code != 200 || bytes.Contains(r.raw, []byte(secret)) {
			t.Fatal("regression: whoami withheld metadata")
		}
		t.Log("whoami withholds registered synthetic credential metadata")
	})
	t.Run("fingerprints", func(t *testing.T) {
		h := newHarness(t)
		const secret = "SyntheticFingerprintLabelCredential0123456789"
		putHostCred(t, h, secret, secret, nil)
		r := h.do("GET", "/v1/leakscan/fingerprints", nil, bearer(h.agent("a8-fp")), false)
		if r.code != 200 || bytes.Contains(r.raw, []byte(secret)) {
			t.Fatal("regression: fingerprint labels withheld")
		}
		t.Log("fingerprint labels pass the common exit")
	})
	t.Run("staging-error", func(t *testing.T) {
		h := newHarness(t)
		const secret = "SyntheticStagedNameCredential0123456789"
		key := h.agent("a8-stage")
		a := mustAgent(t, h, "a8-stage")
		f, err := h.s.staging.start(a.ID, secret, "text/plain", 4)
		if err != nil {
			t.Fatal(err)
		}
		putHostCred(t, h, "fixture", secret, nil)
		good := h.do("GET", "/v1/uploads/"+f.ID, nil, bearer(key), false)
		if good.code != 200 || bytes.Contains(good.raw, []byte(secret)) {
			t.Fatal("guarded status positive control failed")
		}
		req := httptest.NewRequest("PUT", "http://localhost:7399/v1/uploads/"+f.ID, strings.NewReader("GOOD"))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("X-RalX-Offset", "1")
		w := httptest.NewRecorder()
		h.h.ServeHTTP(w, req)
		if w.Code != 409 || strings.Contains(w.Body.String(), secret) {
			t.Fatal("regression: staging error withheld")
		}
		t.Log("GET and wrong-offset PUT both scrub the same staged metadata")
	})
}

func TestAstra8FixPartCapSurvivesAgentExit(t *testing.T) {
	h := newHarness(t)
	const secret = "QWERTYUIOPASDFGH"
	putHostCred(t, h, "fixture", secret, nil)
	h.agent("a8-cap")
	fixture := map[string]any{secret[:8]: 0, "z": secret[8:]}
	control, _ := json.Marshal(fixture)
	if _, withheld := h.s.agentScrub(control); !withheld {
		t.Fatal("below-cap positive control not withheld")
	}
	for i := 0; i < 260; i++ {
		fixture[fmt.Sprintf("padding_%03d", i)] = "ordinary"
	}
	a := &actions.Action{Native: func(context.Context, actions.Env, map[string]any) (any, error) { return fixture, nil }}
	raw, err := h.s.execute(context.Background(), mustAgent(t, h, "a8-cap"), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.s.writeJSONAgent(w, 200, map[string]any{"result": raw})
	if strings.Contains(w.Body.String(), secret[:8]) || strings.Contains(w.Body.String(), secret[8:]) {
		t.Fatal("regression: final agent exit withheld")
	}
	t.Log("CLOSED: same split detected below cap is withheld through execute and final exit with 260 padding fields")
}

func TestAstra8FixMCPStructuredScrubDiscarded(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticStructuredCredential0123456789"
	putHostCred(t, h, "fixture", secret, nil)
	res := h.s.sanitizeMCPResult(&mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: secret}},
		StructuredContent: map[string]any{"summary": secret},
	})
	if strings.Contains(res.Content[0].(*mcp.TextContent).Text, secret) {
		t.Fatal("text positive control was not scrubbed")
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(secret)) {
		t.Fatal("regression: structured content scrub persisted")
	}
	t.Log("text and StructuredContent both retain the scrubbed result")
}

func TestAstra8FixShortCredentialLiteralReadback(t *testing.T) {
	h := newHarness(t)
	const secret = "p4ssXYZ"
	r := h.do("POST", "/admin/api/credentials", map[string]any{
		"name": "short-svc", "kind": "api_key", "provider": "short-svc",
		"meta":   map[string]any{"allowed_hosts": []string{"api.example"}},
		"fields": map[string]string{"token": secret},
	}, nil, true)
	if r.code != 200 {
		t.Fatalf("owner write=%d", r.code)
	}
	calls := 0
	h.s.ext = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "api.example" || r.Header.Get("X-Key") != secret {
			t.Fatal("wrong fixture attachment")
		}
		return fakeResp(r, 200, `{"echo":"`+r.Header.Get("X-Key")+`"}`), nil
	})}
	key := h.agent("a8-short")
	id := astra6Approve(t, h, key, "http.request", map[string]any{"url": "https://api.example/diagnostic", "headers": []string{"X-Key: {{short-svc}}"}})
	h.s.runApproval(id)
	poll := h.do("GET", "/v1/approvals/"+id, nil, bearer(key), false)
	if poll.code != 200 || poll.body["status"] != "executed" || calls != 1 || bytes.Contains(poll.raw, []byte(secret)) {
		t.Fatalf("regression: status=%d calls=%d", poll.code, calls)
	}
	t.Log("CLOSED: admin accepts seven-byte secret; fake provider attachment succeeds; approval poll withholds literal echo")
}
