package daemon

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCatalogOutputRequiresListRequestAndMatchingResponse(t *testing.T) {
	for _, tc := range []struct {
		method, body string
		want         bool
	}{
		{"tools/list", `{"jsonrpc":"2.0","id":2,"result":{"tools":[],"ttlMs":0,"cacheScope":"public"}}`, true},
		{"tools/call", `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`, false},
		{"tools/list", `{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}`, false},
		{"tools/list", `{"jsonrpc":"2.0","id":2,"error":{"tools":[]}}`, false},
		{"tools/list", `{"jsonrpc":"2.0","id":2,"result":{"content":[],"tools":[]}}`, false},
	} {
		raw := `{"jsonrpc":"2.0","id":2,"method":"` + tc.method + `","params":{}}`
		r := httptest.NewRequest("POST", "http://localhost:7399/mcp", strings.NewReader(raw))
		rest, id := catalogRequest(r)
		restored, _ := io.ReadAll(r.Body)
		if string(restored) != raw {
			t.Fatal("request body changed")
		}
		w := &agentWriter{code: http.StatusOK, catalogREST: rest, catalogID: id}
		if got := w.catalogResponse([]byte(tc.body)); got != tc.want {
			t.Fatalf("method=%s response=%s selected=%v", tc.method, tc.body, got)
		}
		w.code = http.StatusUnauthorized
		if w.catalogResponse([]byte(tc.body)) {
			t.Fatal("denied request selected catalog mode")
		}
	}
	h := newHarness(t)
	if r := h.do("GET", "/v1/actions", nil, nil, false); r.code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list=%d", r.code)
	}
	// A large tools-shaped normal result remains under the generic 128-part cap.
	h.s.red.Add("fixture", "SyntheticNormalResultCapCredential012345")
	parts := make([]string, 200)
	for i := range parts {
		parts[i] = "ordinary"
	}
	b, _ := json.Marshal(map[string]any{"tools": parts})
	if _, held := h.s.agentScrub(b); !held {
		t.Fatal("normal result cap lowered")
	}
}
