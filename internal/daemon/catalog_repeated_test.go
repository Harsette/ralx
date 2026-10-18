package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRepeatedBenignUpstreamCatalogLoads(t *testing.T) {
	h := newHarness(t)
	tools := make([]map[string]any, 44)
	for i := range tools {
		tools[i] = map[string]any{"name": fmt.Sprintf("inspect%02d", i), "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}}}}
	}
	// Real page-edit tools exceed the ordinary 128 JSON-fragment result limit.
	// Two complex schemas must still be checked and advertised in full.
	for i := 0; i < 2; i++ {
		properties := map[string]any{}
		for j := 0; j < 70; j++ {
			properties[fmt.Sprintf("field_%02d", j)] = map[string]any{"type": "string"}
		}
		tools[i]["inputSchema"] = map[string]any{"type": "object", "properties": properties}
	}
	calls := 0
	h.s.up.Transport = astra2MCPTransport(tools, &calls)
	started := time.Now()
	if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", "SyntheticBenignCatalogCredential012345"); err != nil {
		t.Fatal(err)
	}
	t.Logf("catalog load: %s", time.Since(started))
	count := 0
	for _, a := range h.s.reg.List() {
		if strings.HasPrefix(a.Name, "demo.") {
			count++
		}
	}
	if count != len(tools) || calls != 0 {
		t.Fatalf("loaded=%d, want44, dispatched=%d", count, calls)
	}
	key := h.agent("catalog-repeated")
	started = time.Now()
	rest := h.do("GET", "/v1/actions", nil, bearer(key), false)
	t.Logf("REST catalog: %s", time.Since(started))
	init := mcpDo(h, key, "", "", true)
	started = time.Now()
	remote := mcpDo(h, key, "", init.Header().Get("Mcp-Session-Id"), false)
	t.Logf("MCP catalog: %s", time.Since(started))
	if rest.code != 200 || remote.Code != 200 || !strings.Contains(string(rest.raw), "demo.inspect43") || !strings.Contains(remote.Body.String(), "demo_inspect43") || !strings.Contains(string(rest.raw), "field_69") || !strings.Contains(remote.Body.String(), "field_69") {
		t.Fatalf("complete catalog missing: REST=%d %.300s MCP=%d %.300s", rest.code, rest.raw, remote.Code, remote.Body.String())
	}
}
