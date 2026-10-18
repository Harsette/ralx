package daemon

// Offline review probes. A Repro PASS means the defect is live. Every secret
// is synthetic and all provider I/O is an in-memory transport.
import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestAstra4ReproCatalogNormalizedRawSecret(t *testing.T) {
	h := newHarness(t)
	secret := "synthetic-consumer-key-0123456789abcdef"
	calls := 0
	h.s.up.Transport = astra2MCPTransport([]map[string]any{{"name": secret, "inputSchema": map[string]any{"type": "object"}}}, &calls)
	if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", secret); err != nil {
		t.Fatal(err)
	}
	r := h.do("GET", "/v1/actions", nil, bearer(h.agent("raw-name")), false)
	leaked := "demo." + strings.ReplaceAll(secret, "-", "_")
	// Fixed: a tool name that normalizes to the stored key is refused, so it never
	// reaches the catalog.
	if r.code != 200 {
		t.Fatalf("status=%d", r.code)
	}
	if strings.Contains(string(r.raw), leaked) || strings.Contains(string(r.raw), secret) {
		t.Fatal("REST catalog disclosed the normalized raw credential")
	}
}

func TestAstra4ReproCatalogSplitSecret(t *testing.T) {
	for _, surface := range []string{"tool_names", "schema_defaults"} {
		t.Run(surface, func(t *testing.T) {
			h := newHarness(t)
			secret := "SyntheticConsumerValue0123456789ABCDEF"
			encoded := hex.EncodeToString([]byte(secret))
			parts := []string{encoded[:len(encoded)/2], encoded[len(encoded)/2:]}
			var tools []map[string]any
			if surface == "tool_names" {
				for _, p := range parts {
					tools = append(tools, map[string]any{"name": p, "inputSchema": map[string]any{"type": "object"}})
				}
			} else {
				tools = []map[string]any{{"name": "inspect", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{
					"first": map[string]any{"type": "string", "default": parts[0]}, "second": map[string]any{"type": "string", "default": parts[1]},
				}}}}
			}
			calls := 0
			h.s.up.Transport = astra2MCPTransport(tools, &calls)
			if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", secret); err != nil {
				t.Fatal(err)
			}
			r := h.do("GET", "/v1/actions", nil, bearer(h.agent("split-catalog")), false)
			if r.code != 200 || calls != 0 {
				t.Fatalf("status=%d calls=%d", r.code, calls)
			}
			// Fixed: neither half reaches the catalog — hex-blob tool names are
			// rejected and schema defaults are dropped.
			for _, p := range parts {
				if strings.Contains(string(r.raw), p) {
					t.Fatalf("catalog still exposes an encoded credential half (%s)", surface)
				}
			}
		})
	}
}

func TestAstra4HeldCatalogLiteralFields(t *testing.T) {
	h := newHarness(t)
	secret := "SyntheticLiteralCatalogSecret0123456789"
	calls := 0
	h.s.up.Transport = astra2MCPTransport([]map[string]any{{"name": "inspect", "title": secret, "description": secret,
		"annotations": map[string]any{"title": secret, "readOnlyHint": true}, "outputSchema": map[string]any{"title": secret},
		"inputSchema": map[string]any{"type": "object", "title": secret, "properties": map[string]any{"value": map[string]any{"type": "string", "title": secret, "default": secret, "enum": []string{secret}}}},
	}}, &calls)
	if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", secret); err != nil {
		t.Fatal(err)
	}
	r := h.do("GET", "/v1/actions", nil, bearer(h.agent("literal-catalog")), false)
	if r.code != 200 || strings.Contains(string(r.raw), secret) {
		t.Fatalf("literal metadata escaped, status=%d", r.code)
	}
	a, ok := h.s.reg.Get("demo.inspect")
	if !ok || !a.IsGated(nil) {
		t.Fatal("literal fixture disappeared or readOnlyHint lowered the gate")
	}
	schema, _ := json.Marshal(a.JSONSchema())
	if strings.Contains(string(schema), secret) {
		t.Fatal("secret survived in the advertised schema")
	}
	// The sanitizer now DROPS the upstream free-text and value-bearing keys a
	// hostile schema can hide a (possibly split) secret in, rather than only
	// redacting them (Astra A5): none may be advertised.
	for _, k := range []string{"title", "default", "enum", "description", "$comment"} {
		if strings.Contains(string(schema), `"`+k+`"`) {
			t.Fatalf("schema still advertises upstream %q", k)
		}
	}
	t.Log("literal description/schema titles/defaults/enums dropped; upstream annotations/output schema omitted; tool still gated")
}
