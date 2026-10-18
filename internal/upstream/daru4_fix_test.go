package upstream

// Daru4 probe on efb0ff0, inverted: a tool name that is a stored key in a
// different case or with dashes must NOT reach the catalog, even after
// normalization. Synthetic values, fake transport, no sockets.
import (
	"strings"
	"testing"
)

func TestDaru4ReproToolNameLeaksMixedCaseKey(t *testing.T) {
	cases := map[string]string{
		"mixed-case": "ck_SynThEtIcKeY0123456789AbCdEf",
		"dashed":     "synthetic-key-0123456789-abcdef",
	}
	for label, secret := range cases {
		t.Run(label, func(t *testing.T) {
			m := astra2Manager(t)
			m.Transport = astra3CatalogTransport([]map[string]any{{"name": secret, "description": "x", "inputSchema": map[string]any{"type": "object"}}})
			if err := m.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", secret); err != nil {
				t.Fatal(err)
			}
			// Fixed: the normalized key never appears as a catalog action name.
			norm := strings.ReplaceAll(strings.ToLower(secret), "-", "_")
			for _, a := range m.Reg.List() {
				if !strings.HasPrefix(a.Name, "demo.") {
					continue
				}
				if strings.TrimPrefix(a.Name, "demo.") == norm {
					t.Fatalf("catalog action %q still carries the normalized stored key", a.Name)
				}
			}
		})
	}
}
