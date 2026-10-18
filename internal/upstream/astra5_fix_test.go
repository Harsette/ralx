package upstream

// Astra5 upstream probes, inverted / kept as controls. Offline, synthetic, no
// sockets: the recording DialContext never opens one.
import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
)

// Trailing-dot "localhost." is the rooted form of localhost and resolves the
// same, so it must be rejected before any dial (Astra5 A11).
func TestAstra5FixTrailingDotLocalhostRejected(t *testing.T) {
	m := astra2Manager(t)
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	dialed := ""
	http.DefaultTransport = &http.Transport{DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = addr
		return nil, errors.New("synthetic terminal dial: no socket opened")
	}}
	var out map[string]any
	if _, err := m.getJSON(context.Background(), "https://localhost./internal", &out); err == nil {
		t.Fatal("defect reproduced: trailing-dot localhost URL was accepted")
	}
	if dialed != "" {
		t.Fatalf("defect reproduced: trailing-dot localhost reached a dial (%q)", dialed)
	}
}

// Control: literal private/loopback/mapped/zoned IPs and CGNAT are rejected, and
// invalid or reserved upstream names (empty, case, Unicode, dotted, too-short,
// reserved) are rejected.
func TestAstra5HeldUpstreamLiteralIPAndPrefixValidation(t *testing.T) {
	m := astra2Manager(t)
	for _, raw := range []string{
		"https://127.0.0.1/mcp", "https://[::1]/mcp", "https://[::ffff:127.0.0.1]/mcp",
		"https://[fe80::1%25fixture]/mcp", "https://10.0.0.1/mcp", "https://100.64.0.1/mcp",
	} {
		if err := m.checkURL(raw); err == nil {
			t.Fatalf("private/literal URL accepted: %s", raw)
		}
	}
	for _, name := range []string{"", "GH", "gh", "gh.issue", "Demo", "dеmo", "ab.cd", "a"} {
		if err := validateName(name); err == nil {
			t.Fatalf("invalid or reserved name accepted: %q", name)
		}
	}
}
