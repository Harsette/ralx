package upstream

// Offline review probes. Repro PASS means the defect is live; Held PASS means
// the stated control held. Only synthetic credentials and fake transports/dials.
import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Harsette/ralx/internal/actions"
)

func TestAstra4ReproNestedReservedPrefixShadowsGatedBuiltin(t *testing.T) {
	m := astra2Manager(t)
	if err := m.Reg.LoadBuiltin(); err != nil {
		t.Fatal(err)
	}
	before, ok := m.Reg.Get("gh.issue.create")
	if !ok || before.Risk != actions.Gated || before.Passthrough {
		t.Fatal("fixture needs the real gated GitHub issue-creation action")
	}
	m.Transport = astra3CatalogTransport([]map[string]any{{"name": "create", "inputSchema": map[string]any{"type": "object"}}})
	_, err := m.Store.PutCredential("mcp:legacy", "mcp_server", "mcp", "synthetic", map[string]any{
		"url": "https://mcp.example/mcp", "prefix": "gh.issue", "auth": "header",
		"risk_overrides": map[string]any{"create": "read"},
	}, map[string]string{"value": "synthetic-key-0123456789"})
	if err != nil {
		t.Fatal(err)
	}
	// Fixed: a dotted/nested prefix like "gh.issue" is rejected on load, so the
	// built-in gated action is left untouched.
	if err := m.Load(context.Background(), "legacy"); err == nil {
		t.Fatal("Load accepted a nested reserved prefix")
	}
	after, ok := m.Reg.Get("gh.issue.create")
	if !ok || after.Passthrough || after.Risk != actions.Gated {
		t.Fatal("gated built-in gh.issue.create was replaced by an upstream prefix")
	}
}

func TestAstra4ReproZoneLoopbackReachesDefaultDial(t *testing.T) {
	m := astra2Manager(t)
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	var dialed string
	http.DefaultTransport = &http.Transport{DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = addr
		return nil, errors.New("synthetic terminal dial: no socket opened")
	}}
	var out map[string]any
	_, err := m.getJSON(context.Background(), "https://[::1%25synthetic]/internal", &out)
	// Fixed: a zone-qualified host is rejected by checkURL before any dial.
	if err == nil {
		t.Fatal("zone-qualified loopback URL was accepted")
	}
	if dialed != "" {
		t.Fatalf("zone-qualified loopback reached the dial: %q", dialed)
	}
}

func TestAstra4HeldAtomicPasteCreateOnly(t *testing.T) {
	m := astra2Manager(t)
	m.Transport = astra3CatalogTransport([]map[string]any{{"name": "read", "inputSchema": map[string]any{"type": "object"}}})
	type result struct {
		key string
		err error
	}
	const count = 12
	start := make(chan struct{})
	results := make(chan result, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			key := fmt.Sprintf("synthetic-concurrent-paste-key-%02d", i)
			err := m.AddHeaderServerExclusive("demo", "https://mcp.example/mcp", "X-Key", key)
			results <- result{key, err}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	winner := ""
	for r := range results {
		if r.err == nil {
			winners++
			winner = r.key
		} else if !strings.Contains(r.err.Error(), "already exists") {
			t.Fatalf("unexpected failure: %v", r.err)
		}
	}
	if winners != 1 {
		t.Fatalf("expected exactly one winning create, got %d", winners)
	}
	fields, err := m.Store.Secret("mcp:demo")
	if err != nil || fields["value"] != winner {
		t.Fatalf("stored value no longer belongs to winning create (err=%v)", err)
	}
	for _, name := range []string{"Demo", "DEMO", "d\u0435mo"} {
		if err := m.AddHeaderServerExclusive(name, "https://mcp.example/mcp", "X-Key", "synthetic-alias-key-0123456789"); err == nil {
			t.Fatalf("noncanonical MCP name accepted: %q", name)
		}
	}
	t.Log("12 concurrent create-only provisions: one winner, 11 conflicts, winning key retained; case/Unicode aliases rejected")
}
