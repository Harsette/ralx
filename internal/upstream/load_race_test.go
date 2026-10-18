package upstream

// A load that started on an old login must not mark, tear down or replace the
// owner's newer connection (Sol final review F-a). Ordering is forced with
// channels in a fake transport: the old load's tools/list is held until the
// owner's reconnect has fully loaded. Synthetic keys, no sockets, no sleeps.
import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

const (
	loadRaceOldKey = "SyntheticLoadRaceOldKey0123456789"
	loadRaceNewKey = "SyntheticLoadRaceNewKey0123456789"
)

// loadRaceTransport answers MCP for both keys, but holds the OLD key's
// tools/list until release closes, then fails it or answers it.
func loadRaceTransport(entered chan<- struct{}, release <-chan struct{}, oldFails bool) http.RoundTripper {
	return astra2RT(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" {
			return astra2Response(r, 405, ""), nil
		}
		var msg struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			return nil, err
		}
		if msg.ID == nil {
			return astra2Response(r, 202, ""), nil
		}
		old := r.Header.Get("X-Key") == loadRaceOldKey
		var result any
		switch msg.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "synthetic", "version": "1"}}
		case "tools/list":
			tool := "search_new"
			if old {
				entered <- struct{}{}
				<-release
				if oldFails {
					return astra2Response(r, 500, ""), nil
				}
				tool = "search_old"
			}
			result = map[string]any{"tools": []map[string]any{{"name": tool, "inputSchema": map[string]any{"type": "object"}}}}
		default:
			return nil, errors.New("unexpected MCP method")
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": result})
		res := astra2Response(r, 200, string(b))
		res.Header.Set("Content-Type", "application/json")
		return res, nil
	})
}

func runLoadRace(t *testing.T, oldFails bool) *Manager {
	t.Helper()
	m := astra2Manager(t)
	entered, release := make(chan struct{}), make(chan struct{})
	m.Transport = loadRaceTransport(entered, release, oldFails)
	meta := map[string]any{"url": "https://mcp.example/mcp", "prefix": "demo", "auth": "header", "header": "X-Key", "gen": "generation-old"}
	if _, err := m.Store.PutCredential(credPrefix+"demo", "mcp_server", "mcp", "fixture", meta, map[string]string{"value": loadRaceOldKey}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.Load(context.Background(), "demo") }()
	<-entered // the old load is waiting on tools/list
	if err := m.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", loadRaceNewKey); err != nil {
		t.Fatalf("owner reconnect: %v", err)
	}
	close(release)
	<-done
	return m
}

func assertNewConnectionIntact(t *testing.T, m *Manager) {
	t.Helper()
	c, _ := m.Store.GetCredential(credPrefix + "demo")
	if c.Meta["status"] != "ok" || c.Meta["error"] != nil {
		t.Errorf("the reconnected upstream is marked %v (%v)", c.Meta["status"], c.Meta["error"])
	}
	m.mu.Lock()
	s := m.sessions["demo"]
	m.mu.Unlock()
	if s == nil || s.genfp != m.genFP("demo") {
		t.Error("the reconnected upstream's live session was torn down or replaced by the old load")
	}
	if _, ok := m.Reg.Get("demo.search_new"); !ok {
		t.Error("the reconnected upstream's tools were replaced by the old load's")
	}
	if _, ok := m.Reg.Get("demo.search_old"); ok {
		t.Error("the old load published its tools over the reconnected upstream")
	}
}

func TestStaleLoadFailureKeepsReconnectedStatus(t *testing.T) {
	assertNewConnectionIntact(t, runLoadRace(t, true))
}

func TestStaleLoadSuccessKeepsReconnectedSession(t *testing.T) {
	assertNewConnectionIntact(t, runLoadRace(t, false))
}
