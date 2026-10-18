package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
)

func TestAstra8HeldStaleActionAfterReconnect(t *testing.T) {
	h := newHarness(t)
	calls := 0
	h.s.up.Transport = astra2MCPTransport([]map[string]any{{"name": "dispatch", "inputSchema": map[string]any{"type": "object"}}}, &calls)
	if err := h.s.up.AddHeaderServer("demo", "https://first.example/mcp", "X-Key", "SyntheticStaleActionAccountACredential0123"); err != nil {
		t.Fatal(err)
	}
	a, ok := h.s.reg.Get("demo.dispatch")
	if !ok {
		t.Fatal("fixture action absent")
	}
	if err := h.s.up.AddHeaderServer("demo", "https://second.example/mcp", "X-Key", "SyntheticStaleActionAccountBCredential9876"); err != nil {
		t.Fatal(err)
	}
	// Simulate runApproval having acquired a before reconnect. This reaches the
	// per-dispatch digest check rather than stopping at runApproval's registry check.
	if _, err := a.Native(context.Background(), nil, map[string]any{}); err == nil {
		t.Fatal("stale action closure dispatched")
	}
	if calls != 0 {
		t.Fatalf("upstream calls=%d", calls)
	}
	t.Log("captured old action closure after completed reconnect: per-dispatch digest refuses, zero calls")
}

func TestAstra8HeldHeaderOnlyReplacement(t *testing.T) {
	h := newHarness(t)
	calls := 0
	h.s.up.Transport = astra2MCPTransport([]map[string]any{{"name": "dispatch", "inputSchema": map[string]any{"type": "object"}}}, &calls)
	if err := h.s.up.AddHeaderServer("demo", "https://first.example/mcp", "X-Old-Key", "SyntheticHeaderOnlyCredential0123456789"); err != nil {
		t.Fatal(err)
	}
	id := astra6Approve(t, h, h.agent("a8-header"), "demo.dispatch", map[string]any{})
	before, err := h.s.store.GetCredential("mcp:demo")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.s.store.UpdateMeta("mcp:demo", map[string]any{"header": "X-New-Key"}); err != nil {
		t.Fatal(err)
	}
	after, err := h.s.store.GetCredential("mcp:demo")
	if err != nil {
		t.Fatal(err)
	}
	if before.Meta["gen"] != after.Meta["gen"] {
		t.Fatal("fixture accidentally changed gen")
	}
	h.s.runApproval(id)
	ap, err := h.s.store.GetApproval(id)
	if err != nil || ap.Status != "failed" || calls != 0 {
		t.Fatalf("status=%v calls=%d err=%v", ap.Status, calls, err)
	}
	t.Log("header changed alone, stored gen unchanged: old approval failed, zero upstream calls")
}

func TestAstra8HeldCallDuringReconnect(t *testing.T) {
	h := newHarness(t)
	calls := 0
	base := astra2MCPTransport([]map[string]any{{"name": "dispatch", "inputSchema": map[string]any{"type": "object"}}}, &calls)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.s.up.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "second.example" && r.Body != nil {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			r.Body = io.NopCloser(bytes.NewReader(b))
			var msg struct {
				Method string `json:"method"`
			}
			_ = json.Unmarshal(b, &msg)
			if msg.Method == "tools/list" {
				once.Do(func() { close(entered); <-release })
			}
		}
		return base.RoundTrip(r)
	})
	if err := h.s.up.AddHeaderServer("demo", "https://first.example/mcp", "X-Key", "SyntheticReconnectAccountACredential012345"); err != nil {
		t.Fatal(err)
	}
	id := astra6Approve(t, h, h.agent("a8-reconnect"), "demo.dispatch", map[string]any{})
	done := make(chan error, 1)
	go func() {
		done <- h.s.up.AddHeaderServer("demo", "https://second.example/mcp", "X-Key", "SyntheticReconnectAccountBCredential987654")
	}()
	<-entered
	h.s.runApproval(id)
	ap, err := h.s.store.GetApproval(id)
	close(release)
	if loadErr := <-done; loadErr != nil {
		t.Fatal(loadErr)
	}
	if err != nil || ap.Status != "failed" || calls != 0 {
		t.Fatalf("status=%v calls=%d err=%v", ap.Status, calls, err)
	}
	t.Log("replacement stored, reconnect paused at tools/list, old approval refused; zero upstream tool calls")
}
