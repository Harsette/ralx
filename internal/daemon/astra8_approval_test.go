package daemon

import (
	"net/http"
	"testing"
)

// Retained original trigger inverted: replacement invalidates the approval.
func TestAstra8FixHTTPApprovalRefusesReplacementKey(t *testing.T) {
	h := newHarness(t)
	const oldKey = "SyntheticHTTPAccountAKey0123456789"
	const newKey = "SyntheticHTTPAccountBKey9876543210"
	putHostCred(t, h, "svc", oldKey, []string{"api.example"})
	calls, used := 0, ""
	h.s.ext = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		used = r.Header.Get("Authorization")
		if r.URL.Host != "api.example" {
			t.Fatalf("unexpected host: %s", r.URL.Host)
		}
		return fakeResp(r, 200, `{"ok":true}`), nil
	})}
	id := astra6Approve(t, h, h.agent("a8-http-replacement"), "http.request", map[string]any{
		"method": "POST", "url": "https://api.example/messages", "headers": []string{"Authorization: Bearer {{svc}}"}, "body": "synthetic message",
	})
	r := h.do("POST", "/admin/api/credentials", map[string]any{
		"name": "svc", "kind": "api_key", "provider": "svc", "meta": map[string]any{"allowed_hosts": []string{"api.example"}}, "fields": map[string]string{"token": newKey},
	}, nil, true)
	if r.code != 200 {
		t.Fatalf("replacement status=%d", r.code)
	}
	h.s.runApproval(id)
	ap, err := h.s.store.GetApproval(id)
	if err != nil || ap.Status != "failed" || calls != 0 || used != "" {
		t.Fatalf("replacement approval accepted: approval=%v calls=%d replacementUsed=%t err=%v", ap, calls, used == "Bearer "+newKey, err)
	}
	t.Log("old approval refuses replacement B with zero provider dispatches")
}
