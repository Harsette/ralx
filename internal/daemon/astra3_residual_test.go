package daemon

// Astra3 probes, inverted: each asserts the FIX, using only synthetic values and
// in-memory HTTP transports/handlers.
import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAstra3ReproSharedFolderNameUngated(t *testing.T) {
	h := newHarness(t)
	var posted map[string]any
	reads := 0
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" {
			reads++
			return fakeResp(r, 200, `{"shared":true,"ownedByMe":true,"permissions":[{"type":"anyone"}]}`), nil
		}
		if r.Method != "POST" || r.URL.Path != "/drive/v3/files" {
			t.Fatalf("unexpected method/path: %s %s", r.Method, r.URL.Path)
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &posted); err != nil {
			t.Fatal(err)
		}
		return fakeResp(r, 200, `{"id":"synthetic-new-folder"}`), nil
	})
	r := h.do("POST", "/v1/actions/drive.create_folder", map[string]any{"args": map[string]any{
		"name": "agent-supplied-private-information", "parent_id": "sharedfolder123", "account": "test@x",
	}}, bearer(h.agent("folder-probe")), false)
	// Fixed: creating a folder inside a specified parent is held for approval, so
	// nothing is POSTed to Drive and no name reaches a shared parent.
	if r.code != 202 {
		t.Fatalf("folder create under a parent should be held: %d %s", r.code, r.raw)
	}
	if posted != nil {
		t.Fatalf("a folder was created without approval: %v", posted)
	}
	_ = reads
}

func TestAstra3ReproLoopbackProxyLocality(t *testing.T) {
	h := newHarness(t)
	h.s.hub.InternetOrigins = []string{"https://public.example"}
	mux := http.NewServeMux()
	h.s.routes(mux)
	handler := h.s.hostGuard(mux)
	r := httptest.NewRequest("POST", "http://localhost:7399/admin/api/credentials/meta", strings.NewReader(`{}`))
	// This is what a local reverse proxy forwarding a client-supplied or
	// rewritten localhost Host presents to the hub. No actual server is used.
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("X-Forwarded-Host", "public.example")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	// Fixed: a loopback proxy forwarding a public host (X-Forwarded-Host) is
	// classified as internet-facing, so sensitive admin is refused (403).
	if w.Code != 403 {
		t.Fatalf("loopback-proxy internet request reached admin auth: %d %s", w.Code, w.Body.String())
	}
}

func TestAstra3ReproPublicInitialSetup(t *testing.T) {
	h := newHarness(t)
	h.s.hub.InternetOrigins = []string{"https://public.example"}
	var err error
	h.s.admin, err = newAdminAuth(h.s.store, h.s.allOrigins())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.s.routes(mux)
	handler := h.s.hostGuard(mux)
	// A synthetic valid RP-bound first-setup capability, as the installer/admin
	// setup-link can mint. This demonstrates missing locality, not guessing it.
	token := h.s.mintSetupToken("public.example", "setup")
	b, _ := json.Marshal(map[string]string{"token": token})
	r := httptest.NewRequest("POST", "https://public.example/admin/api/setup/begin", bytes.NewReader(b))
	r.RemoteAddr = "203.0.113.10:54321"
	r.Header.Set("Origin", "https://public.example")
	r.Header.Set("X-RalX-CSRF", "synthetic")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	// Fixed: first-time setup is refused on an internet origin / public peer,
	// before the capability is even checked.
	if w.Code != 403 {
		t.Fatalf("public-origin initial setup was not refused: %d %s", w.Code, w.Body.String())
	}
}
