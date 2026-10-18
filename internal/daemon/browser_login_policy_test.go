package daemon

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/logins"
	"github.com/Harsette/ralx/internal/store"
)

func TestBrowserLoginHumanAddWriteOnly(t *testing.T) {
	l := newLiveHub(t)
	l.signIn()
	password := "SyntheticHumanWriteOnly!123456789"
	for _, name := range []string{"", "My demo", "Website login"} {
		code, reply, _ := l.browser("POST", "/admin/api/logins", map[string]any{"website": "https://app.example.com:8443/login", "username": "human@example.test", "password": password, "name": name})
		if code != 200 {
			t.Fatalf("human add without extra approval: %d", code)
		}
		b, _ := json.Marshal(reply)
		if strings.Contains(string(b), password) || strings.Contains(string(b), "password") {
			t.Fatal("write-only password echoed")
		}
		login, e := logins.Get(l.s.store, reply["login_id"].(string))
		want := name
		if want == "" {
			want = "app.example.com:8443"
		}
		if e != nil || login.Name != want || login.Kind != "real" || login.CreatedBy != "human" || login.Automatic(login.Origin) {
			t.Fatal("human login metadata or default name incorrect")
		}
	}
}

func TestClerkTestUsernameOption(t *testing.T) {
	h := newHarness(t)
	key := h.agent("clerk-test-option")
	r := h.do("POST", "/v1/actions/logins.new_test", map[string]any{"args": map[string]any{"origin": "http://127.0.0.1:19871", "clerk_test": true}}, bearer(key), false)
	if r.code != 200 {
		t.Fatalf("Clerk test option refused: %d %s", r.code, r.raw)
	}
	result, ok := r.body["result"].(map[string]any)
	if !ok || !strings.HasSuffix(result["username"].(string), "+clerk_test@example.com") {
		t.Fatalf("not a Clerk test email: %v", r.body)
	}
	if strings.Contains(string(r.raw), "password") {
		t.Fatal("password exposed")
	}
}

func TestBrowserLoginLegacyGeneratedDisplayName(t *testing.T) {
	h := newHarness(t)
	id := store.NewID("login_")
	_, e := h.s.store.CreateCredential(id, "website_login", "website", "Website login", map[string]any{"origins": []string{"http://127.0.0.1:19621"}, "username": "legacy@example.test", "kind": "test", "created_by": "agent", "ralx_generated": true}, map[string]string{"password": "SyntheticLegacyDisplay!123456789"})
	if e != nil {
		t.Fatal(e)
	}
	l, e := logins.Get(h.s.store, id)
	if e != nil || l.Name != "127.0.0.1:19621" {
		t.Fatal("legacy generated default did not become site host and port")
	}
}

func TestBrowserLoginPolicyAndReplacement(t *testing.T) {
	h := newHarness(t)
	key := h.agent("browser-policy")
	h.setupPasskey()
	id := store.NewID("login_")
	origin := "http://localhost:19192"
	put := func(password string) {
		r := h.do("POST", "/admin/api/credentials", map[string]any{"name": id, "kind": "website_login", "label": "SealedDisplayName", "meta": map[string]any{"origins": []string{origin}, "username": "sealed-user@example.test", "notes": "SealedPrivateNotes", "kind": "real", "created_by": "human"}, "fields": map[string]string{"password": password}}, nil, true)
		if r.code != 200 {
			t.Fatalf("save: %d", r.code)
		}
	}
	put("SyntheticBrowserPolicyPassword!123456789")
	args := map[string]any{"url": origin + "/signin", "login_id": id}
	first := h.do("POST", "/v1/actions/browser.sign_in", map[string]any{"args": args}, bearer(key), false)
	if first.code != 200 {
		t.Fatalf("held: %d", first.code)
	}
	held := first.body["result"].(map[string]any)
	if held["status"] != "needs_approval" {
		t.Fatal("human real localhost login not gated")
	}
	apID := held["approval_id"].(string)
	state := h.do("GET", "/admin/api/state", nil, nil, true)
	if !strings.Contains(string(state.raw), origin) || !strings.Contains(string(state.raw), "sealed-user@example.test") {
		t.Fatal("owner approval does not show exact destination and username")
	}
	ap, _ := h.s.store.GetApproval(apID)
	stored, _ := json.Marshal(ap)
	if strings.Contains(string(stored), origin) || strings.Contains(string(stored), "sealed-user") {
		t.Fatal("approval persisted plaintext login fields")
	}
	put("SyntheticReplacementPassword!987654321")
	as := h.stepUp("approve:" + apID)
	r := h.do("POST", "/admin/api/approvals/"+apID+"/approve", map[string]any{"assertion": as}, h.browser(), false)
	if r.code != 200 {
		t.Fatal("approve failed")
	}
	for i := 0; i < 100; i++ {
		ap, _ = h.s.store.GetApproval(apID)
		if ap.Status == "failed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ap.Status != "failed" || !strings.Contains(ap.Error, "identity changed") {
		t.Fatalf("old approval survived credential replacement: %s", ap.Status)
	}
	second := h.do("POST", "/v1/actions/browser.sign_in", map[string]any{"args": args}, bearer(key), false)
	held = second.body["result"].(map[string]any)
	newID := held["approval_id"].(string)
	h.do("POST", "/admin/api/approvals/"+newID+"/deny", nil, nil, true)
	third := h.do("POST", "/v1/actions/browser.sign_in", map[string]any{"args": args}, bearer(key), false)
	again := third.body["result"].(map[string]any)
	if again["approval_id"] != newID {
		t.Fatal("denied login silently created another approval")
	}
	l, e := logins.Get(h.s.store, id)
	if e != nil || l.LastUsedAt != 0 {
		t.Fatal("owner read marked a refused login as used")
	}
	// A RalX-generated test password outside HTTP loopback still needs approval.
	outside := h.do("POST", "/v1/actions/logins.new_test", map[string]any{"args": map[string]any{"origin": "https://example.test"}}, bearer(key), false)
	outID := outside.body["result"].(map[string]any)["login_id"]
	outside = h.do("POST", "/v1/actions/browser.sign_in", map[string]any{"args": map[string]any{"url": "https://example.test/signin", "login_id": outID}}, bearer(key), false)
	if outside.body["result"].(map[string]any)["status"] != "needs_approval" {
		t.Fatal("outside test login bypassed approval")
	}
}

func TestBrowserLoginOriginValidationDoesNotInspectSecrets(t *testing.T) {
	h := newHarness(t)
	for _, password := range []string{"http://localhost:19092", "AnotherSyntheticPassword!123456789"} {
		id := store.NewID("login_")
		_, e := h.s.store.CreateCredential(id, "website_login", "website", password, map[string]any{"username": password, "notes": password, "origins": []string{"http://localhost:19092"}, "kind": "real", "created_by": "human"}, map[string]string{"password": password})
		if e != nil {
			t.Fatal("valid origin rejected based on credential contents")
		}
		_, e = h.s.store.CreateCredential(store.NewID("login_"), "website_login", "website", password, map[string]any{"username": password, "origins": []string{"https://user:pass@example.test"}, "kind": "real", "created_by": "human"}, map[string]string{"password": password})
		if e == nil || e.Error() != "invalid website login" {
			t.Fatal("origin syntax error is not uniform")
		}
	}
}

func TestBrowserLoginNullExtraMetadata(t *testing.T) {
	h := newHarness(t)
	_, e := h.s.store.CreateCredential(store.NewID("login_"), "website_login", "website", "Fixture", map[string]any{"origins": []string{"http://localhost:19092"}, "username": "fixture@example.test", "notes": "retained notes", "kind": "real", "created_by": "human"}, map[string]string{"password": "SyntheticNullMetadataPassword!123456789", "metadata": "null"})
	if e != nil {
		t.Fatal(e)
	}
}
