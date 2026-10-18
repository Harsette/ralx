package daemon

import (
	"context"
	"fmt"
	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/browserlogin"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRCProbeCrossAgentCookiePoison(t *testing.T) {
	if os.Getenv("RALX_BROWSER_TESTS") != "1" {
		t.Skip("Chrome requires shared heavy slot")
	}
	h := newHarness(t)
	key := h.agent("unrelated")
	before := h.do("POST", "/v1/actions/test.danger", map[string]any{"args": map[string]any{"thing": "synthetic"}}, bearer(key), false)
	if strings.Contains(string(before.raw), "withheld") {
		t.Fatal("fixture baseline withheld")
	}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/signin" {
			fmt.Fprint(w, `<form method="post" action="/account"><input name="username"><input type="password"><button>Sign in</button></form>`)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "preference", Value: "a", Path: "/"})
		fmt.Fprint(w, `<h1 id="account">Account</h1>`)
	}))
	defer app.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, _ := h.s.browser.SignIn(ctx, "different-agent", browserlogin.Request{Origin: app.URL, URL: app.URL + "/signin", SuccessSelector: "#account"}, "fixture@example.test", "SyntheticPoisonPassword-42")
	if got.Status != "signed_in" {
		t.Fatal(got)
	}
	after := h.do("POST", "/v1/actions/test.danger", map[string]any{"args": map[string]any{"thing": "synthetic"}}, bearer(key), false)
	t.Logf("before=%s after=%s", before.raw, after.raw)
	if strings.Contains(string(after.raw), "withheld") {
		t.Error("BUG: unrelated agent whoami disabled by another site's non-auth cookie")
	}
}

func TestBrowserSessionTokenAgentIsolation(t *testing.T) {
	if os.Getenv("RALX_BROWSER_TESTS") != "1" {
		t.Skip("Chrome requires shared heavy slot")
	}
	h := newHarness(t)
	ownerKey, otherKey := h.agent("cookie-owner"), h.agent("cookie-other")
	owner, err := h.s.store.AuthenticateAgent(ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	const token = "SyntheticScopedSessionToken-42"
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/signin" {
			fmt.Fprint(w, `<form method="post" action="/account"><input name="username"><input type="password"><button>Sign in</button></form>`)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: token, HttpOnly: true, Path: "/"})
		fmt.Fprint(w, `<h1 id="account">Account</h1><p>`+token+`</p>`)
	}))
	defer app.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := browserlogin.Request{Origin: app.URL, URL: app.URL + "/signin", SuccessSelector: "#account"}
	got, _ := h.s.browser.SignIn(ctx, owner.ID, r, "fixture@example.test", "SyntheticIsolationPassword-42")
	if got.Status != "signed_in" {
		t.Fatal(got)
	}
	text, _ := h.s.browser.AccountText(ctx, owner.ID, r)
	if text.Status != "signed_in" || !strings.Contains(text.Text, "Account") || strings.Contains(text.Text, token) {
		t.Fatalf("owning account text did not scrub long token: %+v", text)
	}
	if err := h.s.reg.Add(&actions.Action{Name: "test.session_echo", Risk: actions.Read, Native: func(context.Context, actions.Env, map[string]any) (any, error) {
		return map[string]any{"text": token}, nil
	}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key      string
		contains bool
	}{{otherKey, true}, {ownerKey, false}} {
		out := h.do("POST", "/v1/actions/test.session_echo", map[string]any{"args": map[string]any{}}, bearer(tc.key), false)
		if out.code != 200 || strings.Contains(string(out.raw), token) != tc.contains {
			t.Fatalf("agent scope contains=%v: %d %s", tc.contains, out.code, out.raw)
		}
	}
}
