package browserlogin

import (
	"fmt"
	"net/http"
	"testing"
)

func TestRCProbeCookiePoison(t *testing.T) {
	m, app, ctx := browserFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/signin" {
			fmt.Fprint(w, `<form method="post" action="/account"><input name="username"><input type="password"><button>Sign in</button></form>`)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "preference", Value: "a", Path: "/"})
		fmt.Fprint(w, `<h1 id="account">Account</h1>`)
	})
	got, _ := m.SignIn(ctx, "poison", Request{Origin: app.URL, URL: app.URL + "/signin", SuccessSelector: "#account"}, "fixture@example.test", "SyntheticPoisonPassword-42")
	if got.Status != "signed_in" {
		t.Fatalf("fixture sign-in: %+v", got)
	}
	out, bad := m.ScrubOutput([]byte(`{"agent":"unrelated","connections":[]}`))
	t.Logf("unrelated response withheld=%v output=%q", bad, out)
	if bad {
		t.Error("BUG: one ordinary short cookie poisons daemon-wide output")
	}
}
