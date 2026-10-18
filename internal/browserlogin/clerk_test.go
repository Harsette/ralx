package browserlogin

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClerkTestEmailVerificationJourney(t *testing.T) {
	var codePosts atomic.Int64
	m, app, ctx := browserFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/signup":
			fmt.Fprint(w, `<form method="post" action="/verify"><input name="username"><input name="password" type="password"><button>Sign up</button></form>`)
		case "/verify":
			r.ParseForm()
			if r.FormValue("password") == "" {
				http.Error(w, "fixture password required", 400)
				return
			}
			fmt.Fprint(w, `<h1>Verify your email</h1><form method="post" action="/finish"><input name="code" autocomplete="one-time-code" maxlength="6"><button>Verify</button></form>`)
		case "/split-signup":
			fmt.Fprint(w, `<form method="post" action="/split-verify"><input name="username"><input name="password" type="password"><button>Sign up</button></form>`)
		case "/split-verify":
			fmt.Fprint(w, `<h1>Verify your email</h1><form method="post" action="/finish"><input name="c1" inputmode="numeric" maxlength="1"><input name="c2" inputmode="numeric" maxlength="1"><input name="c3" inputmode="numeric" maxlength="1"><input name="c4" inputmode="numeric" maxlength="1"><input name="c5" inputmode="numeric" maxlength="1"><input name="c6" inputmode="numeric" maxlength="1"><button>Verify</button></form>`)
		case "/finish":
			r.ParseForm()
			code := r.FormValue("code")
			if code == "" {
				for _, k := range []string{"c1", "c2", "c3", "c4", "c5", "c6"} {
					code += r.FormValue(k)
				}
			}
			codePosts.Add(1)
			if code != "424242" {
				http.Error(w, "fixture code rejected", 400)
				return
			}
			http.Redirect(w, r, "/account", 303)
		case "/account":
			fmt.Fprint(w, `<h1 id="account">Signed in</h1>`)
		}
	})
	for _, route := range []string{"/signup", "/split-signup"} {
		got, _ := m.SignUp(ctx, "clerk", Request{Origin: app.URL, URL: app.URL + route, SuccessSelector: "#account"}, "fixture+clerk_test@example.com", "SyntheticClerkPassword-42")
		if got.Status != "signed_in" {
			t.Fatalf("test verification step unsupported: %+v", got)
		}
	}
	for _, username := range []string{"real@example.com", "fixture+clerk_test_spoof@example.com"} {
		got, _ := m.SignUp(ctx, "ordinary", Request{Origin: app.URL, URL: app.URL + "/signup", SuccessSelector: "#account"}, username, "SyntheticClerkPassword-42")
		if got.Status != "needs_verification" || !strings.Contains(got.Reason, "verification") {
			t.Fatalf("ordinary verification not handed back safely: %+v", got)
		}
	}
	if codePosts.Load() != 2 {
		t.Fatalf("test code sent for an ordinary address: %d", codePosts.Load())
	}
}
