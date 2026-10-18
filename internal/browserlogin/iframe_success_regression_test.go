package browserlogin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRCProbeSuccessWithForeignIframe(t *testing.T) {
	widget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "harmless third-party widget") }))
	defer widget.Close()
	m, app, ctx := browserFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/signin" {
			fmt.Fprint(w, `<form method="post" action="/account"><input name="username"><input type="password"><button>Sign in</button></form>`)
			return
		}
		fmt.Fprintf(w, `<h1 id="account">Account</h1><iframe src="%s"></iframe>`, widget.URL)
	})
	for _, selector := range []string{"#account", ""} {
		got, _ := m.SignIn(ctx, "origin"+selector, Request{Origin: app.URL, URL: app.URL + "/signin", SuccessSelector: selector}, "fixture@example.test", "SyntheticWidgetPassword-42")
		t.Logf("selector=%q signed-in page with unrelated iframe: status=%s", selector, got.Status)
		if got.Status != "signed_in" {
			t.Errorf("BUG: unrelated visible cross-origin iframe rejects successful same-origin sign-in: %+v", got)
		}
	}
}
