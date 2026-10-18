package browserlogin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestRCProbeJSGET(t *testing.T) {
	for _, variant := range []string{"submit-mutation", "input-fetch", "hidden-on-input", "input-fetch-path", "input-fetch-form", "input-fetch-double", "input-fetch-malformed"} {
		t.Run(variant, func(t *testing.T) {
			const secret = "SyntheticRCQuery /+?%Password-42"
			var mu sync.Mutex
			var captures []string
			m, app, ctx := browserFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/capture") {
					mu.Lock()
					captures = append(captures, r.URL.RequestURI())
					mu.Unlock()
					fmt.Fprint(w, `<h1 id="account">Signed in</h1>`)
					return
				}
				fmt.Fprint(w, `<form method="post" action="/capture"><input name="username"><input name="password" type="password"><button>Sign in</button></form><script>`)
				switch variant {
				case "submit-mutation":
					fmt.Fprint(w, `document.querySelector('form').addEventListener('submit',e=>e.target.method='GET');`)
				case "input-fetch":
					fmt.Fprint(w, `document.querySelector('[type=password]').addEventListener('input',e=>fetch('/capture?password='+encodeURIComponent(e.target.value)));document.querySelector('form').onsubmit=e=>{e.preventDefault();location.href='/capture?ok=1'};`)
				case "hidden-on-input":
					fmt.Fprint(w, `document.querySelector('[type=password]').addEventListener('input',e=>{e.target.type='hidden';e.target.form.method='GET'});`)
				case "input-fetch-path":
					fmt.Fprint(w, `document.querySelector('[type=password]').addEventListener('input',e=>fetch('/capture/'+encodeURIComponent(e.target.value)));document.querySelector('form').onsubmit=e=>{e.preventDefault();location.href='/capture?ok=1'};`)
				case "input-fetch-form":
					fmt.Fprint(w, `document.querySelector('[type=password]').addEventListener('input',e=>fetch('/capture?'+new URLSearchParams({password:e.target.value})));document.querySelector('form').onsubmit=e=>{e.preventDefault();location.href='/capture?ok=1'};`)
				case "input-fetch-double":
					fmt.Fprint(w, `document.querySelector('[type=password]').addEventListener('input',e=>fetch('/capture?password='+encodeURIComponent(encodeURIComponent(e.target.value))));document.querySelector('form').onsubmit=e=>{e.preventDefault();location.href='/capture?ok=1'};`)
				case "input-fetch-malformed":
					fmt.Fprintf(w, "%s", `document.querySelector('[type=password]').addEventListener('input',e=>fetch('/capture?padding=%broken&password='+encodeURIComponent(e.target.value)));document.querySelector('form').onsubmit=e=>{e.preventDefault();location.href='/capture?ok=1'};`)
				}
				fmt.Fprint(w, `</script>`)
			})
			got, _ := m.SignIn(ctx, "jsget", Request{Origin: app.URL, URL: app.URL + "/signin", SuccessSelector: "#account"}, "fixture@example.test", secret)
			mu.Lock()
			joined := strings.Join(captures, "\n")
			mu.Unlock()
			t.Logf("status=%s captures=%q", got.Status, joined)
			if got.Status != "failed" || got.Reason != "the page tried to put the password in a web address" {
				t.Errorf("unsafe outcome: %+v", got)
			}
			for _, raw := range captures {
				u, err := url.ParseRequestURI(raw)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(u.Path, secret) || strings.Contains(u.Query().Get("password"), secret) {
					t.Errorf("BUG: password reached fixture URL via %s", variant)
				}
			}
		})
	}
}

func TestPasswordURLRepresentations(t *testing.T) {
	const password = "Synthetic /+?%Password-42"
	for _, raw := range []string{"https://example.test/" + password, "https://example.test/" + url.PathEscape(password), "https://example.test/?p=" + url.QueryEscape(password), "https://example.test/?p=" + url.QueryEscape(url.QueryEscape(password)), "https://example.test/?bad=%broken&p=" + url.QueryEscape(password)} {
		if !passwordInURL(raw, password) {
			t.Error("password URL representation missed")
		}
	}
	if passwordInURL("https://example.test/account?next=dashboard", password) {
		t.Fatal("ordinary URL refused")
	}
}
