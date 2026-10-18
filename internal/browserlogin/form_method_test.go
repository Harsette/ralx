package browserlogin

import (
	"fmt"
	"github.com/chromedp/chromedp"
	"net/http"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPasswordGETFormsRefusedBeforeTyping(t *testing.T) {
	var submissions atomic.Int64
	m, app, ctx := browserFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/capture" {
			submissions.Add(1)
			fmt.Fprint(w, "unexpected submit")
			return
		}
		form, button := "", ""
		switch r.URL.Path {
		case "/override":
			form = `method="post"`
			button = `formmethod="get"`
		case "/external-button":
			form = `id="login" method="post"`
		case "/post":
			form = `method="post"`
		}
		fmt.Fprintf(w, `<form %s action="/capture"><input name="username"><input name="password" type="password"><button %s>Sign in</button></form>`, form, button)
		if r.URL.Path == "/external-button" {
			fmt.Fprint(w, `<button form="login" formmethod="GET">Other submit</button>`)
		}
		fmt.Fprint(w, `<script>window.typed=0;addEventListener('input',()=>window.typed++)</script>`)
	})
	for _, route := range []string{"/default", "/override", "/external-button"} {
		t.Run(route, func(t *testing.T) {
			r := Request{Origin: app.URL, URL: app.URL + route, Field: "password"}
			got, _ := m.Fill(ctx, "get-fill", r, "SyntheticGETPassword-42")
			if got.Status != "failed" || !strings.Contains(got.Reason, "GET") {
				t.Fatalf("GET password fill accepted: %+v", got)
			}
			s, _ := m.session("get-fill", r)
			typed, _ := chromedp.Run(s.ctx, chromedp.Evaluate[int](`window.typed`))
			if typed != 0 {
				t.Fatal("typed before refusal")
			}
			got, _ = m.SignIn(ctx, "get-signin", r, "fixture@example.test", "SyntheticGETPassword-42")
			if got.Status != "failed" || !strings.Contains(got.Reason, "GET") {
				t.Fatalf("GET sign-in accepted: %+v", got)
			}
			s, _ = m.session("get-signin", r)
			typed, _ = chromedp.Run(s.ctx, chromedp.Evaluate[int](`window.typed`))
			if typed != 0 {
				t.Fatal("identifier/password typed before refusal")
			}
		})
	}
	got, _ := m.Fill(ctx, "post-control", Request{Origin: app.URL, URL: app.URL + "/post", Field: "password"}, "SyntheticGETPassword-42")
	if got.Status != "filled" {
		t.Fatalf("POST control refused: %+v", got)
	}
	if submissions.Load() != 0 {
		t.Fatal("GET password submitted")
	}
}

// Exercise the exact browser-side predicate without launching Chrome, so the
// default method and submitter overrides also have a small deterministic proof.

func TestPasswordGETFormPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, method, override string
		password, allowed      bool
	}{
		{"default-get", "get", "", true, false},
		{"post", "post", "", true, true},
		{"button-override", "post", "get", true, false},
		{"identifier-only-get", "get", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setup := `global.location=new URL('http://127.0.0.1:12345');global.top={location};const button={type:'submit',disabled:false,formAction:location.href,formMethod:` + quoted(tc.override) + `,hasAttribute:n=>n==='formmethod'&&` + quoted(tc.override) + `!==''};const form={method:` + quoted(tc.method) + `,action:location.href,elements:[],querySelectorAll:s=>s.includes('password')?(` + fmt.Sprint(tc.password) + `?[field]:[]):[]};const field={isConnected:true,type:` + quoted(map[bool]string{true: "password", false: "text"}[tc.password]) + `,form,disabled:false,getClientRects:()=>[1]};form.elements=[field,button];global.document={querySelectorAll:s=>s.includes('password')?(` + fmt.Sprint(tc.password) + `?[field]:[]):[]};field.ownerDocument=document;document.defaultView=global;global.window=global;`
			cmd := exec.Command("node", "-e", setup+`process.stdout.write(`+inPage("http://127.0.0.1:12345", `return safe(field)?'allowed':'refused';`)+`);`)
			b, e := cmd.CombinedOutput()
			if e != nil {
				t.Fatalf("predicate execution: %v %s", e, b)
			}
			if (string(b) == "allowed") != tc.allowed {
				t.Fatalf("password form policy returned %q", b)
			}
		})
	}
}
