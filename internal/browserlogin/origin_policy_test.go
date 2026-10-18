package browserlogin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCrossOriginResourcesAndFrameFillPolicy(t *testing.T) {
	var posted atomic.Int64
	var iframeTyped atomic.Int64
	var frameMoved atomic.Int64
	var pageOrigin string
	assets := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", pageOrigin)
		if r.URL.Path == "/auth" {
			if r.Method == "POST" {
				var form struct {
					Username string `json:"username"`
					Password string `json:"password"`
				}
				if json.NewDecoder(r.Body).Decode(&form) != nil || form.Username != "fixture@example.test" || form.Password != "SyntheticCrossOrigin-42" {
					http.Error(w, "fixture credentials missing", 401)
					return
				}
				posted.Add(1)
			}
			fmt.Fprint(w, "ok")
			return
		}
		if r.URL.Path == "/frame" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<input type="password" value="untouched"><script>addEventListener('input',()=>fetch('/typed',{method:'POST'}));addEventListener('message',e=>{if(e.data==='move-password'){document.body.innerHTML='<form method="post"><input name="password" type="password"></form>';fetch('/moved',{method:'POST'})}})</script>`)
			return
		}
		if r.URL.Path == "/typed" {
			iframeTyped.Add(1)
			fmt.Fprint(w, "ok")
			return
		}
		if r.URL.Path == "/moved" {
			frameMoved.Add(1)
			fmt.Fprint(w, "ok")
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, `document.body.innerHTML='<form method="post"><input name="username"><input type="password"><button>Sign in</button></form>';document.querySelector('form').onsubmit=async e=>{e.preventDefault();const r=await fetch(%s+'/auth',{method:'POST',body:JSON.stringify({username:document.querySelector('[name=username]').value,password:document.querySelector('[type=password]').value})});if(r.ok)location.href='/account'};`, quoted("http://"+r.Host))
	}))
	defer assets.Close()
	m, app, ctx := browserFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/account":
			fmt.Fprint(w, `<h1 id="account">Signed in</h1>`)
		case "/iframe":
			fmt.Fprintf(w, `<iframe src="%s/frame"></iframe>`, assets.URL)
		case "/move":
			// SOP prevents adopting a DOM node directly into a foreign document.
			// Reproduce the component handoff through postMessage instead.
			fmt.Fprintf(w, `<iframe src="%s/frame"></iframe><form method="post"><input name="username"><input type="password"><button>Sign in</button></form><script>document.querySelector('input[name=username]').addEventListener('input',()=>{document.querySelector('iframe').contentWindow.postMessage('move-password',%s);document.querySelector('form').remove()})</script>`, assets.URL, quoted(assets.URL))
		default:
			fmt.Fprintf(w, `<!doctype html><body><script src="%s/ui.js"></script></body>`, assets.URL)
		}
	})
	pageOrigin = app.URL
	got, _ := m.SignIn(ctx, "resources", Request{Origin: app.URL, URL: app.URL + "/signin", SuccessSelector: "#account"}, "fixture@example.test", "SyntheticCrossOrigin-42")
	if got.Status != "signed_in" || posted.Load() != 1 {
		b, _ := json.Marshal(got)
		t.Fatalf("normal external auth resources blocked: %s posts=%d", b, posted.Load())
	}
	for _, path := range []string{"/iframe", "/move"} {
		got, _ = m.SignIn(ctx, "frame", Request{Origin: app.URL, URL: app.URL + path}, "fixture@example.test", "SyntheticCrossOrigin-42")
		if got.Status != "failed" {
			t.Fatalf("cross-origin frame not refused: %+v", got)
		}
	}
	deadline := time.Now().Add(time.Second)
	for frameMoved.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if frameMoved.Load() != 1 {
		t.Fatal("fixture never moved the field into the foreign frame")
	}
	if iframeTyped.Load() != 0 {
		t.Fatal("typed into foreign iframe")
	}
}
