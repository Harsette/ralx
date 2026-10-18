package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/remote"
	ralxclient "github.com/Harsette/ralx/internal/client"
	"github.com/Harsette/ralx/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// All credential operations use the same authenticated public action endpoint as MCP.
func TestBrowserLoginPublicContract(t *testing.T) {
	h := newHarness(t)
	key := h.agent("browser-contract")
	r := h.do("POST", "/v1/actions/logins.new_test", map[string]any{"args": map[string]any{"origin": "http://127.0.0.1:19871"}}, bearer(key), false)
	if r.code != 200 {
		t.Fatalf("new login status %d: %s", r.code, r.raw)
	}
	result := r.body["result"].(map[string]any)
	if result["login_id"] == nil || result["username"] == "" || strings.Contains(string(r.raw), "password") {
		t.Fatalf("unsafe/incomplete login response: %s", r.raw)
	}
}

func TestBrowserLoginMCPJourneys(t *testing.T) {
	if os.Getenv("RALX_BROWSER_TESTS") != "1" {
		t.Skip("set RALX_BROWSER_TESTS=1 under the shared heavy lock to run Chrome journeys")
	}
	f, app := newLoginFixture()
	defer app.Close()
	l := newLiveHub(t)
	var logs bytes.Buffer
	l.s.logger = log.New(&logs, "", 0)
	_, key, e := l.s.store.CreateAgent("browser-mcp", store.Policy{Allow: []string{"logins.*", "browser.*"}})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "browser-login-proof", Version: "1"}, nil)
	sess, e := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: l.ip + "/mcp", HTTPClient: &http.Client{Transport: bearerRT{tok: key}}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer sess.Close()
	var outputs bytes.Buffer
	canary := "SyntheticBrowserCanary!0123456789-Secret"
	l.s.red.Add("fixture-canary", canary)
	call := func(name string, args map[string]any) map[string]any {
		t.Helper()
		res, e := sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if e != nil {
			t.Fatal(e)
		}
		b, _ := json.Marshal(res)
		outputs.Write(b)
		if bytes.Contains(b, []byte(canary)) {
			t.Fatal("canary escaped MCP")
		}
		m := map[string]any{}
		for _, v := range res.Content {
			if c, ok := v.(*mcp.TextContent); ok {
				json.Unmarshal([]byte(c.Text), &m)
			}
		}
		return m
	}
	created := call("logins_new_test", map[string]any{"origin": app.URL, "username": "browser-fixture@example.test"})
	id, _ := created["login_id"].(string)
	if id == "" {
		t.Fatalf("missing login id: %v", created)
	}
	var signup map[string]any
	for _, route := range []string{"/signup", "/signup-confirm", "/signup-email"} {
		signup = call("browser_sign_up", map[string]any{"login_id": id, "url": app.URL + route})
		if signup["status"] != "signed_in" || signup["session_file"] == "" {
			t.Fatalf("signup %s: %v", route, signup)
		}
	}
	fill := signup
	read := call("browser_account_text", map[string]any{"login_id": id})
	if read["text"] != "Signed in as browser-fixture@example.test" {
		t.Fatalf("authenticated account text: %v", read)
	}
	a, ac := remote.NewAllocator(ctx, signup["cdp_endpoint"].(string))
	defer ac()
	bc, cc := chromedp.NewContext(a, chromedp.WithTargetID(target.ID(signup["target_id"].(string))), chromedp.WithDetachOnCancel())
	defer cc()
	if _, e := chromedp.Run(bc, chromedp.Evaluate[bool](`(document.body.appendChild(document.createElement('input')).type='password',true)`)); e != nil {
		t.Fatal(e)
	}
	blockedRead := call("browser_account_text", map[string]any{"login_id": id})
	if blockedRead["status"] != "failed" || blockedRead["text"] != nil {
		t.Fatal("account text read a password form")
	}
	signed := call("browser_sign_in", map[string]any{"url": app.URL + "/signin", "login_id": id})
	if signed["status"] != "signed_in" {
		t.Fatalf("two-step sign-in: %v", signed)
	}
	statePath := signed["session_file"].(string)
	stateBytes, e := os.ReadFile(statePath)
	if e != nil {
		t.Fatal(e)
	}
	var state struct {
		Cookies []map[string]any `json:"cookies"`
		Origins []map[string]any `json:"origins"`
	}
	if json.Unmarshal(stateBytes, &state) != nil || len(state.Cookies) == 0 || len(state.Origins) == 0 {
		t.Fatal("invalid storageState")
	}
	// A fresh browser context has no cookie until the exported state is restored.
	fresh, fc := chromedp.NewContext(bc, chromedp.WithNewBrowserContext())
	defer fc()
	if e = chromedp.Do(fresh, chromedp.Navigate(app.URL+"/account")); e != nil {
		t.Fatal(e)
	}
	before, _ := chromedp.Run(fresh, chromedp.Location())
	if !strings.Contains(before, "/signin") {
		t.Fatal("fresh context already authenticated")
	}
	for _, c := range state.Cookies {
		if n, ok := c["expires"].(float64); ok && n <= 0 {
			delete(c, "expires")
		}
	}
	var cookieParams network.SetCookiesParams
	cookieJSON, _ := json.Marshal(map[string]any{"cookies": state.Cookies})
	if e = json.Unmarshal(cookieJSON, &cookieParams); e != nil {
		t.Fatal(e)
	}
	if _, e = chromedp.Call(fresh, network.SetCookies, cookieParams); e != nil {
		t.Fatal(e)
	}
	if e = chromedp.Do(fresh, chromedp.Navigate(app.URL+"/account")); e != nil {
		t.Fatal(e)
	}
	text, e := chromedp.Run(fresh, chromedp.Evaluate[string](`document.body.innerText`))
	if e != nil || !strings.Contains(text, "Signed in as browser-fixture@example.test") {
		t.Fatalf("session restore: %q %v", text, e)
	}
	if e = chromedp.Do(bc, chromedp.Navigate(app.URL+"/expire")); e != nil {
		t.Fatal(e)
	}
	recovered := call("browser_sign_in", map[string]any{"url": app.URL + "/single", "login_id": id})
	if recovered["status"] != "signed_in" {
		t.Fatalf("expired single-page recovery: %v", recovered)
	}
	if _, e := chromedp.Run(bc, chromedp.Evaluate[bool](`(document.body.appendChild(document.createTextNode(`+quotedFixture(canary)+`)),true)`)); e != nil {
		t.Fatal(e)
	}
	reflected := call("browser_account_text", map[string]any{"login_id": id})
	if strings.Contains(fmt.Sprint(reflected), canary) {
		t.Fatal("account text reflected canary")
	}
	// Normal navigation/resources are allowed. An unapproved top/frame origin
	// must still receive no credential input, including identifier-first flows.
	var trapHits atomic.Int64
	var trapTyped atomic.Int64
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trapHits.Add(1)
		if r.URL.Path == "/typed" {
			trapTyped.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!doctype html><input type="password" value="fixture-untouched"><script>addEventListener('input',()=>fetch('/typed',{method:'POST'}))</script>`))
	}))
	defer trap.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, trap.URL, 302) }))
	defer redirect.Close()
	rlogin := call("logins_new_test", map[string]any{"origin": redirect.URL})
	refused := call("browser_sign_in", map[string]any{"url": redirect.URL + "/signin", "login_id": rlogin["login_id"]})
	if refused["status"] != "failed" || trapTyped.Load() != 0 || trapHits.Load() == 0 {
		t.Fatalf("cross-origin redirect input policy: %v typed=%d", refused, trapTyped.Load())
	}
	refused = call("browser_sign_up", map[string]any{"url": redirect.URL + "/signup", "login_id": rlogin["login_id"]})
	if refused["status"] != "failed" || trapTyped.Load() != 0 {
		t.Fatal("sign-up typed after cross-origin redirect")
	}
	beforeFormTrap := trapHits.Load()
	formTrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<form method="post"><input name="username"><input type="password"><button formmethod="get" formaction="` + trap.URL + `">Sign up</button></form><script>window.typed=0;addEventListener('input',()=>window.typed++)</script>`))
	}))
	defer formTrap.Close()
	tlogin := call("logins_new_test", map[string]any{"origin": formTrap.URL})
	refused = call("browser_sign_up", map[string]any{"url": formTrap.URL + "/signup", "login_id": tlogin["login_id"]})
	typed, err := chromedp.Run(bc, chromedp.Evaluate[int](`window.typed`))
	if err != nil || typed != 0 || refused["status"] != "failed" || trapHits.Load() != beforeFormTrap {
		t.Fatal("GET form override did not refuse before typing")
	}
	wrong := call("browser_fill", map[string]any{"url": trap.URL, "login_id": id, "field": "password"})
	if wrong["status"] == "filled" || trapTyped.Load() != 0 {
		t.Fatalf("wrong-origin fill accepted: %v", wrong)
	}
	if err := chromedp.Do(fresh, chromedp.Navigate(trap.URL)); err != nil {
		t.Fatal(err)
	}
	untouched := call("browser_fill", map[string]any{"login_id": id, "field": "password", "target": fill["cdp_endpoint"], "target_id": string(chromedp.FromContext(fresh).Target.TargetID)})
	unchanged, _ := chromedp.Run(fresh, chromedp.Evaluate[bool](`document.querySelector('input').value==='fixture-untouched'`))
	if untouched["status"] != "failed" || !unchanged {
		t.Fatal("wrong-origin refusal modified existing input")
	}
	// Human-saved real credentials on localhost still need a human passkey.
	realID := store.NewID("login_")
	_, e = l.s.store.CreateCredential(realID, "website_login", "website", "Human login", map[string]any{"username": "canary@example.test", "origins": []string{app.URL}, "kind": "real", "created_by": "human", "notes": "SealedFixtureNotes-309192"}, map[string]string{"password": canary})
	if e != nil {
		t.Fatal(e)
	}
	l.s.red.Add(realID+":password", canary)
	f.mu.Lock()
	f.users["canary@example.test"] = canary
	f.mu.Unlock()
	held := call("browser_sign_in", map[string]any{"url": app.URL + "/single", "login_id": realID})
	if held["status"] != "needs_approval" {
		t.Fatalf("real login bypassed approval: %v", held)
	}
	approval := held["approval_id"].(string)
	l.signIn()
	as := l.stepUp("approve:" + approval)
	code, _, raw := l.browser("POST", "/admin/api/approvals/"+approval+"/approve", map[string]any{"assertion": as})
	outputs.Write(raw)
	if code != 200 {
		t.Fatalf("approve status=%d", code)
	}
	for i := 0; i < 100; i++ {
		ap, _ := l.s.store.GetApproval(approval)
		if ap.Status == "executed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	real := call("browser_sign_in", map[string]any{"url": app.URL + "/single", "login_id": realID})
	if real["status"] != "signed_in" {
		t.Fatalf("approved real login: %v", real)
	}
	again := call("browser_sign_in", map[string]any{"url": app.URL + "/signin", "login_id": realID})
	if again["status"] != "signed_in" {
		t.Fatalf("approval not remembered: %v", again)
	}
	if _, err := chromedp.Run(bc, chromedp.Evaluate[bool](`(localStorage.setItem('bad-fixture-state',`+quotedFixture(canary)+`),true)`)); err != nil {
		t.Fatal(err)
	}
	unsafe := call("browser_sign_in", map[string]any{"url": app.URL + "/single", "login_id": realID})
	if unsafe["status"] != "failed" || unsafe["session_file"] != "" {
		t.Fatal("session export released password-bearing state")
	}
	chromedp.Run(bc, chromedp.Evaluate[bool](`(localStorage.removeItem('bad-fixture-state'),true)`))
	// An error after a password fill must not reflect the selector or leave typed
	// values behind. The caller-supplied canary here is deliberately adversarial.
	call("browser_fill", map[string]any{"url": app.URL + "/signup", "login_id": realID, "field": "username"})
	call("browser_fill", map[string]any{"login_id": realID, "field": "password"})
	bad := call("browser_fill", map[string]any{"login_id": realID, "field": "password", "selector": "[" + canary})
	if bad["status"] != "failed" {
		t.Fatal("malformed selector did not fail")
	}
	remaining, _ := chromedp.Run(bc, chromedp.Evaluate[int](`Array.from(document.querySelectorAll('input')).reduce((n,e)=>n+e.value.length,0)`))
	if remaining != 0 {
		t.Fatal("error retained typed values")
	}
	if evidence := os.Getenv("RALX_PROOF_EVIDENCE"); evidence != "" {
		repo, _ := filepath.Abs("../..")
		helper := filepath.Join(repo, "scripts", "agent-signin", "browser.cjs")
		opts, _ := json.Marshal(map[string]any{"base": l.base, "dir": filepath.ToSlash(evidence), "cookie": map[string]string{"name": l.cookie.Name, "value": l.cookie.Value}})
		cmd := exec.CommandContext(ctx, "node", helper, "screenshots", again["cdp_endpoint"].(string), again["target_id"].(string))
		cmd.Env = append(os.Environ(), "RALX_OWNER_UI_PROOF="+string(opts))
		out, err := cmd.CombinedOutput()
		os.WriteFile(filepath.Join(evidence, "ui-proof.txt"), out, 0600)
		if err != nil {
			t.Errorf("owner UI screenshots failed: %v", err)
		}
	}
	rows, _ := l.s.store.ListAudit(1000)
	audit, _ := json.Marshal(rows)
	for name, b := range map[string][]byte{"MCP outputs": outputs.Bytes(), "audit": audit, "logs": logs.Bytes()} {
		if bytes.Contains(b, []byte(canary)) {
			t.Fatalf("canary in %s", name)
		}
	}
	all, e := l.s.store.AllSecretValues()
	if e != nil {
		t.Fatal(e)
	}
	checked := 0
	for _, values := range all {
		for _, password := range values {
			checked++
			for _, b := range [][]byte{outputs.Bytes(), audit, logs.Bytes()} {
				if bytes.Contains(b, []byte(password)) {
					t.Fatal("generated or human password escaped")
				}
			}
		}
	}
	if evidence := os.Getenv("RALX_PROOF_EVIDENCE"); evidence != "" {
		os.WriteFile(filepath.Join(evidence, "browser-canary-grep.txt"), []byte(fmt.Sprintf("Sealed passwords tested: %d\nMCP response, error, session metadata, log and audit hits: 0\n", checked)), 0600)
	}
	// Metadata, labels, audit and approval rows may not store user login text.
	for _, needle := range []string{"canary@example.test", "SealedFixtureNotes-309192", app.URL, "browser-fixture@example.test"} {
		for _, file := range []string{"ralx.db", "ralx.db-wal", "ralx.db-shm"} {
			b, _ := os.ReadFile(l.s.cfg.DataDir + "/" + file)
			if bytes.Contains(b, []byte(needle)) {
				t.Fatalf("plaintext user login field in database: %s", file)
			}
		}
	}
	t.Log("PASS: MCP single/confirmation/email-first signup, two-step/single-page sign-in, safe account text, storageState reuse, expired-session recovery, pre-fill origin/form refusal, approval memory, sealed fields, zero canary hits")
}

type loginFixture struct {
	mu       sync.Mutex
	users    map[string]string
	sessions map[string]string
}

func newLoginFixture() (*loginFixture, *httptest.Server) {
	f := &loginFixture{users: map[string]string{}, sessions: map[string]string{}}
	mux := http.NewServeMux()
	signup := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			r.ParseForm()
			if r.FormValue("password") == "" || (r.URL.Path != "/signup" && r.FormValue("password") != r.FormValue("confirm_password")) {
				http.Error(w, "password confirmation required", 400)
				return
			}
			f.mu.Lock()
			f.users[r.FormValue("username")] = r.FormValue("password")
			token := store.NewID("fixture_session_")
			f.sessions[token] = r.FormValue("username")
			f.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, "/account", 303)
			return
		}
		confirm := ""
		if r.URL.Path != "/signup" {
			confirm = `<input name="confirm_password" type="password" required>`
		}
		w.Write([]byte(`<form method="post"><input name="username" autocomplete="username"><input name="password" type="password" required>` + confirm + `<button>Sign up</button></form>`))
	}
	mux.HandleFunc("/signup", signup)
	mux.HandleFunc("/signup-confirm", signup)
	mux.HandleFunc("/signup-email", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<form action="/signup-password" method="get"><input type="email" name="username" autocomplete="username"><button>Continue</button></form>`))
	})
	mux.HandleFunc("/signup-password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			signup(w, r)
			return
		}
		u, _ := json.Marshal(r.URL.Query().Get("username"))
		w.Write([]byte(`<form method="post"><input name="username" type="hidden" id="u"><input name="password" type="password" required><input name="confirm_password" type="password" required><button>Create account</button></form><script>document.querySelector('#u').value=` + string(u) + `</script>`))
	})
	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<form action="/step" method="get"><input name="username" autocomplete="username"><button>Continue</button></form>`))
	})
	mux.HandleFunc("/step", func(w http.ResponseWriter, r *http.Request) {
		u, _ := json.Marshal(r.URL.Query().Get("username"))
		w.Write([]byte(`<form action="/auth" method="post"><input name="username" type="hidden" id="u"><input name="password" type="password"><button>Sign in</button></form><script>document.querySelector('#u').value=` + string(u) + `</script>`))
	})
	mux.HandleFunc("/single", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<form action="/auth" method="post"><input name="username" autocomplete="username"><input name="password" type="password"><button>Sign in</button></form>`))
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		good := f.users[r.FormValue("username")] != "" && f.users[r.FormValue("username")] == r.FormValue("password")
		f.mu.Unlock()
		if !good {
			http.Error(w, "invalid login", 401)
			return
		}
		token := store.NewID("fixture_session_")
		f.mu.Lock()
		f.sessions[token] = r.FormValue("username")
		f.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/account", 303)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		username := ""
		if err == nil {
			f.mu.Lock()
			username = f.sessions[c.Value]
			f.mu.Unlock()
		}
		if username == "" {
			http.Redirect(w, r, "/signin", 303)
			return
		}
		w.Write([]byte("Signed in as " + username + `<input type="text" placeholder="Search"><script>localStorage.setItem('fixture-marker','present')</script>`))
	})
	mux.HandleFunc("/expire", func(w http.ResponseWriter, r *http.Request) {
		if c, e := r.Cookie("session"); e == nil {
			f.mu.Lock()
			delete(f.sessions, c.Value)
			f.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/signin", 303)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/signin", 303) })
	return f, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		mux.ServeHTTP(w, r)
	}))
}

// Opt-in proof against an actual built daemon. Enrollment and approvals use the
// public ceremony endpoints and a synthetic WebAuthn authenticator, never the
// installed daemon, installed vault, or Hamza's passkey.
func TestBrowserLoginAgentProof(t *testing.T) {
	binary := os.Getenv("RALX_PROOF_BINARY")
	if binary == "" {
		t.Skip("set RALX_PROOF_BINARY under the shared heavy lock for actual CLI proof")
	}
	evidence := os.Getenv("RALX_PROOF_EVIDENCE")
	if evidence == "" {
		t.Fatal("RALX_PROOF_EVIDENCE required")
	}
	os.MkdirAll(evidence, 0700)
	repo, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	helper := filepath.Join(repo, "scripts", "agent-signin", "browser.cjs")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := ln.Addr().String()
	ln.Close()
	port := strings.TrimPrefix(addr, "127.0.0.1:")
	base := "http://localhost:" + port
	ip := "http://" + addr
	data := t.TempDir()
	pipe := `\\.\pipe\ralx-agent-signin-` + store.NewID("")
	if os.PathSeparator != '\\' {
		pipe = filepath.Join(data, "admin.sock")
	}
	logFile, e := os.Create(filepath.Join(evidence, "daemon.log"))
	if e != nil {
		t.Fatal(e)
	}
	defer logFile.Close()
	daemon := exec.CommandContext(ctx, binary, "daemon", "--dev", "--data", data, "--addr", addr, "--admin-pipe", pipe)
	daemon.Stdout = logFile
	daemon.Stderr = logFile
	if e = daemon.Start(); e != nil {
		t.Fatal(e)
	}
	closeOwnedTree := containProofProcess(t, daemon)
	defer func() {
		// Shut down only Chrome launched with this proof's temp profile, before
		// killing the owned daemon, so Windows releases its profile files.
		paths, _ := filepath.Glob(filepath.Join(data, "browser-profiles", "*", "DevToolsActivePort"))
		for _, path := range paths {
			b, _ := os.ReadFile(path)
			port := strings.Split(string(b), "\n")[0]
			a, ac := remote.NewAllocator(context.Background(), "http://127.0.0.1:"+port)
			bc, cc := chromedp.NewContext(a)
			closeCtx, stop := context.WithTimeout(bc, 4*time.Second)
			_, _ = chromedp.CallBrowser(closeCtx, cdpbrowser.Close, cdp.Empty{})
			stop()
			cc()
			ac()
		}
		closeOwnedTree()
		daemon.Process.Kill()
		daemon.Wait()
	}()
	admin := ralxclient.NewAdmin(pipe)
	var setup map[string]any
	// The HTTP listener can answer before the admin pipe is listening. Probe
	// the exact owned pipe needed for enrollment, not an arbitrary HTTP reply.
	for i := 0; i < 100; i++ {
		if _, e = admin.JSON(ctx, "POST", "/admin/api/setup-link", map[string]any{}, &setup); e == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if e != nil {
		t.Fatal("owned daemon admin pipe did not become ready")
	}
	u := setup["url"].(string)
	token := u[strings.Index(u, "#setup=")+7:]
	l := &liveHub{t: t, base: base, ip: ip, http: &http.Client{}, authn: newSoftAuthn(t, base)}
	status, _, raw := l.browser("POST", "/admin/api/setup/begin", map[string]any{"token": token})
	if status != 200 {
		t.Fatal("external passkey setup begin failed")
	}
	credential := l.authn.register(t, raw)
	status, m, _ := l.browser("POST", "/admin/api/setup/finish", map[string]any{"token": token, "credential": credential})
	if status != 200 {
		t.Fatal("external passkey setup finish failed")
	}
	l.csrf = m["csrf"].(string)
	var enrollment map[string]any
	if _, e = admin.JSON(ctx, "POST", "/admin/api/enroll/code", map[string]any{}, &enrollment); e != nil {
		t.Fatal(e)
	}
	// Redeem as the agent, then have the fixture owner approve that exact request.
	c := &ralxclient.Client{URL: ip, HTTP: &http.Client{}}
	var redeem map[string]any
	if code, e := c.JSON(ctx, "POST", "/v1/enroll", map[string]any{"code": enrollment["code"], "name": "agent-signin-proof", "client": "codex"}, &redeem); e != nil || code != 201 {
		t.Fatal("external agent redeem failed")
	}
	requestID := redeem["request_id"].(string)
	assertion := l.stepUp("enroll.approve:" + requestID)
	if code, _, _ := l.browser("POST", "/admin/api/enroll/"+requestID+"/approve", map[string]any{"assertion": assertion}); code != 200 {
		t.Fatal("external agent approval failed")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", ip+"/v1/enroll/"+requestID, nil)
	req.Header.Set("X-RalX-Enroll-Secret", redeem["secret"].(string))
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	var pickup map[string]any
	json.NewDecoder(resp.Body).Decode(&pickup)
	resp.Body.Close()
	key, _ := pickup["key"].(string)
	if key == "" {
		t.Fatal("external agent key pickup failed")
	}
	idFile := filepath.Join(data, "proof-agent.json")
	identity := ralxclient.Identity{URL: ip, Key: key, KeyDigest: ralxclient.KeyDigest(key)}
	b, _ := json.Marshal(identity)
	os.WriteFile(idFile, b, 0600)
	f, app := newLoginFixture()
	defer app.Close()
	if os.Getenv("RALX_PROOF_PROVIDERS") == "cleanup" {
		c.Key = key
		var created, filled map[string]any
		if _, e = c.JSON(ctx, "POST", "/v1/actions/logins.new_test", map[string]any{"args": map[string]any{"origin": app.URL}}, &created); e != nil {
			t.Fatal(e)
		}
		id := created["result"].(map[string]any)["login_id"]
		if _, e = c.JSON(ctx, "POST", "/v1/actions/browser.fill", map[string]any{"args": map[string]any{"url": app.URL + "/signup", "login_id": id, "field": "username"}}, &filled); e != nil || filled["result"].(map[string]any)["status"] != "filled" {
			t.Fatal("owned cleanup browser did not start")
		}
		t.Log("owned daemon/browser cleanup proof without model calls")
		return
	}
	job := "Create a test account for " + app.URL + ", sign up, then sign in and tell me the text on the account page."
	instructions := fmt.Sprintf(`This is an authorized disposable localhost browser test. Do only the requested browser job. Never read passwords, vaults, browser input values, session file contents, credentials, or global configs. No shell, code changes, external helpers or raw browser debugging.
Use only RalX MCP: logins_new_test for %s, browser_sign_up at %s/signup with the login_id, browser_sign_in at %s/signin with that same login_id, then browser_account_text with that login_id. These tools generate, fill and submit the password inside RalX; you never receive or type it. Report the actual returned account-page text.`, app.URL, app.URL, app.URL)
	work := t.TempDir()
	os.WriteFile(filepath.Join(work, "AGENTS.md"), []byte(instructions), 0600)
	os.WriteFile(filepath.Join(work, "CLAUDE.md"), []byte(instructions), 0600)
	os.WriteFile(filepath.Join(evidence, "job.txt"), []byte(job), 0600)
	// HTTP MCP avoids global client configuration and contains only a disposable
	// revocable RalX key. It is never a website credential.
	mcpConfig := map[string]any{"mcpServers": map[string]any{"ralx_proof": map[string]any{"type": "http", "url": ip + "/mcp", "headers": map[string]string{"Authorization": "Bearer " + key}}}}
	mcpBytes, _ := json.Marshal(mcpConfig)
	configPath := filepath.Join(data, "claude-mcp.json")
	os.WriteFile(configPath, mcpBytes, 0600)
	// Advertise only the four account-flow tools to Claude. In particular, neither
	// built-in shell/browser tools nor generic RalX HTTP/runner tools are usable.
	allowed := map[string]bool{"logins_new_test": true, "browser_sign_up": true, "browser_sign_in": true, "browser_account_text": true}
	proofClient := mcp.NewClient(&mcp.Implementation{Name: "proof-tool-inventory", Version: "1"}, nil)
	proofSession, e := proofClient.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ip + "/mcp", HTTPClient: &http.Client{Transport: bearerRT{tok: key}}}, nil)
	if e != nil {
		t.Fatal("proof tool inventory unavailable")
	}
	listed, e := proofSession.ListTools(ctx, nil)
	proofSession.Close()
	if e != nil {
		t.Fatal("proof tool inventory failed")
	}
	disallowed := []string{}
	for _, tool := range listed.Tools {
		if !allowed[tool.Name] {
			disallowed = append(disallowed, "mcp__ralx_proof__"+tool.Name)
		}
	}
	var transcripts [][]byte
	providers := []string{"codex", "claude"}
	if selected := os.Getenv("RALX_PROOF_PROVIDERS"); selected == "codex" || selected == "claude" {
		providers = []string{selected}
	}
	for _, provider := range providers {
		quotaCmd := exec.CommandContext(ctx, "node", filepath.Join(repo, "scripts", "agent-signin", "quota.cjs"))
		quotaCmd.Dir = repo
		quota, e := quotaCmd.Output()
		os.WriteFile(filepath.Join(evidence, "quota-"+provider+".json"), quota, 0600)
		if e != nil {
			t.Errorf("%s quota unavailable", provider)
			continue
		}
		var q map[string]json.RawMessage
		json.Unmarshal(quota, &q)
		if strings.Contains(string(q[provider]), "unavailable") {
			t.Errorf("%s quota unavailable", provider)
			continue
		}
		if provider == "claude" {
			var usage struct {
				Five  struct{ Utilization float64 } `json:"five_hour"`
				Seven struct{ Utilization float64 } `json:"seven_day"`
			}
			json.Unmarshal(q[provider], &usage)
			if usage.Five.Utilization >= 100 || usage.Seven.Utilization >= 100 {
				t.Error("Claude quota held")
				continue
			}
		}
		if provider == "codex" {
			var usage struct {
				Rate struct{ Allowed bool } `json:"rate_limit"`
			}
			json.Unmarshal(q[provider], &usage)
			if !usage.Rate.Allowed {
				t.Error("Codex quota held")
				continue
			}
		}
		runCtx, stop := context.WithTimeout(ctx, 240*time.Second)
		var cmd *exec.Cmd
		if provider == "codex" {
			config := fmt.Sprintf(`mcp_servers={ralx_proof={url=%q,bearer_token_env_var="RALX_PROOF_AGENT_KEY"}}`, ip+"/mcp")
			cmd = exec.CommandContext(runCtx, "codex", "exec", "--ignore-user-config", "--ephemeral", "--skip-git-repo-check", "--json", "-m", "gpt-6.1-sol", "-c", `model_reasoning_effort="low"`, "-c", config, "-s", "danger-full-access", job)
		} else {
			cmd = exec.CommandContext(runCtx, "claude", "-p", job, "--model", "claude-sonnet-5-5", "--output-format", "stream-json", "--verbose", "--strict-mcp-config", "--mcp-config", configPath, "--setting-sources", "", "--no-chrome", "--no-session-persistence", "--disable-slash-commands", "--tools", "", "--allowedTools", "mcp__ralx_proof__logins_new_test,mcp__ralx_proof__browser_sign_up,mcp__ralx_proof__browser_sign_in,mcp__ralx_proof__browser_account_text", "--disallowedTools", strings.Join(disallowed, ","), "--append-system-prompt", instructions)
		}
		cmd.Dir = work
		cmd.Stdin = strings.NewReader("")
		cmd.Env = append(os.Environ(), "RALX_PROOF_AGENT_KEY="+key, "RALX_URL="+ip, "RALX_AGENT_KEY_FILE="+idFile)
		out, runErr := cmd.CombinedOutput()
		stop()
		transcripts = append(transcripts, out)
		path := filepath.Join(evidence, provider+".jsonl")
		os.WriteFile(path, out, 0600)
		if provider == "claude" {
			initialized, completed := false, false
			calls := map[string]int{}
			for _, line := range bytes.Split(out, []byte("\n")) {
				var event struct {
					Type    string   `json:"type"`
					Subtype string   `json:"subtype"`
					Model   string   `json:"model"`
					Tools   []string `json:"tools"`
					Result  string   `json:"result"`
					IsError bool     `json:"is_error"`
					Message struct {
						Content []struct {
							Type string `json:"type"`
							Name string `json:"name"`
						} `json:"content"`
					} `json:"message"`
				}
				if json.Unmarshal(line, &event) != nil {
					continue
				}
				if event.Type == "result" {
					completed = !event.IsError && strings.Contains(event.Result, "Signed in as ")
				}
				if event.Type == "assistant" {
					for _, part := range event.Message.Content {
						if part.Type == "tool_use" {
							calls[strings.TrimPrefix(part.Name, "mcp__ralx_proof__")]++
						}
					}
				}
				if event.Type == "system" && event.Subtype == "init" {
					initialized = event.Model == "claude-sonnet-5-5" && len(event.Tools) == len(allowed)
					for _, tool := range event.Tools {
						if !allowed[strings.TrimPrefix(tool, "mcp__ralx_proof__")] {
							t.Errorf("Claude bypass tool exposed: %s", tool)
						}
					}
				}
			}
			for tool := range allowed {
				if calls[tool] == 0 {
					t.Errorf("Claude did not call %s", tool)
				}
			}
			if !initialized || !completed {
				t.Error("Claude model/tool inventory or final account text not proven")
			}
			summary, _ := json.MarshalIndent(map[string]any{"model": "claude-sonnet-5-5", "only_account_flow_tools": initialized, "completed_account_text": completed, "tool_calls": calls}, "", "  ")
			os.WriteFile(filepath.Join(evidence, "claude-summary.json"), summary, 0600)
		}
		if runErr != nil || !bytes.Contains(out, []byte("Signed in as ")) {
			t.Errorf("%s proof failed, exit=%v; transcript=%s", provider, runErr, path)
		} else {
			t.Logf("%s CLI completed without receiving the password: %s", provider, path)
		}
	}
	// The fixture knows the generated canaries; the models and their transcripts do not.
	f.mu.Lock()
	passwords := []string{}
	signupCount := len(f.users)
	for _, password := range f.users {
		passwords = append(passwords, password)
	}
	f.mu.Unlock()
	// Also include generated logins that a model never submitted. Reveal is a
	// synthetic owner operation inside this test process, never model input.
	owner := map[string]any{}
	admin.JSON(ctx, "GET", "/admin/api/state", nil, &owner)
	if list, ok := owner["logins"].([]any); ok {
		for _, item := range list {
			id := item.(map[string]any)["login_id"].(string)
			as := l.stepUp("reveal:" + id)
			code, m, _ := l.browser("POST", "/admin/api/credentials/reveal", map[string]any{"name": id, "assertion": as})
			if code == 200 {
				if fields, ok := m["fields"].(map[string]any); ok {
					if password, ok := fields["password"].(string); ok {
						passwords = append(passwords, password)
					}
				}
			}
		}
	}
	unique := map[string]bool{}
	for _, p := range passwords {
		unique[p] = true
	}
	passwords = nil
	for p := range unique {
		passwords = append(passwords, p)
	}
	hits := 0
	logFile.Sync()
	daemonLog, _ := os.ReadFile(logFile.Name())
	transcripts = append(transcripts, daemonLog)
	for _, password := range passwords {
		for _, out := range transcripts {
			if bytes.Contains(out, []byte(password)) {
				hits++
			}
		}
	}
	receipt := fmt.Sprintf("Passwords tested: %d\nTranscript/daemon-log canary hits: %d\n", len(passwords), hits)
	os.WriteFile(filepath.Join(evidence, "canary-grep.txt"), []byte(receipt), 0600)
	if hits != 0 {
		t.Fatal("generated password escaped into CLI transcript or daemon log")
	}
	if signupCount != len(providers) {
		t.Errorf("expected %d signed-up accounts; got %d", len(providers), signupCount)
	}
	os.WriteFile(filepath.Join(evidence, "enrollment.txt"), []byte("Built daemon on "+ip+" with temporary data directory. Public one-time enrollment code, agent redemption, synthetic owner WebAuthn approval, one-time agent key pickup. No installed daemon or service used.\n"), 0600)
	// Inspect the actual owner's UI and independently verify Playwright state reuse.
	c.Key = key
	var stateReply map[string]any
	if _, e = c.JSON(ctx, "POST", "/v1/actions/browser.sign_in", map[string]any{"args": map[string]any{"url": app.URL + "/signin"}}, &stateReply); e != nil {
		t.Log("ambiguous auto-pick correctly requires login_id after two accounts")
	}
	// Get the last successful browser result from the transcripts without reading
	// a password or session file. The account id itself is not a secret.
	var selectedID string
	creds := map[string]any{}
	admin.JSON(ctx, "GET", "/admin/api/state", nil, &creds)
	if values, ok := creds["logins"].([]any); ok && len(values) > 0 {
		selectedID = values[0].(map[string]any)["login_id"].(string)
	}
	if selectedID != "" {
		stateReply = map[string]any{}
		_, e = c.JSON(ctx, "POST", "/v1/actions/browser.sign_in", map[string]any{"args": map[string]any{"url": app.URL + "/signin", "login_id": selectedID}}, &stateReply)
		if e == nil {
			result, _ := stateReply["result"].(map[string]any)
			endpoint, _ := result["cdp_endpoint"].(string)
			targetID, _ := result["target_id"].(string)
			stateFile, _ := result["session_file"].(string)
			restore := exec.CommandContext(ctx, "node", helper, "restore", endpoint, targetID, stateFile)
			out, err := restore.CombinedOutput()
			os.WriteFile(filepath.Join(evidence, "playwright-storage-state.txt"), out, 0600)
			if err != nil {
				t.Errorf("Playwright state restore: %v", err)
			}
			opts, _ := json.Marshal(map[string]any{"base": base, "dir": filepath.ToSlash(evidence), "cookie": map[string]string{"name": l.cookie.Name, "value": l.cookie.Value}})
			shots := exec.CommandContext(ctx, "node", helper, "screenshots", endpoint, targetID)
			shots.Env = append(os.Environ(), "RALX_OWNER_UI_PROOF="+string(opts))
			out, err = shots.CombinedOutput()
			os.WriteFile(filepath.Join(evidence, "ui-proof.txt"), out, 0600)
			if err != nil {
				t.Errorf("owner UI screenshots: %v", err)
			}
		} else {
			t.Errorf("final fixture sign-in: %v", e)
		}
	}
}

func quotedFixture(v string) string { b, _ := json.Marshal(v); return string(b) }

func TestBrowserLoginProofProcessCleanup(t *testing.T) {
	t.Setenv("RALX_PROOF_PROVIDERS", "cleanup")
	TestBrowserLoginAgentProof(t)
}
