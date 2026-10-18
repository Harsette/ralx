// Package browserlogin performs credential attachment inside a CDP browser.
// It never exports screenshots, field values, or raw browser errors. Account
// text is available only on the verified success page, without password fields.
package browserlogin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/remote"
	"github.com/Harsette/ralx/internal/logins"
	"github.com/Harsette/ralx/internal/redact"
)

type Manager struct {
	mu             sync.Mutex
	dir            string
	sessions       map[string]*Session
	scrub          func([]byte) ([]byte, bool)
	sessionSecrets map[string]*redact.Redactor
}
type Session struct {
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	Endpoint      string
	ID            string
	verifiedURL   string
	verifiedLogin string
	passwordGuard *passwordGuard
}
type Request struct{ Target, TargetID, URL, Origin, Field, Selector, SuccessSelector, LoginID string }
type Result struct {
	Status      string `json:"status"`
	Username    string `json:"username"`
	FinalURL    string `json:"final_url"`
	SessionFile string `json:"session_file"`
	CDPEndpoint string `json:"cdp_endpoint"`
	TargetID    string `json:"target_id,omitempty"`
	Reason      string `json:"reason"`
	ApprovalID  string `json:"approval_id,omitempty"`
	Text        string `json:"text,omitempty"`
}

func New(dir string, scrub func([]byte) ([]byte, bool)) *Manager {
	return &Manager{dir: dir, sessions: map[string]*Session{}, scrub: scrub, sessionSecrets: map[string]*redact.Redactor{}}
}

// ScrubOutput checks only the owning agent's observed session values. Session material is
// intentionally separate from the vault-only export guard: agents may receive
// it in a protected session file, but never in conversation text or metadata.
func (m *Manager) ScrubOutput(b []byte, actor ...string) ([]byte, bool) {
	if len(actor) == 0 || actor[0] == "" {
		return b, false
	}
	m.mu.Lock()
	secrets := m.sessionSecrets[actor[0]]
	m.mu.Unlock()
	if secrets == nil {
		return b, false
	}
	out := secrets.Bytes(b)
	if secrets.DeepContainsSecret(string(out)) {
		return nil, true
	}
	return out, false
}

func (m *Manager) observeValue(actor, label, value string) {
	// Short preferences are not session credentials and must not poison output.
	if len(value) < 16 {
		return
	}
	m.mu.Lock()
	secrets := m.sessionSecrets[actor]
	if secrets == nil {
		secrets = redact.New()
		m.sessionSecrets[actor] = secrets
	}
	m.mu.Unlock()
	secrets.Add(label, value)
}
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		s.cancel()
	}
	m.sessions = map[string]*Session{}
}

// Endpoint accepts literal loopback only, preventing a CDP target from becoming SSRF.
func Endpoint(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "ws") || u.Port() == "" {
		return errors.New("CDP endpoint must be HTTP or WS on literal loopback")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return errors.New("CDP endpoint must use a literal loopback IP")
	}
	return nil
}

func debuggerURL(raw string) (string, error) {
	if e := Endpoint(raw); e != nil {
		return "", e
	}
	u, _ := url.Parse(raw)
	if u.Scheme == "ws" && strings.HasPrefix(u.Path, "/devtools/browser/") {
		return raw, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+u.Host+"/json/version", nil)
	c := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := c.Do(req)
	if e != nil {
		return "", errors.New("CDP discovery failed")
	}
	defer resp.Body.Close()
	var info struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&info) != nil {
		return "", errors.New("invalid CDP discovery response")
	}
	ws, e := url.Parse(info.WebSocketDebuggerURL)
	if e != nil || Endpoint(info.WebSocketDebuggerURL) != nil || ws.Scheme != "ws" || ws.Host != u.Host || !strings.HasPrefix(ws.Path, "/devtools/browser/") {
		return "", errors.New("CDP discovery changed endpoint")
	}
	return info.WebSocketDebuggerURL, nil
}

func (m *Manager) session(actor string, r Request) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := actor + "|" + r.Target + "|" + r.TargetID
	if s := m.sessions[key]; s != nil {
		return s, nil
	}
	for k, s := range m.sessions {
		if strings.HasPrefix(k, actor+"|") && (r.Target == s.Endpoint || r.Target == "managed" || r.Target == "") && r.TargetID == s.ID {
			return s, nil
		}
	}
	var a context.Context
	var ac context.CancelFunc
	var endpoint string
	managed := r.Target == "" || r.Target == "managed" || r.Target == "managed-edge"
	if managed {
		executable, err := systemBrowser(r.Target == "managed-edge")
		if err != nil {
			return nil, err
		}
		profile := filepath.Join(m.dir, "browser-profiles", actor)
		if e := PrivateDir(profile); e != nil {
			return nil, errors.New("cannot protect browser profile")
		}
		var closeBrowser func()
		endpoint, closeBrowser, err = startPipeBrowser(executable, profile)
		if err != nil {
			return nil, err
		}
		var remoteCancel context.CancelFunc
		a, remoteCancel = remote.NewAllocator(context.Background(), endpoint, remote.NoModifyURL, remote.WithDialTimeout(5*time.Second))
		ac = func() { remoteCancel(); closeBrowser() }
	} else {
		if e := Endpoint(r.Target); e != nil {
			return nil, e
		}
		ws, e := debuggerURL(r.Target)
		if e != nil {
			return nil, e
		}
		endpoint = r.Target
		a, ac = remote.NewAllocator(context.Background(), ws, remote.NoModifyURL, remote.WithDialTimeout(5*time.Second))
	}
	opts := []chromedp.ContextOption{chromedp.WithLogf(func(string, ...any) {}), chromedp.WithErrorf(func(string, ...any) {})}
	if r.TargetID != "" {
		opts = append(opts, chromedp.WithTargetID(target.ID(r.TargetID)), chromedp.WithDetachOnCancel())
	}
	ctx, cc := chromedp.NewContext(a, opts...)
	cleanup := func() { cc(); ac() }
	// Initialize on the lifetime context; operation timeouts must not kill the browser.
	if e := chromedp.Do(ctx); e != nil {
		cleanup()
		return nil, errors.New("browser could not be started or attached")
	}
	s := &Session{ctx: ctx, cancel: cleanup, Endpoint: endpoint, ID: string(chromedp.FromContext(ctx).Target.TargetID)}
	m.sessions[key] = s
	return s, nil
}

func systemBrowser(edgeOnly bool) (string, error) {
	chrome, edge := []string{}, []string{}
	switch runtime.GOOS {
	case "windows":
		chrome = []string{`C:\Program Files\Google\Chrome\Application\chrome.exe`, `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`}
		edge = []string{`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, `C:\Program Files\Microsoft\Edge\Application\msedge.exe`}
	case "darwin":
		home, _ := os.UserHomeDir()
		chrome, edge = macBrowserCandidates(home)
	default:
		chrome = []string{`/opt/google/chrome/chrome`, `/usr/bin/google-chrome`, `/usr/bin/google-chrome-stable`, `/usr/bin/chromium`, `/usr/bin/chromium-browser`, `/snap/bin/chromium`}
		edge = []string{`/opt/microsoft/msedge/msedge`, `/usr/bin/microsoft-edge`}
	}
	candidates := edge
	if !edgeOnly {
		candidates = append(chrome, edge...)
	}
	for _, p := range candidates {
		real, e := filepath.EvalSymlinks(p)
		if e != nil {
			continue
		}
		info, e := os.Stat(real)
		if e == nil && info.Mode().IsRegular() {
			return real, nil
		}
	}
	return "", errors.New("no system Chrome/Edge installation found; attach an existing loopback CDP browser")
}

func macBrowserCandidates(home string) (chrome, edge []string) {
	for _, root := range []string{"/Applications", filepath.Join(home, "Applications")} {
		for _, bundle := range []string{"Google Chrome.app/Contents/MacOS/Google Chrome", "Chromium.app/Contents/MacOS/Chromium", "Brave Browser.app/Contents/MacOS/Brave Browser", "Arc.app/Contents/MacOS/Arc"} {
			chrome = append(chrome, filepath.Join(root, bundle))
		}
		edge = append(edge, filepath.Join(root, "Microsoft Edge.app/Contents/MacOS/Microsoft Edge"))
	}
	return
}

func quoted(v string) string { b, _ := json.Marshal(v); return string(b) }

// inPage returns fixed codes only. Top/frame origins, form method and field
// type are checked synchronously with the assignment or submission, with no gap
// in which a navigation can change which document receives the password.
func inPage(origin, body string) string {
	return `(()=>{
const approved=` + quoted(origin) + `;
try{if(location.origin!==approved||window.top.location.origin!==approved)return 'wrong_origin'}catch{return 'wrong_origin'};
const visible=e=>!!(e&&e.getClientRects().length&&!e.disabled);
const password=()=>[...document.querySelectorAll('input[type=password]')].find(visible);
const username=()=>[...document.querySelectorAll('input[autocomplete=username],input[type=email],input[name=identifier],input[name=username],input[name=email],input[type=text],input:not([type])')].find(visible);
const verification=()=>{const one=[...document.querySelectorAll('input[autocomplete="one-time-code"],input[name=code],input[name=verificationCode],input[data-input-otp],input[aria-label*="verification code" i]')].find(visible);if(one)return [one];const digits=[...document.querySelectorAll('input[maxlength="1"][inputmode="numeric"]')].filter(visible);return digits.length===6?digits:[]};
const getForm=e=>{const f=e.form;if(!f||![...f.elements].some(x=>x.type==='password'&&visible(x)))return false;return f.method.toLowerCase()==='get'||[...f.elements].some(b=>!b.disabled&&['submit','image'].includes(b.type)&&b.hasAttribute('formmethod')&&b.formMethod.toLowerCase()==='get')};
const fieldOrigin=e=>{try{return !!e&&e.isConnected&&location.origin===approved&&window.top.location.origin===approved&&e.ownerDocument.defaultView.location.origin===approved}catch{return false}};
const safe=e=>fieldOrigin(e)&&!getForm(e);
` + body + `})()`
}
func eval(ctx context.Context, script string) (string, error) {
	v, e := chromedp.Run(ctx, chromedp.Evaluate[string](script))
	if e != nil {
		return "", errors.New("browser operation failed")
	}
	return v, nil
}

func fill(ctx context.Context, r Request, value string) (string, error) {
	choose := "username()"
	if r.Field == "password" {
		choose = "password()"
	}
	if r.Selector != "" {
		choose = "document.querySelector(" + quoted(r.Selector) + ")"
	}
	expected := "e.type!=='password'"
	if r.Field == "password" {
		expected = "e.type==='password'"
	}
	return eval(ctx, inPage(r.Origin, `const e=`+choose+`;if(!visible(e)||e.tagName!=='INPUT'||!(`+expected+`))return "field_missing";if(getForm(e))return "password form uses GET; refused before typing";if(!safe(e))return "wrong_origin";const set=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;set.call(e,`+quoted(value)+`);e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));return "filled";`))
}

func (m *Manager) operate(ctx context.Context, actor string, r Request, fn func(context.Context, *Session) (Result, error)) (Result, error) {
	s, e := m.session(actor, r)
	if e != nil {
		return Result{Status: "failed", Reason: e.Error()}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	op, cancel := context.WithTimeout(s.ctx, 25*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	fail := func(reason string) (Result, error) {
		s.verifiedURL = ""
		clearCtx, clearCancel := context.WithTimeout(s.ctx, 2*time.Second)
		defer clearCancel()
		_, _ = eval(clearCtx, inPage(r.Origin, `document.querySelectorAll('input').forEach(e=>{e.value=''});return 'cleared';`))
		return Result{Status: "failed", CDPEndpoint: s.Endpoint, TargetID: s.ID, Reason: reason}, nil
	}
	if r.URL != "" {
		s.verifiedURL = ""
		if e = chromedp.Do(op, chromedp.Navigate(r.URL)); e != nil {
			return fail("navigation failed or cross-origin redirect refused")
		}
	}
	current, e := chromedp.Run(op, chromedp.Location())
	if e != nil {
		return fail("cannot check current origin")
	}
	if o, e := logins.Origin(current); e != nil || o != r.Origin {
		return fail("wrong origin: refused before filling")
	}
	res, e := fn(op, s)
	if guardErr := s.passwordGuard.reason(); guardErr != nil {
		if res.SessionFile != "" {
			_ = os.Remove(res.SessionFile)
		}
		return fail(guardErr.Error())
	}
	if e != nil {
		return fail(e.Error())
	}
	res.CDPEndpoint = s.Endpoint
	res.TargetID = s.ID
	// URLs can reflect a typed value. Never expose query/fragment, and the daemon
	// also applies its existing secret redactor and deep scanner to this result.
	final, _ := chromedp.Run(op, chromedp.Location())
	if origin, err := logins.Origin(final); err != nil || origin != r.Origin {
		if res.SessionFile != "" {
			_ = os.Remove(res.SessionFile)
		}
		return fail("origin changed before browser result")
	}
	u, _ := url.Parse(final)
	if u != nil {
		u.RawQuery = ""
		u.Fragment = ""
		u.User = nil
		res.FinalURL = u.String()
	}
	return res, nil
}

func (m *Manager) Fill(ctx context.Context, actor string, r Request, value string) (Result, error) {
	return m.operate(ctx, actor, r, func(ctx context.Context, s *Session) (Result, error) {
		s.verifiedURL = ""
		if r.Field == "password" {
			if e := s.guardPassword(value); e != nil {
				return Result{}, e
			}
		}
		code, e := fill(ctx, r, value)
		if e != nil {
			return Result{}, e
		}
		if code != "filled" {
			return Result{}, errors.New(code)
		}
		return Result{Status: "filled"}, nil
	})
}

func (m *Manager) SignIn(ctx context.Context, actor string, r Request, username, password string) (Result, error) {
	return m.authenticate(ctx, actor, r, username, password, false)
}

func (m *Manager) SignUp(ctx context.Context, actor string, r Request, username, password string) (Result, error) {
	return m.authenticate(ctx, actor, r, username, password, true)
}

// AccountText cannot navigate or read a populated form. It only reads the exact
// success URL verified by the preceding sign-up/sign-in on this agent's tab.
func (m *Manager) AccountText(ctx context.Context, actor string, r Request) (Result, error) {
	r.URL = ""
	return m.operate(ctx, actor, r, func(ctx context.Context, s *Session) (Result, error) {
		if s.verifiedURL == "" || s.verifiedLogin != r.LoginID {
			return Result{}, errors.New("sign in before reading account text")
		}
		if _, e := m.observe(ctx, actor, r.Origin); e != nil {
			return Result{}, e
		}
		text, e := chromedp.Run(ctx, chromedp.Evaluate[string](`(()=>{if(location.origin!==`+quoted(r.Origin)+`||location.href!==`+quoted(s.verifiedURL)+`||document.querySelector('input[type=password]'))throw Error('not verified');return document.body.innerText.slice(0,16000)})()`))
		if e != nil {
			return Result{}, errors.New("account page changed or contains a password field")
		}
		// Include rotations that happened while the text was being captured.
		if _, e = m.observe(ctx, actor, r.Origin); e != nil {
			return Result{}, e
		}
		b, bad := m.ScrubOutput([]byte(text), actor)
		if bad {
			return Result{}, errors.New("account text withheld: contains session material")
		}
		if m.scrub != nil {
			b, bad = m.scrub(b)
			if bad {
				return Result{}, errors.New("account text withheld: contains credential material")
			}
		}
		return Result{Status: "signed_in", Text: string(b)}, nil
	})
}

func (m *Manager) authenticate(ctx context.Context, actor string, r Request, username, password string, signup bool) (Result, error) {
	return m.operate(ctx, actor, r, func(ctx context.Context, s *Session) (Result, error) {
		if e := s.guardPassword(password); e != nil {
			return Result{}, e
		}
		startURL := r.URL
		submitted := false
		didPassword := false
		lastSubmit := ""
		stable := time.Time{}
		verificationAt := time.Time{}
		for ctx.Err() == nil {
			if e := s.passwordGuard.reason(); e != nil {
				return Result{}, e
			}
			code, e := eval(ctx, inPage(r.Origin, `return verification().length?'verification':password()?'password':username()?'username':'none';`))
			if e != nil {
				time.Sleep(75 * time.Millisecond)
				continue
			}
			if code == "wrong_origin" {
				return Result{}, errors.New("cross-origin navigation refused")
			}
			if code == "verification" {
				hint := Result{Status: "needs_verification", Reason: "Complete the website's email verification in this browser. Clerk test codes require an exact +clerk_test address and test mode enabled."}
				if !signup || !logins.ClerkTestEmail(username) {
					return hint, nil
				}
				if !verificationAt.IsZero() {
					if time.Since(verificationAt) > 2*time.Second {
						return hint, nil
					}
					time.Sleep(75 * time.Millisecond)
					continue
				}
				// This public test code is never used for an ordinary address.
				// Each assignment and submit repeats the same field/origin checks.
				c, err := eval(ctx, inPage(r.Origin, `const vs=verification();if(!vs.length)return 'changed';const set=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;for(let i=0;i<vs.length;i++){const e=vs[i];if(!visible(e)||!safe(e))return 'wrong_origin';set.call(e,vs.length===1?'424242':'424242'[i]);e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}))}const e=vs[0];if(!safe(e))return 'wrong_origin';const f=e.form;const b=f?[...f.elements].find(x=>visible(x)&&x.type==='submit'):null;if(b){if(!safe(b))return 'wrong_origin';b.click()}else if(f)f.requestSubmit();return 'verification_submitted';`))
				if err != nil || c != "verification_submitted" {
					return hint, nil
				}
				verificationAt = time.Now()
				time.Sleep(100 * time.Millisecond)
				continue
			}
			current, _ := chromedp.Run(ctx, chromedp.Location())
			// A dashboard search box is not another identifier step. Once the
			// password is submitted, only check success or wait for the outcome.
			if code == "username" && ((submitted && didPassword) || (current != startURL && !signInRoute(current))) {
				code = "none"
			}
			if code == "none" {
				success := false
				if r.SuccessSelector != "" {
					v, _ := eval(ctx, inPage(r.Origin, `return visible(document.querySelector(`+quoted(r.SuccessSelector)+`))?'yes':'no';`))
					success = v == "yes"
				} else {
					success = current != startURL && !signInRoute(current) && (!submitted || didPassword)
				}
				if success {
					if stable.IsZero() {
						stable = time.Now()
					}
					if time.Since(stable) > 350*time.Millisecond {
						_, _ = eval(ctx, inPage(r.Origin, `document.querySelectorAll('input[type=password]').forEach(e=>e.value='');return 'cleared';`))
						path, e := m.export(ctx, actor, r.Origin)
						if e != nil {
							return Result{}, e
						}
						s.verifiedURL = current
						s.verifiedLogin = r.LoginID
						return Result{Status: "signed_in", SessionFile: path}, nil
					}
				} else {
					stable = time.Time{}
					// Check success first: account pages may contain harmless widgets.
					// Refuse a foreign frame only when it contains a field we'd fill.
					if foreignLoginField(ctx, r.Origin) {
						return Result{}, errors.New("cross-origin sign-in field refused")
					}
				}
				time.Sleep(75 * time.Millisecond)
				continue
			}
			stable = time.Time{}
			if lastSubmit == current+"|"+code {
				time.Sleep(75 * time.Millisecond)
				continue
			}
			ur := r
			ur.Field = "username"
			ur.Selector = ""
			preflight, err := eval(ctx, inPage(r.Origin, `return [...document.querySelectorAll('input[type=password]')].filter(visible).some(getForm)?'GET':'ok';`))
			if err != nil {
				return Result{}, err
			}
			if preflight == "GET" {
				return Result{}, errors.New("password form uses GET; refused before typing")
			}
			_, _ = fill(ctx, ur, username)
			// Check each field origin/method before typing, then fill password(s) and
			// submit in one JS task so no agent tool call is needed in between.
			passwords := `password()?[password()]:[]`
			if signup {
				passwords = `[...document.querySelectorAll('input[type=password]')].filter(visible)`
			}
			c, e := eval(ctx, inPage(r.Origin, `const ps=`+passwords+`;const e=password()||username();if((e&&getForm(e))||ps.some(getForm))return 'password form uses GET; refused before typing';if(!e||!safe(e)||ps.some(x=>!safe(x)))return 'wrong_origin';const f=e.form;const b=f?[...f.querySelectorAll('button,input[type=submit]')].find(x=>visible(x)&&x.type==='submit'):[...document.querySelectorAll('button')].find(x=>visible(x)&&/^(continue|sign in|sign up|create account|register|log in|login)$/i.test(x.textContent.trim()));if(!b&&!f)return 'submit_missing';const set=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;for(const p of ps){if(getForm(p))return 'password form uses GET; refused before typing';if(!visible(p)||!safe(p))return 'wrong_origin';set.call(p,`+quoted(password)+`);p.dispatchEvent(new Event('input',{bubbles:true}));p.dispatchEvent(new Event('change',{bubbles:true}))}if(location.origin!==`+quoted(r.Origin)+`||!safe(e))return 'wrong_origin';if(getForm(e))return 'password form uses GET; refused before typing';if(b){if(!safe(b))return 'wrong_origin';b.click()}else f.requestSubmit();return 'submitted';`))
			if e != nil || c != "submitted" {
				if c == "password form uses GET; refused before typing" {
					return Result{}, errors.New(c)
				}
				return Result{}, errors.New("sign-in submit refused")
			}
			submitted = true
			if code == "password" {
				didPassword = true
			}
			lastSubmit = current + "|" + code
			time.Sleep(100 * time.Millisecond)
		}
		return Result{}, errors.New("sign-in did not reach a verified success page")
	})
}

func signInRoute(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil {
		return true
	}
	p := strings.ToLower(u.Path)
	for _, s := range []string{"signin", "sign-in", "sign_in", "signup", "sign-up", "sign_up", "register", "login", "log-in", "log_in", "password", "/step", "/auth"} {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

type Cookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	SameSite string  `json:"sameSite"`
}
type StorageItem struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type StorageOrigin struct {
	Origin       string        `json:"origin"`
	LocalStorage []StorageItem `json:"localStorage"`
}
type StorageState struct {
	Cookies []Cookie        `json:"cookies"`
	Origins []StorageOrigin `json:"origins"`
}

func (m *Manager) observe(ctx context.Context, actor, origin string) (StorageState, error) {
	got, e := chromedp.CallBrowser(ctx, storage.GetCookies, storage.GetCookiesParams{BrowserContextID: chromedp.FromContext(ctx).BrowserContextID})
	if e != nil {
		return StorageState{}, errors.New("cannot inspect session cookies")
	}
	state := StorageState{Cookies: []Cookie{}, Origins: []StorageOrigin{}}
	u, _ := url.Parse(origin)
	for _, c := range got.Cookies {
		m.observeValue(actor, "browser-session:cookie", c.Value)
		d := strings.TrimPrefix(c.Domain, ".")
		if u.Hostname() != d && !strings.HasSuffix(u.Hostname(), "."+d) {
			continue
		}
		same := string(c.SameSite)
		if same == "" {
			same = "Lax"
		}
		state.Cookies = append(state.Cookies, Cookie{c.Name, c.Value, c.Domain, c.Path, c.Expires, c.HTTPOnly, c.Secure, same})
	}
	items, e := chromedp.Run(ctx, chromedp.Evaluate[[]StorageItem](`(()=>{if(location.origin!==`+quoted(origin)+`)throw Error('origin changed');return Object.keys(localStorage).map(name=>({name,value:localStorage.getItem(name)}))})()`))
	if e != nil {
		return StorageState{}, errors.New("cannot inspect local storage")
	}
	if items == nil {
		items = []StorageItem{}
	}
	state.Origins = append(state.Origins, StorageOrigin{origin, items})
	for _, item := range items {
		m.observeValue(actor, "browser-session:storage", item.Value)
	}
	sessionItems, e := chromedp.Run(ctx, chromedp.Evaluate[[]StorageItem](`(()=>{if(location.origin!==`+quoted(origin)+`)throw Error('origin changed');return Object.keys(sessionStorage).map(name=>({name,value:sessionStorage.getItem(name)}))})()`))
	if e != nil {
		return StorageState{}, errors.New("cannot inspect session storage")
	}
	for _, item := range sessionItems {
		m.observeValue(actor, "browser-session:storage", item.Value)
	}
	return state, nil
}

func (m *Manager) export(ctx context.Context, actor, origin string) (string, error) {
	state, e := m.observe(ctx, actor, origin)
	if e != nil {
		return "", e
	}
	b, e := json.Marshal(state)
	if e != nil {
		return "", errors.New("cannot encode session state")
	}
	if m.scrub != nil {
		clean, bad := m.scrub(b)
		if bad || !bytes.Equal(clean, b) {
			return "", errors.New("session export refused: state contains credential material")
		}
	}
	dir := filepath.Join(m.dir, "browser-sessions", actor)
	if e = PrivateDir(dir); e != nil {
		return "", errors.New("cannot protect session folder")
	}
	f, e := os.CreateTemp(dir, "state-*.json")
	if e != nil {
		return "", errors.New("cannot create session file")
	}
	path := f.Name()
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if e = PrivateFile(path); e != nil {
		return "", errors.New("cannot protect session file")
	}
	if _, e = f.Write(b); e != nil {
		return "", errors.New("cannot write session file")
	}
	if e = f.Sync(); e != nil {
		return "", errors.New("cannot flush session file")
	}
	ok = true
	return path, nil
}
