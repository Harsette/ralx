package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// liveHub runs the full hub on a real loopback port.
type liveHub struct {
	t      *testing.T
	s      *Server
	base   string // http://localhost:PORT (browser origin)
	ip     string // http://127.0.0.1:PORT (API base for non-browser clients)
	cookie *http.Cookie
	csrf   string
	authn  *softAuthn
	http   *http.Client
}

func newLiveHub(t *testing.T) *liveHub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	addr := "127.0.0.1:" + itoa(port)
	s, err := New(Config{DataDir: t.TempDir(), Addr: addr, Dev: true, Version: "test"}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.reg.Add(&actions.Action{Name: "test.danger", Risk: actions.Gated, GateReason: "deletes", Description: "dangerous",
		Params: []actions.Param{{Name: "thing", Type: "string", Required: true, Pattern: "[a-z]+"}},
		Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
			return map[string]any{"deleted": args["thing"]}, nil
		}})
	_ = s.reg.Add(&actions.Action{Name: "test.hello", Risk: actions.Read, Description: "says hi",
		Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
			return map[string]any{"hello": env.AgentName()}, nil
		}})
	mux := http.NewServeMux()
	s.routes(mux)
	srv := &http.Server{Handler: s.hostGuard(mux)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); s.Close() })
	base := "http://localhost:" + itoa(port)
	return &liveHub{t: t, s: s, base: base, ip: "http://" + addr, authn: newSoftAuthn(t, base),
		http: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func itoa(n int) string { return strconv.Itoa(n) }

// browser performs a request as Hamza's browser on http://localhost:PORT.
func (l *liveHub) browser(method, path string, body any) (int, map[string]any, []byte) {
	l.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, l.ip+path, rd)
	req.Host = strings.TrimPrefix(l.base, "http://")
	req.Header.Set("Origin", l.base)
	req.Header.Set("Content-Type", "application/json")
	csrf := l.csrf
	if csrf == "" {
		csrf = "1"
	}
	req.Header.Set("X-RalX-CSRF", csrf)
	if l.cookie != nil {
		req.AddCookie(l.cookie)
	}
	resp, err := l.http.Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			l.cookie = c
		}
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, raw
}

func (l *liveHub) signIn() {
	l.t.Helper()
	// setup link via the "pipe" (call the handler logic directly)
	tok := l.s.mintSetupToken("localhost", "first")
	code, m, raw := l.browser("POST", "/admin/api/setup/begin", map[string]any{"token": tok})
	if code != 200 {
		l.t.Fatalf("setup begin %d %s", code, raw)
	}
	opts, _ := json.Marshal(m)
	cred := l.authn.register(l.t, opts)
	code, m, raw = l.browser("POST", "/admin/api/setup/finish", map[string]any{"token": tok, "credential": cred})
	if code != 200 {
		l.t.Fatalf("setup finish %d %s", code, raw)
	}
	l.csrf = m["csrf"].(string)
}

func (l *liveHub) stepUp(op string) json.RawMessage {
	l.t.Helper()
	code, m, raw := l.browser("POST", "/admin/api/stepup/begin", map[string]any{"op": op})
	if code != 200 {
		l.t.Fatalf("stepup %d %s", code, raw)
	}
	opts, _ := json.Marshal(m)
	return l.authn.assert(l.t, opts)
}

type bearerRT struct {
	tok  string
	host string
}

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func pkce() (verifier, challenge string) {
	verifier = randID(48)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestOAuthConnectorEndToEnd(t *testing.T) {
	l := newLiveHub(t)
	ctx := context.Background()

	// 1. Unauthenticated MCP request: 401 pointing at resource metadata.
	resp, err := http.Post(l.ip+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("expected 401 with resource_metadata, got %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// 2. Discovery.
	var prm, asm map[string]any
	getJSON(t, l.ip+"/.well-known/oauth-protected-resource", &prm)
	getJSON(t, l.ip+"/.well-known/oauth-authorization-server", &asm)
	if prm["resource"] != l.ip+"/mcp" || asm["registration_endpoint"] == nil {
		t.Fatalf("metadata wrong: %v %v", prm, asm)
	}

	// 3. Dynamic client registration (public client, like ChatGPT).
	redirect := "https://chatgpt.com/connector_platform_oauth_redirect"
	var reg map[string]any
	postJSON(t, l.ip+"/oauth/register", map[string]any{"client_name": "ChatGPT", "redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none"}, 201, &reg)
	clientID := reg["client_id"].(string)

	// bad redirect registration is refused
	var bad map[string]any
	postJSON(t, l.ip+"/oauth/register", map[string]any{"redirect_uris": []string{"http://evil.example/cb"}}, 400, &bad)

	// 4. Authorization request -> consent page.
	verifier, challenge := pkce()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "state": {"xyz"}, "resource": {l.ip + "/mcp"}, "scope": {"ralx"}}
	resp, err = l.http.Get(l.ip + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 302 || !strings.Contains(loc, "#connect=") {
		t.Fatalf("authorize: %d %s", resp.StatusCode, loc)
	}
	reqID := loc[strings.Index(loc, "#connect=")+9:]

	// redirect_uri not registered: error page, no redirect
	q2 := url.Values{}
	for k, v := range q {
		q2[k] = v
	}
	q2.Set("redirect_uri", "https://evil.example/cb")
	resp, _ = l.http.Get(l.ip + "/oauth/authorize?" + q2.Encode())
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("unregistered redirect accepted: %d", resp.StatusCode)
	}

	// 5. Hamza signs in with his passkey and approves as agent "dot".
	if code, _, _ := l.browser("POST", "/oauth/approve", map[string]any{"id": reqID, "agent": "dot"}); code != 401 {
		t.Fatalf("approve without session: %d", code)
	}
	l.signIn()
	if code, _, _ := l.browser("POST", "/oauth/approve", map[string]any{"id": reqID, "agent": "dot"}); code != 403 {
		t.Fatalf("approve without passkey step-up: %d", code)
	}
	code, info, _ := l.browser("GET", "/oauth/request/"+reqID, nil)
	if code != 200 || info["suggested_agent"] != "dot" || info["verified"] != true {
		t.Fatalf("request info: %d %v", code, info)
	}
	assertion := l.stepUp("oauth.approve:" + reqID + ":dot:full")
	code, ap, raw := l.browser("POST", "/oauth/approve", map[string]any{"id": reqID, "agent": "dot", "assertion": assertion})
	if code != 200 {
		t.Fatalf("approve: %d %s", code, raw)
	}
	cb, _ := url.Parse(ap["redirect"].(string))
	if cb.Query().Get("state") != "xyz" || cb.Query().Get("code") == "" {
		t.Fatalf("callback: %s", cb)
	}
	authCode := cb.Query().Get("code")

	// 6. Token exchange: wrong verifier fails (and burns the code).
	form := url.Values{"grant_type": {"authorization_code"}, "code": {authCode}, "redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {"wrong"}}
	if code, _ := postForm(t, l.ip+"/oauth/token", form); code != 400 {
		t.Fatalf("bad verifier accepted: %d", code)
	}
	// redo the flow to get a fresh code
	resp, _ = l.http.Get(l.ip + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	loc = resp.Header.Get("Location")
	reqID = loc[strings.Index(loc, "#connect=")+9:]
	assertion = l.stepUp("oauth.approve:" + reqID + ":dot:full")
	_, ap, _ = l.browser("POST", "/oauth/approve", map[string]any{"id": reqID, "agent": "dot", "assertion": assertion})
	cb, _ = url.Parse(ap["redirect"].(string))
	form.Set("code", cb.Query().Get("code"))
	form.Set("code_verifier", verifier)
	code, tok := postForm(t, l.ip+"/oauth/token", form)
	if code != 200 || tok["access_token"] == nil || tok["refresh_token"] == nil {
		t.Fatalf("token: %d %v", code, tok)
	}
	// the code is single-use
	if code, _ := postForm(t, l.ip+"/oauth/token", form); code != 400 {
		t.Fatalf("code reuse accepted: %d", code)
	}
	access := tok["access_token"].(string)

	// 7. Real MCP session with the access token.
	client := mcp.NewClient(&mcp.Implementation{Name: "chatgpt-sim", Version: "1"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: l.ip + "/mcp", HTTPClient: &http.Client{Transport: bearerRT{tok: access}}}, nil)
	if err != nil {
		t.Fatalf("mcp connect: %v", err)
	}
	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tl := range tools.Tools {
		names[tl.Name] = true
	}
	for _, want := range []string{"test_hello", "test_danger", "ralx_status", "ralx_approval", "gh_repo_list", "drive_list"} {
		if !names[want] {
			t.Fatalf("tool %s missing from %v", want, names)
		}
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "test_hello", Arguments: map[string]any{}})
	if err != nil || res.IsError || !strings.Contains(textOf(res), `"hello": "dot"`) {
		t.Fatalf("hello: %v %s", err, textOf(res))
	}
	res, err = sess.CallTool(ctx, &mcp.CallToolParams{Name: "test_danger", Arguments: map[string]any{"thing": "repo"}})
	if err != nil || !strings.Contains(textOf(res), "HELD") {
		t.Fatalf("danger not held: %v %s", err, textOf(res))
	}

	// 8. Refresh rotates; a retry inside the grace window works, reuse after
	// it kills the family.
	rform := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {clientID}}
	code, tok2 := postForm(t, l.ip+"/oauth/token", rform)
	if code != 200 || tok2["access_token"] == access {
		t.Fatalf("refresh: %d %v", code, tok2)
	}
	if code, _ := postForm(t, l.ip+"/oauth/token", rform); code != 200 {
		t.Fatalf("retry within grace window refused: %d", code)
	}
	store.RefreshGraceSeconds = -1
	defer func() { store.RefreshGraceSeconds = 30 }()
	if code, _ := postForm(t, l.ip+"/oauth/token", rform); code != 400 {
		t.Fatalf("refresh reuse accepted: %d", code)
	}
	if _, _, _, _, err := l.s.authenticateBearer(tok2["access_token"].(string)); err == nil {
		t.Fatalf("family not revoked after refresh reuse")
	}

	// 9. Revoke the agent: the live MCP session's next call fails.
	a, _ := l.s.store.GetAgentByName("dot")
	_ = l.s.store.RevokeAgent(a.ID)
	res, err = sess.CallTool(ctx, &mcp.CallToolParams{Name: "test_hello", Arguments: map[string]any{}})
	if err == nil && !res.IsError {
		t.Fatalf("revoked agent still served: %s", textOf(res))
	}
	_ = sess.Close()
}

func TestRemoteMCPWithAgentKey(t *testing.T) {
	l := newLiveHub(t)
	ctx := context.Background()
	_, key, err := l.s.store.CreateAgent("daru", store.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "hermes-sim", Version: "1"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: l.ip + "/mcp", HTTPClient: &http.Client{Transport: bearerRT{tok: key}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "ralx_status", Arguments: map[string]any{}})
	if err != nil || !strings.Contains(textOf(res), `"agent": "daru"`) {
		t.Fatalf("status: %v %s", err, textOf(res))
	}
	// another agent's key can't ride this session
	_, other, _ := l.s.store.CreateAgent("other", store.Policy{})
	bad := mcp.NewClient(&mcp.Implementation{Name: "x", Version: "1"}, nil)
	if _, err := bad.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: l.ip + "/mcp", HTTPClient: &http.Client{Transport: bearerRT{tok: other + "x"}}}, nil); err == nil {
		t.Fatalf("tampered key connected")
	}
}

// A proxy/tunnel delivers requests on loopback with the public Host header.
func TestRemoteMCPBehindProxyHost(t *testing.T) {
	l := newLiveHub(t)
	l.s.hub.PublicOrigins = []string{"https://hub.example.test"}
	// rebuild the handler with the new config
	mux := http.NewServeMux()
	l.s.routes(mux)
	h := l.s.hostGuard(mux)
	_, key, _ := l.s.store.CreateAgent("daru", store.Policy{})
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	do := func(host string) int {
		req, _ := http.NewRequest("POST", "http://127.0.0.1/mcp", strings.NewReader(body))
		req.Host = host
		req.RemoteAddr = "127.0.0.1:5555"
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		rec := &recorder{h: http.Header{}}
		h.ServeHTTP(rec, req)
		return rec.code
	}
	if c := do("hub.example.test"); c != 200 {
		t.Fatalf("public host refused: %d", c)
	}
	if c := do("evil.example.test"); c != 403 {
		t.Fatalf("unknown host accepted: %d", c)
	}
}

type recorder struct {
	h    http.Header
	code int
	buf  bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.h }
func (r *recorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = 200
	}
	return r.buf.Write(b)
}
func (r *recorder) WriteHeader(c int) {
	if r.code == 0 {
		r.code = c
	}
}
func (r *recorder) Flush() {}

func textOf(r *mcp.CallToolResult) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func getJSON(t *testing.T, u string, out any) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("%s: %v", u, err)
	}
}

func postJSON(t *testing.T, u string, in any, want int, out any) {
	t.Helper()
	b, _ := json.Marshal(in)
	resp, err := http.Post(u, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("%s: got %d want %d: %s", u, resp.StatusCode, want, raw)
	}
	_ = json.Unmarshal(raw, out)
}

func postForm(t *testing.T, u string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

var _ = time.Second
