// Package google is RalX's own OAuth broker for Gmail, Drive and YouTube.
// It uses the owner's own Google Cloud OAuth client (Desktop app type), runs the
// loopback consent flow with PKCE straight into the daemon, keeps refresh
// tokens encrypted in the vault and access tokens only in memory.
package google

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Harsette/ralx/internal/redact"
	"github.com/Harsette/ralx/internal/store"
)

const (
	ClientCredential = "google-oauth-client"
	authEndpoint     = "https://accounts.google.com/o/oauth2/v2/auth"
	tokenEndpoint    = "https://oauth2.googleapis.com/token"
	revokeEndpoint   = "https://oauth2.googleapis.com/revoke"
	credPrefix       = "google:"
)

// ServiceScopes maps the services an agent can ask for to Google scopes.
var ServiceScopes = map[string][]string{
	"drive":   {"https://www.googleapis.com/auth/drive"},
	"gmail":   {"https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.compose"},
	"youtube": {"https://www.googleapis.com/auth/youtube.readonly", "https://www.googleapis.com/auth/youtube.upload"},
}

var baseScopes = []string{"openid", "email"}

type Flow struct {
	ID        string   `json:"id"`
	Services  []string `json:"services"`
	Status    string   `json:"status"` // pending | connected | error | expired
	Account   string   `json:"account,omitempty"`
	Error     string   `json:"error,omitempty"`
	AuthURL   string   `json:"auth_url"`
	CreatedAt int64    `json:"created_at"`
	Agent     string   `json:"agent"`

	state    string
	verifier string
}

type Broker struct {
	Store       *store.Store
	Redactor    *redact.Redactor
	HTTP        *http.Client
	RedirectURI string // e.g. http://127.0.0.1:7317/oauth/google/callback
	OnEvent     func(actor, action, outcome, detail string)
	// TrustAnyUploadHost relaxes the resumable-session host check for tests
	// (which use a loopback/fixture host). Production requires a googleapis host.
	TrustAnyUploadHost bool

	mu     sync.Mutex
	flows  map[string]*Flow // by id
	states map[string]*Flow // by state

	tokMu  sync.Mutex
	tokens map[string]*accessToken // account -> token
	locks  map[string]*sync.Mutex
}

type accessToken struct {
	value                           string
	expiry                          time.Time
	accountIdentity, clientIdentity string
}

func NewBroker(s *store.Store, r *redact.Redactor, redirectURI string) *Broker {
	return &Broker{
		Store: s, Redactor: r, RedirectURI: redirectURI,
		// Never follow a redirect: a 307/308 from the token endpoint would
		// otherwise replay the refresh token and client secret to another origin,
		// and a redirect on an API call would re-send the bearer (Astra R9).
		HTTP:  &http.Client{Timeout: 0, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		flows: map[string]*Flow{}, states: map[string]*Flow{},
		tokens: map[string]*accessToken{}, locks: map[string]*sync.Mutex{},
	}
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (b *Broker) client() (id, secret string, err error) {
	f, err := b.Store.Secret(ClientCredential)
	if err != nil {
		return "", "", errors.New("Google isn't set up yet: the owner needs to add the RalX Google OAuth client (ralx admin google-client <client_secret.json>)")
	}
	return f["client_id"], f["client_secret"], nil
}

// ClientConfigured reports whether the OAuth client is in the vault.
func (b *Broker) ClientConfigured() bool {
	_, err := b.Store.GetCredential(ClientCredential)
	return err == nil
}

func scopesFor(services []string) ([]string, error) {
	set := map[string]bool{}
	for _, s := range baseScopes {
		set[s] = true
	}
	for _, svc := range services {
		sc, ok := ServiceScopes[svc]
		if !ok {
			return nil, fmt.Errorf("unknown Google service %q (use drive, gmail, youtube)", svc)
		}
		for _, s := range sc {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

// StartFlow begins a consent flow and returns the URL to open in a browser.
// The URL holds no secret: the client secret and PKCE verifier stay here.
func (b *Broker) StartFlow(services []string, agent, loginHint string) (*Flow, error) {
	if len(services) == 0 {
		services = []string{"drive", "gmail", "youtube"}
	}
	clientID, _, err := b.client()
	if err != nil {
		return nil, err
	}
	scopes, err := scopesFor(services)
	if err != nil {
		return nil, err
	}
	f := &Flow{ID: store.NewID("flow_"), Services: services, Status: "pending", CreatedAt: time.Now().Unix(), Agent: agent,
		state: randToken(24), verifier: randToken(48)}
	sum := sha256.Sum256([]byte(f.verifier))
	q := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {b.RedirectURI},
		"response_type": {"code"},
		"scope":         {strings.Join(scopes, " ")},
		"access_type":   {"offline"},
		// No named account: open Google's account chooser so the owner can add
		// another account instead of silently reusing the signed-in one.
		"prompt":                 {"select_account consent"},
		"include_granted_scopes": {"true"},
		"state":                  {f.state},
		"code_challenge":         {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method":  {"S256"},
	}
	if loginHint != "" {
		q.Set("login_hint", loginHint)
		q.Set("prompt", "consent")
	}
	f.AuthURL = authEndpoint + "?" + q.Encode()
	b.mu.Lock()
	b.gcFlowsLocked()
	b.flows[f.ID] = f
	b.states[f.state] = f
	b.mu.Unlock()
	return f, nil
}

func (b *Broker) gcFlowsLocked() {
	cut := time.Now().Add(-30 * time.Minute).Unix()
	for id, f := range b.flows {
		if f.CreatedAt < cut {
			delete(b.flows, id)
			delete(b.states, f.state)
		}
	}
}

func (b *Broker) GetFlow(id string) (*Flow, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.flows[id]
	if !ok {
		return nil, false
	}
	cp := *f
	if cp.Status == "pending" && time.Now().Unix()-cp.CreatedAt > 15*60 {
		cp.Status = "expired"
	}
	return &cp, true
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"`
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (b *Broker) postToken(ctx context.Context, form url.Values) (*tokenResponse, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}
	if tr.Error != "" {
		return &tr, fmt.Errorf("google: %s", tr.Error)
	}
	return &tr, nil
}

func emailFromIDToken(idt string) string {
	parts := strings.Split(idt, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Email string `json:"email"`
	}
	_ = json.Unmarshal(payload, &c)
	return strings.ToLower(c.Email)
}

var donePage = template.Must(template.New("done").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RalX</title>
<style>:root{color-scheme:light dark}body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:#f6f6f4;color:#151515}
@media (prefers-color-scheme:dark){body{background:#111;color:#eee}.card{background:#1a1a1a!important;border-color:#2a2a2a!important}}
.card{background:#fff;border:1px solid #e6e6e2;border-radius:16px;padding:32px 36px;max-width:420px;text-align:center}
.mark{font-size:40px;line-height:1}h1{font-size:20px;margin:12px 0 4px}p{margin:0;opacity:.7}</style></head>
<body><div class="card"><div class="mark">{{if .OK}}✓{{else}}✕{{end}}</div><h1>{{.Title}}</h1><p>{{.Body}}</p></div></body></html>`))

// HandleCallback receives Google's redirect, exchanges the code server-side
// and stores the refresh token in the vault.
func (b *Broker) HandleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	b.mu.Lock()
	f, ok := b.states[q.Get("state")]
	if ok {
		delete(b.states, f.state)
	}
	b.mu.Unlock()
	render := func(okv bool, title, body string) {
		// Redact the rendered body: an agent can start a Google connect flow and reach
		// this page, and a provider error could echo a stored secret into it. red.String
		// rewrites known forms; a form that still reconstructs after that is withheld
		// (defence in depth , Astra7 self-review callback render).
		body = b.Redactor.String(body)
		if b.Redactor.DeepContainsSecret(body) {
			body = "withheld"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = donePage.Execute(w, map[string]any{"OK": okv, "Title": title, "Body": body})
	}
	if !ok {
		w.WriteHeader(400)
		render(false, "This link has expired", "Start again with: ralx connect google")
		return
	}
	fail := func(msg string) {
		b.mu.Lock()
		f.Status, f.Error = "error", msg
		b.mu.Unlock()
		b.event(f.Agent, "google.connect", "error", msg)
		render(false, "Google didn't connect", msg)
	}
	if e := q.Get("error"); e != "" {
		fail("Google said: " + e)
		return
	}
	clientID, clientSecret, err := b.client()
	if err != nil {
		fail(err.Error())
		return
	}
	tr, err := b.postToken(r.Context(), url.Values{
		"code":          {q.Get("code")},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {b.RedirectURI},
		"grant_type":    {"authorization_code"},
		"code_verifier": {f.verifier},
	})
	if err != nil {
		fail(err.Error())
		return
	}
	email := emailFromIDToken(tr.IDToken)
	if email == "" {
		fail("Google didn't return the account email")
		return
	}
	if tr.RefreshToken == "" {
		fail("Google didn't return a refresh token; remove RalX at myaccount.google.com/permissions and connect again")
		return
	}
	name := credPrefix + email
	meta := map[string]any{"email": email, "scopes": strings.Fields(tr.Scope), "services": servicesFromScopes(tr.Scope), "status": "ok", "connected_at": time.Now().Unix()}
	existing, _ := b.Store.GetCredential(name)
	if existing != nil {
		meta["default"] = existing.Meta["default"]
	} else if b.DefaultAccount() == "" {
		meta["default"] = true
	} else {
		meta["default"] = false
	}
	if existing != nil {
		meta["default_for"] = existing.Meta["default_for"]
	}
	if _, err := b.Store.PutCredential(name, "oauth_token", "google", email, meta, map[string]string{"refresh_token": tr.RefreshToken}); err != nil {
		fail("couldn't save to the vault: " + err.Error())
		return
	}
	// A newly granted service with no default account yet gets this one.
	var claim []string
	for _, svc := range servicesFromScopes(tr.Scope) {
		taken := false
		for _, c := range b.Accounts() {
			if c.Label != email && contains(metaList(c.Meta, "default_for"), svc) {
				taken = true
			}
		}
		if !taken {
			claim = append(claim, svc)
		}
	}
	if len(claim) > 0 {
		cur := []string{}
		if existing != nil {
			cur = metaList(existing.Meta, "default_for")
		}
		for _, s := range claim {
			if !contains(cur, s) {
				cur = append(cur, s)
			}
		}
		_ = b.Store.UpdateMeta(name, map[string]any{"default_for": cur})
	}
	b.Redactor.Add(name+":refresh_token", tr.RefreshToken)
	// Do not associate this callback token with a later same-named replacement.
	// The first action refreshes from a checked account/client snapshot.
	b.Redactor.Add(name+":access_token", tr.AccessToken)
	b.tokMu.Lock()
	delete(b.tokens, email)
	b.tokMu.Unlock()
	b.mu.Lock()
	f.Status, f.Account = "connected", email
	b.mu.Unlock()
	b.event(f.Agent, "google.connect", "ok", email+" "+strings.Join(servicesFromScopes(tr.Scope), ","))
	render(true, "Google is connected to RalX", email+". You can close this tab; your agents can use it now without ever seeing the keys.")
}

func servicesFromScopes(scope string) []string {
	var out []string
	for svc, scs := range ServiceScopes {
		all := true
		for _, s := range scs {
			if !strings.Contains(" "+scope+" ", " "+s+" ") {
				all = false
			}
		}
		if all {
			out = append(out, svc)
		}
	}
	sort.Strings(out)
	return out
}

func (b *Broker) event(actor, action, outcome, detail string) {
	if b.OnEvent != nil {
		b.OnEvent(actor, action, outcome, b.Redactor.String(detail))
	}
}

func (b *Broker) cacheToken(account, tok string, expiresIn int, accountIdentity, clientIdentity string) {
	if tok == "" {
		return
	}
	b.Redactor.Add(credPrefix+account+":access_token", tok)
	b.tokMu.Lock()
	b.tokens[account] = &accessToken{value: tok, expiry: time.Now().Add(time.Duration(expiresIn) * time.Second), accountIdentity: accountIdentity, clientIdentity: clientIdentity}
	b.tokMu.Unlock()
}

// Accounts lists connected Google accounts (non-secret metadata only).
func (b *Broker) Accounts() []*store.Credential {
	creds, _ := b.Store.ListCredentials()
	var out []*store.Credential
	for _, c := range creds {
		if c.Provider == "google" && c.Kind == "oauth_token" {
			out = append(out, c)
		}
	}
	return out
}

func (b *Broker) DefaultAccount() string {
	accts := b.Accounts()
	for _, c := range accts {
		if d, _ := c.Meta["default"].(bool); d {
			return c.Label
		}
	}
	if len(accts) == 1 {
		return accts[0].Label
	}
	return ""
}

func (b *Broker) SetDefault(account string) error {
	found := false
	for _, c := range b.Accounts() {
		isDef := c.Label == account
		found = found || isDef
		_ = b.Store.UpdateMeta(c.Name, map[string]any{"default": isDef})
	}
	if !found {
		return store.ErrNotFound
	}
	return nil
}

func metaList(m map[string]any, k string) []string {
	var out []string
	switch v := m[k].(type) {
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = v
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// DefaultAccountFor returns the account used for a service (drive, gmail,
// youtube) when an agent doesn't name one.
func (b *Broker) DefaultAccountFor(service string) string {
	for _, c := range b.Accounts() {
		if contains(metaList(c.Meta, "default_for"), service) {
			return c.Label
		}
	}
	return b.DefaultAccount()
}

// SetDefaultFor makes account the default for the given services, taking
// them away from any other account.
func (b *Broker) SetDefaultFor(account string, services []string) error {
	found := false
	for _, c := range b.Accounts() {
		cur := metaList(c.Meta, "default_for")
		var next []string
		for _, s := range cur {
			if !contains(services, s) {
				next = append(next, s)
			}
		}
		if c.Label == account {
			found = true
			next = append(next, services...)
		}
		if next == nil {
			next = []string{}
		}
		_ = b.Store.UpdateMeta(c.Name, map[string]any{"default_for": next})
	}
	if !found {
		return store.ErrNotFound
	}
	return nil
}

// pick resolves the account for an action: the explicit argument, else the
// service default.
func (b *Broker) pick(args map[string]any, service string) string {
	if a, _ := args["account"].(string); a != "" {
		return strings.ToLower(a)
	}
	return b.DefaultAccountFor(service)
}

func (b *Broker) lockFor(account string) *sync.Mutex {
	b.tokMu.Lock()
	defer b.tokMu.Unlock()
	m, ok := b.locks[account]
	if !ok {
		m = &sync.Mutex{}
		b.locks[account] = m
	}
	return m
}

// AccessToken returns a valid access token for account ("" = default),
// refreshing it if needed. Internal use only: it is attached to outgoing
// Google requests and never returned to an agent.
func (b *Broker) AccessToken(ctx context.Context, account string) (string, string, error) {
	if account == "" {
		account = b.DefaultAccount()
	}
	if account == "" {
		return "", "", errors.New("no Google account connected; run: ralx connect google")
	}
	l := b.lockFor(account)
	l.Lock()
	defer l.Unlock()
	name := credPrefix + account
	cred, fields, err := b.Store.BoundSecret(ctx, name)
	if err != nil {
		return "", "", err
	}
	client, clientFields, err := b.Store.BoundSecret(ctx, ClientCredential)
	if err != nil {
		return "", "", err
	}
	identity, clientIdentity := store.CredentialIdentity(cred), store.CredentialIdentity(client)
	b.tokMu.Lock()
	t := b.tokens[account]
	b.tokMu.Unlock()
	if t != nil && t.accountIdentity == identity && t.clientIdentity == clientIdentity && time.Until(t.expiry) > 2*time.Minute {
		return t.value, account, nil
	}
	clientID, clientSecret := clientFields["client_id"], clientFields["client_secret"]
	tr, err := b.postToken(ctx, url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"refresh_token": {fields["refresh_token"]},
		"grant_type":    {"refresh_token"},
	})
	if err != nil {
		if tr != nil && tr.Error == "invalid_grant" {
			// Only the login this refresh used; a reconnect in between keeps its status.
			_, _ = b.Store.UpdateMetaIf(name, func(c *store.Credential) bool { return store.CredentialIdentity(c) == identity },
				map[string]any{"status": "reconnect_needed"})
			b.event("ralx", "google.refresh", "error", account+": Google revoked or expired the login (invalid_grant)")
			return "", "", fmt.Errorf("Google login for %s expired or was revoked; reconnect with: ralx connect google", account)
		}
		return "", "", err
	}
	currentClient, err := b.Store.GetCredential(ClientCredential)
	if err != nil || store.CredentialIdentity(currentClient) != clientIdentity {
		return "", "", errors.New("Google client changed during refresh; retry")
	}
	patch := map[string]string{}
	if tr.RefreshToken != "" {
		patch["refresh_token"] = tr.RefreshToken
	}
	ok, err := b.Store.CASFields(name, func(c *store.Credential, f map[string]string) bool {
		return store.CredentialIdentity(c) == identity && f["refresh_token"] == fields["refresh_token"]
	}, patch)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", errors.New("Google account changed during refresh; retry")
	}
	if tr.RefreshToken != "" && tr.RefreshToken != fields["refresh_token"] {
		b.Redactor.Add(name+":refresh_token", tr.RefreshToken)
	}
	b.cacheToken(account, tr.AccessToken, tr.ExpiresIn, identity, clientIdentity)
	return tr.AccessToken, account, nil
}

// Disconnect revokes the grant at Google and deletes it from the vault.
func (b *Broker) Disconnect(ctx context.Context, account string) error {
	name := credPrefix + account
	fields, err := b.Store.Secret(name)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", revokeEndpoint, strings.NewReader(url.Values{"token": {fields["refresh_token"]}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, err := b.HTTP.Do(req); err == nil {
		resp.Body.Close()
	}
	b.tokMu.Lock()
	delete(b.tokens, account)
	b.tokMu.Unlock()
	return b.Store.DeleteCredential(name)
}

// APIError is a Google API failure with the response body (secrets redacted).
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string { return fmt.Sprintf("google api %d: %s", e.Status, e.Body) }

// Do sends an authenticated request. For GETs it retries once after a 401.
func (b *Broker) Do(ctx context.Context, account string, build func(token string) (*http.Request, error)) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		tok, acct, err := b.AccessToken(ctx, account)
		if err != nil {
			return nil, err
		}
		req, err := build(tok)
		if err != nil {
			return nil, err
		}
		req = req.WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := b.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == 401 && attempt == 0 && req.Method == "GET" {
			resp.Body.Close()
			b.tokMu.Lock()
			delete(b.tokens, acct)
			b.tokMu.Unlock()
			continue
		}
		return resp, nil
	}
	return nil, errors.New("google: unauthorized")
}

// JSON performs a request and decodes a JSON response, turning non-2xx into
// an APIError.
func (b *Broker) JSON(ctx context.Context, account, method, u string, body any, out any) error {
	resp, err := b.Do(ctx, account, func(tok string) (*http.Request, error) {
		var rd io.Reader
		if body != nil {
			bb, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			rd = strings.NewReader(string(bb))
		}
		req, err := http.NewRequest(method, u, rd)
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, nil
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return &APIError{Status: resp.StatusCode, Body: b.Redactor.String(string(data))}
	}
	// Propagate a body-read error instead of silently treating a truncated/unread
	// 2xx body as success , a caller that fingerprints the response (Drive audience)
	// must not mistake an unread body for an empty-but-valid one (Daru6 P1).
	if rerr != nil {
		return fmt.Errorf("reading response from %s: %w", u, rerr)
	}
	if out != nil {
		// A caller that wants a document must get one: an empty or `null` 2xx body
		// is treated as an error, so an unread/empty later page can't look like a
		// clean end-of-list (Daru6 self-review P1).
		if t := strings.TrimSpace(string(data)); t == "" || t == "null" {
			return fmt.Errorf("empty response document from %s", u)
		}
		return json.Unmarshal(data, out)
	}
	return nil
}
