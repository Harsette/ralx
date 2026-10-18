package daemon

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/store"
)

// oauthServer is RalX's own OAuth 2.1 authorization server, so chat agents
// in other clouds (ChatGPT, Grok, Muse) can add RalX as a custom MCP
// connector and sign in. Every grant needs the owner's passkey on the consent
// page, and every grant becomes a normal revocable RalX agent.
//
// Implements: RFC 9728 protected resource metadata, RFC 8414 server
// metadata, RFC 7591 dynamic client registration, Client ID Metadata
// Documents (HTTPS URL client ids), PKCE S256 (required), RFC 8707 resource
// indicators, rotating refresh tokens with reuse detection, RFC 7009
// revocation.
type oauthServer struct {
	s *Server

	mu       sync.Mutex
	requests map[string]*authRequest // consent page requests
	codes    map[string]*authCode    // code hash -> code
}

type authRequest struct {
	ID          string
	ClientID    string
	ClientName  string
	RedirectURI string
	State       string
	Challenge   string
	Resource    string
	Scope       string
	Origin      string
	Created     time.Time
}

type authCode struct {
	ClientID    string
	RedirectURI string
	Challenge   string
	Resource    string
	Scope       string
	AgentID     string
	Expires     time.Time
}

const (
	accessTTL  = time.Hour
	refreshTTL = 60 * 24 * time.Hour
	scopeRalx  = "ralx"
)

func newOAuthServer(s *Server) *oauthServer {
	return &oauthServer{s: s, requests: map[string]*authRequest{}, codes: map[string]*authCode{}}
}

func corsPublic(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Protocol-Version")
}

func (o *oauthServer) public(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		corsPublic(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

func (o *oauthServer) routes(mux *http.ServeMux) {
	prm := o.public(o.handleResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource", prm)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", prm)
	asm := o.public(o.handleServerMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server", asm)
	mux.HandleFunc("/.well-known/oauth-authorization-server/mcp", asm)
	mux.HandleFunc("/.well-known/openid-configuration", asm)
	mux.HandleFunc("/oauth/register", o.public(o.handleRegister))
	mux.HandleFunc("/oauth/token", o.public(o.handleToken))
	mux.HandleFunc("/oauth/revoke", o.public(o.handleRevoke))
	mux.HandleFunc("GET /oauth/authorize", o.handleAuthorize)
	mux.HandleFunc("GET /oauth/request/{id}", o.s.adminOnly(o.handleRequestInfo))
	mux.HandleFunc("POST /oauth/approve", o.s.adminOnly(o.handleApprove))
	mux.HandleFunc("POST /oauth/deny", o.s.adminOnly(o.handleDeny))
	mux.HandleFunc("POST /admin/api/oauth-clients", o.s.localAdminOnly(o.handleCreateStaticClient))
}

// handleCreateStaticClient pre-registers a confidential client for apps that
// ask for a client id and secret instead of registering themselves (Grok's
// "OAuth credentials required" dialog, ChatGPT's static credentials).
func (o *oauthServer) handleCreateStaticClient(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	name := strings.TrimSpace(rawString(body, "name"))
	var redirects []string
	_ = json.Unmarshal(body["redirect_uris"], &redirects)
	if name == "" || len(redirects) == 0 {
		o.s.fail(w, 400, "name and redirect_uris required")
		return
	}
	for _, u := range redirects {
		if !validRedirect(u) {
			o.s.fail(w, 400, "redirect URIs must be https (or http on localhost): "+u)
			return
		}
	}
	if err := o.s.stepUp(ac, "oauth.client:"+name, body, true); err != nil {
		o.s.fail(w, 403, err.Error())
		return
	}
	c, secret, err := o.s.store.RegisterOAuthClient(name, redirects, map[string]any{"token_endpoint_auth_method": "client_secret_post", "static": true}, true)
	if err != nil {
		o.s.fail(w, 500, err.Error())
		return
	}
	// Static clients count as used, so they are never pruned.
	_, _ = o.s.store.TouchOAuthClient(c.ID)
	o.s.store.Audit("owner", "oauth.client", "ok", 0, name+" "+c.ID)
	writeJSON(w, 200, map[string]any{"client_id": c.ID, "client_secret": secret, "redirect_uris": redirects,
		"authorize_url": o.s.originFor(r) + "/oauth/authorize", "token_url": o.s.originFor(r) + "/oauth/token"})
}

func (o *oauthServer) resourceFor(origin string) string { return origin + "/mcp" }

func (o *oauthServer) handleResourceMetadata(w http.ResponseWriter, r *http.Request) {
	origin := o.s.originFor(r)
	writeJSON(w, 200, map[string]any{
		"resource":                 o.resourceFor(origin),
		"authorization_servers":    []string{origin},
		"scopes_supported":         []string{scopeRalx},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "RalX",
		"resource_documentation":   origin + "/",
	})
}

func (o *oauthServer) handleServerMetadata(w http.ResponseWriter, r *http.Request) {
	origin := o.s.originFor(r)
	writeJSON(w, 200, map[string]any{
		"issuer":                                         origin,
		"authorization_endpoint":                         origin + "/oauth/authorize",
		"token_endpoint":                                 origin + "/oauth/token",
		"registration_endpoint":                          origin + "/oauth/register",
		"revocation_endpoint":                            origin + "/oauth/revoke",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_post", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":     []string{"none", "client_secret_post", "client_secret_basic"},
		"scopes_supported":                               []string{scopeRalx, "offline_access"},
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
	})
}

func oauthError(w http.ResponseWriter, code int, errCode, desc string) {
	writeJSON(w, code, map[string]any{"error": errCode, "error_description": desc})
}

// validRedirect accepts https URLs and loopback http URLs (native apps).
func validRedirect(u string) bool {
	p, err := url.Parse(u)
	if err != nil || p.Fragment != "" || p.Host == "" {
		return false
	}
	switch p.Scheme {
	case "https":
		return true
	case "http":
		h := p.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

func (o *oauthServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, 405, "invalid_request", "POST only")
		return
	}
	var req struct {
		RedirectURIs            []string `json:"redirect_uris"`
		ClientName              string   `json:"client_name"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		Scope                   string   `json:"scope"`
		ClientURI               string   `json:"client_uri"`
		LogoURI                 string   `json:"logo_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		oauthError(w, 400, "invalid_client_metadata", "body must be JSON client metadata")
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		oauthError(w, 400, "invalid_redirect_uri", "1 to 10 redirect_uris required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !validRedirect(u) {
			oauthError(w, 400, "invalid_redirect_uri", "redirect URIs must be https, or http on localhost: "+u)
			return
		}
	}
	method := req.TokenEndpointAuthMethod
	if method == "" {
		method = "none"
	}
	if method != "none" && method != "client_secret_post" && method != "client_secret_basic" {
		oauthError(w, 400, "invalid_client_metadata", "unsupported token_endpoint_auth_method")
		return
	}
	if o.s.store.CountOAuthClients() > 1000 {
		o.s.store.PruneOAuthClients(7 * 24 * time.Hour)
		if o.s.store.CountOAuthClients() > 1000 {
			oauthError(w, 429, "temporarily_unavailable", "too many registered clients")
			return
		}
	}
	name := strings.TrimSpace(req.ClientName)
	if len(name) > 80 {
		name = name[:80]
	}
	meta := map[string]any{"token_endpoint_auth_method": method, "client_uri": req.ClientURI}
	c, secret, err := o.s.store.RegisterOAuthClient(name, req.RedirectURIs, meta, method != "none")
	if err != nil {
		oauthError(w, 500, "server_error", err.Error())
		return
	}
	o.s.store.Audit("oauth", "oauth.register", "ok", 0, c.ID+" "+name)
	resp := map[string]any{
		"client_id": c.ID, "client_id_issued_at": c.CreatedAt, "client_name": name,
		"redirect_uris": req.RedirectURIs, "token_endpoint_auth_method": method,
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
	}
	if secret != "" {
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
	}
	writeJSON(w, 201, resp)
}

// resolveClient finds a registered client, or fetches a Client ID Metadata
// Document when the client id is an HTTPS URL.
func (o *oauthServer) resolveClient(ctx context.Context, id string) (*store.OAuthClient, error) {
	if strings.HasPrefix(id, "https://") {
		return fetchClientMetadata(ctx, id)
	}
	return o.s.store.GetOAuthClient(id)
}

var errBlockedAddr = errors.New("address not allowed")

// safeDialer refuses private, loopback and link-local destinations, so a
// client-supplied URL can't be used to probe the hub's network.
func safeDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, Control: func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() || isCGNAT(ip) {
			return errBlockedAddr
		}
		return nil
	}}
}

func isCGNAT(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 100 && ip4[1]&0xC0 == 64
}

func safeHTTPClient() *http.Client {
	tr := &http.Transport{DialContext: safeDialer().DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func fetchClientMetadata(ctx context.Context, id string) (*store.OAuthClient, error) {
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" || u.Path == "" || u.Path == "/" {
		return nil, errors.New("client id URL must be https with a path")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", id, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := safeHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("client metadata document returned " + resp.Status)
	}
	var doc struct {
		ClientID     string   `json:"client_id"`
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&doc); err != nil {
		return nil, err
	}
	if doc.ClientID != id {
		return nil, errors.New("client metadata document's client_id doesn't match its URL")
	}
	for _, r := range doc.RedirectURIs {
		if !validRedirect(r) {
			return nil, errors.New("bad redirect uri in client metadata")
		}
	}
	name := doc.ClientName
	if name == "" {
		name = u.Host
	}
	return &store.OAuthClient{ID: id, Name: name, RedirectURIs: doc.RedirectURIs, Metadata: map[string]any{"token_endpoint_auth_method": "none", "cimd": true}}, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// handleAuthorize validates the request and shows the consent page. Errors
// that make the redirect untrustworthy are shown on the page, never
// redirected (OAuth 2.1 §4.1.2.1).
func (o *oauthServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := func(code int, title, msg string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(code)
		_ = errorPage.Execute(w, map[string]string{"Title": title, "Msg": msg})
	}
	client, err := o.resolveClient(r.Context(), q.Get("client_id"))
	if err != nil {
		page(400, "Unknown app", "This connector isn't registered with RalX. Remove it and add it again.")
		return
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" && len(client.RedirectURIs) == 1 {
		redirect = client.RedirectURIs[0]
	}
	if !contains(client.RedirectURIs, redirect) {
		page(400, "Redirect mismatch", "The app asked to send you somewhere it didn't register.")
		return
	}
	fail := func(errCode, desc string) {
		u, _ := url.Parse(redirect)
		v := u.Query()
		v.Set("error", errCode)
		v.Set("error_description", desc)
		if st := q.Get("state"); st != "" {
			v.Set("state", st)
		}
		v.Set("iss", o.s.originFor(r))
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only code is supported")
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		fail("invalid_request", "PKCE with S256 is required")
		return
	}
	origin := o.s.originFor(r)
	resource := q.Get("resource")
	if resource != "" && strings.TrimRight(resource, "/") != o.resourceFor(origin) && strings.TrimRight(resource, "/") != origin {
		fail("invalid_target", "unknown resource")
		return
	}
	if resource == "" {
		resource = o.resourceFor(origin)
	}
	ar := &authRequest{ID: randID(18), ClientID: client.ID, ClientName: client.Name, RedirectURI: redirect, State: q.Get("state"),
		Challenge: q.Get("code_challenge"), Resource: resource, Scope: q.Get("scope"), Origin: origin, Created: time.Now()}
	o.mu.Lock()
	for id, old := range o.requests {
		if time.Since(old.Created) > 15*time.Minute {
			delete(o.requests, id)
		}
	}
	o.requests[ar.ID] = ar
	o.mu.Unlock()
	// The admin app renders the consent screen (passkey sign-in + approve).
	http.Redirect(w, r, origin+"/#connect="+ar.ID, http.StatusFound)
}

func (o *oauthServer) getRequest(id string) (*authRequest, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	ar, ok := o.requests[id]
	if ok && time.Since(ar.Created) > 15*time.Minute {
		delete(o.requests, id)
		return nil, false
	}
	return ar, ok
}

var agentNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,40}$`)

func suggestAgentName(client string) string {
	n := strings.ToLower(client)
	switch {
	case strings.Contains(n, "chatgpt") || strings.Contains(n, "openai"):
		return "dot"
	case strings.Contains(n, "grok") || strings.Contains(n, "xai"):
		return "grok"
	case strings.Contains(n, "muse") || strings.Contains(n, "meta"):
		return "muse"
	case strings.Contains(n, "claude"):
		return "claude"
	}
	n = regexp.MustCompile(`[^a-z0-9._-]+`).ReplaceAllString(n, "-")
	n = strings.Trim(n, "-")
	if n == "" || !agentNameRe.MatchString(n) {
		return "connector"
	}
	return n
}

// knownConnectors maps redirect hosts of the chat apps RalX is built for to
// their real names. A client's self-chosen name is never trusted on its own.
var knownConnectors = map[string][2]string{
	"chatgpt.com":   {"ChatGPT", "dot"},
	"grok.com":      {"Grok", "grok"},
	"agent.meta.ai": {"Meta Muse", "muse"},
	"claude.ai":     {"Claude", "claude"},
}

func (o *oauthServer) handleRequestInfo(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	ar, ok := o.getRequest(r.PathValue("id"))
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "this sign-in request expired; start again from the app"})
		return
	}
	u, _ := url.Parse(ar.RedirectURI)
	host := strings.ToLower(u.Hostname())
	name, agent, verified := ar.ClientName, "connector", false
	if k, ok := knownConnectors[host]; ok && u.Scheme == "https" {
		name, agent, verified = k[0], k[1], true
	} else if h := u.Hostname(); h == "localhost" || h == "127.0.0.1" {
		agent = "local-client"
	}
	if name == "" {
		name = host
	}
	writeJSON(w, 200, map[string]any{"id": ar.ID, "client_name": name, "claimed_name": ar.ClientName, "verified": verified,
		"redirect_host": u.Host, "suggested_agent": agent, "resource": ar.Resource})
}

func (o *oauthServer) handleApprove(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	id := rawString(body, "id")
	ar, ok := o.getRequest(id)
	if !ok {
		o.s.fail(w, 404, "this sign-in request expired")
		return
	}
	name := strings.ToLower(strings.TrimSpace(rawString(body, "agent")))
	if !agentNameRe.MatchString(name) {
		o.s.fail(w, 400, "agent name: letters, numbers, dots or dashes")
		return
	}
	access := rawString(body, "access")
	if access != "read" {
		access = "full"
	}
	readOnly := access == "read"
	// The passkey is bound to the exact agent name and access level the owner saw,
	// so neither can be swapped after he signs (Astra finding 8).
	if err := o.s.stepUp(ac, "oauth.approve:"+id+":"+name+":"+access, body, false); err != nil {
		o.s.fail(w, 403, err.Error())
		return
	}
	agent, err := o.s.store.GetAgentByName(name)
	if err == nil && agent.RevokedAt != 0 {
		o.s.fail(w, 409, "an agent called "+name+" was revoked; pick another name")
		return
	}
	if err != nil {
		pol := store.Policy{}
		if readOnly {
			pol.Allow = o.s.readOnlyActions()
		}
		agent, _, err = o.s.store.CreateAgent(name, pol)
		if err != nil {
			o.s.fail(w, 400, err.Error())
			return
		}
	} else if readOnly && !o.s.isReadOnlyAgent(agent) {
		// Reusing an existing name must never silently widen "read only" into
		// that agent's broader access (Astra finding 6). Make the owner pick a
		// fresh name so the grant is genuinely read-only.
		o.s.fail(w, 409, "an agent called "+name+" already exists with broader access; choose a new name for a read-only connection")
		return
	}
	code := randID(32)
	o.mu.Lock()
	delete(o.requests, id)
	o.codes[store.HashToken(code)] = &authCode{ClientID: ar.ClientID, RedirectURI: ar.RedirectURI, Challenge: ar.Challenge,
		Resource: ar.Resource, Scope: scopeRalx, AgentID: agent.ID, Expires: time.Now().Add(2 * time.Minute)}
	o.mu.Unlock()
	o.s.store.Audit("owner", "oauth.approve", "ok", 0, ar.ClientName+" as agent "+name)
	u, _ := url.Parse(ar.RedirectURI)
	v := u.Query()
	v.Set("code", code)
	if ar.State != "" {
		v.Set("state", ar.State)
	}
	v.Set("iss", ar.Origin)
	u.RawQuery = v.Encode()
	writeJSON(w, 200, map[string]any{"redirect": u.String(), "agent": name})
}

func (o *oauthServer) handleDeny(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	ar, ok := o.getRequest(rawString(body, "id"))
	if !ok {
		o.s.fail(w, 404, "this sign-in request expired")
		return
	}
	o.mu.Lock()
	delete(o.requests, ar.ID)
	o.mu.Unlock()
	u, _ := url.Parse(ar.RedirectURI)
	v := u.Query()
	v.Set("error", "access_denied")
	if ar.State != "" {
		v.Set("state", ar.State)
	}
	v.Set("iss", ar.Origin)
	u.RawQuery = v.Encode()
	o.s.store.Audit("owner", "oauth.deny", "ok", 0, ar.ClientName)
	writeJSON(w, 200, map[string]any{"redirect": u.String()})
}

// clientAuth checks the client's credentials at the token endpoint.
func (o *oauthServer) clientAuth(r *http.Request) (*store.OAuthClient, error) {
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	} else {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	}
	c, err := o.resolveClient(r.Context(), id)
	if err != nil {
		return nil, errors.New("unknown client")
	}
	if c.SecretHash != "" {
		if subtle.ConstantTimeCompare([]byte(store.HashToken(secret)), []byte(c.SecretHash)) != 1 {
			return nil, errors.New("bad client secret")
		}
	}
	return c, nil
}

func (o *oauthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, 405, "invalid_request", "POST only")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "form body required")
		return
	}
	w.Header().Set("Pragma", "no-cache")
	client, err := o.clientAuth(r)
	if err != nil {
		oauthError(w, 401, "invalid_client", err.Error())
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		h := store.HashToken(r.PostForm.Get("code"))
		o.mu.Lock()
		c, ok := o.codes[h]
		delete(o.codes, h) // single use
		o.mu.Unlock()
		if !ok || time.Now().After(c.Expires) || c.ClientID != client.ID {
			oauthError(w, 400, "invalid_grant", "code is invalid or expired")
			return
		}
		if ru := r.PostForm.Get("redirect_uri"); ru != "" && ru != c.RedirectURI {
			oauthError(w, 400, "invalid_grant", "redirect_uri mismatch")
			return
		}
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != c.Challenge {
			oauthError(w, 400, "invalid_grant", "PKCE verification failed")
			return
		}
		if res := r.PostForm.Get("resource"); res != "" && strings.TrimRight(res, "/") != c.Resource && strings.TrimRight(res, "/")+"/mcp" != c.Resource {
			oauthError(w, 400, "invalid_target", "resource mismatch")
			return
		}
		o.issue(w, c.AgentID, client.ID, "", c.Resource, c.Scope)
	case "refresh_token":
		t, err := o.s.store.RedeemRefresh(r.PostForm.Get("refresh_token"), client.ID)
		if err != nil {
			oauthError(w, 400, "invalid_grant", err.Error())
			return
		}
		o.issue(w, t.AgentID, client.ID, t.Family, t.Resource, t.Scope)
	default:
		oauthError(w, 400, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

func (o *oauthServer) issue(w http.ResponseWriter, agentID, clientID, family, resource, scope string) {
	access, refresh, err := o.s.store.IssueTokens(agentID, clientID, family, resource, scope, accessTTL, refreshTTL)
	if err != nil {
		oauthError(w, 500, "server_error", "could not issue tokens")
		return
	}
	writeJSON(w, 200, map[string]any{
		"access_token": access, "token_type": "Bearer", "expires_in": int(accessTTL.Seconds()),
		"refresh_token": refresh, "scope": scope,
	})
}

func (o *oauthServer) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, 405, "invalid_request", "POST only")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	_ = r.ParseForm()
	client, err := o.clientAuth(r)
	if err != nil {
		oauthError(w, 401, "invalid_client", err.Error())
		return
	}
	// RFC 7009: a client may only revoke its own tokens. Revoking succeeds
	// silently (200) either way, but a token belonging to another client is
	// left alone (Astra finding 7).
	if err := o.s.store.RevokeTokenForClient(r.PostForm.Get("token"), client.ID); err != nil {
		oauthError(w, 500, "server_error", "could not complete revocation")
		return
	}
	w.WriteHeader(200)
}

// readOnlyActions lists actions an agent granted "read only" may use.
func (s *Server) readOnlyActions() []string {
	var out []string
	for _, a := range s.reg.List() {
		if a.Risk == "read" {
			out = append(out, a.Name)
		}
	}
	return out
}

// isReadOnlyAgent reports whether an agent's policy only permits read actions
// (every allowed action exists and is read-risk, and nothing non-read slips
// through an empty allow list).
func (s *Server) isReadOnlyAgent(a *store.Agent) bool {
	if len(a.Policy.Allow) == 0 {
		return false // empty allow = everything
	}
	for _, g := range a.Policy.Allow {
		for _, act := range s.reg.List() {
			if act.Risk != "read" && actions.Allowed(act.Name, []string{g}, a.Policy.Deny) {
				return false
			}
		}
	}
	return true
}

var errorPage = template.Must(template.New("e").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RalX</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;background:#0D1321;color:#F6F3ED}div{max-width:420px;padding:24px;text-align:center}h1{font-size:22px;margin:0 0 8px}p{opacity:.75;margin:0}</style>
</head><body><div><h1>{{.Title}}</h1><p>{{.Msg}}</p></div></body></html>`))
