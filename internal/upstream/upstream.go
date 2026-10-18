// Package upstream aggregates other MCP servers (Notion's hosted MCP,
// Composio, ...) behind the hub. RalX is the MCP client: it holds their
// credentials in the vault, attaches them on the way out, and re-exposes
// their tools as RalX actions with the usual approval gate.
package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/redact"
	"github.com/Harsette/ralx/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const credPrefix = "mcp:"

// Manager keeps one live client session per upstream server.
type Manager struct {
	Store    *store.Store
	Red      *redact.Redactor
	Reg      *actions.Registry
	Callback string // OAuth redirect for upstream sign-in, e.g. http://127.0.0.1:7317/oauth/mcp/callback
	Logf     func(string, ...any)
	// Transport and AllowHTTP exist for tests (an in-process upstream).
	Transport http.RoundTripper
	AllowHTTP bool

	mu       sync.Mutex
	sessions map[string]*upSession
	flows    map[string]*flow // state -> pending OAuth sign-in
	tokMu    sync.Mutex
}

// upSession is one live upstream session plus an immutable snapshot of the
// connection-generation FINGERPRINT it was established under (see connGen). Every
// dispatch recomputes the fingerprint from the currently-persisted credential and
// refuses if it differs, so a credential/endpoint/key replacement , even one whose
// reconnect failed and left the old session live, and even one made through a
// generic write path that didn't bump a stored token , can't dispatch an approved
// call under the new identity or to the old host with the new key (Daru6 run6 F5 /
// Astra7 F4/F5).
type upSession struct {
	sess  *mcp.ClientSession
	genfp string
}

// connGen derives an upstream connection's generation from its security-relevant
// identity: endpoint, auth mode, header name, and the LONG-LIVED secret , the
// static header value, or the OAuth client identity (client_id / token_endpoint /
// resource), never the rotating access/refresh tokens that change on a legitimate
// refresh. Any owner change to the endpoint, header, auth mode or key changes the
// fingerprint, so a pending approval pinned to the old generation is refused at
// dispatch; no write path has to remember to bump a stored token (the generic admin
// credential replacement did not , Astra7 F4). Binding host+header+key into one
// generation, recomputed at use, is the atomic binding Daru asked for.
func connGen(c *store.Credential, fields map[string]string) string {
	auth, _ := c.Meta["auth"].(string)
	u, _ := c.Meta["url"].(string)
	header, _ := c.Meta["header"].(string)
	// meta.gen is a per-reconnect random token (set fresh by every connect path and by
	// the admin credential write for an mcp_server), so including it means an OAuth
	// ACCOUNT replacement that keeps the same public client_id/endpoint/resource , which
	// the content fields alone can't distinguish , still changes the generation and
	// invalidates the old approval (Astra7 self-review OAuth account replacement). A
	// legitimate token REFRESH updates only the secret fields (CASFields), never meta, so
	// it leaves the generation stable and the live session valid.
	gen, _ := c.Meta["gen"].(string)
	var ident string
	switch auth {
	case "header":
		ident = fields["value"]
	case "oauth":
		cid, _ := c.Meta["client_id"].(string)
		te, _ := c.Meta["token_endpoint"].(string)
		res, _ := c.Meta["resource"].(string)
		ident = cid + "\x00" + te + "\x00" + res
	}
	return b64sha(u + "\x00" + auth + "\x00" + header + "\x00" + gen + "\x00" + ident)
}

// genFP reads the credential + secret and returns its connection-generation
// fingerprint, or "" if it can't be read.
func (m *Manager) genFP(name string) string {
	c, err := m.Store.GetCredential(credPrefix + name)
	if err != nil {
		return ""
	}
	f, err := m.Store.Secret(credPrefix + name)
	if err != nil {
		return ""
	}
	return connGen(c, f)
}

type flow struct {
	Name, URL, Prefix         string
	ClientID, TokenEndpoint   string
	Verifier, Resource, Scope string
	Created                   time.Time
	Status, Error             string
}

func NewManager(s *store.Store, r *redact.Redactor, reg *actions.Registry, callback string) *Manager {
	return &Manager{Store: s, Red: r, Reg: reg, Callback: callback, sessions: map[string]*upSession{}, flows: map[string]*flow{},
		Logf: func(string, ...any) {}}
}

// ---------- configuration ----------

type serverConf struct {
	Name, URL, Prefix, Auth string // auth: oauth | header | none
	Header                  string // header name for Auth=header
	Gen                     string // connection/account generation (bumped on owner reconnect)
	Overrides               map[string]string
}

func confOf(c *store.Credential) serverConf {
	sc := serverConf{Name: strings.TrimPrefix(c.Name, credPrefix)}
	sc.URL, _ = c.Meta["url"].(string)
	sc.Prefix, _ = c.Meta["prefix"].(string)
	sc.Auth, _ = c.Meta["auth"].(string)
	sc.Header, _ = c.Meta["header"].(string)
	sc.Gen, _ = c.Meta["gen"].(string)
	if sc.Prefix == "" {
		sc.Prefix = sc.Name
	}
	if ov, ok := c.Meta["risk_overrides"].(map[string]any); ok {
		sc.Overrides = map[string]string{}
		for k, v := range ov {
			sc.Overrides[k], _ = v.(string)
		}
	}
	return sc
}

// AddHeaderServer registers an upstream that authenticates with a static
// header (e.g. Composio's x-api-key). The value goes straight to the vault.
// AddHeaderServerExclusive is AddHeaderServer but create-only: it fails if a
// server with that name already exists, so a paste link can't silently overwrite
// one (Astra R13). The insert is atomic, so two concurrent new pastes can't both
// win.
func (m *Manager) AddHeaderServerExclusive(name, rawURL, header, value string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := m.checkURL(rawURL); err != nil {
		return err
	}
	meta := map[string]any{"url": rawURL, "prefix": name, "auth": "header", "header": header, "gen": randToken(12)}
	if _, err := m.Store.CreateCredential(credPrefix+name, "mcp_server", "mcp", name+" (MCP)", meta, map[string]string{"value": value}); err != nil {
		return err
	}
	m.Red.Add(credPrefix+name+":value", value)
	return m.Load(context.Background(), name)
}

func (m *Manager) AddHeaderServer(name, rawURL, header, value string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := m.checkURL(rawURL); err != nil {
		return err
	}
	meta := map[string]any{"url": rawURL, "prefix": name, "auth": "header", "header": header, "gen": randToken(12)}
	_, err := m.Store.PutCredential(credPrefix+name, "mcp_server", "mcp", name+" (MCP)", meta, map[string]string{"value": value})
	if err != nil {
		return err
	}
	m.Store.Audit("owner", "credential.put", "ok", 0, credPrefix+name+" via mcp add")
	m.Red.Add(credPrefix+name+":value", value)
	return m.Load(context.Background(), name)
}

// CheckURL reports whether u is an acceptable upstream MCP endpoint (https,
// or http only when AllowHTTP is set for tests). Callers validating a URL
// before it reaches the Manager (e.g. a paste link) use this so there is one
// rule.
func (m *Manager) CheckURL(u string) error { return m.checkURL(u) }

func (m *Manager) checkURL(u string) error {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" || (p.Scheme != "https" && !(m.AllowHTTP && p.Scheme == "http")) {
		return errors.New("upstream MCP URL must be https")
	}
	// Reject a URL that points at a private/loopback/link-local address or a
	// local hostname, so a discovery or token endpoint can't be aimed at an
	// internal service (Astra N5/R12). Tests connect to loopback and set
	// AllowHTTP, so skip it there.
	host := strings.ToLower(p.Hostname())
	// A zone id (e.g. [::1%eth0]) is never valid in a public URL and slips
	// net.ParseIP, which would skip the private-address check (Astra A11).
	if strings.ContainsRune(host, '%') {
		return fmt.Errorf("%s is not a valid host", host)
	}
	// A trailing dot ("localhost.") is the rooted form of the same name and
	// resolves identically, but would slip a plain string compare (Astra5 A11).
	host = strings.TrimSuffix(host, ".")
	if !m.AllowHTTP {
		if host == "localhost" || host == "localhost.localdomain" || strings.HasSuffix(host, ".localhost") {
			return fmt.Errorf("%s is not a public address", host)
		}
		if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip) {
			return fmt.Errorf("%s is not a public address", host)
		}
	}
	return nil
}

// noProxyTransport is the default outbound transport when no test transport is
// installed: a clone of the standard transport with environment proxies off, so
// upstream discovery/token calls can't be routed through a proxy (Astra R12).
func noProxyTransport() http.RoundTripper {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		c := t.Clone()
		c.Proxy = nil
		return c
	}
	return http.DefaultTransport
}

// isPublicIP reports whether ip is a routable public address.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	// 100.64.0.0/10 (CGNAT) is not public either.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return false
	}
	return true
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9]{1,30}$`)

// reservedPrefixes are the built-in action namespaces. An upstream may not take
// one of them, or its tools would replace RalX's own actions and their gates
// (Astra N7). Keep in sync with the catalogs and native actions, and with the
// audit events RalX writes itself (upstream.connect, credential.put), which the
// home screen reads as logins rather than calls.
var reservedPrefixes = map[string]bool{
	"http": true, "gh": true, "drive": true, "gmail": true, "youtube": true,
	"google": true, "social": true, "vercel": true, "cloudflare": true,
	"supabase": true, "mcp": true, "test": true, "stage": true,
	"upstream": true, "credential": true,
}

// ReservedName reports whether name collides with a built-in action namespace.
func ReservedName(name string) bool { return reservedPrefixes[strings.ToLower(name)] }

// validateName checks an upstream name: well-formed and not a reserved built-in.
func validateName(name string) error {
	if !nameRe.MatchString(name) {
		return errors.New("name: lowercase letters/digits, 2-31 chars")
	}
	if ReservedName(name) {
		return fmt.Errorf("%q is a built-in RalX namespace and can't be used for an upstream", name)
	}
	return nil
}

// ---------- loading ----------

// LoadAll connects every configured upstream and registers its tools.
// It returns the upstreams worth retrying: those that failed for a reason other
// than a refused sign-in (which only the owner's reconnect can fix).
func (m *Manager) LoadAll(ctx context.Context) (retry []string) {
	creds, _ := m.Store.ListCredentials()
	for _, c := range creds {
		if c.Kind == "mcp_server" {
			name := strings.TrimPrefix(c.Name, credPrefix)
			if err := m.Load(ctx, name); err != nil {
				m.Logf("upstream %s: %v", c.Name, err)
				if retryable(err) {
					retry = append(retry, name)
				}
			}
		}
	}
	return retry
}

// configError is a load failure a retry can't fix: a removed record, a bad URL
// or prefix, or a catalog RalX refuses.
type configError struct{ error }

func (e configError) Unwrap() error { return e.error }

// retryable reports whether a failed load may succeed later by itself. A
// refused sign-in (only the owner's reconnect fixes it) arrives through the MCP
// client as text, so it is matched by its wording.
func retryable(err error) bool {
	var ce configError
	return !errors.As(err, &ce) && !strings.Contains(err.Error(), signInRefused)
}

// RetryFailed reloads upstreams that failed to load, e.g. because the network
// wasn't up yet when the service started at boot. It waits delays[i] before
// attempt i (repeating the last delay) until each loads, fails in a way a retry
// can't fix, is removed or loaded elsewhere, or ctx ends.
func (m *Manager) RetryFailed(ctx context.Context, names []string, delays []time.Duration) {
	for i := 0; len(names) > 0 && len(delays) > 0; i++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delays[min(i, len(delays)-1)]):
		}
		var still []string
		for _, n := range names {
			m.mu.Lock()
			live := m.sessions[n] != nil
			m.mu.Unlock()
			if live {
				continue // loaded elsewhere, e.g. the owner reconnected it
			}
			if err := m.Load(ctx, n); err != nil {
				m.Logf("upstream %s%s: retry: %v", credPrefix, n, err)
				if retryable(err) {
					still = append(still, n)
				}
				continue
			}
			m.Logf("upstream %s%s: loaded on retry", credPrefix, n)
		}
		names = still
	}
}

// Load (re)connects one upstream and refreshes its tools in the registry.
func (m *Manager) Load(ctx context.Context, name string) error {
	c, err := m.Store.GetCredential(credPrefix + name)
	if err != nil {
		return configError{err}
	}
	sc := confOf(c)
	// Every status write is for the login this load read. If the owner reconnects
	// while it runs, the newer load reports its own status (Sol F-a).
	identity := loadIdentity(c)
	setStatus := func(patch map[string]any) {
		_, _ = m.Store.UpdateMetaIf(c.Name, func(cur *store.Credential) bool { return loadIdentity(cur) == identity }, patch)
	}
	// A persisted record must pass the same checks as a new one. The prefix must
	// be a single, non-reserved segment: a reserved name (R8) or a dotted prefix
	// like "gh.issue" would shadow a built-in gated action (Astra A7).
	if ReservedName(name) || ReservedName(sc.Prefix) || !nameRe.MatchString(sc.Prefix) {
		setStatus(map[string]any{"status": "error", "error": "invalid or reserved RalX namespace"})
		return configError{fmt.Errorf("upstream %q has an invalid or reserved prefix %q", name, sc.Prefix)}
	}
	// Re-validate the persisted URL on load, so an old/hand-written record can't
	// point the hub at a private or local address (Astra A11).
	if err := m.checkURL(sc.URL); err != nil {
		setStatus(map[string]any{"status": "error", "error": m.Red.String(err.Error())})
		return configError{fmt.Errorf("upstream %q: %w", name, err)}
	}
	// An OAuth upstream refreshes through its stored token endpoint; one that can never
	// pass postToken's check is a config problem, so boot must not retry it (R2-2).
	if sc.Auth == "oauth" {
		te, _ := c.Meta["token_endpoint"].(string)
		if err := m.checkURL(te); err != nil {
			err = fmt.Errorf("upstream %q token endpoint: %w; reconnect it in RalX", name, err)
			setStatus(map[string]any{"status": "error", "error": m.Red.String(err.Error())})
			return configError{err}
		}
	}
	// Snapshot the connection-generation fingerprint this session is established
	// under (endpoint+auth+header+long-lived key). Every later dispatch recomputes it
	// and refuses on a mismatch, so an owner credential/endpoint/key replacement can't
	// run an approval pinned to this connection (Astra7 F4/F5).
	fields, err := m.Store.Secret(credPrefix + name)
	if err != nil {
		setStatus(map[string]any{"status": "error", "error": m.Red.String(err.Error())})
		return configError{fmt.Errorf("upstream %q: %w", name, err)}
	}
	genfp := connGen(c, fields)
	client := mcp.NewClient(&mcp.Implementation{Name: "ralx", Version: "1"}, nil)
	// Never follow redirects on an authenticated upstream request: a 3xx to
	// another host would otherwise carry the stored credential away (Astra N5).
	hc := &http.Client{Timeout: 0, Transport: &authRT{m: m, name: name, conf: sc, genfp: genfp}, CheckRedirect: noRedirect}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	sess, err := client.Connect(cctx, &mcp.StreamableClientTransport{Endpoint: sc.URL, HTTPClient: hc}, nil)
	if err != nil {
		setStatus(map[string]any{"status": "error", "error": m.Red.String(err.Error())})
		return fmt.Errorf("connect %s: %w", name, err)
	}
	var tools []*mcp.Tool
	var cursor string
	for i := 0; i < 20; i++ {
		res, err := sess.ListTools(cctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			sess.Close()
			err = fmt.Errorf("list tools of %s: %w", name, err)
			setStatus(map[string]any{"status": "error", "error": m.Red.String(err.Error())})
			return err
		}
		tools = append(tools, res.Tools...)
		if res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
	}
	acts := make([]*actions.Action, 0, len(tools))
	seen := map[string]bool{}
	var catalogParts []string // every ADVERTISED tool's strings, scanned as one document
	for _, t := range tools {
		a := m.toAction(name, sc, genfp, t)
		// A hostile upstream can return its own stored key as a tool name (names
		// aren't redacted into the catalog the way descriptions are); refuse any
		// tool whose raw or normalized name contains a known secret, including a
		// case- or dash-folded form that normalization would otherwise hide
		// (Astra R2 / Daru4).
		if m.Red.String(a.Name) != a.Name || m.Red.String(t.Name) != t.Name ||
			m.Red.SecretInNormalized(a.Name) || m.Red.SecretInNormalized(t.Name) ||
			looksLikeEncodedBlob(t.Name) {
			m.Logf("upstream %s: a tool name looks like a secret or encoded blob; skipping it", name)
			continue
		}
		// Backstop: never advertise a tool whose advertised entry reconstructs a
		// stored secret , across its name, description, and every schema KEY (property
		// / $defs name) and value, in either join order. The JSON value scan skips
		// object keys, so a secret split across property NAMES would otherwise reach
		// the agent-facing catalog (and /mcp) with no approval (Astra A2/A5, Daru6 F2).
		entryStrings := append([]string{a.Name, t.Name, a.Description}, schemaStrings(a.RawSchema)...)
		sj, _ := json.Marshal(a.RawSchema)
		if catalogContainsSecret(m.Red, entryStrings) || m.Red.DeepContainsCatalogSecret(string(sj)) {
			// AnyOrderingContainsSecret catches a secret split across names/keys/values;
			// the serialized-schema deep check also catches NUMERIC encodings (a decimal
			// byte-value array a hostile schema can smuggle, which schemaStrings skips ,
			// Daru6 run6 self-review).
			raw, distinct, size := catalogSizes(entryStrings)
			m.Logf("upstream %s: a tool catalog entry hits a credential or scan limit; skipping it (raw=%d distinct_seen=%d bytes_seen=%d)", name, raw, distinct, size)
			continue
		}
		// Two distinct tool names can normalise to the same action name (e.g.
		// "a-b" and "a_b"); refuse rather than silently overwrite one with the
		// other and change what a policy or approval refers to (Astra N7).
		if seen[a.Name] {
			sess.Close()
			err := fmt.Errorf("%s exposes two tools that collide as %q; refusing to load it", name, a.Name)
			setStatus(map[string]any{"status": "error", "error": m.Red.String(err.Error())})
			return configError{err}
		}
		seen[a.Name] = true
		acts = append(acts, a)
		catalogParts = append(catalogParts, entryStrings...)
		// Also feed any decimal-byte NUMBER array (decoded to its bytes) into the
		// whole-catalog cross-check, so a numeric secret split across two tools is caught
		// (schemaStrings omits numbers , Astra7 self-review numeric cross-tool).
		catalogParts = append(catalogParts, schemaNumericBytes(a.RawSchema)...)
	}
	// Whole-catalog cross-check: a secret can be split across TWO DIFFERENT tools (a
	// half in each tool's name or a schema property name), which the per-tool scan
	// can't see. Scan every advertised tool's strings as one document; if they
	// reconstruct a secret in any pairwise order, or the bounded raw/distinct
	// catalog scan cannot finish, withhold ALL of
	// this upstream's tools rather than advertise a recoverable cross-tool split
	// (Astra7 catalog cross-tool / 256-part cap). core/decisions.md records the
	// fail-closed trade-off for very large catalogs.
	if catalogContainsSecret(m.Red, catalogParts) {
		raw, distinct, size := catalogSizes(catalogParts)
		m.Logf("upstream %s: its catalog hits a credential or scan limit; withholding all its tools (raw=%d distinct_seen=%d bytes_seen=%d)", name, raw, distinct, size)
		acts = acts[:0]
	}
	// Publish the new catalog BEFORE the new session. Otherwise there is a window where
	// a dispatch finds the OLD action (old digest, matching a stale approval) but is sent
	// on the NEW session/account. With this order a dispatch in the gap finds the NEW
	// action (new digest) and no session yet, takes the Load-missing path, and re-verifies
	// the approved digest there , so a stale approval can't ride a reconnect to a new
	// account (Astra7 self-review reconnect window).
	// Both happen under m.mu, and only if the login is still the one this load read:
	// a reconnect that finished while this load waited keeps its catalog and session.
	m.mu.Lock()
	if cur, err := m.Store.GetCredential(c.Name); err != nil {
		m.mu.Unlock()
		sess.Close()
		return configError{err}
	} else if loadIdentity(cur) != identity {
		m.mu.Unlock()
		sess.Close()
		m.Logf("upstream %s: reconnected while loading; keeping the newer connection", name)
		return nil
	}
	if err := m.Reg.ReplacePrefix(sc.Prefix+".", acts); err != nil {
		m.mu.Unlock()
		sess.Close()
		setStatus(map[string]any{"status": "error", "error": m.Red.String(err.Error())})
		return configError{err}
	}
	if old := m.sessions[name]; old != nil {
		old.sess.Close()
	}
	m.sessions[name] = &upSession{sess: sess, genfp: genfp}
	m.mu.Unlock()
	setStatus(map[string]any{"status": "ok", "tools": len(acts), "loaded_at": time.Now().Unix(), "error": nil})
	return nil
}

// loadIdentity is the credential identity without the keys Load itself writes, so
// two loads of the same login don't mistake each other's status for a reconnect.
func loadIdentity(c *store.Credential) string {
	cp := *c
	cp.Meta = map[string]any{}
	for k, v := range c.Meta {
		switch k {
		case "error", "tools", "loaded_at":
			continue
		}
		cp.Meta[k] = v
	}
	return store.CredentialIdentity(&cp)
}

var toolNameRe = regexp.MustCompile(`[^a-z0-9_]+`)

func actionName(prefix, tool string) string {
	n := strings.Trim(toolNameRe.ReplaceAllString(strings.ToLower(tool), "_"), "_")
	if n == "" {
		n = "tool"
	}
	return prefix + "." + n
}

var (
	reDelete  = regexp.MustCompile(`(?i)(^|[_\-. ])(delete|remove|trash|destroy|drop|archive|purge|revoke|unpublish)`)
	rePost    = regexp.MustCompile(`(?i)(^|[_\-. ])(post|publish|tweet|reply|comment|share|invite|broadcast)`)
	reEmail   = regexp.MustCompile(`(?i)(^|[_\-. ])(send|email|mail|message|sms|notify)`)
	reDeploy  = regexp.MustCompile(`(?i)(^|[_\-. ])(deploy|merge|release|promote|rollback)`)
	rePay     = regexp.MustCompile(`(?i)(^|[_\-. ])(pay|charge|refund|transfer|purchase|checkout|invoice|subscribe)`)
	reExecute = regexp.MustCompile(`(?i)(^|[_\-. ])(execute|run_command|shell|bash|eval)`)
	// reNeverLower matches meta-tools that run arbitrary actions and must stay
	// gated no matter what override an owner sets.
	reNeverLower = regexp.MustCompile(`(?i)(multi.?execute|remote.?bash|remote.?workbench|workbench|(^|[_\-. ])(bash|shell|eval|exec|run_command))`)
)

// classify decides the risk of an upstream tool. A downstream server (Composio,
// Notion, anything an owner plugs in) is treated as hostile: its tool names and
// annotations are documentation, never authorization (Astra N3). The only thing
// that can make a tool run without approval is an owner-maintained override for
// that exact tool. Everything else is gated; the verbs in the name just pick a
// clearer reason for the approval card.
func classify(t *mcp.Tool, override string) (actions.Risk, string) {
	// Some upstream meta-tools run arbitrary actions across every connected app
	// (Composio's MULTI_EXECUTE / REMOTE_BASH / REMOTE_WORKBENCH, or any
	// shell/eval tool). They can never be lowered by an owner override: one
	// approval would otherwise authorise anything (Daru review).
	if reNeverLower.MatchString(t.Name) {
		return actions.Gated, "runs arbitrary actions"
	}
	switch override {
	case "read":
		return actions.Read, ""
	case "write":
		return actions.Write, ""
	case "deletes", "posts", "emails", "deploys", "pays", "publishes":
		return actions.Gated, override
	}
	name := t.Name
	switch {
	case rePay.MatchString(name):
		return actions.Gated, "pays"
	case reDeploy.MatchString(name):
		return actions.Gated, "deploys"
	case reEmail.MatchString(name):
		return actions.Gated, "emails"
	case rePost.MatchString(name):
		return actions.Gated, "posts"
	case reDelete.MatchString(name):
		return actions.Gated, "deletes"
	case reExecute.MatchString(name):
		return actions.Gated, "deploys"
	}
	// No owner rule and no recognised outward verb: still gated, because a
	// hostile upstream controls both the name and any read-only hint.
	return actions.Gated, "sensitive"
}

func (m *Manager) toAction(name string, sc serverConf, genfp string, t *mcp.Tool) *actions.Action {
	risk, reason := classify(t, sc.Overrides[t.Name])
	var pageEditGate func(map[string]any) bool
	if sc.Overrides[t.Name] == "notion-page-edits" && notionPageTool(sc, t.Name) {
		risk, reason = actions.Write, "changes or deletes page content"
		pageEditGate = notionPageEditGated
	}
	// A hostile upstream controls its schema, so sanitize it before it is ever
	// advertised: drop the value-bearing keys (default/enum/examples/const) and
	// redact every remaining string, so no recoverable credential bytes reach the
	// catalog (Astra A2/N6). The upstream's description, annotations and output
	// schema are not advertised at all , the catalog metadata is static.
	schema := map[string]any{"type": "object"}
	rawSchemaJSON := ""
	if t.InputSchema != nil {
		b, _ := json.Marshal(t.InputSchema)
		rawSchemaJSON = string(b) // the FULL raw definition, for the private digest
		var raw any
		if json.Unmarshal(b, &raw) == nil {
			if san, ok := sanitizeSchema(raw, m.Red).(map[string]any); ok {
				schema = san
			}
		}
		if schema["type"] != "object" {
			schema["type"] = "object"
		}
	}
	desc := "[" + name + "] upstream MCP tool; held for the owner's approval unless an owner has reviewed and lowered it"
	if pageEditGate != nil {
		desc = "[" + name + "] reviewed Notion property update or content insertion; replacements, deletion flags and unknown arguments remain held"
	}
	toolName := t.Name
	actName := actionName(sc.Prefix, t.Name)
	// Digest the provider, its endpoint origin, the auth mode + header, the
	// connection/account generation AND the content-derived generation fingerprint
	// (connGen: endpoint+header+long-lived key), the exact raw tool name and the FULL
	// RAW tool schema (not the sanitized/advertised one), so an approval is pinned to
	// this exact definition AND this exact account AND this exact key/endpoint. Using
	// the raw schema means a change to an effect-relevant default/enum the sanitizer
	// drops (e.g. a recipient default Alice→Bob) still changes the digest and
	// invalidates the old approval (Astra R7/A5, Daru6 run6 F6); including genfp means a
	// key/endpoint replacement does too, even through a generic write path (Astra7 F4).
	// The raw schema and genfp are only hashed, never advertised.
	digest := b64sha(name + "\x00" + sc.URL + "\x00" + sc.Auth + "\x00" + sc.Header + "\x00" + sc.Gen + "\x00" + genfp + "\x00" + t.Name + "\x00" + rawSchemaJSON + "\x00policy-v1:" + sc.Overrides[t.Name])
	return &actions.Action{
		Name: actName, Description: desc, Risk: risk, GateReason: reason,
		GateFunc: pageEditGate,
		Requires: []string{credPrefix + name}, Passthrough: true, RawSchema: schema, DefDigest: digest,
		SummaryTemplate: name + ": " + t.Name,
		Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
			return m.Call(ctx, name, toolName, actName, digest, args)
		},
	}
}

// sanitizeSchema makes an upstream JSON schema safe to advertise: it drops the
// value-bearing keys a hostile upstream could split a secret across (default,
// enum, examples, const) and the free-text keys it could hide one in (title,
// description, $comment), redacts every remaining string VALUE, and drops any
// map KEY (e.g. a property or $defs name) that is itself a secret, so the
// catalog never carries recoverable credential bytes in a value OR a key (Astra
// A2/A5). A backstop deep-scan of the whole sanitized schema is applied by the
// caller.
func sanitizeSchema(v any, red *redact.Redactor) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			switch strings.ToLower(k) {
			case "default", "enum", "examples", "const", "title", "description", "$comment":
				continue
			}
			// A property/$defs key is attacker-controlled text; drop it if it is (or
			// normalizes to, or is an encoded blob of) a stored secret.
			if red.String(k) != k || red.SecretInNormalized(k) || looksLikeEncodedBlob(k) {
				continue
			}
			out[k] = sanitizeSchema(val, red)
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			out = append(out, sanitizeSchema(e, red))
		}
		return out
	case string:
		return red.String(x)
	default:
		return v
	}
}

var hexRunRe = regexp.MustCompile(`[0-9a-fA-F]{24,}`)

// schemaStrings collects every object KEY and string VALUE in a (sanitized) schema,
// recursively, so the catalog backstop can scan across property names as well as
// values (Daru6 run6 F2 , a secret split across two property names).
func schemaStrings(v any) []string {
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				out = append(out, k)
				walk(val)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case string:
			out = append(out, t)
		}
	}
	walk(v)
	return out
}

// schemaNumericBytes decodes any decimal-byte NUMBER array in a schema (e.g.
// "x-data":[65,66,67,…]) to its byte string, recursively. schemaStrings omits
// numbers, so without this a secret smuggled as a numeric array and SPLIT across two
// tools would slip the whole-catalog cross-check even though each array is advertised
// verbatim to the agent (Astra7 self-review numeric cross-tool).
func schemaNumericBytes(v any) []string {
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for _, val := range t {
				walk(val)
			}
		case []any:
			var b []byte
			allByte := len(t) > 0
			for _, e := range t {
				f, ok := e.(float64)
				if !ok || f < 0 || f > 255 || f != float64(int(f)) {
					allByte = false
					break
				}
				b = append(b, byte(int(f)))
			}
			if allByte && len(b) >= 8 {
				out = append(out, string(b))
			}
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// looksLikeEncodedBlob reports whether s contains a long run of hex , a tool or
// schema name that is really a chunk of an encoded credential, not a real tool.
// The run is matched anywhere in the name, so a benign-looking prefix
// ("part_<hex>") can't hide it (Astra A2/A5 split names).
func looksLikeEncodedBlob(s string) bool {
	return hexRunRe.MatchString(s)
}

// Call forwards one tool call to the upstream session, reconnecting once. If it
// has to (re)connect, it re-verifies the just-loaded definition against the
// digest the approval was pinned to (approvedDigest) before dispatching: a lazy
// reconnect must never silently send an approved call to a changed origin,
// account or tool definition (Astra A5). approvedDigest is empty for an
// un-pinned internal call.
func (m *Manager) Call(ctx context.Context, name, tool, actionName, approvedDigest string, args map[string]any) (any, error) {
	for attempt := 0; attempt < 2; attempt++ {
		m.mu.Lock()
		entry := m.sessions[name]
		m.mu.Unlock()
		if entry == nil {
			if err := m.Load(ctx, name); err != nil {
				return nil, err
			}
			// The reload may have replaced the definition (new origin/account/tool).
			// An approval authorized one specific definition; if the freshly loaded
			// one differs, return to authorization instead of dispatching (Astra A5).
			if approvedDigest != "" {
				a, ok := m.Reg.Get(actionName)
				if !ok || a.DefDigest != approvedDigest {
					return nil, errors.New("the upstream reconnected with a changed definition or account; this approval is no longer valid , request it again")
				}
			}
			continue
		}
		// Re-verify the approved DEFINITION on EVERY dispatch, not only after a lazy
		// reconnect: an owner reconnect can publish a new session (new account/definition)
		// under the same name while this approval waits, and the generation check below only
		// compares the live session to the CURRENT credential, not to what was approved. If
		// the live definition differs from the one the approval was pinned to, return to
		// authorization (Astra7 self-review reconnect-to-new-account).
		if approvedDigest != "" {
			if a, ok := m.Reg.Get(actionName); !ok || a.DefDigest != approvedDigest {
				return nil, errors.New("the upstream reconnected with a changed definition or account; this approval is no longer valid , request it again")
			}
		}
		// On EVERY dispatch (not only after a reconnect), recompute the current
		// credential's connection-generation fingerprint and compare it to the live
		// session's. If the owner replaced the credential/endpoint/key , even if that
		// reconnect FAILED and left this old session live, and even through a generic
		// write path that preserved the stored gen token , the fingerprints differ and
		// we refuse, so the call is never sent to the old host with the new key nor
		// under a swapped identity (Daru6 run6 F5 / Astra7 F4).
		if fp := m.genFP(name); fp != entry.genfp {
			return nil, errors.New("this upstream connection changed since the action was approved; request it again")
		}
		res, err := entry.sess.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil {
			if attempt == 0 {
				m.mu.Lock()
				delete(m.sessions, name)
				m.mu.Unlock()
				continue
			}
			return nil, err
		}
		var texts []string
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				texts = append(texts, tc.Text)
			}
		}
		joined := strings.Join(texts, "\n")
		if res.IsError {
			// An error result is still attacker-controlled output; if it reconstructs
			// a credential under any recognised transform, withhold it whole rather
			// than return a recoverable copy in the error text (Astra A5).
			if m.Red.DeepContainsSecret(joined) {
				return nil, errors.New("upstream error withheld , it reconstructs a credential")
			}
			return nil, errors.New(m.Red.String(joined))
		}
		// A hostile upstream holds its own key and controls its output bytes; if
		// the result reconstructs a credential under any recognised transform,
		// withhold it whole rather than hand the agent a recoverable copy (A2).
		structured := res.StructuredContent
		if m.Red.DeepContainsSecret(joined) || (structured != nil && m.deepContainsStructured(structured)) {
			return map[string]any{"content": "[REDACTED: upstream result withheld , it reconstructs a credential]"}, nil
		}
		out := map[string]any{"content": joined}
		if structured != nil {
			out["structured"] = structured
		}
		return out, nil
	}
	return nil, errors.New("upstream unavailable")
}

// deepContainsStructured reports whether an upstream tool's structured result
// reconstructs a credential (it is JSON-marshaled and deep-scanned).
func (m *Manager) deepContainsStructured(v any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return true // can't inspect it: withhold
	}
	return m.Red.DeepContainsSecret(string(b))
}

// Close ends every upstream session.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, e := range m.sessions {
		_ = e.sess.Close()
		delete(m.sessions, name)
	}
}

// Names lists configured upstreams (for UI/status).
func (m *Manager) Names() []string {
	creds, _ := m.Store.ListCredentials()
	var out []string
	for _, c := range creds {
		if c.Kind == "mcp_server" {
			out = append(out, strings.TrimPrefix(c.Name, credPrefix))
		}
	}
	sort.Strings(out)
	return out
}

// ---------- auth on outgoing requests ----------

type authRT struct {
	m     *Manager
	name  string
	conf  serverConf
	genfp string // connection-generation fingerprint captured when the session connected
}

func (a *authRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	// Attach the stored credential only to the exact configured upstream origin.
	// A redirect to another host (or a reconfigured scheme) must never carry it
	// (Astra N5); combined with the no-redirect client, the credential can only
	// reach the server the owner configured.
	cu, err := url.Parse(a.conf.URL)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(r.URL.Scheme, cu.Scheme) || !strings.EqualFold(r.URL.Host, cu.Host) {
		return nil, fmt.Errorf("refusing to send %s's credential to %s", a.name, r.URL.Host)
	}
	// Bind the key to this session's connection-generation fingerprint inside
	// credential attachment: if the owner replaced the endpoint/header/key after the
	// session connected , even in the tiny window between Call's check and here, and
	// even through a generic write path that preserved the stored gen token , the
	// fingerprint differs and we do NOT attach the replacement key to this (old) origin
	// (Daru6 run6 F5 / Astra7 F4). One snapshot read backs the comparison and the
	// attachment, so they can't straddle a replacement.
	c, f, err := a.m.Store.SecretWithMeta(credPrefix + a.name)
	if err != nil {
		return nil, err
	}
	if connGen(c, f) != a.genfp {
		return nil, fmt.Errorf("%s's credential changed since this session connected; refusing to attach the replacement key", a.name)
	}
	switch a.conf.Auth {
	case "header":
		h := a.conf.Header
		if h == "" {
			h = "Authorization"
		}
		r.Header.Set(h, f["value"])
	case "oauth":
		// Pass the generation we verified above: accessToken's fast path returns this
		// snapshot's token (already bound to a.genfp), and its refresh path re-reads under
		// the token lock and refuses if the stored credential no longer matches a.genfp ,
		// so a replacement that lands while we wait on the lock can't have its token
		// attached to this old origin (Astra7 self-review OAuth re-read race).
		tok, err := a.m.accessToken(r.Context(), a.name, f, a.genfp)
		if err != nil {
			return nil, err
		}
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	tr := a.m.Transport
	if tr == nil {
		tr = noProxyTransport()
	}
	resp, err := tr.RoundTrip(r)
	if err == nil && resp.StatusCode == 401 && a.conf.Auth == "oauth" && r.Method != http.MethodPost {
		// let the next call refresh
		_ = a.m.Store.UpdateFields(credPrefix+a.name, map[string]string{"expires_at": "0"})
	}
	return resp, err
}

// ---------- OAuth client for upstream servers ----------

func b64sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// noRedirect stops any client from following 3xx responses, so an authenticated
// or token request can never be replayed to a redirect target (Astra N5).
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// client is the Manager's outbound HTTP client for discovery and token calls.
// It honours the test transport seam, never follows redirects, and (in
// production) carries the SSRF guards the daemon installs via Transport.
func (m *Manager) client() *http.Client {
	tr := m.Transport
	if tr == nil {
		tr = noProxyTransport()
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: noRedirect}
}

// getJSON fetches and decodes a discovery document. The URL is validated first
// (https, and the SSRF/numeric-address checks when a guarded transport is
// installed), and redirects are not followed.
func (m *Manager) getJSON(ctx context.Context, u string, out any) (*http.Response, error) {
	if err := m.checkURL(u); err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return resp, fmt.Errorf("%s returned %d", u, resp.StatusCode)
	}
	return resp, json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

var rmRe = regexp.MustCompile(`resource_metadata="([^"]+)"`)

// StartOAuth discovers the upstream's authorization server, registers RalX
// as a client (dynamic registration) and returns the consent URL.
func (m *Manager) StartOAuth(ctx context.Context, name, mcpURL string) (string, error) {
	if err := validateName(name); err != nil {
		return "", err
	}
	if err := m.checkURL(mcpURL); err != nil {
		return "", err
	}
	// 1. resource metadata (from the 401 challenge, else well-known)
	prmURL := ""
	req, _ := http.NewRequestWithContext(ctx, "POST", mcpURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if resp, err := m.client().Do(req); err == nil {
		if mm := rmRe.FindStringSubmatch(resp.Header.Get("WWW-Authenticate")); mm != nil {
			prmURL = mm[1]
		}
		resp.Body.Close()
	}
	u, _ := url.Parse(mcpURL)
	origin := u.Scheme + "://" + u.Host
	if prmURL == "" {
		prmURL = origin + "/.well-known/oauth-protected-resource" + strings.TrimRight(u.Path, "/")
	}
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		Scopes               []string `json:"scopes_supported"`
	}
	issuer := origin
	if _, err := m.getJSON(ctx, prmURL, &prm); err == nil && len(prm.AuthorizationServers) > 0 {
		issuer = strings.TrimRight(prm.AuthorizationServers[0], "/")
	}
	// 2. authorization server metadata
	var asm struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		RegistrationEndpoint  string `json:"registration_endpoint"`
	}
	iu, _ := url.Parse(issuer)
	candidates := []string{iu.Scheme + "://" + iu.Host + "/.well-known/oauth-authorization-server" + strings.TrimRight(iu.Path, "/"),
		iu.Scheme + "://" + iu.Host + "/.well-known/openid-configuration" + strings.TrimRight(iu.Path, "/")}
	var lastErr error
	for _, c := range candidates {
		if _, lastErr = m.getJSON(ctx, c, &asm); lastErr == nil && asm.AuthorizationEndpoint != "" {
			break
		}
	}
	if asm.AuthorizationEndpoint == "" || asm.TokenEndpoint == "" {
		return "", fmt.Errorf("couldn't discover %s's sign-in server: %v", name, lastErr)
	}
	if asm.RegistrationEndpoint == "" {
		return "", fmt.Errorf("%s doesn't support dynamic client registration", name)
	}
	// Every discovered endpoint must be a valid https (SSRF-checked) URL before
	// we send anything to it (Astra N5).
	for _, ep := range []string{asm.AuthorizationEndpoint, asm.TokenEndpoint, asm.RegistrationEndpoint} {
		if err := m.checkURL(ep); err != nil {
			return "", fmt.Errorf("%s advertised an unusable endpoint %q: %w", name, ep, err)
		}
	}
	// 3. dynamic client registration
	regBody, _ := json.Marshal(map[string]any{"client_name": "RalX", "redirect_uris": []string{m.Callback},
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none"})
	rreq, _ := http.NewRequestWithContext(ctx, "POST", asm.RegistrationEndpoint, strings.NewReader(string(regBody)))
	rreq.Header.Set("Content-Type", "application/json")
	rresp, err := m.client().Do(rreq)
	if err != nil {
		return "", err
	}
	defer rresp.Body.Close()
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(io.LimitReader(rresp.Body, 1<<16)).Decode(&reg); err != nil || reg.ClientID == "" {
		return "", fmt.Errorf("%s client registration failed (%d)", name, rresp.StatusCode)
	}
	// 4. PKCE authorize URL
	f := &flow{Name: name, URL: mcpURL, Prefix: name, ClientID: reg.ClientID, TokenEndpoint: asm.TokenEndpoint,
		Verifier: randToken(48), Resource: prm.Resource, Created: time.Now(), Status: "pending"}
	if f.Resource == "" {
		f.Resource = mcpURL
	}
	f.Scope = strings.Join(prm.Scopes, " ")
	state := randToken(24)
	q := url.Values{"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {m.Callback},
		"code_challenge": {b64sha(f.Verifier)}, "code_challenge_method": {"S256"}, "state": {state}, "resource": {f.Resource}}
	if f.Scope != "" {
		q.Set("scope", f.Scope)
	}
	m.mu.Lock()
	m.flows[state] = f
	m.mu.Unlock()
	sep := "?"
	if strings.Contains(asm.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return asm.AuthorizationEndpoint + sep + q.Encode(), nil
}

// Callback finishes an upstream sign-in: code -> tokens -> vault -> load.
func (m *Manager) HandleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	m.mu.Lock()
	f, ok := m.flows[q.Get("state")]
	delete(m.flows, q.Get("state"))
	m.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := func(title, msg string) {
		// Best-effort backstop on the rendered body: an agent can reach this callback via a
		// valid owner-initiated flow, and a token-endpoint/query error could echo a stored
		// secret. Redact, then withhold the detail if it still reconstructs one (parity with
		// the Google callback , Astra7 self-review).
		msg = m.Red.String(msg)
		if m.Red.DeepContainsSecret(msg) {
			msg = "withheld"
		}
		fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RalX</title><body style="margin:0;min-height:100vh;display:grid;place-items:center;font:16px system-ui;background:#0D1321;color:#F6F3ED"><div style="text-align:center;max-width:420px;padding:24px"><h1 style="font-size:22px">%s</h1><p style="opacity:.75">%s</p></div>`, title, msg)
	}
	if !ok || time.Since(f.Created) > 15*time.Minute {
		page("This link expired", "Start the connection again from RalX.")
		return
	}
	if e := q.Get("error"); e != "" {
		page("Not connected", "The app said: "+htmlEscape(e))
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {m.Callback},
		"client_id": {f.ClientID}, "code_verifier": {f.Verifier}, "resource": {f.Resource}}
	tok, err := m.postToken(r.Context(), f.TokenEndpoint, form)
	if err != nil {
		page("Not connected", htmlEscape(m.Red.String(err.Error())))
		return
	}
	meta := map[string]any{"url": f.URL, "prefix": f.Prefix, "auth": "oauth", "client_id": f.ClientID, "token_endpoint": f.TokenEndpoint, "resource": f.Resource, "gen": randToken(12)}
	fields := map[string]string{"access_token": tok.AccessToken, "refresh_token": tok.RefreshToken, "expires_at": fmt.Sprint(time.Now().Unix() + int64(tok.ExpiresIn))}
	if _, err := m.Store.PutCredential(credPrefix+f.Name, "mcp_server", "mcp", f.Name+" (MCP)", meta, fields); err != nil {
		page("Not connected", "couldn't save to the vault")
		return
	}
	// Marks the replacement so refusals of calls made with the old login stop counting.
	m.Store.Audit("owner", "credential.put", "ok", 0, credPrefix+f.Name+" via mcp oauth")
	m.Red.Add(credPrefix+f.Name+":access_token", tok.AccessToken)
	m.Red.Add(credPrefix+f.Name+":refresh_token", tok.RefreshToken)
	if err := m.Load(context.Background(), f.Name); err != nil {
		page(htmlEscape(f.Name)+" signed in", "RalX saved the sign-in but couldn't load its tools yet: "+htmlEscape(m.Red.String(err.Error())))
		return
	}
	page(htmlEscape(f.Name)+" is connected to RalX", "Its tools are now available to your agents through RalX. You can close this tab.")
}

// tokenRefusedError is a token endpoint that answered and refused the request,
// as opposed to one RalX couldn't reach.
type tokenRefusedError struct{ msg string }

func (e *tokenRefusedError) Error() string { return e.msg }

// signInRefused is the wording of a refused refresh; it also marks errors that
// a retry can't fix.
const signInRefused = "sign-in expired"

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

func (m *Manager) postToken(ctx context.Context, endpoint string, form url.Values) (*tokenResp, error) {
	// The token endpoint must be a valid https URL, and we never follow a
	// redirect from it: a 307 would otherwise replay the refresh-token body to
	// another host, over HTTP (Astra N5).
	if err := m.checkURL(endpoint); err != nil {
		return nil, fmt.Errorf("token endpoint %q: %w", endpoint, err)
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var t tokenResp
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t)
	if resp.StatusCode/100 != 2 || t.AccessToken == "" {
		msg := fmt.Sprintf("token endpoint returned %d %s", resp.StatusCode, t.Error)
		// Only an explicit refusal of the grant or client means the sign-in is dead.
		// A rate limit, an outage or a garbled reply is retried (RFC 6749 5.2).
		if resp.StatusCode == 401 || resp.StatusCode == 403 || (resp.StatusCode == 400 &&
			(t.Error == "invalid_grant" || t.Error == "invalid_client" || t.Error == "unauthorized_client")) {
			return nil, &tokenRefusedError{msg}
		}
		return nil, errors.New(msg)
	}
	if t.ExpiresIn == 0 {
		t.ExpiresIn = 3600
	}
	return &t, nil
}

// accessToken returns a valid upstream access token for the expectedGen connection,
// refreshing it (and storing a rotated refresh token) when it is about to expire. It
// refuses whenever the stored credential no longer matches expectedGen, so neither the
// fast path nor a refresh that completes after an owner replacement can attach the
// replacement's token to the old origin (Astra7 self-review OAuth re-read race). The
// caller passes the generation it already verified against the SAME snapshot `f`, so
// the fast path below returns a token consistent with that verification.
func (m *Manager) accessToken(ctx context.Context, name string, f map[string]string, expectedGen string) (string, error) {
	var exp int64
	fmt.Sscan(f["expires_at"], &exp)
	if exp-time.Now().Unix() > 120 {
		return f["access_token"], nil
	}
	m.tokMu.Lock()
	defer m.tokMu.Unlock()
	// Re-read under the lock as a consistent snapshot and re-verify the generation: a
	// replacement may have landed while we waited for the lock, and its token must not be
	// returned for this (old) session (Astra7 self-review re-read race).
	c, f, err := m.Store.SecretWithMeta(credPrefix + name)
	if err != nil {
		return "", err
	}
	if connGen(c, f) != expectedGen {
		return "", fmt.Errorf("%s changed since this session connected; refusing to use the replacement token", name)
	}
	fmt.Sscan(f["expires_at"], &exp)
	if exp-time.Now().Unix() > 120 {
		return f["access_token"], nil
	}
	clientID, _ := c.Meta["client_id"].(string)
	endpoint, _ := c.Meta["token_endpoint"].(string)
	resource, _ := c.Meta["resource"].(string)
	if f["refresh_token"] == "" {
		return "", fmt.Errorf("%s sign-in expired; reconnect it in RalX", name)
	}
	t, err := m.postToken(ctx, endpoint, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {f["refresh_token"]}, "client_id": {clientID}, "resource": {resource}})
	if err != nil {
		// Only a token endpoint that answered and refused means the sign-in is dead.
		// Keep its reason (status and OAuth error code, never the request body). A
		// network failure (e.g. at boot, before the network is up) is retried.
		var refused *tokenRefusedError
		if errors.As(err, &refused) {
			// Only the sign-in this refresh used; a reconnect in between keeps its status.
			identity := store.CredentialIdentity(c)
			_, _ = m.Store.UpdateMetaIf(c.Name, func(cur *store.Credential) bool { return store.CredentialIdentity(cur) == identity },
				map[string]any{"status": "reconnect_needed"})
			return "", fmt.Errorf("%s %s (%s); reconnect it in RalX", name, signInRefused, m.Red.String(err.Error()))
		}
		return "", fmt.Errorf("couldn't reach %s's sign-in server (%s); RalX retries by itself", name, m.Red.String(err.Error()))
	}
	upd := map[string]string{"access_token": t.AccessToken, "expires_at": fmt.Sprint(time.Now().Unix() + int64(t.ExpiresIn))}
	if t.RefreshToken != "" {
		upd["refresh_token"] = t.RefreshToken
	}
	// Persist atomically, and ONLY if the stored credential is still expectedGen: if the
	// owner reconnected this upstream while our refresh request was in flight, the
	// refreshed token belongs to the OLD identity and must neither overwrite the
	// replacement nor be attached to the new host. On a mismatch we discard the refreshed
	// token and let the caller retry with the replacement (Astra7 refresh race).
	ok, err := m.Store.CASFields(credPrefix+name, func(cur *store.Credential, curFields map[string]string) bool {
		return connGen(cur, curFields) == expectedGen
	}, upd)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%s was reconnected during a token refresh; retry", name)
	}
	if t.RefreshToken != "" {
		m.Red.Add(credPrefix+name+":refresh_token", t.RefreshToken)
	}
	m.Red.Add(credPrefix+name+":access_token", t.AccessToken)
	return t.AccessToken, nil
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
