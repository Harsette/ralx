package daemon

import (
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/Harsette/ralx/internal/social"
	"github.com/Harsette/ralx/internal/store"
)

// The owner home screen lists every service this build can connect, with its
// real status and the connect flow the UI starts. Metadata only: no secret
// value is read or returned here.

type connectorSpec struct {
	ID, Name   string
	Services   []string // what agents get, in plain words
	Connect    string   // google | key | cli | mcp_oauth
	Credential string   // vault credential the actions require
	Field      string   // secret field a pasted key goes into
	Tool       string   // CLI the actions run, "" for native actions
	Prefixes   []string // action-name prefixes, for the last-call check
	URL        string   // upstream MCP server
	Help       string   // where the key comes from
}

var connectorSpecs = []connectorSpec{
	{ID: "google", Name: "Google", Services: []string{"Gmail", "Drive", "YouTube"}, Connect: "google",
		Prefixes: []string{"gmail.", "drive.", "youtube."}},
	{ID: "github", Name: "GitHub", Services: []string{"repos", "issues", "pull requests"}, Connect: "key",
		Credential: "github", Field: "token", Tool: "gh", Prefixes: []string{"gh."},
		Help: "A GitHub personal access token from github.com/settings/tokens."},
	{ID: "vercel", Name: "Vercel", Services: []string{"projects", "deployments", "domains"}, Connect: "cli",
		Credential: "vercel", Tool: "vercel", Prefixes: []string{"vercel."}},
	{ID: "cloudflare", Name: "Cloudflare", Services: []string{"Pages", "KV"}, Connect: "key",
		Credential: "cloudflare", Field: "token", Tool: "wrangler", Prefixes: []string{"cloudflare."},
		Help: "An API token from dash.cloudflare.com/profile/api-tokens."},
	{ID: "uploadpost", Name: "Upload-Post", Services: []string{"posts to every social account"}, Connect: "key",
		Credential: social.Credential, Field: "api_key", Prefixes: []string{"social."},
		Help: "Your Upload-Post API key and the profile to post as."},
	{ID: "notion", Name: "Notion", Services: []string{"pages", "databases", "search"}, Connect: "mcp_oauth",
		Credential: "mcp:notion", URL: "https://mcp.notion.com/mcp", Prefixes: []string{"notion."}},
}

type connectorAccount struct {
	Name     string   `json:"name"`
	Label    string   `json:"label"`
	Status   string   `json:"status"` // ok | error
	Reason   string   `json:"reason,omitempty"`
	Services []string `json:"services,omitempty"`
	Default  []string `json:"default_for,omitempty"`
	Profile  string   `json:"profile,omitempty"`
	LastUsed int64    `json:"last_used_at,omitempty"`
}

type connectorView struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Services   []string           `json:"services"`
	Connect    string             `json:"connect"`
	Credential string             `json:"credential,omitempty"`
	Field      string             `json:"field,omitempty"`
	URL        string             `json:"url,omitempty"`
	Help       string             `json:"help,omitempty"`
	Status     string             `json:"status"` // connected | error | not_connected | setup_needed
	Reason     string             `json:"reason,omitempty"`
	Detail     string             `json:"detail,omitempty"`
	Accounts   []connectorAccount `json:"accounts"`
}

// authFailure matches provider replies that mean the saved login itself was refused.
var authFailure = regexp.MustCompile(`(?i)HTTP 401|Bad credentials|invalid_grant|unauthori[sz]ed|invalid (api )?(key|token)|authentication (error|failed)`)

func (s *Server) handleConnectors(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	creds, _ := s.store.ListCredentials()
	byName := map[string]*store.Credential{}
	for _, c := range creds {
		byName[c.Name] = c
	}
	audit, _ := s.store.ListAudit(500)
	var out []connectorView
	for _, sp := range connectorSpecs {
		out = append(out, s.connectorView(sp, byName, audit))
	}
	// Any other upstream MCP server the owner plugged in gets its own row.
	var extra []string
	for _, c := range creds {
		if c.Kind == "mcp_server" && byName[c.Name] != nil && !specCredential(c.Name) {
			extra = append(extra, c.Name)
		}
	}
	sort.Strings(extra)
	for _, n := range extra {
		c := byName[n]
		name := strings.TrimPrefix(n, "mcp:")
		sp := connectorSpec{ID: n, Name: name, Services: []string{"MCP tools"}, Credential: n, Prefixes: []string{name + "."}}
		if auth, _ := c.Meta["auth"].(string); auth == "oauth" {
			sp.Connect = "mcp_oauth"
			sp.URL, _ = c.Meta["url"].(string)
		} else {
			sp.Connect = "admin"
			sp.Help = "Replace its key in an admin terminal: ralx admin mcp add " + name + " <url> --header <header>"
		}
		out = append(out, s.connectorView(sp, byName, audit))
	}
	writeJSON(w, 200, map[string]any{"connectors": out})
}

func specCredential(name string) bool {
	for _, sp := range connectorSpecs {
		if sp.Credential == name {
			return true
		}
	}
	return false
}

func (s *Server) connectorView(sp connectorSpec, byName map[string]*store.Credential, audit []*store.AuditEntry) connectorView {
	v := connectorView{ID: sp.ID, Name: sp.Name, Services: sp.Services, Connect: sp.Connect, Credential: sp.Credential,
		Field: sp.Field, URL: sp.URL, Help: sp.Help, Accounts: []connectorAccount{}}
	switch {
	case sp.Connect == "google":
		if !s.google.ClientConfigured() {
			v.Status, v.Reason = "setup_needed", "Optional. Connect Gmail, Drive and YouTube with your own Google app."
			return v
		}
		for _, c := range s.google.Accounts() {
			a := connectorAccount{Name: c.Name, Label: c.Label, Status: "ok", Services: metaStrings(c.Meta, "services"),
				Default: metaStrings(c.Meta, "default_for"), LastUsed: c.LastUsedAt}
			if st, _ := c.Meta["status"].(string); st != "" && st != "ok" {
				a.Status, a.Reason = "error", "Google says this sign-in expired or was revoked. Reconnect it."
			}
			v.Accounts = append(v.Accounts, a)
		}
	default:
		c := byName[sp.Credential]
		if c == nil {
			v.Status = "not_connected"
			if sp.Tool != "" {
				if _, ok := s.run.Tools[sp.Tool]; !ok {
					v.Reason = "RalX can't find the " + sp.Tool + " CLI it runs, so this won't work until it's installed."
				}
			}
			return v
		}
		a := connectorAccount{Name: c.Name, Label: c.Label, Status: "ok", LastUsed: c.LastUsedAt}
		if sp.ID == "notion" {
			a.Label = "Notion workspace"
		}
		if sp.Connect == "mcp_oauth" || c.Kind == "mcp_server" {
			if st, _ := c.Meta["status"].(string); st != "" && st != "ok" {
				detail, _ := c.Meta["error"].(string)
				v.Detail = s.red.String(detail)
				a.Status = "error"
				if strings.Contains(detail, "sign-in expired") || st == "reconnect_needed" {
					a.Reason = sp.Name + "'s sign-in expired and couldn't be renewed. Reconnect to sign in again."
				} else if strings.Contains(detail, "couldn't reach") {
					a.Reason = "RalX couldn't reach " + sp.Name + ". It keeps retrying by itself."
				} else {
					a.Reason = sp.Name + " didn't load its tools."
				}
			}
		}
		if sp.ID == "uploadpost" {
			a.Profile, _ = c.Meta["profile"].(string)
			if a.Profile == "" {
				a.Status, a.Reason = "error", "Set the Upload-Post profile to post as."
			}
		}
		if sp.Tool != "" {
			if _, ok := s.run.Tools[sp.Tool]; !ok {
				a.Status, a.Reason = "error", "RalX can't find the "+sp.Tool+" CLI it runs."
			}
		}
		if a.Status == "ok" && lastCallRefused(audit, sp.Prefixes, c.Name) {
			a.Status, a.Reason = "error", "The last call was refused: the saved login looks expired or revoked."
		}
		v.Accounts = append(v.Accounts, a)
	}
	v.Status = "not_connected"
	for _, a := range v.Accounts {
		if a.Status != "ok" {
			v.Status, v.Reason = "error", a.Reason
			break
		}
		v.Status = "connected"
	}
	return v
}

// lastCallRefused reports whether the newest finished call for these actions
// failed because the provider refused the saved login. Calls that started before
// the owner last saved the credential tried the old login, so they don't count,
// even when they finish after the save (R2-3). A call's start is its finish
// minus its duration; audit times are whole seconds, so a call that may have
// started in the save's own second is treated as an old-login call.
func lastCallRefused(audit []*store.AuditEntry, prefixes []string, credential string) bool {
	putAt, newer := int64(-1), audit // newest first
	for i, e := range audit {
		if e.Action == "credential.put" && (e.Detail == credential || strings.HasPrefix(e.Detail, credential+" via ")) {
			putAt, newer = e.TS, audit[:i]
			break
		}
	}
	for _, e := range newer {
		if putAt >= 0 && e.TS*1000-e.DurationMS < (putAt+1)*1000 {
			continue
		}
		// A failed connect attempt says nothing about the saved login.
		if loginEvent(e.Action) {
			continue
		}
		match := false
		for _, p := range prefixes {
			match = match || strings.HasPrefix(e.Action, p)
		}
		if !match || (e.Outcome != "ok" && e.Outcome != "error" && e.Outcome != "executed" && e.Outcome != "failed") {
			continue
		}
		return (e.Outcome == "error" || e.Outcome == "failed") && authFailure.MatchString(e.Detail)
	}
	return false
}

// loginEvent reports whether action is one of the connect events RalX itself
// audits. Their namespaces are reserved, so no upstream tool action matches.
func loginEvent(action string) bool {
	if action == "google.connect" || action == "upstream.connect" {
		return true
	}
	tool, ok := strings.CutSuffix(action, ".connect")
	_, cli := cliLogins[tool]
	return ok && cli
}

func metaStrings(m map[string]any, k string) []string {
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
