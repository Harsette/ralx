package daemon

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Harsette/ralx/internal/store"
	"github.com/Harsette/ralx/internal/upstream"
)

// Paste links: a one-time page where a human pastes a key and it goes
// straight into the vault, never through a chat, terminal or transcript.
// Only the owner (elevated CLI, or passkey session) can mint one.

type dropLink struct {
	Name, Field, Provider, Label string
	Kind                         string // "api_key" (default) or "mcp_server"
	Meta                         map[string]any
	Expires                      time.Time
}

type dropBox struct {
	mu sync.Mutex
	m  map[string]*dropLink // token hash -> link
}

var drops = &dropBox{m: map[string]*dropLink{}}

func (s *Server) handleDropCreate(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	name := rawString(body, "name")
	if name == "" || strings.HasPrefix(name, "google:") || strings.Contains(name, " ") {
		s.fail(w, 400, "a credential name is required")
		return
	}
	if err := s.stepUp(ac, "drop:"+name, body, true); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	var meta map[string]any
	_ = json.Unmarshal(body["meta"], &meta)
	kind := rawString(body, "kind")
	if kind == "" {
		kind = "api_key"
	}
	if kind != "api_key" && kind != "mcp_server" {
		s.fail(w, 400, "unknown paste-link kind")
		return
	}
	field := rawString(body, "field")
	// An mcp_server paste link provisions a downstream MCP server (Composio,
	// etc.): the pasted value becomes the auth header, and the server is
	// connected the moment it is pasted. Validate the non-secret parts now so
	// a bad link can't be minted.
	if kind == "mcp_server" {
		if !upstreamNameRe.MatchString(name) {
			s.fail(w, 400, "mcp server name: lowercase letters/digits, 2-31 chars")
			return
		}
		if upstream.ReservedName(name) {
			s.fail(w, 400, "that name is a built-in RalX namespace; pick another for the mcp server")
			return
		}
		u, _ := meta["url"].(string)
		if err := s.up.CheckURL(u); err != nil {
			s.fail(w, 400, "mcp server needs an https url in --meta url=")
			return
		}
		if h, _ := meta["header"].(string); strings.TrimSpace(h) == "" {
			s.fail(w, 400, "mcp server needs a header name in --meta header= (e.g. x-api-key)")
			return
		}
		if field == "" {
			field = "value"
		}
	}
	if field == "" {
		field = "token"
	}
	tok := randID(24)
	drops.mu.Lock()
	for k, d := range drops.m {
		if time.Now().After(d.Expires) {
			delete(drops.m, k)
		}
	}
	drops.m[store.HashToken(tok)] = &dropLink{Name: name, Field: field, Kind: kind, Provider: rawString(body, "provider"), Label: rawString(body, "label"), Meta: meta, Expires: time.Now().Add(10 * time.Minute)}
	drops.mu.Unlock()
	origin := rawString(body, "origin")
	if origin == "" {
		origin = s.origin
	}
	s.store.Audit("owner", "drop.create", "ok", 0, name)
	writeJSON(w, 200, map[string]any{"url": origin + "/#drop=" + tok, "expires_in": 600})
}

func (s *Server) handleDropInfo(w http.ResponseWriter, r *http.Request) {
	if s.isInternetOrigin(r) || remoteIsPublic(r) || funneled(r) {
		s.fail(w, 403, "paste links only work on RalX's local or tailnet address")
		return
	}
	drops.mu.Lock()
	d, ok := drops.m[store.HashToken(r.PathValue("token"))]
	drops.mu.Unlock()
	if !ok || time.Now().After(d.Expires) {
		s.fail(w, 404, "this paste link has expired or was used")
		return
	}
	label := d.Label
	if label == "" {
		label = d.Name
	}
	writeJSON(w, 200, map[string]any{"label": label, "field": d.Field})
}

func (s *Server) handleDropSubmit(w http.ResponseWriter, r *http.Request) {
	// A paste link is a local/tailnet capability: never consumable from the
	// public URL or a public internet peer (Astra N11).
	if s.isInternetOrigin(r) || remoteIsPublic(r) || funneled(r) {
		s.fail(w, 403, "paste links only work on RalX's local or tailnet address")
		return
	}
	if o := r.Header.Get("Origin"); o != "" && o != s.originFor(r) {
		s.fail(w, 403, "cross-origin request refused")
		return
	}
	body, _ := readBody(r)
	h := store.HashToken(rawString(body, "token"))
	drops.mu.Lock()
	d, ok := drops.m[h]
	delete(drops.m, h) // single use
	drops.mu.Unlock()
	if !ok || time.Now().After(d.Expires) {
		s.fail(w, 404, "this paste link has expired or was used")
		return
	}
	val := strings.TrimSpace(rawString(body, "value"))
	if len(val) < 8 || len(val) > 8192 {
		s.fail(w, 400, "that doesn't look like a key")
		return
	}
	if d.Kind == "mcp_server" {
		u, _ := d.Meta["url"].(string)
		header, _ := d.Meta["header"].(string)
		// AddHeaderServerExclusive saves the key to the vault (registered with the
		// redactor) and then connects. It is create-only and atomic, so a paste
		// can't silently overwrite an already-connected server or race another
		// paste for the same new name (Astra R13 / delta review). If only the
		// first connect fails, the key is still saved and retried on reload.
		if err := s.up.AddHeaderServerExclusive(d.Name, u, header, val); err != nil {
			// A create-only conflict means it already exists: refuse, don't report
			// "saved" (delta review / R13).
			if strings.Contains(err.Error(), "already exists") {
				s.fail(w, 409, d.Name+" is already connected; remove it in RalX before pasting a new key")
				return
			}
			saved := false
			for _, n := range s.up.Names() {
				if n == d.Name {
					saved = true
					break
				}
			}
			// The error text comes from the upstream server and could carry the
			// pasted key back in an encoded form the redactor misses, and this
			// page is reachable on any origin, so return only a fixed message and
			// keep the detail in the owner-side audit log (delta review).
			if saved {
				s.store.Audit("owner", "upstream.connect", "saved", 0, d.Name+" via paste link, not reachable yet: "+s.red.String(err.Error()))
				writeJSON(w, 200, map[string]any{"ok": true, "note": "Saved. RalX couldn't reach it yet , check its status in RalX."})
				return
			}
			s.store.Audit("owner", "upstream.connect", "error", 0, d.Name+" via paste link: "+s.red.String(err.Error()))
			s.fail(w, 502, "couldn't connect to that server; check the URL and key")
			return
		}
		s.store.Audit("owner", "upstream.connect", "ok", 0, d.Name+" via paste link")
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	provider := d.Provider
	if provider == "" {
		provider = d.Name
	}
	if _, err := s.store.PutCredential(d.Name, "api_key", provider, d.Label, d.Meta, map[string]string{d.Field: val}); err != nil {
		s.fail(w, 500, err.Error())
		return
	}
	if store.SecretField(d.Kind, d.Field) {
		s.red.Add(d.Name+":"+d.Field, val)
	}
	s.store.Audit("owner", "credential.put", "ok", 0, d.Name+" via paste link")
	writeJSON(w, 200, map[string]any{"ok": true})
}
