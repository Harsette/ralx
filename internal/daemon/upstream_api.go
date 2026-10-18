package daemon

import (
	"context"
	"net/http"
	"regexp"
	"time"
)

var upstreamNameRe = regexp.MustCompile(`^[a-z][a-z0-9]{1,30}$`)

// handleUpstreamOAuth starts signing RalX in to an upstream MCP server that
// uses OAuth (e.g. Notion's hosted MCP). the owner approves in the browser; the
// tokens go to the vault.
func (s *Server) handleUpstreamOAuth(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	name, u := rawString(body, "name"), rawString(body, "url")
	if !upstreamNameRe.MatchString(name) {
		s.fail(w, 400, "name: lowercase letters and digits")
		return
	}
	if err := s.stepUp(ac, "upstream:"+name, body, true); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	authURL, err := s.up.StartOAuth(ctx, name, u)
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	s.store.Audit("owner", "upstream.connect", "started", 0, name+" "+u)
	writeJSON(w, 200, map[string]any{"auth_url": authURL})
}

// handleUpstreamHeader adds an upstream that takes a static header key.
func (s *Server) handleUpstreamHeader(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	name := rawString(body, "name")
	if !upstreamNameRe.MatchString(name) {
		s.fail(w, 400, "name: lowercase letters and digits")
		return
	}
	if err := s.stepUp(ac, "upstream:"+name, body, true); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	header := rawString(body, "header")
	if header == "" {
		header = "Authorization"
	}
	if err := s.up.AddHeaderServer(name, rawString(body, "url"), header, rawString(body, "value")); err != nil {
		s.fail(w, 400, s.red.String(err.Error()))
		return
	}
	s.store.Audit("owner", "upstream.connect", "ok", 0, name)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleUpstreamReload(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	s.up.LoadAll(ctx)
	writeJSON(w, 200, map[string]any{"upstreams": s.up.Names()})
}
