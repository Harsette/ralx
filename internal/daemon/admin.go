package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/google"
	"github.com/Harsette/ralx/internal/store"
)

type adminCtx struct {
	via  string // "pipe" (elevated local admin) or "passkey"
	sess *adminSession
	rp   string
}

func isPipe(r *http.Request) bool { v, _ := r.Context().Value(ctxPipeAdmin).(bool); return v }

func (s *Server) adminOnly(h func(http.ResponseWriter, *http.Request, adminCtx)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isPipe(r) {
			h(w, r, adminCtx{via: "pipe"})
			return
		}
		rp := s.rpFor(r)
		sess := s.admin.session(r, rp)
		if sess == nil {
			s.fail(w, http.StatusUnauthorized, "sign in to RalX with your passkey")
			return
		}
		if err := s.admin.checkBrowser(r, sess, s.originFor(r)); err != nil {
			s.fail(w, http.StatusForbidden, err.Error())
			return
		}
		h(w, r, adminCtx{via: "passkey", sess: sess, rp: rp})
	}
}

// localAdminOnly is adminOnly plus a refusal on internet-facing origins: the
// credential/agent/connection surface is reachable only from the local pipe or
// a tailnet/LAN address, never from the public URL (Daru's split, item b).
func (s *Server) localAdminOnly(h func(http.ResponseWriter, *http.Request, adminCtx)) http.HandlerFunc {
	inner := s.adminOnly(h)
	return func(w http.ResponseWriter, r *http.Request) {
		if !isPipe(r) {
			if s.isInternetOrigin(r) {
				s.fail(w, http.StatusForbidden, "this is only available on RalX's local or tailnet address, not the public URL")
				return
			}
			// Locality can't rest on the Host header alone: refuse a
			// local/tailnet-looking request that actually comes from a public
			// internet peer, or one tunnelled in over Tailscale Funnel (Astra
			// N11 / Daru review).
			if remoteIsPublic(r) || funneled(r) {
				s.fail(w, http.StatusForbidden, "this is only available on RalX's local or tailnet address")
				return
			}
		}
		inner(w, r)
	}
}

// localBrowserOnly is browserOnly plus a refusal on internet-facing origins,
// for first-time passkey setup: the first passkey is registered locally or over
// the tailnet, never from the public URL (Astra R14). Phone pairing of a further
// passkey is a separate, localAdminOnly route.
func (s *Server) localBrowserOnly(h http.HandlerFunc) http.HandlerFunc {
	inner := s.browserOnly(h)
	return func(w http.ResponseWriter, r *http.Request) {
		if !isPipe(r) && (s.isInternetOrigin(r) || remoteIsPublic(r) || funneled(r)) {
			s.fail(w, http.StatusForbidden, "first-time setup is only available on RalX's local or tailnet address")
			return
		}
		inner(w, r)
	}
}

// browserOnly is for the passkey ceremonies themselves (no session yet).
func (s *Server) browserOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && o != s.originFor(r) {
			s.fail(w, http.StatusForbidden, "cross-origin request refused")
			return
		}
		if r.Header.Get("X-RalX-CSRF") == "" {
			s.fail(w, http.StatusForbidden, "missing CSRF header")
			return
		}
		h(w, r)
	}
}

func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/api/session", s.handleSession)
	mux.HandleFunc("POST /admin/api/setup/begin", s.localBrowserOnly(s.handleSetupBegin))
	mux.HandleFunc("POST /admin/api/setup/finish", s.localBrowserOnly(s.handleSetupFinish))
	mux.HandleFunc("POST /admin/api/login/begin", s.browserOnly(s.handleLoginBegin))
	mux.HandleFunc("POST /admin/api/login/finish", s.browserOnly(s.handleLoginFinish))
	mux.HandleFunc("POST /admin/api/logout", s.adminOnly(func(w http.ResponseWriter, r *http.Request, ac adminCtx) {
		s.admin.endSession(w, r)
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	mux.HandleFunc("POST /admin/api/stepup/begin", s.adminOnly(s.handleStepUpBegin))
	mux.HandleFunc("GET /admin/api/state", s.adminOnly(s.handleState))
	mux.HandleFunc("POST /admin/api/approvals/{id}/approve", s.adminOnly(s.handleApprove))
	mux.HandleFunc("POST /admin/api/approvals/{id}/deny", s.adminOnly(s.handleDeny))
	// Sensitive surface: local pipe or tailnet/LAN only, never the public URL.
	mux.HandleFunc("GET /admin/api/connectors", s.localAdminOnly(s.handleConnectors))
	mux.HandleFunc("POST /admin/api/credentials", s.localAdminOnly(s.handlePutCredential))
	mux.HandleFunc("POST /admin/api/logins", s.localAdminOnly(s.handleAddLogin))
	mux.HandleFunc("POST /admin/api/credentials/reveal", s.localAdminOnly(s.handleReveal))
	mux.HandleFunc("POST /admin/api/credentials/delete", s.localAdminOnly(s.handleDeleteCredential))
	mux.HandleFunc("POST /admin/api/credentials/meta", s.localAdminOnly(s.handleCredentialMeta))
	mux.HandleFunc("POST /admin/api/google/default", s.localAdminOnly(s.handleGoogleDefault))
	mux.HandleFunc("POST /admin/api/agents", s.localAdminOnly(s.handleCreateAgent))
	mux.HandleFunc("POST /admin/api/agents/{id}/revoke", s.localAdminOnly(s.handleRevokeAgent))
	mux.HandleFunc("POST /admin/api/passkeys/begin", s.localAdminOnly(s.handlePasskeyAddBegin))
	mux.HandleFunc("POST /admin/api/passkeys/finish", s.localAdminOnly(s.handlePasskeyAddFinish))
	mux.HandleFunc("POST /admin/api/setup-link", s.localAdminOnly(s.handleSetupLink))
	mux.HandleFunc("POST /admin/api/pair", s.localAdminOnly(s.handlePair))
	mux.HandleFunc("POST /admin/api/drop", s.localAdminOnly(s.handleDropCreate))
	mux.HandleFunc("GET /drop/{token}", s.handleDropInfo)
	mux.HandleFunc("POST /drop/submit", s.handleDropSubmit)
	mux.HandleFunc("POST /admin/api/connect/google", s.localAdminOnly(s.handleAdminConnectGoogle))
	s.enrollRoutes(mux)
}

func readBody(r *http.Request) (map[string]json.RawMessage, error) {
	m := map[string]json.RawMessage{}
	if r.ContentLength == 0 {
		return m, nil
	}
	err := decodeJSON(r, &m)
	return m, err
}

func rawString(m map[string]json.RawMessage, k string) string {
	var s string
	_ = json.Unmarshal(m[k], &s)
	return s
}

// stepUp requires a fresh passkey assertion bound to this exact operation.
// The elevated admin pipe may perform an operation only if pipeOK is true.
func (s *Server) stepUp(ac adminCtx, op string, body map[string]json.RawMessage, pipeOK bool) error {
	if ac.via == "pipe" {
		if pipeOK {
			return nil
		}
		return errors.New("this needs the owner's passkey in the RalX app; it can't be done from the command line")
	}
	assertion := body["assertion"]
	if len(assertion) == 0 || string(assertion) == "null" {
		return errors.New("passkey confirmation required")
	}
	return s.admin.finishAssertion("op:"+ac.sess.id+":"+op, ac.rp, assertion)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	rp := s.rpFor(r)
	resp := map[string]any{"setup_needed": !s.admin.hasPasskeys(rp), "authenticated": false, "version": s.cfg.Version, "dev": s.cfg.Dev, "rp": rp}
	if isPipe(r) {
		resp["authenticated"], resp["via"] = true, "pipe"
	} else if sess := s.admin.session(r, rp); sess != nil {
		resp["authenticated"], resp["via"], resp["csrf"] = true, "passkey", sess.csrf
	}
	writeJSON(w, 200, resp)
}

// checkSetupToken validates a one-time passkey setup link for this rp. A
// "first" link (from the elevated CLI) only works while the rp has no
// passkeys; a "pair" link was minted by an already-signed-in owner.
func (s *Server) checkSetupToken(tok, rp string) bool {
	h := s.store.Setting("setup_token_hash")
	exp, _ := strconv.ParseInt(s.store.Setting("setup_token_exp"), 10, 64)
	if h == "" || tok == "" || store.HashToken(tok) != h || time.Now().Unix() >= exp || s.store.Setting("setup_token_rp") != rp {
		return false
	}
	if s.store.Setting("setup_token_mode") == "pair" {
		return true
	}
	return !s.admin.hasPasskeys(rp)
}

func (s *Server) mintSetupToken(rp, mode string) string {
	tok := randID(24)
	_ = s.store.SetSetting("setup_token_hash", store.HashToken(tok))
	_ = s.store.SetSetting("setup_token_rp", rp)
	_ = s.store.SetSetting("setup_token_mode", mode)
	_ = s.store.SetSetting("setup_token_exp", strconv.FormatInt(time.Now().Add(15*time.Minute).Unix(), 10))
	return tok
}

func (s *Server) handleSetupBegin(w http.ResponseWriter, r *http.Request) {
	body, _ := readBody(r)
	tok := rawString(body, "token")
	rp := s.rpFor(r)
	if !s.checkSetupToken(tok, rp) {
		s.fail(w, 403, "This setup link expired. Run ralx open for a fresh one.")
		return
	}
	opts, err := s.admin.beginRegistration("setup:"+store.HashToken(tok), rp)
	if err != nil {
		s.fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, opts)
}

func (s *Server) handleSetupFinish(w http.ResponseWriter, r *http.Request) {
	body, _ := readBody(r)
	tok := rawString(body, "token")
	rp := s.rpFor(r)
	if !s.checkSetupToken(tok, rp) {
		s.fail(w, 403, "this setup link is invalid or expired")
		return
	}
	pk, err := s.admin.finishRegistration("setup:"+store.HashToken(tok), rp, rawString(body, "name"), body["credential"])
	if err != nil {
		s.fail(w, 400, "passkey registration failed: "+err.Error())
		return
	}
	_ = s.store.SetSetting("setup_token_hash", "")
	s.store.Audit("owner", "admin.setup", "ok", 0, "passkey "+pk.Name+" for "+rp)
	sess := s.admin.newSession(w, rp, strings.HasPrefix(s.originFor(r), "https://"))
	writeJSON(w, 200, map[string]any{"ok": true, "csrf": sess.csrf})
}

// handlePair (signed in, passkey step-up) mints a one-time link that lets
// the owner register a passkey on another address of the hub, e.g. his phone on
// the HTTPS hostname.
func (s *Server) handlePair(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	origin := strings.TrimRight(rawString(body, "origin"), "/")
	ok := false
	for _, o := range s.hub.PublicOrigins {
		if o == origin {
			ok = true
		}
	}
	if !ok {
		s.fail(w, 400, "that address isn't one of the hub's configured HTTPS origins")
		return
	}
	if err := s.stepUp(ac, "pair:"+origin, body, false); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	tok := s.mintSetupToken(rpIDOf(origin), "pair")
	s.store.Audit("owner", "passkey.pair", "ok", 0, origin)
	writeJSON(w, 200, map[string]any{"url": origin + "/#setup=" + tok, "expires_in": 900})
}

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	key := "login:" + randID(16)
	opts, err := s.admin.beginAssertion(key, s.rpFor(r))
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ceremony": key, "options": opts})
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	body, _ := readBody(r)
	key := rawString(body, "ceremony")
	if !strings.HasPrefix(key, "login:") {
		s.fail(w, 400, "bad ceremony")
		return
	}
	if err := s.admin.finishAssertion(key, s.rpFor(r), body["credential"]); err != nil {
		s.store.Audit("browser", "admin.login", "rejected", 0, err.Error())
		s.fail(w, 401, "passkey sign-in failed: "+err.Error())
		return
	}
	sess := s.admin.newSession(w, s.rpFor(r), strings.HasPrefix(s.originFor(r), "https://"))
	s.store.Audit("owner", "admin.login", "ok", 0, "")
	writeJSON(w, 200, map[string]any{"ok": true, "csrf": sess.csrf})
}

func (s *Server) handleStepUpBegin(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	if ac.via != "passkey" {
		s.fail(w, 400, "step-up is for the browser")
		return
	}
	body, _ := readBody(r)
	op := rawString(body, "op")
	if op == "" || len(op) > 300 {
		s.fail(w, 400, "op required")
		return
	}
	opts, err := s.admin.beginAssertion("op:"+ac.sess.id+":"+op, ac.rp)
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, opts)
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	pending, _ := s.store.ListApprovals("pending", 100)
	var pend []*store.Approval
	for _, a := range pending {
		s.browserApprovalDisplay(a)
		if a.Status == "pending" {
			pend = append(pend, a)
		}
	}
	// On the public URL, the phone sees only what it needs to approve: the
	// pending list. The credential/agent/connection surface is hidden there
	// (Daru's split, item b).
	if ac.via == "passkey" && s.isInternetOrigin(r) {
		writeJSON(w, 200, map[string]any{"pending": pend, "version": s.cfg.Version, "remote": true})
		return
	}
	creds, _ := s.store.ListCredentials()
	agents, _ := s.store.ListAgents()
	recent, _ := s.store.ListApprovals("", 50)
	audit, _ := s.store.ListAudit(150)
	pks, _ := s.store.ListPasskeys()
	tools := map[string]string{}
	for k, v := range s.run.Tools {
		tools[k] = v
	}
	var acts []map[string]any
	for _, a := range s.reg.List() {
		acts = append(acts, map[string]any{"name": a.Name, "risk": a.Risk, "gate_reason": a.GateReason, "ready": s.actionReady(a), "description": a.Description})
	}
	writeJSON(w, 200, map[string]any{
		"credentials": creds, "agents": agents, "pending": pend, "approvals": recent, "audit": audit,
		"passkeys": pks, "tools": tools, "actions": acts, "dev": s.cfg.Dev, "version": s.cfg.Version,
		"google_client": s.google.ClientConfigured(), "google_default": s.google.DefaultAccount(),
		"warnings": s.warnings(), "uptime": int(time.Since(s.started).Seconds()),
		"public_origins": s.hub.PublicOrigins, "this_origin": s.originFor(r),
		"enrollments": s.enroll.pending(),
		"logins":      s.ownerLogins(),
	})
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	id := r.PathValue("id")
	body, _ := readBody(r)
	// Approvals never accept the admin pipe: only a live passkey check counts.
	if err := s.stepUp(ac, "approve:"+id, body, false); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	if err := s.store.DecideApproval(id, "approved", "owner (passkey)"); err != nil {
		s.fail(w, 409, err.Error())
		return
	}
	s.store.Audit("owner", "approval", "approved", 0, id)
	go s.runApproval(id)
	writeJSON(w, 200, map[string]any{"ok": true, "status": "approved"})
}

func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	id := r.PathValue("id")
	if err := s.store.DecideApproval(id, "denied", "owner ("+ac.via+")"); err != nil {
		s.fail(w, 409, err.Error())
		return
	}
	s.store.Audit("owner", "approval", "denied", 0, id)
	writeJSON(w, 200, map[string]any{"ok": true, "status": "denied"})
}

// testHookKeepMetaMerged runs (in tests only) after a keep_meta replacement has
// merged the stored meta and before it writes, to interleave a concurrent write.
var testHookKeepMetaMerged func()

func (s *Server) handlePutCredential(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, err := readBody(r)
	if err != nil {
		s.fail(w, 400, "bad JSON")
		return
	}
	name := rawString(body, "name")
	if err := s.stepUp(ac, "credential.put:"+name, body, true); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	var fields map[string]string
	var meta map[string]any
	_ = json.Unmarshal(body["fields"], &fields)
	_ = json.Unmarshal(body["meta"], &meta)
	kind, provider, label := rawString(body, "kind"), rawString(body, "provider"), rawString(body, "label")
	if kind == "" {
		kind = "api_key"
	}
	if provider == "" {
		provider = name
	}
	if name == google.ClientCredential {
		kind, provider = "oauth_client", "google"
		if fields["client_id"] == "" || fields["client_secret"] == "" {
			s.fail(w, 400, "the Google client needs client_id and client_secret")
			return
		}
	}
	if strings.HasPrefix(name, "google:") {
		s.fail(w, 400, "Google accounts are added with the Connect Google button, not pasted")
		return
	}
	// An upstream-MCP credential write is an owner reconnect/replacement: always stamp a
	// fresh connection generation so any pending upstream approval pinned to the old
	// generation is refused, even when the caller re-submits the previous meta (and even
	// an OAuth account swap that keeps the same public client/endpoint) , Astra7
	// self-review account replacement. Legitimate token refreshes don't go through here.
	// keep_meta: the home screen replaces only the key, so the owner's settings on
	// it (allowed_hosts, profile) survive; the old key's load status does not. The
	// write only lands if the stored meta is still the one merged, so a concurrent
	// settings change is re-merged, never overwritten with the older copy (R2-1).
	var keep bool
	_ = json.Unmarshal(body["keep_meta"], &keep)
	var c *store.Credential
	for attempt := 1; ; attempt++ {
		m := map[string]any{}
		var match func(*store.Credential) bool
		if keep {
			old, err := s.store.GetCredential(name)
			if err == nil {
				for k, v := range old.Meta {
					switch k {
					case "status", "error", "tools", "loaded_at", "last_refresh":
						continue
					}
					m[k] = v
				}
				match = func(cur *store.Credential) bool { return cur != nil && reflect.DeepEqual(cur.Meta, old.Meta) }
			} else {
				match = func(cur *store.Credential) bool { return cur == nil }
			}
		}
		for k, v := range meta {
			m[k] = v
		}
		if keep && testHookKeepMetaMerged != nil {
			testHookKeepMetaMerged()
		}
		if kind == "mcp_server" || strings.HasPrefix(name, "mcp:") {
			m["gen"] = store.NewID("")
		}
		var ok bool
		c, ok, err = s.store.PutCredentialIf(name, kind, provider, label, m, fields, match)
		if err != nil {
			s.fail(w, 400, err.Error())
			return
		}
		if ok {
			break
		}
		if attempt == 3 {
			s.fail(w, 409, "the settings on "+name+" kept changing while the key was replaced; try again")
			return
		}
	}
	for k, v := range fields {
		if store.SecretField(c.Kind, k) {
			s.red.Add(name+":"+k, v)
		}
	}
	s.store.Audit("owner", "credential.put", "ok", 0, name+" via "+ac.via)
	writeJSON(w, 200, c)
}

func (s *Server) handleCredentialMeta(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	name := rawString(body, "name")
	var patch map[string]any
	_ = json.Unmarshal(body["meta"], &patch)
	// Only harmless display/config keys may be changed without a passkey.
	for k := range patch {
		if k != "profile" && k != "label" && k != "note" {
			s.fail(w, 400, "only profile, label and note can be changed here")
			return
		}
	}
	if err := s.store.UpdateMeta(name, patch); err != nil {
		s.fail(w, 404, err.Error())
		return
	}
	s.store.Audit("owner", "credential.meta", "ok", 0, name)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleReveal(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	name := rawString(body, "name")
	if err := s.stepUp(ac, "reveal:"+name, body, false); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	fields, err := s.store.Secret(name)
	if err != nil {
		s.fail(w, 404, "no such credential")
		return
	}
	s.store.Audit("owner", "credential.reveal", "ok", 0, name)
	writeJSON(w, 200, map[string]any{"name": name, "fields": fields})
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	name := rawString(body, "name")
	var err error
	if strings.HasPrefix(name, "google:") {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		err = s.google.Disconnect(ctx, strings.TrimPrefix(name, "google:"))
	} else {
		err = s.store.DeleteCredential(name)
	}
	if err != nil {
		s.fail(w, 404, err.Error())
		return
	}
	s.store.Audit("owner", "credential.delete", "ok", 0, name+" via "+ac.via)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleGoogleDefault(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	acct := rawString(body, "account")
	if err := s.stepUp(ac, "google.default:"+acct, body, true); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	var services []string
	_ = json.Unmarshal(body["services"], &services)
	var err error
	if len(services) > 0 {
		for _, sv := range services {
			if _, ok := google.ServiceScopes[sv]; !ok {
				s.fail(w, 400, "unknown service "+sv)
				return
			}
		}
		err = s.google.SetDefaultFor(acct, services)
	} else {
		err = s.google.SetDefault(acct)
	}
	if err != nil {
		s.fail(w, 404, "no such Google account")
		return
	}
	s.store.Audit("owner", "google.default", "ok", 0, acct+" "+strings.Join(services, ","))
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleCreateAgent(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	name := rawString(body, "name")
	if err := s.stepUp(ac, "agent.create:"+name, body, true); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	var pol store.Policy
	_ = json.Unmarshal(body["policy"], &pol)
	for _, g := range append(append([]string{}, pol.Allow...), pol.Deny...) {
		if !actions.Allowed("x", []string{g}, nil) && strings.ContainsAny(g, "[\\") {
			s.fail(w, 400, "bad policy glob "+g)
			return
		}
	}
	a, key, err := s.store.CreateAgent(name, pol)
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	s.store.Audit("owner", "agent.create", "ok", 0, name+" via "+ac.via)
	writeJSON(w, 200, map[string]any{"agent": a, "key": key})
}

func (s *Server) handleRevokeAgent(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	id := r.PathValue("id")
	a, err := s.store.GetAgent(id)
	if err != nil {
		a, err = s.store.GetAgentByName(id)
	}
	if err != nil {
		s.fail(w, 404, "no such agent")
		return
	}
	if err := s.store.RevokeAgent(a.ID); err != nil {
		s.fail(w, 409, "agent already revoked")
		return
	}
	s.store.Audit("owner", "agent.revoke", "ok", 0, a.Name+" via "+ac.via)
	writeJSON(w, 200, map[string]any{"ok": true, "agent": a.Name})
}

func (s *Server) handlePasskeyAddBegin(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	if err := s.stepUp(ac, "passkey.add", body, false); err != nil {
		s.fail(w, 403, err.Error())
		return
	}
	opts, err := s.admin.beginRegistration("add:"+ac.sess.id, ac.rp)
	if err != nil {
		s.fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, opts)
}

func (s *Server) handlePasskeyAddFinish(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	if ac.via != "passkey" {
		s.fail(w, 400, "browser only")
		return
	}
	body, _ := readBody(r)
	pk, err := s.admin.finishRegistration("add:"+ac.sess.id, ac.rp, rawString(body, "name"), body["credential"])
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	s.store.Audit("owner", "passkey.add", "ok", 0, pk.Name)
	writeJSON(w, 200, pk)
}

// handleSetupLink (admin pipe only) mints a one-time link to register the
// first passkey, or with reset=true wipes passkeys so the owner can start over.
func (s *Server) handleSetupLink(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	if ac.via != "pipe" {
		s.fail(w, 403, "setup links come from `ralx open` on this computer")
		return
	}
	body, _ := readBody(r)
	var reset bool
	_ = json.Unmarshal(body["reset"], &reset)
	origin := strings.TrimRight(rawString(body, "origin"), "/")
	if origin == "" {
		origin = s.origin
	}
	known := origin == s.origin
	for _, o := range s.hub.PublicOrigins {
		known = known || o == origin
	}
	if !known {
		s.fail(w, 400, "unknown origin; add it to public_origins in config.yaml first")
		return
	}
	rp := rpIDOf(origin)
	if s.admin.hasPasskeys(rp) {
		if !reset {
			writeJSON(w, 200, map[string]any{"url": origin + "/", "setup_needed": false})
			return
		}
		_ = s.store.DeleteAllPasskeys()
		s.admin.endAllSessions()
		s.store.Audit("admin", "passkey.reset", "ok", 0, "all passkeys removed via elevated CLI")
	}
	tok := s.mintSetupToken(rp, "first")
	writeJSON(w, 200, map[string]any{"url": origin + "/#setup=" + tok, "setup_needed": true})
}

func (s *Server) handleAdminConnectGoogle(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, _ := readBody(r)
	var services []string
	_ = json.Unmarshal(body["services"], &services)
	f, err := s.google.StartFlow(services, "owner", rawString(body, "login_hint"))
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, f)
}

func (s *Server) warnings() []string {
	var out []string
	if s.cfg.Dev {
		out = append(out, "RalX runs as you, so programs you run could read its files. For stronger protection, run it as a service: ralx admin install.")
	}
	if w := uacWarning(); w != "" {
		out = append(out, w)
	}
	return out
}
