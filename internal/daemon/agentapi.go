package daemon

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/store"
)

// agentOnly authenticates the bearer agent key. Browsers are refused: an
// agent call never carries an Origin header.
func (s *Server) agentOnly(h func(http.ResponseWriter, *http.Request, *store.Agent)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
			s.fail(w, http.StatusForbidden, "browser requests are not accepted on the agent API")
			return
		}
		auth := r.Header.Get("Authorization")
		raw := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if raw == "" || raw == auth {
			s.fail(w, http.StatusUnauthorized, "missing agent key (set up with: ralx agent setup)")
			return
		}
		agent, _, resource, family, err := s.authenticateBearer(raw)
		if err == nil {
			err = s.checkAudience(resource, r)
		}
		if err != nil {
			hint := raw
			if len(hint) > 12 {
				hint = hint[:12]
			}
			s.store.Audit("unknown", "auth", "rejected", 0, "key "+hint+"…: "+err.Error())
			msg := "invalid agent key"
			if err.Error() == "agent revoked" {
				msg = "this agent has been revoked in RalX"
			}
			s.fail(w, http.StatusUnauthorized, msg)
			return
		}
		// Carry the token's grant family so an action this request queues can be
		// bound to it and refused later if the grant is revoked (Astra N9).
		if family != "" {
			r = r.WithContext(context.WithValue(r.Context(), ctxGrantFamily, family))
		}
		h(w, r, agent)
	}
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	writeJSON(w, 200, map[string]any{"agent": a.Name, "id": a.ID, "ralx": s.cfg.Version, "ui": s.origin})
}

type actionInfo struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Risk        string         `json:"risk"`
	GateReason  string         `json:"gate_reason,omitempty"`
	Ready       bool           `json:"ready"`
	Stream      bool           `json:"stream,omitempty"`
	Schema      map[string]any `json:"input_schema"`
}

func (s *Server) actionReady(a *actions.Action) bool {
	if a.CLI != nil {
		if _, ok := s.run.Tools[a.CLI.Tool]; !ok {
			return false
		}
	}
	for _, req := range a.Requires {
		switch req {
		case "google":
			if s.google.DefaultAccount() == "" {
				return false
			}
		default:
			if _, err := s.store.GetCredential(req); err != nil {
				return false
			}
		}
	}
	return true
}

func (s *Server) handleListActions(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	var out []actionInfo
	for _, a := range s.reg.List() {
		if !actions.Allowed(a.Name, agent.Policy.Allow, agent.Policy.Deny) {
			continue
		}
		out = append(out, actionInfo{Name: a.Name, Description: a.Description, Risk: string(a.Risk), GateReason: a.GateReason,
			Ready: s.actionReady(a), Stream: a.Stream, Schema: a.JSONSchema()})
	}
	s.writeJSONAgentCatalog(w, map[string]any{"actions": out})
}

func (s *Server) handleCallAction(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	var body struct {
		Args map[string]any `json:"args"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &body); err != nil {
			s.fail(w, 400, "body must be JSON: {\"args\": {...}}")
			return
		}
	}
	code, resp := s.callAction(r.Context(), agent, r.PathValue("name"), body.Args)
	// Through the agent-bound choke point: the result was already checked in execute(),
	// but routing the whole response here too keeps a single fail-closed exit for every
	// agent byte, error strings included (Astra7).
	s.writeJSONAgent(w, code, resp)
}

// handleGetApproval lets the requesting agent check (and long-poll) its own
// held action. ?wait=N waits up to N seconds for a decision.
func (s *Server) handleGetApproval(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	id := r.PathValue("id")
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if wait > 120 {
		wait = 120
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		a, err := s.store.GetApproval(id)
		if err != nil || a.AgentID != agent.ID {
			s.fail(w, 404, "no such approval for this agent")
			return
		}
		done := a.Status != "pending" && a.Status != "approved"
		if done || time.Now().After(deadline) {
			resp := map[string]any{"id": a.ID, "action": a.Action, "status": a.Status, "summary": a.Summary, "created_at": a.CreatedAt}
			if a.Result != nil {
				resp["result"] = a.Result
			}
			if a.Error != "" {
				resp["error"] = a.Error
			}
			s.writeJSONAgent(w, 200, resp)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// handleConnections shows which services are connected: names and status,
// never secret values.
func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	creds, _ := s.store.ListCredentials()
	var out []map[string]any
	for _, c := range creds {
		if c.Kind == "oauth_client" {
			continue
		}
		item := map[string]any{"provider": c.Provider, "name": c.Name, "label": c.Label}
		for _, k := range []string{"status", "services", "default", "email"} {
			if v, ok := c.Meta[k]; ok {
				item[k] = v
			}
		}
		out = append(out, item)
	}
	tools := []string{}
	for t := range s.run.Tools {
		tools = append(tools, t)
	}
	s.writeJSONAgent(w, 200, map[string]any{"connections": out, "tools": tools, "google_client_configured": s.google.ClientConfigured()})
}

func (s *Server) handleConnectGoogle(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	var body struct {
		Services  []string `json:"services"`
		LoginHint string   `json:"login_hint"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &body); err != nil {
			s.fail(w, 400, "bad JSON")
			return
		}
	}
	f, err := s.google.StartFlow(body.Services, agent.Name, body.LoginHint)
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	s.store.Audit(agent.Name, "google.connect", "started", 0, strings.Join(f.Services, ","))
	s.writeJSONAgent(w, 200, f)
}

func (s *Server) handleGetFlow(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	f, ok := s.google.GetFlow(r.PathValue("id"))
	if !ok || f.Agent != agent.Name {
		s.fail(w, 404, "no such connect flow")
		return
	}
	s.writeJSONAgent(w, 200, f)
}

// ---------- uploads ----------

func (s *Server) handleStartUpload(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	var body struct {
		Target        string `json:"target"`
		Name          string `json:"name"`
		Size          int64  `json:"size"`
		MimeType      string `json:"mime_type"`
		ParentID      string `json:"parent_id"`
		Description   string `json:"description"`
		Account       string `json:"account"`
		ApprovalID    string `json:"approval_id"`
		MediaUploadID string `json:"media_upload_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.fail(w, 400, "bad JSON")
		return
	}
	start := time.Now()
	switch body.Target {
	case "drive":
		if !actions.Allowed("drive.upload", agent.Policy.Allow, agent.Policy.Deny) {
			s.fail(w, 403, "drive.upload not allowed for this agent")
			return
		}
		// Finishing a previously approved shared-folder upload: everything is
		// re-checked against what the owner approved, the approval is claimed
		// atomically, and the exact staged bytes are sent server-side.
		if body.ApprovalID != "" {
			res, err := s.finishApprovedDriveUpload(r.Context(), body.ApprovalID, agent)
			if err != nil {
				s.store.Audit(agent.Name, "drive.upload", "error", time.Since(start), s.red.String(err.Error()))
				s.fail(w, 403, s.red.String(err.Error()))
				return
			}
			s.store.Audit(agent.Name, "drive.upload", "ok", time.Since(start), s.red.String(body.ApprovalID+" (approved) done"))
			s.writeJSONAgent(w, 200, map[string]any{"status": "ok", "result": res})
			return
		}
		// Resolve the account now and bind that exact identity, so a later change
		// to the default account can't redirect an approved upload to account B
		// (Astra R6).
		account := body.Account
		if account == "" {
			account = s.google.DefaultAccountFor("drive")
		}
		// A gated (shared-folder) upload is bound to one account at approval. If no
		// Google account resolves, refuse now rather than bind to whatever becomes
		// the default before the upload runs (Astra A3 no-default).
		if account == "" {
			s.fail(w, 400, "no Google account is connected; connect one in RalX before uploading to Drive")
			return
		}
		shared, who, audience := false, "", ""
		if body.ParentID != "" {
			var err error
			shared, who, audience, err = s.google.DestinationShared(r.Context(), account, body.ParentID)
			if err != nil {
				s.fail(w, 502, s.red.String(err.Error()))
				return
			}
		}
		if shared {
			// A shared destination sends the file to other people, so it is held
			// for the owner. To bind the approval to the exact bytes (not just a name
			// and size), the file must be staged first; the approval records its
			// SHA-256, size, account, folder, name, description and MIME.
			if body.MediaUploadID == "" {
				s.fail(w, 400, "uploading into a shared Drive folder needs a staged file: stage it first (target \"staging\"), then pass media_upload_id so the owner can approve the exact bytes")
				return
			}
			_, nm, mime, sha, size, err := s.staging.StagedFile(body.MediaUploadID, agent.ID)
			if err != nil {
				s.fail(w, 400, s.red.String(err.Error()))
				return
			}
			name := body.Name
			if name == "" {
				name = nm
			}
			short := sha
			if len(short) > 12 {
				short = short[:12]
			}
			appr := &store.Approval{AgentID: agent.ID, AgentName: agent.Name, Action: "drive.upload", GateReason: "publishes",
				Origin:  approvalOrigin(r.Context()),
				Summary: s.red.String(fmt.Sprintf("Upload %q (%d bytes, sha256 %s) into a Drive folder shared with %s", name, size, short, who))}
			// Bind the grant that queued this upload, so revoking it cancels the
			// pending work even though another live key for the same agent exists
			// (Astra R1).
			if fam, _ := r.Context().Value(ctxGrantFamily).(string); fam != "" {
				appr.GrantFamily = fam
			}
			appr.Args = mustJSON(map[string]any{"media_upload_id": body.MediaUploadID, "sha256": sha, "size": size,
				"name": name, "parent_id": body.ParentID, "account": account, "description": body.Description, "mime_type": mime,
				"recipients": who, "audience": audience})
			appr.CredentialBindings, err = s.bindCredentials(&actions.Action{Name: "drive.upload"}, map[string]any{"account": account})
			if err != nil {
				s.fail(w, 500, "could not bind upload credentials")
				return
			}
			if err := s.store.CreateApproval(appr); err != nil {
				s.fail(w, 500, err.Error())
				return
			}
			s.store.Audit(agent.Name, "drive.upload", "held", 0, appr.ID+" "+appr.Summary)
			// Through the agent-bound choke point: the summary embeds the audience
			// (recipient emails/domains), which could carry an encoded stored key before
			// approval (Astra7 F1 held-summary).
			s.writeJSONAgent(w, 202, map[string]any{"status": "held", "approval_id": appr.ID, "summary": appr.Summary,
				"message": "Uploading into a shared Drive folder waits for the owner's approval. Poll the approval id; once approved, call /v1/uploads again with just the approval_id to send the same file."})
			return
		}
		// Own My Drive (or a folder you own that is not shared). A staged file is
		// sent server-side; otherwise the agent streams the bytes itself (so very
		// large own-Drive uploads are not capped by staging).
		if body.MediaUploadID != "" {
			res, err := s.pushStagedToDrive(r.Context(), agent, body.MediaUploadID, body.Name, body.ParentID, account, body.Description)
			if err != nil {
				s.store.Audit(agent.Name, "drive.upload", "error", time.Since(start), s.red.String(err.Error()))
				s.fail(w, 502, s.red.String(err.Error()))
				return
			}
			s.store.Audit(agent.Name, "drive.upload", "ok", time.Since(start), s.red.String(body.Name+" (own folder) done"))
			s.writeJSONAgent(w, 200, map[string]any{"status": "ok", "result": res})
			return
		}
		meta := map[string]any{"name": body.Name}
		if body.ParentID != "" {
			meta["parents"] = []string{body.ParentID}
		}
		if body.Description != "" {
			meta["description"] = body.Description
		}
		if body.MimeType != "" {
			meta["mimeType"] = body.MimeType
		}
		u, err := s.google.StartUpload(r.Context(), "drive", account, agent.Name, body.Size, body.MimeType, meta)
		if err != nil {
			s.store.Audit(agent.Name, "drive.upload", "error", time.Since(start), s.red.String(err.Error()))
			s.fail(w, 502, s.red.String(err.Error()))
			return
		}
		s.store.Audit(agent.Name, "drive.upload", "started", time.Since(start), u.ID+" "+body.Name+" "+strconv.FormatInt(body.Size, 10)+" bytes")
		s.writeJSONAgent(w, 200, u)
	case "staging":
		u, err := s.staging.start(agent.ID, body.Name, body.MimeType, body.Size)
		if err != nil {
			s.fail(w, 400, err.Error())
			return
		}
		s.writeJSONAgent(w, 200, u)
	default:
		s.fail(w, 400, "target must be drive or staging (YouTube uploads go through the youtube.upload action on a staged file)")
	}
}

// finishApprovedDriveUpload sends a shared-folder upload that the owner approved.
// It re-reads the staged file and checks its SHA-256 and size against the
// approval (so the bytes can't have changed), re-checks the destination, claims
// the approval atomically so two restarts can't both send, then streams the
// exact staged bytes to Drive server-side and consumes the staged file.
func (s *Server) finishApprovedDriveUpload(ctx context.Context, id string, agent *store.Agent) (map[string]any, error) {
	appr, err := s.store.GetApproval(id)
	if err != nil || appr.AgentID != agent.ID || appr.Action != "drive.upload" {
		return nil, errors.New("no such approval for this agent")
	}
	if appr.Status != "approved" {
		return nil, fmt.Errorf("that upload is %s, not approved", appr.Status)
	}
	var a struct {
		MediaUploadID string `json:"media_upload_id"`
		SHA256        string `json:"sha256"`
		Size          int64  `json:"size"`
		Name          string `json:"name"`
		ParentID      string `json:"parent_id"`
		Account       string `json:"account"`
		Description   string `json:"description"`
		MimeType      string `json:"mime_type"`
		Recipients    string `json:"recipients"`
		Audience      string `json:"audience"`
	}
	_ = json.Unmarshal(appr.Args, &a)
	ctx, err = s.approvalCredentials(ctx, appr, &actions.Action{Name: "drive.upload"}, map[string]any{"account": a.Account})
	if err != nil {
		return nil, err
	}
	// If the grant that queued this upload was revoked while it waited, don't
	// finish it even with another live key for the same agent (Astra R1).
	if appr.GrantFamily != "" && s.store.FamilyRevoked(appr.GrantFamily) {
		return nil, errors.New("the grant that requested this upload has been revoked")
	}
	// Recheck the destination's audience against the canonical fingerprint bound at
	// approval. If the folder's sharing changed since the owner approved (Alice -> Bob,
	// a new domain, a membership change on a shared drive , all of which a display
	// summary would collapse), the fingerprint differs and we refuse rather than
	// send to a different audience (Astra A4/A5). An empty stored fingerprint (an
	// unresolvable audience) never matches, so it also refuses.
	if a.ParentID != "" {
		shared, _, audience, derr := s.google.DestinationShared(ctx, a.Account, a.ParentID)
		if derr != nil {
			return nil, derr
		}
		if !shared || audience == "" || audience != a.Audience {
			return nil, errors.New("the folder's sharing changed since the owner approved this upload; request it again")
		}
	}
	path, _, mime, sha, size, err := s.staging.StagedFile(a.MediaUploadID, agent.ID)
	if err != nil {
		return nil, err
	}
	if sha != a.SHA256 || size != a.Size {
		return nil, errors.New("the staged file is not the one the owner approved (its bytes changed)")
	}
	if a.MimeType != "" {
		mime = a.MimeType
	}
	// Claim first: only the caller that moves the approval approved->executing
	// is allowed to send, so concurrent restarts can't double-upload.
	won, err := s.store.ClaimApproval(id)
	if err != nil {
		return nil, err
	}
	if !won {
		return nil, errors.New("that upload is already being sent")
	}
	meta := map[string]any{"name": a.Name}
	if a.ParentID != "" {
		meta["parents"] = []string{a.ParentID}
	}
	if a.Description != "" {
		meta["description"] = a.Description
	}
	if mime != "" {
		meta["mimeType"] = mime
	}
	res, err := s.google.UploadLocalFile(ctx, "drive", a.Account, agent.Name, path, size, mime, meta)
	msg := ""
	if err != nil {
		msg = s.red.String(err.Error())
	}
	// Persist the result redacted in place. It is read back only through agent-bound
	// exits , the REST poll (writeJSONAgent) and MCP ralx_approval (sanitizeMCPResult) ,
	// which BOTH deep-check and withhold the whole response if the stored metadata still
	// reconstructs a credential, so neither readback can release a recoverable copy
	// (Astra R3 / Astra7 F1 readback choke point).
	_ = s.store.FinishApproval(id, json.RawMessage(s.red.Bytes(mustJSON(map[string]any{"result": res}))), msg)
	if err != nil {
		return nil, err
	}
	s.staging.remove(a.MediaUploadID)
	return res, nil
}

// pushStagedToDrive streams a staged file to an own (non-shared) Drive folder
// server-side and consumes it.
func (s *Server) pushStagedToDrive(ctx context.Context, agent *store.Agent, stagedID, name, parentID, account, description string) (map[string]any, error) {
	path, nm, mime, _, size, err := s.staging.StagedFile(stagedID, agent.ID)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = nm
	}
	meta := map[string]any{"name": name}
	if parentID != "" {
		meta["parents"] = []string{parentID}
	}
	if description != "" {
		meta["description"] = description
	}
	if mime != "" {
		meta["mimeType"] = mime
	}
	res, err := s.google.UploadLocalFile(ctx, "drive", account, agent.Name, path, size, mime, meta)
	if err != nil {
		return nil, err
	}
	s.staging.remove(stagedID)
	return res, nil
}

func (s *Server) handlePutChunk(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	id := r.PathValue("id")
	offset, err := strconv.ParseInt(r.Header.Get("X-RalX-Offset"), 10, 64)
	if err != nil || r.ContentLength <= 0 {
		s.fail(w, 400, "need X-RalX-Offset and a Content-Length body")
		return
	}
	if strings.HasPrefix(id, "stg_") {
		u, err := s.staging.put(id, agent.ID, offset, r.ContentLength, r.Body)
		if err != nil {
			writeJSON(w, 409, map[string]any{"error": err.Error(), "upload": u})
			return
		}
		s.writeJSONAgent(w, 200, u)
		return
	}
	// Re-check the policy on every chunk: narrowing drive.upload must stop an
	// in-flight upload, not just new starts (Astra A12).
	if !actions.Allowed("drive.upload", agent.Policy.Allow, agent.Policy.Deny) {
		s.fail(w, 403, "drive.upload is no longer allowed for this agent")
		return
	}
	u, err := s.google.PutChunk(r.Context(), id, agent.Name, offset, r.ContentLength, r.Body)
	if err != nil {
		code := 502
		if err == store.ErrNotFound {
			code = 404
		}
		// Through the agent-bound choke point: a provider error can carry an encoded
		// stored key, which plain writeJSON+red.String would not withhold (Astra7 F1).
		s.writeJSONAgent(w, code, map[string]any{"error": err.Error(), "upload": u})
		return
	}
	if u.Done {
		s.store.Audit(agent.Name, u.Target+".upload", "ok", 0, s.red.String(u.ID+" "+u.Name+" "+strconv.FormatInt(u.Size, 10)+" bytes done"))
	}
	s.writeJSONAgent(w, 200, u)
}

func (s *Server) handleUploadStatus(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	id := r.PathValue("id")
	if strings.HasPrefix(id, "stg_") {
		u, err := s.staging.status(id, agent.ID)
		if err != nil {
			s.fail(w, 404, err.Error())
			return
		}
		s.writeJSONAgent(w, 200, u)
		return
	}
	if !actions.Allowed("drive.upload", agent.Policy.Allow, agent.Policy.Deny) {
		s.fail(w, 403, "drive.upload is no longer allowed for this agent")
		return
	}
	u, err := s.google.UploadStatus(r.Context(), id, agent.Name)
	if err != nil {
		code := 502
		if err == store.ErrNotFound {
			code = 404
		}
		// Through the agent-bound choke point (Astra7 F1): a provider error could carry
		// an encoded stored key that red.String alone would not withhold.
		s.writeJSONAgent(w, code, map[string]any{"error": err.Error(), "upload": u})
		return
	}
	s.writeJSONAgent(w, 200, u)
}

func (s *Server) handleDriveDownload(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	if !actions.Allowed("drive.download", agent.Policy.Allow, agent.Policy.Deny) {
		s.fail(w, 403, "drive.download not allowed for this agent")
		return
	}
	id := r.PathValue("id")
	if len(id) < 10 || len(id) > 200 || strings.ContainsAny(id, "/?#%") {
		s.fail(w, 400, "bad file id")
		return
	}
	start := time.Now()
	if err := s.google.Download(r.Context(), r.URL.Query().Get("account"), id, w); err != nil {
		s.store.Audit(agent.Name, "drive.download", "error", time.Since(start), s.red.String(id+" "+err.Error()))
		s.fail(w, 502, err.Error())
		return
	}
	s.store.Audit(agent.Name, "drive.download", "ok", time.Since(start), id)
}

// fingerprintWindow is the fixed window width for leak-scan fingerprints.
// Only secrets at least this long are fingerprinted: a shorter, possibly
// low-entropy secret (a password or PIN) would make the fingerprint a
// brute-force oracle for the agent, so such secrets are never handed out.
const fingerprintWindow = 24

// handleFingerprints gives the leak scanner per-scan HMAC fingerprints of
// fixed-width windows of every long secret, so the scan runs as the agent (on
// files only the agent can see) without the agent learning a secret. A fresh
// random key each scan stops precomputation and cross-scan correlation; the
// window is wide enough that a real token window is infeasible to brute force.
func (s *Server) handleFingerprints(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	all, _ := s.store.AllSecretValues()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	type fp struct {
		Label  string   `json:"label"`
		Hashes []string `json:"hashes"`
	}
	var out []fp
	skippedShort := 0
	for label, vals := range all {
		for _, v := range vals {
			if len(v) < fingerprintWindow {
				skippedShort++
				continue
			}
			offsets := []int{0, len(v)/2 - fingerprintWindow/2, len(v) - fingerprintWindow}
			seen := map[string]bool{}
			var hs []string
			for _, o := range offsets {
				mac := hmac.New(sha256.New, key)
				mac.Write([]byte(v[o : o+fingerprintWindow]))
				h := hex.EncodeToString(mac.Sum(nil))
				if !seen[h] {
					seen[h] = true
					hs = append(hs, h)
				}
			}
			out = append(out, fp{Label: label, Hashes: hs})
		}
	}
	s.store.Audit(agent.Name, "leakscan", "fingerprints", 0, fmt.Sprintf("%d long secrets, %d short skipped", len(out), skippedShort))
	writeJSON(w, 200, map[string]any{"scan_key": hex.EncodeToString(key), "window": fingerprintWindow, "fingerprints": out})
}
