package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/store"
)

// actionEnv is what native actions see. It can read secrets for internal use
// but everything an action returns goes through the redactor afterwards.
type actionEnv struct {
	ctx   context.Context
	s     *Server
	agent *store.Agent
}

func (e *actionEnv) Secret(name string) (map[string]string, error) {
	c, f, err := e.s.store.BoundSecret(e.ctx, name)
	if err != nil {
		return nil, err
	}
	for k, v := range f {
		if store.SecretField(c.Kind, k) {
			e.s.red.Add(name+":"+k, v)
		}
	}
	return f, nil
}
func (e *actionEnv) Redact(s string) string { return e.s.red.String(s) }
func (e *actionEnv) AgentName() string      { return e.agent.Name }
func (e *actionEnv) StagedFile(id string) (string, string, string, string, int64, error) {
	return e.s.staging.StagedFile(id, e.agent.ID)
}

// execute runs a validated, already-authorized action and returns a result
// that is safe to hand to the agent (redacted JSON).
func (s *Server) execute(ctx context.Context, agent *store.Agent, a *actions.Action, args map[string]any) (json.RawMessage, error) {
	var out any
	var err error
	switch {
	case a.CLI != nil:
		out, err = s.execCLI(ctx, a, args)
	case a.Native != nil:
		out, err = a.Native(ctx, &actionEnv{ctx: ctx, s: s, agent: agent}, args)
	default:
		return nil, fmt.Errorf("%s moves file bytes; use the ralx CLI file commands or the MCP drive_upload/drive_download tools", a.Name)
	}
	if err != nil {
		scrubbedErr, withheld := s.agentScrub([]byte(err.Error()), agent.ID)
		if withheld {
			return nil, errors.New("[REDACTED: error withheld , it reconstructs a credential]")
		}
		return nil, errors.New(string(scrubbedErr))
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	// The result path of the central fail-closed choke point (agentScrub): no matter
	// which action produced this result (a named Google/gh read, CLI stdout, Drive
	// metadata, an upstream tool), if the SCRUBBED output still reconstructs a
	// registered credential under any recognised transform (an encoded/percent/split
	// form red.Bytes couldn't rewrite in place), withhold the whole result rather than
	// release a recoverable copy (Daru6 run6 F4 / Astra7).
	scrubbed, withheld := s.agentScrub(raw, agent.ID)
	if withheld {
		return json.RawMessage(`{"status":"withheld","error":"result withheld , it reconstructs a credential"}`), nil
	}
	return json.RawMessage(scrubbed), nil
}

func (s *Server) execCLI(ctx context.Context, a *actions.Action, args map[string]any) (any, error) {
	argv, err := a.BuildArgv(args)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	for k, v := range a.CLI.Env {
		if cred, field, ok := actions.ParseSecretRef(v); ok {
			c, fields, err := s.store.BoundSecret(ctx, cred)
			if err != nil {
				return nil, fmt.Errorf("%s is not connected in RalX yet (missing credential %q)", a.Name, cred)
			}
			val := fields[field]
			if val == "" {
				return nil, fmt.Errorf("credential %q has no field %q", cred, field)
			}
			if store.SecretField(c.Kind, field) {
				s.red.Add(cred+":"+field, val)
			}
			env[k] = val
			continue
		}
		env[k] = v
	}
	timeout := time.Duration(a.CLI.Timeout) * time.Second
	res, err := s.run.Run(ctx, a.CLI.Tool, argv, env, timeout, nil)
	if err != nil {
		return nil, err
	}
	stdout := s.red.String(res.Stdout)
	stderr := s.red.String(strings.TrimSpace(res.Stderr))
	if res.ExitCode != 0 {
		msg := stderr
		if msg == "" {
			msg = strings.TrimSpace(stdout)
		}
		return nil, fmt.Errorf("%s exited %d: %s", a.CLI.Tool, res.ExitCode, msg)
	}
	result := map[string]any{}
	if a.CLI.Output == "json" {
		var parsed any
		if err := json.Unmarshal([]byte(stdout), &parsed); err == nil {
			result["data"] = parsed
		} else {
			result["output"] = stdout
		}
	} else {
		result["output"] = strings.TrimSpace(stdout)
	}
	if res.Truncated {
		result["truncated"] = true
	}
	if stderr != "" {
		result["stderr"] = stderr
	}
	return result, nil
}

func argsDigest(args map[string]any) string {
	b, _ := json.Marshal(args)
	if len(b) > 600 {
		return string(b[:600]) + "…"
	}
	return string(b)
}

// callAction is the single entry point for every agent action call: policy,
// validation, the approval gate, execution and the audit record.
func (s *Server) callAction(ctx context.Context, agent *store.Agent, name string, raw map[string]any) (int, map[string]any) {
	start := time.Now()
	a, ok := s.reg.Get(name)
	if !ok || !actions.Allowed(name, agent.Policy.Allow, agent.Policy.Deny) {
		s.store.Audit(agent.Name, name, "denied", 0, "unknown or not allowed")
		return 404, map[string]any{"error": "no such action (or not allowed for this agent): " + name}
	}
	if raw == nil {
		raw = map[string]any{}
	}
	args, err := a.Validate(normalizeNumbers(raw))
	if err != nil {
		s.store.Audit(agent.Name, name, "invalid", 0, s.red.String(err.Error()))
		return 400, map[string]any{"error": s.red.String(err.Error())}
	}
	if a.Stream {
		return 400, map[string]any{"error": name + " moves file bytes; use the `ralx` CLI file commands or the MCP drive_upload/drive_download tools"}
	}
	// A staged upload must be complete before it can be gated: an approval is
	// bound to a finished, immutable file (its size + SHA-256), never to an id
	// whose bytes the agent can still supply after approval (Astra N1).
	if id, ok := args["media_upload_id"].(string); ok && id != "" {
		if _, _, _, _, _, err := s.staging.StagedFile(id, agent.ID); err != nil {
			s.store.Audit(agent.Name, name, "invalid", 0, s.red.String(err.Error()))
			return 400, map[string]any{"error": s.red.String(err.Error())}
		}
	}
	if a.IsGated(args) {
		// Bind the Google account now, so an approval given while the default is
		// account A can't execute as account B after the default changes (Astra
		// A3). The account param survives re-validation at run time. If no account
		// resolves, refuse to create the approval rather than bind it to whatever
		// becomes the default before it runs (Astra A3 no-default).
		if svc := googleServiceOf(name); svc != "" {
			if acct, _ := args["account"].(string); acct == "" {
				def := s.google.DefaultAccountFor(svc)
				if def == "" {
					s.store.Audit(agent.Name, name, "invalid", 0, "no Google account connected")
					return 400, map[string]any{"error": "no Google account is connected; connect one in RalX before this action can be approved"}
				}
				args["account"] = def
			}
		}
		// Bind the Upload-Post social profile now, so an approval given while the
		// default profile is A can't execute under profile B after the owner changes
		// the default (Astra A3 counterpart). Refuse if none resolves.
		if needsSocialProfile(name) {
			if p, _ := args["profile"].(string); p == "" {
				def := s.defaultSocialProfile()
				if def == "" {
					s.store.Audit(agent.Name, name, "invalid", 0, "no Upload-Post profile set")
					return 400, map[string]any{"error": "no Upload-Post profile is set; set the default profile on the Upload-Post credential in RalX before this action can be approved"}
				}
				args["profile"] = def
			}
		}
		summary := a.Summary(args)
		// A passthrough (upstream MCP) action's name alone can hide what it does
		// , a Composio meta-tool like COMPOSIO_MULTI_EXECUTE_TOOL carries the real
		// app, action and arguments inside its args. Put a compact view of them in
		// the approval summary so the owner sees the inner call, not just the wrapper
		// (Daru review). The summary is redacted below.
		if a.Passthrough {
			summary += " , " + argsDigest(args)
		}
		// Bind the approval to the exact staged bytes (its size + SHA-256), so
		// the owner approves a specific file, not just a title. The file is complete
		// (checked above) and immutable once complete, so these bytes are what
		// will be sent.
		if id, ok := args["media_upload_id"].(string); ok && id != "" {
			if _, nm, _, sha, size, err := s.staging.StagedFile(id, agent.ID); err == nil {
				short := sha
				if len(short) > 12 {
					short = short[:12]
				}
				summary += fmt.Sprintf(" , file %q, %d bytes, sha256 %s", nm, size, short)
			}
		}
		appr := &store.Approval{AgentID: agent.ID, AgentName: agent.Name, Action: name, Summary: s.red.String(summary), GateReason: gateReason(a), DefDigest: a.DefDigest, Origin: approvalOrigin(ctx)}
		appr.CredentialBindings, err = s.bindCredentials(a, args)
		if err != nil {
			return 500, map[string]any{"error": "could not bind approval credentials"}
		}
		if fam, _ := ctx.Value(ctxGrantFamily).(string); fam != "" {
			appr.GrantFamily = fam
		}
		appr.Args, _ = json.Marshal(args)
		appr.Args = json.RawMessage(s.red.Bytes(appr.Args))
		if err := s.store.CreateApproval(appr); err != nil {
			return 500, map[string]any{"error": err.Error()}
		}
		s.store.Audit(agent.Name, name, "held", 0, appr.ID+" "+appr.Summary)
		return 202, map[string]any{
			"status":      "held",
			"approval_id": appr.ID,
			"summary":     appr.Summary,
			"message":     "This " + appr.GateReason + " action is waiting for the owner's approval in RalX (http://localhost:" + s.port + "). Check back with the approval id; do not retry the call.",
		}
	}
	res, err := s.execute(ctx, agent, a, args)
	if err != nil {
		s.store.Audit(agent.Name, name, "error", time.Since(start), s.red.String(actionAuditArgs(name, args)+" → "+err.Error()))
		return 502, map[string]any{"error": err.Error()}
	}
	outcome := "ok"
	if name == "browser.sign_in" || name == "browser.sign_up" || name == "browser.account_text" || name == "browser.fill" {
		var result struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(res, &result) == nil {
			switch result.Status {
			case "signed_in", "failed", "needs_approval", "filled":
				outcome = result.Status
			}
		}
	}
	s.store.Audit(agent.Name, name, outcome, time.Since(start), s.red.String(actionAuditArgs(name, args)))
	return 200, map[string]any{"status": "ok", "result": res}
}

// approvalOrigin records how the request that is queuing an approval was
// authenticated, so unknown-provenance (legacy) rows are never trusted to run
// later (Astra A6). An OAuth request carries a grant family; an agent key does
// not.
func approvalOrigin(ctx context.Context) string {
	if fam, _ := ctx.Value(ctxGrantFamily).(string); fam != "" {
		return "oauth"
	}
	return "key"
}

// needsSocialProfile reports whether a gated Upload-Post action is bound to a
// specific social profile (the identity/audience it posts under or deletes from).
func needsSocialProfile(name string) bool {
	return name == "social.post" || name == "social.unpublish"
}

// defaultSocialProfile is the owner's default Upload-Post profile, or "".
func (s *Server) defaultSocialProfile() string {
	if c, err := s.store.GetCredential("uploadpost"); err == nil {
		p, _ := c.Meta["profile"].(string)
		return p
	}
	return ""
}

// googleServiceOf maps a Google action name to its account service, or "".
func googleServiceOf(name string) string {
	switch {
	case strings.HasPrefix(name, "gmail."):
		return "gmail"
	case strings.HasPrefix(name, "drive."):
		return "drive"
	case strings.HasPrefix(name, "youtube."):
		return "youtube"
	}
	return ""
}

func gateReason(a *actions.Action) string {
	if a.GateReason != "" {
		return a.GateReason
	}
	return "sensitive"
}

// normalizeNumbers converts json.Number values to float64 for validation.
func normalizeNumbers(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch x := v.(type) {
		case json.Number:
			if f, err := x.Float64(); err == nil {
				out[k] = f
			} else {
				out[k] = x.String()
			}
		case []any:
			out[k] = x
		default:
			out[k] = v
		}
	}
	return out
}

// runApproval executes an approved action under the requesting agent's
// identity, exactly with the arguments the owner saw.
func (s *Server) runApproval(id string) {
	appr, err := s.store.GetApproval(id)
	if err != nil || appr.Status != "approved" {
		return
	}
	start := time.Now()
	finish := func(res json.RawMessage, e error) {
		msg := ""
		if e != nil {
			msg = s.red.String(e.Error())
		}
		_ = s.store.FinishApproval(id, res, msg)
		outcome := "executed"
		if e != nil {
			outcome = "failed"
		}
		s.store.Audit(appr.AgentName, appr.Action, outcome, time.Since(start), id+" "+s.red.String(msg))
	}
	agent, err := s.store.GetAgent(appr.AgentID)
	if err != nil || agent.RevokedAt != 0 {
		finish(nil, errors.New("the requesting agent has been revoked"))
		return
	}
	// An approval with no recorded provenance can't be authenticated as agent-key
	// or OAuth work; a grant revoked before this binary's upgrade would leave
	// exactly such a row with no token to map it to. Never run it (Astra A6).
	if appr.Origin == "" {
		finish(nil, errors.New("this approval predates provenance tracking and can't be authenticated; request it again"))
		return
	}
	// If the OAuth grant that queued this action was revoked while it waited,
	// don't run it: revocation must cancel the grant's pending work, not just
	// block new requests (Astra N9).
	if appr.GrantFamily != "" && s.store.FamilyRevoked(appr.GrantFamily) {
		finish(nil, errors.New("the grant that requested this action has been revoked"))
		return
	}
	// Re-check the agent's policy at run time: if it was narrowed to forbid
	// this action while the approval was pending, don't run it (Astra finding 5).
	if !actions.Allowed(appr.Action, agent.Policy.Allow, agent.Policy.Deny) {
		finish(nil, errors.New("this action is no longer allowed for the agent"))
		return
	}
	a, ok := s.reg.Get(appr.Action)
	if !ok {
		finish(nil, errors.New("action no longer exists"))
		return
	}
	// If the action carries a definition digest (an upstream tool) it must match
	// the one recorded at approval. Keying off the action's digest (not the
	// approval's) also refuses a legacy approval whose digest is empty against a
	// now-digested action (Astra R7/A5).
	if a.DefDigest != "" && appr.DefDigest != a.DefDigest {
		finish(nil, errors.New("this action's definition changed since it was approved"))
		return
	}
	// Client-streamed uploads (drive.upload) can't be run server-side; the
	// approval stays "approved" and the agent re-starts the upload with the
	// approval id, which marks it executed once the bytes are moving.
	if a.Stream {
		return
	}
	var raw map[string]any
	dec := json.NewDecoder(strings.NewReader(string(appr.Args)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		finish(nil, err)
		return
	}
	args, err := a.Validate(normalizeNumbers(raw))
	if err != nil {
		finish(nil, err)
		return
	}
	// A gated Google action must have had an account bound at approval. A legacy
	// row with no account would otherwise resolve to whatever became the default
	// after approval (Astra A3 no-default); refuse it.
	if svc := googleServiceOf(appr.Action); svc != "" {
		if acct, _ := args["account"].(string); acct == "" {
			finish(nil, errors.New("this Google action has no account bound to its approval; request it again"))
			return
		}
	}
	// Likewise refuse a gated social action whose approval never bound a profile
	// (Astra A3 counterpart).
	if needsSocialProfile(appr.Action) {
		if p, _ := args["profile"].(string); p == "" {
			finish(nil, errors.New("this social action has no profile bound to its approval; request it again"))
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	ctx, err = s.approvalCredentials(ctx, appr, a, args)
	if err != nil {
		finish(nil, err)
		return
	}
	res, err := s.execute(ctx, agent, a, args)
	finish(res, err)
}
