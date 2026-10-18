package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/browserlogin"
	"github.com/Harsette/ralx/internal/logins"
	"github.com/Harsette/ralx/internal/store"
)

func stringArg(args map[string]any, key string) string { v, _ := args[key].(string); return v }
func actionAuditArgs(name string, args map[string]any) string {
	if name == "logins.new_test" {
		return "website test login generated"
	}
	if name == "browser.fill" || name == "browser.sign_in" || name == "browser.sign_up" || name == "browser.account_text" {
		safe := map[string]any{}
		for _, k := range []string{"login_id", "field"} {
			if v, ok := args[k]; ok {
				safe[k] = v
			}
		}
		return argsDigest(safe)
	}
	return argsDigest(args)
}

// Decrypt only for the signed-in owner's existing approval card. SQLite keeps
// the generic summary and keyed origin hash, never this display text.
func (s *Server) browserApprovalDisplay(ap *store.Approval) {
	if ap.Action != "browser.authorize" {
		return
	}
	var args map[string]any
	if json.Unmarshal(ap.Args, &args) != nil {
		return
	}
	l, e := logins.ResolveHash(s.store, stringArg(args, "login_id"), stringArg(args, "origin_hash"))
	if e != nil {
		return
	}
	ap.Summary = s.red.String("Allow website login " + l.Username + " on " + l.Origin + " (" + l.ID + ")")
}
func (s *Server) ownerLogins() []*logins.Login {
	out := []*logins.Login{}
	creds, e := s.store.ListCredentials()
	if e != nil {
		return out
	}
	for _, c := range creds {
		if c.Kind != logins.CredentialKind {
			continue
		}
		if l, e := logins.Get(s.store, c.Name); e == nil {
			out = append(out, l)
		}
	}
	return out
}
func (s *Server) loginGrantKey(l *logins.Login, origin string) string {
	h := sha256.Sum256([]byte(l.ID + "|" + s.store.LoginOriginHash(origin) + "|" + store.CredentialIdentity(l.Credential)))
	return "browser_login_grant:" + hex.EncodeToString(h[:])
}

func (s *Server) registerBrowserLogins() error {
	s.browser = browserlogin.New(s.cfg.DataDir, s.vaultScrub)
	params := []actions.Param{
		{Name: "login_id", Type: "string", MaxLen: 100, Description: "Opaque website login id. Omit on sign-in only when exactly one login matches."},
		{Name: "url", Type: "string", MaxLen: 4096, Description: "Website sign-up/sign-in URL, or optional URL to navigate before browser_fill."},
		{Name: "target", Type: "string", MaxLen: 1024, Default: "managed", Description: "managed (headless Chrome), managed-edge, or an HTTP/WS CDP endpoint on literal loopback. Returns cdp_endpoint for your browser tool."},
		{Name: "target_id", Type: "string", MaxLen: 256, Description: "Existing CDP page id. Omit to use RalX's tab; attached endpoints get a new owned tab."},
	}
	list := []*actions.Action{
		{Name: "logins.new_test", Risk: actions.Write, Description: "Generate and seal a strong test-account password. Returns login_id, username and origin only. Then use browser_sign_up -> browser_sign_in -> browser_account_text; no shell needed. Never ask for or read the password.", Params: []actions.Param{{Name: "origin", Type: "string", Required: true, MaxLen: 2048}, {Name: "username", Type: "string", MaxLen: 254}, {Name: "clerk_test", Type: "boolean", Description: "Generate a +clerk_test@example.com address for Clerk test-mode email verification. Never sends a real email code."}}, Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
			l, p, e := logins.NewTest(s.store, stringArg(args, "origin"), stringArg(args, "username"), args["clerk_test"] == true)
			if e != nil {
				return nil, e
			}
			s.red.Add(l.ID+":password", p)
			return map[string]any{"login_id": l.ID, "username": l.Username, "origin": l.Origin}, nil
		}},
		{Name: "browser.authorize", Risk: actions.Gated, GateReason: "sensitive", SummaryTemplate: "Allow website login {login_id} for the selected exact origin", Description: "Remember one human-approved login and exact origin. Normally requested by browser_fill/browser_sign_up/browser_sign_in. Approve through RalX, then retry the browser operation.", Params: []actions.Param{{Name: "login_id", Type: "string", Required: true, MaxLen: 100}, {Name: "origin_hash", Type: "string", Required: true, MaxLen: 64}}, Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
			l, e := logins.ResolveHash(s.store, stringArg(args, "login_id"), stringArg(args, "origin_hash"))
			if e != nil {
				return nil, e
			}
			origin := l.Origin
			// Only runApproval carries a binding. This action is always gated, never
			// callable by an agent as an ordinary direct native action.
			if _, e = logins.Password(ctx, s.store, l); e != nil {
				return nil, e
			}
			if e = s.store.SetSetting(s.loginGrantKey(l, origin), "approved"); e != nil {
				return nil, errors.New("cannot remember login approval")
			}
			return map[string]any{"status": "approved", "login_id": l.ID, "origin_hash": s.store.LoginOriginHash(origin)}, nil
		}},
	}
	const honesty = " Passwords never enter the agent's conversation through RalX. An agent with raw browser debugging access to the same page could still read a filled field before submit; browser_sign_up/sign_in submit immediately to keep that window minimal."
	for _, kind := range []string{"fill", "sign_in", "sign_up", "account_text"} {
		kind := kind
		p := append([]actions.Param{}, params...)
		if kind == "fill" {
			p = append(p, actions.Param{Name: "field", Type: "string", Required: true, Enum: []string{"username", "password"}}, actions.Param{Name: "selector", Type: "string", MaxLen: 1024, Description: "Optional CSS selector. Password fills require a visible password input."})
		} else if kind != "account_text" {
			p = append(p, actions.Param{Name: "success_selector", Type: "string", MaxLen: 1024, Description: "Optional authenticated-page selector. Must be visible after password fields disappear."})
		}
		if kind == "sign_up" || kind == "account_text" {
			p[0].Required = true
		}
		if kind == "sign_in" || kind == "sign_up" {
			p[1].Required = true
		}
		if kind == "account_text" {
			p = append(p[:1], p[2:4]...)
		}
		list = append(list, &actions.Action{Name: "browser." + kind, Risk: actions.Write, Description: map[string]string{"fill": "Fill an odd-form username/password field without submitting. Prefer logins_new_test -> browser_sign_up -> browser_sign_in for test accounts; no shell needed.", "sign_up": "Create a website account using a vault login. Start with logins_new_test, then browser_sign_up at the signup URL, then browser_sign_in. Fills identifier, password and confirmation, handles Continue flows and immediately submits. Returns signed_in/failed/needs_approval/needs_verification, session_file (Playwright storageState), cdp_endpoint. If needs_approval, check ralx_approval then retry.", "sign_in": "Sign in using a vault login, including identifier/Continue/password flows. Use logins_new_test -> browser_sign_up -> browser_sign_in. Returns signed_in/failed/needs_approval/needs_verification, session_file (Playwright storageState), cdp_endpoint. Then browser_account_text reads the verified account page without shell or raw browser debugging. If needs_approval, check ralx_approval then retry.", "account_text": "Read scrubbed text only from this agent's exact verified success page after browser_sign_up/browser_sign_in. Cannot navigate, inspect inputs, or read pages containing password fields. Returns text; use it to report the account page without shell/browser debugging."}[kind] + honesty, Params: p, Native: func(ctx context.Context, env actions.Env, args map[string]any) (any, error) {
			return s.browserLogin(ctx, env.(*actionEnv), kind, args)
		}})
	}
	for _, a := range list {
		if e := s.reg.Add(a); e != nil {
			return e
		}
	}
	return nil
}

func (s *Server) browserLogin(ctx context.Context, env *actionEnv, kind string, args map[string]any) (any, error) {
	rawURL := stringArg(args, "url")
	id := stringArg(args, "login_id")
	// For a fill without navigation, use the explicitly selected login origin.
	origin := ""
	if rawURL != "" {
		var e error
		origin, e = logins.Origin(rawURL)
		if e != nil {
			return nil, e
		}
	} else {
		if kind == "sign_in" || kind == "sign_up" || id == "" {
			return nil, errors.New("url is required for sign-in/sign-up; login_id is required for fill/read")
		}
		login, e := logins.Get(s.store, id)
		if e != nil {
			return nil, e
		}
		if len(login.Origins) != 1 {
			return nil, errors.New("supply url for a login with multiple origins")
		}
		origin = login.Origin
	}
	l, e := logins.Resolve(s.store, id, origin)
	if e != nil {
		return nil, e
	}
	if !l.Automatic(origin) && s.store.Setting(s.loginGrantKey(l, origin)) != "approved" {
		// Reuse a pending identical request; a denial remains denied until a new
		// explicit authorization request, rather than silently creating retries.
		grantArgs := map[string]any{"login_id": l.ID, "origin_hash": s.store.LoginOriginHash(origin)}
		b, _ := json.Marshal(grantArgs)
		pending, _ := s.store.ListApprovals("pending", 200)
		for _, ap := range pending {
			if ap.AgentID == env.agent.ID && ap.Action == "browser.authorize" && string(ap.Args) == string(b) {
				return browserlogin.Result{Status: "needs_approval", Username: l.Username, ApprovalID: ap.ID, Reason: "approve this login and exact origin in RalX, then retry"}, nil
			}
		}
		denied, _ := s.store.ListApprovals("denied", 200)
		for _, ap := range denied {
			if ap.AgentID == env.agent.ID && ap.Action == "browser.authorize" && string(ap.Args) == string(b) {
				return browserlogin.Result{Status: "needs_approval", Username: l.Username, ApprovalID: ap.ID, Reason: "human denied this login; a new explicit browser_authorize request is required"}, nil
			}
		}
		_, out := s.callAction(ctx, env.agent, "browser.authorize", grantArgs)
		if ap, ok := out["approval_id"].(string); ok {
			return browserlogin.Result{Status: "needs_approval", Username: l.Username, ApprovalID: ap, Reason: "approve this login and exact origin in RalX, then retry"}, nil
		}
		return nil, errors.New("login approval could not be requested")
	}
	password, e := logins.Password(ctx, s.store, l)
	if e != nil {
		return nil, e
	}
	s.red.Add(l.ID+":password", password)
	r := browserlogin.Request{LoginID: l.ID, Origin: origin, URL: rawURL, Target: stringArg(args, "target"), TargetID: stringArg(args, "target_id"), Field: stringArg(args, "field"), Selector: stringArg(args, "selector"), SuccessSelector: stringArg(args, "success_selector")}
	var out browserlogin.Result
	if kind == "fill" {
		value := l.Username
		if r.Field == "password" {
			value = password
		}
		out, e = s.browser.Fill(ctx, env.agent.ID, r, value)
	} else if kind == "sign_up" {
		out, e = s.browser.SignUp(ctx, env.agent.ID, r, l.Username, password)
	} else if kind == "account_text" {
		out, e = s.browser.AccountText(ctx, env.agent.ID, r)
	} else {
		out, e = s.browser.SignIn(ctx, env.agent.ID, r, l.Username, password)
	}
	out.Username = l.Username
	return out, e
}

// The signed-in human saves a write-only login without another approval ceremony.
// localAdminOnly supplies the existing owner session, locality and CSRF checks.
func (s *Server) handleAddLogin(w http.ResponseWriter, r *http.Request, ac adminCtx) {
	body, e := readBody(r)
	if e != nil {
		s.fail(w, 400, "invalid website login")
		return
	}
	origin, e := logins.Origin(rawString(body, "website"))
	if e != nil {
		s.fail(w, 400, "invalid website login")
		return
	}
	id := store.NewID("login_")
	password := rawString(body, "password")
	_, e = s.store.CreateCredential(id, logins.CredentialKind, "website", "", map[string]any{"origins": []string{origin}, "kind": "real", "created_by": "human"}, map[string]string{"password": password, "username": rawString(body, "username"), "name": rawString(body, "name")})
	if e != nil {
		s.fail(w, 400, "invalid website login")
		return
	}
	s.red.Add(id+":password", password)
	s.store.Audit("owner", "login.add", "saved", 0, id)
	writeJSON(w, 200, map[string]any{"login_id": id})
}
