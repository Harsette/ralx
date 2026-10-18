package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/google"
	"github.com/Harsette/ralx/internal/store"
)

func (s *Server) bindCredentials(a *actions.Action, args map[string]any) (string, error) {
	names := map[string]bool{}
	if a.Name == "browser.authorize" {
		if name, _ := args["login_id"].(string); name != "" {
			names[name] = true
		}
	}
	// Upstream MCP already binds its definition, auth and generation at dispatch.
	if a.DefDigest == "" {
		for _, name := range a.Requires {
			if name != "google" {
				names[name] = true
			}
		}
		if a.CLI != nil {
			for _, ref := range a.CLI.Env {
				if name, _, ok := actions.ParseSecretRef(ref); ok {
					names[name] = true
				}
			}
		}
		if a.Name == "http.request" {
			url, _ := args["url"].(string)
			body, _ := args["body"].(string)
			for _, ref := range placeholderRe.FindAllStringSubmatch(url+"\n"+strings.Join(httpHeaderLines(args), "\n")+"\n"+body, -1) {
				names[ref[1]] = true
			}
		}
		if googleServiceOf(a.Name) != "" {
			account, _ := args["account"].(string)
			names["google:"+strings.ToLower(account)] = true
			names[google.ClientCredential] = true
		}
	}
	bindings := map[string]string{}
	for name := range names {
		c, err := s.store.GetCredential(name)
		if errors.Is(err, store.ErrNotFound) {
			bindings[name] = "missing"
			continue
		}
		if err != nil {
			return "", err
		}
		bindings[name] = store.CredentialIdentity(c)
	}
	b, err := json.Marshal(bindings)
	return string(b), err
}

func (s *Server) approvalCredentials(ctx context.Context, ap *store.Approval, a *actions.Action, args map[string]any) (context.Context, error) {
	expected := map[string]string{}
	if ap.CredentialBindings == "" {
		// Legacy approvals without credential dependencies still work. Credential-
		// bearing approvals require a new assertion after the upgrade.
		current, err := s.bindCredentials(a, args)
		if err != nil || current != "{}" {
			return nil, errors.New("approval predates credential identity binding; request it again")
		}
	} else if err := json.Unmarshal([]byte(ap.CredentialBindings), &expected); err != nil || expected == nil {
		return nil, errors.New("invalid approval credential binding")
	}
	for name, identity := range expected {
		c, err := s.store.GetCredential(name)
		if err != nil || identity != store.CredentialIdentity(c) {
			return nil, errors.New("credential identity changed since approval; request it again")
		}
	}
	return store.WithCredentialBindings(ctx, expected), nil
}
