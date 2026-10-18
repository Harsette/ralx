package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const approvalGeneration = "_approval_generation"

func replacementMeta(meta map[string]any) map[string]any {
	out := make(map[string]any, len(meta)+1)
	for k, v := range meta {
		out[k] = v
	}
	out[approvalGeneration] = NewID("")
	return out
}

// CredentialIdentity excludes display/default/refresh bookkeeping. Owner replace,
// delete/recreate, host restrictions and account/profile changes invalidate it;
// a same-account CAS refresh preserves it. No secret digest is exposed to agents.
func CredentialIdentity(c *Credential) string {
	meta := map[string]any{}
	for k, v := range c.Meta {
		switch k {
		case "status", "last_refresh", "default", "default_for", "services":
			continue
		}
		meta[k] = v
	}
	b, err := json.Marshal([]any{c.ID, c.Name, c.Kind, c.Provider, meta})
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type credentialBindingsKey struct{}

func WithCredentialBindings(ctx context.Context, bindings map[string]string) context.Context {
	return context.WithValue(ctx, credentialBindingsKey{}, bindings)
}

// CheckCredentialBinding is called on the same row snapshot used for attachment.
// An unrecorded dependency in an approved execution is refused, including legacy
// approvals. Ordinary reads without an approval context retain existing behavior.
func CheckCredentialBinding(ctx context.Context, c *Credential) error {
	bindings, bound := ctx.Value(credentialBindingsKey{}).(map[string]string)
	if !bound {
		return nil
	}
	if expected := bindings[c.Name]; expected == "" || expected != CredentialIdentity(c) {
		return errors.New("credential identity changed since approval; request it again")
	}
	return nil
}

func (s *Store) BoundSecret(ctx context.Context, name string) (*Credential, map[string]string, error) {
	c, fields, err := s.SecretWithMeta(name)
	if err != nil {
		return nil, nil, err
	}
	if err := CheckCredentialBinding(ctx, c); err != nil {
		return nil, nil, err
	}
	return c, fields, nil
}
