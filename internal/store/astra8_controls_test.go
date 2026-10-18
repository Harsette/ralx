package store

import (
	"context"
	"github.com/Harsette/ralx/internal/secretbox"
	"path/filepath"
	"testing"
	"time"
)

func astra8Store(t *testing.T) *Store {
	t.Helper()
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(t.TempDir(), "fixture.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAstra8FixRevokeControlsAndFailure(t *testing.T) {
	s := astra8Store(t)
	a, _, err := s.CreateAgent("fixture", Policy{})
	if err != nil {
		t.Fatal(err)
	}
	at, rt, err := s.IssueTokens(a.ID, "client-a", "family-a", "https://hub.example/mcp", "ralx", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthenticateAccessToken(at); err != nil {
		t.Fatal("legitimate access failed", err)
	}
	if err := s.RevokeTokenForClient(rt, "client-b"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthenticateAccessToken(at); err != nil {
		t.Fatal("cross-client revoke affected owner")
	}
	if err := s.RevokeTokenForClient("unknown", "client-a"); err != nil {
		t.Fatal("unknown revoke disclosed state")
	}
	if _, err := s.db.Exec(`CREATE TRIGGER refuse_tombstone BEFORE INSERT ON oauth_revoked_families BEGIN SELECT RAISE(ABORT, 'synthetic insert failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(rt); err == nil {
		t.Fatal("tombstone failure hidden")
	}
	if _, err := s.db.Exec(`DROP TRIGGER refuse_tombstone`); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(rt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthenticateAccessToken(at); err == nil {
		t.Fatal("normal revoke did not deny")
	}
	if _, _, err := s.IssueTokens(a.ID, "client-a", "family-a", "https://hub.example/mcp", "ralx", time.Hour, time.Hour); err == nil {
		t.Fatal("revoked family reissued")
	}
	s.Close()
	if !s.FamilyRevoked("unknown") {
		t.Fatal("revocation lookup failure was safe")
	}
}

func TestAstra8FixCredentialBindingMetadataAndRefresh(t *testing.T) {
	s := astra8Store(t)
	c, err := s.PutCredential("svc", "api_key", "fixture", "display", map[string]any{"allowed_hosts": []string{"api.example"}}, map[string]string{"token": "SyntheticCredentialA0123456789"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithCredentialBindings(context.Background(), map[string]string{"svc": CredentialIdentity(c)})
	if _, _, err := s.BoundSecret(ctx, "svc"); err != nil {
		t.Fatal("unchanged snapshot refused")
	}
	if err := s.UpdateMeta("svc", map[string]any{"status": "ok", "default": true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.BoundSecret(ctx, "svc"); err != nil {
		t.Fatal("display/default bookkeeping invalidated identity")
	}
	if err := s.UpdateMeta("svc", map[string]any{"allowed_hosts": []string{"other.example"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.BoundSecret(ctx, "svc"); err == nil {
		t.Fatal("host change retained approval")
	}
}
