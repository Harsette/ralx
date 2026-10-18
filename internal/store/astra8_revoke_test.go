package store

import (
	"github.com/Harsette/ralx/internal/secretbox"
	"path/filepath"
	"testing"
	"time"
)

func TestAstra8FixRevokedFamilyAccessDeniedAfterDeleteFailure(t *testing.T) {
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(t.TempDir(), "fixture.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, _, err := s.CreateAgent("a8-revoke", Policy{})
	if err != nil {
		t.Fatal(err)
	}
	access, refresh, err := s.IssueTokens(a.ID, "synthetic-client", "synthetic-family", "https://hub.example/mcp", "ralx", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic storage-failure injection, not an attacker permission assumption.
	if _, err := s.db.Exec(`CREATE TRIGGER astra8_delete_fault BEFORE DELETE ON oauth_tokens BEGIN SELECT RAISE(ABORT, 'synthetic delete failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(refresh); err == nil {
		t.Fatal("cleanup failure was hidden")
	}
	if !s.FamilyRevoked("synthetic-family") {
		t.Fatal("fixture did not persist revocation")
	}
	_, _, err = s.AuthenticateAccessToken(access)
	if err == nil {
		t.Fatalf("revoked access was accepted: err=%v", err)
	}
	if _, err := s.RedeemRefresh(refresh, "synthetic-client"); err == nil {
		t.Fatal("refresh control should see tombstone")
	}
	t.Log("family tombstone persists despite cleanup error; access and refresh both denied")
}
