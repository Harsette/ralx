package store

// Astra 7 self-review regression: SecretWithMeta must decrypt the row it read, not a
// stale cache entry, so metadata and fields are a consistent snapshot. Synthetic DB.
import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Harsette/ralx/internal/secretbox"
)

func TestAstra7SelfReviewSecretWithMetaSnapshot(t *testing.T) {
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(t.TempDir(), "fixture.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Version A: cache and row both hold A's fields.
	if _, err := s.PutCredential("svc", "api_key", "svc", "", map[string]any{"allowed_hosts": []any{"old.example"}}, map[string]string{"token": "AAAAAAAAAAAA"}); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetCredential("svc")
	if err != nil {
		t.Fatal(err)
	}
	// Write B directly to the ROW (bypassing the write path, so the cache still holds A):
	// this is the deterministic form of an owner replacement that publishes B into the
	// cache before a pending SecretWithMeta snapshot decrypts.
	plainB, _ := json.Marshal(map[string]string{"token": "BBBBBBBBBBBB"})
	nonceB, ctB, err := box.Seal(plainB, credAD(c.ID, "svc"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE credentials SET ciphertext=?, nonce=? WHERE name=?`, ctB, nonceB, "svc"); err != nil {
		t.Fatal(err)
	}
	_, fields, err := s.SecretWithMeta("svc")
	if err != nil {
		t.Fatal(err)
	}
	if fields["token"] != "BBBBBBBBBBBB" {
		t.Fatalf("defect reproduced: SecretWithMeta returned stale cached fields %q, not the row it read", fields["token"])
	}
}

// UpdateMeta changes only metadata and UpdateFields changes only secret fields; neither
// restores the other half of a different version. (The atomic transaction prevents the
// mixed-row interleaving; this confirms sequential per-call semantics only, not a
// concurrency/race-detector proof.)
func TestAstra7SelfReviewUpdateKeepsOtherHalf(t *testing.T) {
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(t.TempDir(), "fixture.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.PutCredential("svc", "mcp_server", "mcp", "", map[string]any{"url": "https://first.example", "gen": "gen-a"}, map[string]string{"access_token": "AAAAAAAAAAAA"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateMeta("svc", map[string]any{"gen": "gen-b"}); err != nil {
		t.Fatal(err)
	}
	c, fields, err := s.SecretWithMeta("svc")
	if err != nil {
		t.Fatal(err)
	}
	if c.Meta["gen"] != "gen-b" || c.Meta["url"] != "https://first.example" || fields["access_token"] != "AAAAAAAAAAAA" {
		t.Fatalf("UpdateMeta mixed state: gen=%v url=%v token=%q", c.Meta["gen"], c.Meta["url"], fields["access_token"])
	}
	if err := s.UpdateFields("svc", map[string]string{"access_token": "CCCCCCCCCCCC"}); err != nil {
		t.Fatal(err)
	}
	c, fields, err = s.SecretWithMeta("svc")
	if err != nil {
		t.Fatal(err)
	}
	if c.Meta["gen"] != "gen-b" || fields["access_token"] != "CCCCCCCCCCCC" {
		t.Fatalf("UpdateFields mixed state: gen=%v token=%q", c.Meta["gen"], fields["access_token"])
	}
}
