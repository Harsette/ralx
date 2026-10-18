package store

// Astra 7 control (Held): the origin-provenance migration must fail Open on an UPDATE
// error without marking itself done, and a retry after the fault is removed must deny
// the legacy approval and set the flag. Synthetic fixture DB only.
import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Harsette/ralx/internal/secretbox"
)

func TestAstra7HeldMigrationUpdateError(t *testing.T) {
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.db")
	s, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`DELETE FROM settings WHERE k='mig_deny_unauthenticated_origin';
	INSERT INTO approvals(id,agent_id,agent_name,action,args,summary,gate_reason,status,created_at,expires_at,origin) VALUES('synthetic-approval','synthetic-agent','fixture','test.danger','{}','fixture','deletes','pending',1,9999999999,'');
	CREATE TRIGGER astra7_refuse_deny BEFORE UPDATE ON approvals BEGIN SELECT RAISE(ABORT,'synthetic migration failure'); END;`)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	failed, err := Open(path, box)
	if err == nil {
		failed.Close()
		t.Fatal("migration UPDATE failure did not fail Open")
	}
	if !strings.Contains(err.Error(), "origin provenance migration") {
		t.Fatalf("unexpected error: %v", err)
	}
	// Inspect only this test's fixture database, through the same driver.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err = db.QueryRow(`SELECT COUNT(*) FROM settings WHERE k='mig_deny_unauthenticated_origin'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed migration set flag: n=%d err=%v", n, err)
	}
	if _, err = db.Exec(`DROP TRIGGER astra7_refuse_deny`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ap, err := s.GetApproval("synthetic-approval")
	if err != nil || ap.Status != "denied" || s.Setting("mig_deny_unauthenticated_origin") != "1" {
		t.Fatal("retry did not deny and mark success")
	}
}
