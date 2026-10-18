package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpgradeVersionDetection(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		same bool
	}{{"0.1.0", "v0.1.0", true}, {"0.1.0-combined-7cb1de2", "0.1.0", false}, {"0.1.0-dev", "0.1.0-dev", true}, {"0.1.1", "0.1.0", false}} {
		if got := sameUpgradeVersion(tt.a, tt.b); got != tt.same {
			t.Fatalf("%q %q: %v", tt.a, tt.b, got)
		}
	}
	if e := checkUpgradeDirection("0.1.0-combined-7cb1de2", "0.1.0"); e != nil {
		t.Fatal(e)
	}
	if e := checkUpgradeDirection("0.2.0", "0.1.0"); e == nil {
		t.Fatal("newer install would be downgraded")
	}
	if e := checkUpgradeDirection("0.1.0", "0.1.0-dev"); e == nil {
		t.Fatal("stable install would be downgraded")
	}
}
func TestUpgradeOnlineBackupRollback(t *testing.T) {
	binary := os.Getenv("RALX_TEST_BINARY")
	if binary == "" {
		t.Skip("set RALX_TEST_BINARY to test the verified release executable")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	t.Setenv("RALX_SETUP_SANDBOX", "1")
	data := filepath.Join(home, "data")
	if e := os.MkdirAll(data, 0700); e != nil {
		t.Fatal(e)
	}
	old := filepath.Join(home, "old.exe")
	if e := copyUpgradeFile(binary, old, 0700); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(data, "ralx.db"))+"?_pragma=journal_mode(WAL)")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec("CREATE TABLE proof (value TEXT); INSERT INTO proof VALUES ('committed WAL data')"); e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(data, "vault.key")
	_ = os.WriteFile(key, []byte("synthetic-key-blob"), 0600)
	l := upgradeLayout{Binary: old, Data: data, Addr: "127.0.0.1:27317"}
	target := filepath.Join(home, "new.exe")
	dir, e := makeUpgradeBackup(l, target)
	if e != nil {
		t.Fatal(e)
	}
	m, e := readUpgradeBackup(dir)
	if e != nil {
		t.Fatal(e)
	}
	var snapshot string
	for _, f := range m.Files {
		if f.Source == filepath.Join(data, "ralx.db") {
			snapshot = filepath.Join(dir, f.Copy)
		}
	}
	sdb, e := sql.Open("sqlite", "file:"+filepath.ToSlash(snapshot)+"?mode=ro")
	if e != nil {
		t.Fatal(e)
	}
	var got string
	e = sdb.QueryRow("SELECT value FROM proof").Scan(&got)
	sdb.Close()
	if e != nil || got != "committed WAL data" {
		t.Fatal("committed WAL not backed up", e)
	}
	db.Close()
	_ = os.WriteFile(key, []byte("changed"), 0600)
	_ = os.WriteFile(filepath.Join(data, "new-file"), []byte("remove on rollback"), 0600)
	if e = saveSetup(setupState{Mode: "local", Data: filepath.Join(home, "another-instance"), Addr: l.Addr, Exe: target}); e != nil {
		t.Fatal(e)
	}
	if e = restoreUpgrade(context.Background(), dir); e == nil || !strings.Contains(e.Error(), "another RalX setup") {
		t.Fatal("rollback accepted another instance", e)
	}
	if b, _ := os.ReadFile(key); string(b) != "changed" {
		t.Fatal("wrong-instance rollback changed data")
	}
	if e = os.Remove(setupStatePath()); e != nil {
		t.Fatal(e)
	}
	if e = restoreUpgrade(context.Background(), dir); e != nil {
		t.Fatal(e)
	}
	for _, f := range m.Files {
		h, e := fileDigest(f.Source)
		if e != nil || h != f.SHA256 {
			t.Fatalf("restore differs: %s (%v)", f.Source, e)
		}
	}
	if _, e = os.Stat(filepath.Join(data, "new-file")); !os.IsNotExist(e) {
		t.Fatal("new data file survived rollback")
	}
	_ = os.WriteFile(filepath.Join(dir, m.Files[0].Copy), []byte("tampered"), 0600)
	if _, e = readUpgradeBackup(dir); e == nil || !strings.Contains(e.Error(), "hash mismatch") {
		t.Fatal("tampered backup accepted", e)
	}
}
