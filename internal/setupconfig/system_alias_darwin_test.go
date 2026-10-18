package setupconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigMacSystemAliases(t *testing.T) {
	for _, path := range []string{"/var", "/tmp", "/etc"} {
		info, err := os.Lstat(path)
		if err != nil || !macSystemAlias(path, info) {
			t.Fatalf("macOS system alias %s was not recognized: %v", path, err)
		}
	}
	dir, err := os.MkdirTemp("/tmp", "ralx-system-alias-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "config.json")
	if err := Write(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(real); err != nil || string(b) != "{}\n" {
		t.Fatal("write through system alias failed", err)
	}
}

func TestConfigMacRejectsUserSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "original.json")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Write(link, []byte("changed"), 0600); err == nil {
		t.Fatal("accepted a symlink to a user config")
	}
	if err := os.Symlink(dir, filepath.Join(dir, "linked-folder")); err != nil {
		t.Fatal(err)
	}
	if err := Write(filepath.Join(dir, "linked-folder", "new.json"), []byte("changed"), 0600); err == nil {
		t.Fatal("accepted a symlink in a parent folder")
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "unchanged" {
		t.Fatal("original config changed", err)
	}
}
