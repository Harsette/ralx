//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestUpgradeBackupOwnerIsTheUser(t *testing.T) {
	dir := t.TempDir()
	if e := secureUpgradeDir(dir); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "manifest.json")
	if e := os.WriteFile(file, []byte("synthetic backup manifest"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := finishUpgradeBackup(dir); e != nil {
		t.Fatal(e)
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{dir, file} {
		sd, e := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if e != nil {
			t.Fatal(e)
		}
		owner, _, e := sd.Owner()
		if e != nil || owner.String() != user.User.Sid.String() {
			t.Fatalf("backup owner differs from user: %s (%v)", p, e)
		}
	}
}

func TestUpgradeLockedPriorImageDoesNotBlockRollback(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "ralx.exe")
	previous := dst + ".ralx-replaced"
	for _, p := range []string{dst, previous} {
		if e := os.WriteFile(p, []byte("synthetic-old-image"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	name, _ := windows.UTF16PtrFromString(previous)
	handle, e := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(handle)
	if e = os.Remove(previous); e == nil {
		t.Fatal("negative control: old image is not locked")
	}
	candidate := filepath.Join(dir, "candidate.exe")
	if e = os.WriteFile(candidate, []byte("synthetic-new-image"), 0600); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e = replaceUpgradeBinaryOrFile(candidate, dst, 0700); e != nil {
			t.Fatalf("swap %d blocked by prior mapped image: %v", i, e)
		}
	}
	got, e := os.ReadFile(dst)
	if e != nil || string(got) != "synthetic-new-image" {
		t.Fatal("replacement differs", e)
	}
}
