//go:build !windows

package runner

import (
	"os"
	"path/filepath"
	"testing"
)

// Astra 8: a tool that is a symlink into an agent-writable directory must be
// rejected, because the real target can be swapped after verification.
func TestVerifyToolPathFollowsSymlinkTargetAncestors(t *testing.T) {
	root := t.TempDir()

	// A world-writable directory holding the real binary. Mkdir's mode is
	// filtered by the process umask (0755 under the usual 0022), so force the
	// permissions explicitly and confirm they stuck, instead of changing the
	// process-wide umask in a test.
	writable := filepath.Join(root, "writable")
	if err := os.Mkdir(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(writable); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm()&0o022 == 0 {
		t.Fatal("fixture is not group/world writable")
	}
	target := filepath.Join(writable, "tool")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A safe directory holding only a symlink to the real binary.
	safe := filepath.Join(root, "safe")
	if err := os.Mkdir(safe, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(safe, "tool")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := VerifyToolPathInManagedSandbox(link); err == nil {
		t.Fatal("symlink into a world-writable directory was accepted")
	}

	// A plain binary under a safe, non-writable directory still passes.
	okBin := filepath.Join(safe, "ok")
	if err := os.WriteFile(okBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToolPathInManagedSandbox(okBin); err != nil {
		t.Fatalf("safe binary rejected: %v", err)
	}
}

// Astra N8 (reverse direction): a symlink that itself sits in an agent-writable
// directory must be rejected even when its current target is safe, because the
// link can be re-pointed after verification. The old code only walked the
// resolved target's ancestors and accepted it.
func TestVerifyToolPathRejectsWritableOriginalRouting(t *testing.T) {
	root := t.TempDir()

	trusted := filepath.Join(root, "trusted")
	if err := os.Mkdir(trusted, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(trusted, "tool")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	writable := filepath.Join(root, "writable")
	if err := os.Mkdir(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(writable); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm()&0o022 == 0 {
		t.Fatal("fixture is not group/world writable")
	}
	link := filepath.Join(writable, "tool")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := VerifyToolPathInManagedSandbox(link); err == nil {
		t.Fatal("symlink in a world-writable directory was accepted despite a safe target")
	}
}
