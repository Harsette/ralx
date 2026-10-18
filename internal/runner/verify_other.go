//go:build !windows

package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func TrustSID(string) {}

// VerifyToolPath requires the tool binary and every parent directory to be
// owned by root (or the daemon user) and not group/world writable. It checks
// two chains:
//
//   - the resolved real file and its real ancestors (EvalSymlinks), so a tool
//     that is a symlink into an agent-writable directory is caught by its real
//     target and real parents; and
//   - the original routing directories, so a symlink sitting in an
//     agent-writable directory is rejected even when its current target is
//     safe, because that link can be re-pointed after this check (Astra N8).
//
// The caller runs the returned canonical path (the single resolution checked
// here), never the original, so there is no second resolution to race and no
// fallback to an unverified path (Astra R11).
func VerifyToolPath(p string) (string, error) {
	return verifyToolPath(p, false)
}

// VerifyToolPathInManagedSandbox explicitly trusts only the platform-provided
// read-only namespace root. Use a self-owned TMPDIR; unknown /tmp owners still
// fail. This is for a trusted development sandbox, never production defaults.
func VerifyToolPathInManagedSandbox(p string) (string, error) {
	return verifyToolPath(p, true)
}

func verifyToolPath(p string, trustedSandbox bool) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	if err := verifyOwnedChain(real, trustedSandbox); err != nil {
		return "", err
	}
	// The directories the original path routes through must also be safe: a
	// writable one lets an attacker replace the entry (a symlink or the file)
	// after verification.
	if err := verifyOwnedChain(filepath.Dir(abs), trustedSandbox); err != nil {
		return "", err
	}
	return real, nil
}

// verifyOwnedChain walks start and every ancestor up to the root, requiring each
// to be owned by root or the daemon user and not group/world writable. A sticky
// world-writable directory such as /tmp is allowed as an ancestor because others
// cannot replace entries they do not own. Each component is resolved (os.Stat),
// so a symlinked directory is judged by its real target rather than the
// meaningless mode bits of the link itself.
func verifyOwnedChain(start string, trustedSandbox bool) error {
	self := os.Getuid()
	for cur := start; ; cur = filepath.Dir(cur) {
		fi, err := os.Stat(cur)
		if err != nil {
			return err
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 && int(st.Uid) != self &&
			!(fi.IsDir() && namespaceDirectoryOwner(cur, st.Uid, self, trustedSandbox)) {
			return fmt.Errorf("%s is owned by uid %d, which could replace it", cur, st.Uid)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			if !(fi.IsDir() && fi.Mode()&os.ModeSticky != 0) {
				return fmt.Errorf("%s is group/world writable", cur)
			}
		}
		if filepath.Dir(cur) == cur {
			return nil
		}
	}
}
