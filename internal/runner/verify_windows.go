//go:build windows

package runner

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Trusted principals may write tool binaries; anyone else being able to
// replace a binary RalX runs with secrets in its environment would be a way
// around the vault, so VerifyToolPath refuses such tools.
var trustedSIDs = map[string]bool{
	"S-1-5-18":     true, // SYSTEM
	"S-1-5-32-544": true, // Administrators
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true, // TrustedInstaller
}

const (
	fileWriteData    = 0x2 // also FILE_ADD_FILE on directories
	fileAppendData   = 0x4 // also FILE_ADD_SUBDIRECTORY
	fileDeleteChild  = 0x40
	deleteRight      = 0x10000
	writeDAC         = 0x40000
	writeOwner       = 0x80000
	genericWrite     = 0x40000000
	genericAll       = 0x10000000
	dangerousFile    = fileWriteData | fileAppendData | deleteRight | writeDAC | writeOwner | genericWrite | genericAll
	dangerousDir     = fileWriteData | fileAppendData | fileDeleteChild | deleteRight | writeDAC | writeOwner | genericWrite | genericAll
	accessAllowedAce = 0
)

// TrustSID adds an extra trusted SID (the RalX service account itself).
func TrustSID(sid string) { trustedSIDs[sid] = true }

// VerifyToolPath returns the verified canonical path; the caller runs exactly
// that (Astra R11).
func VerifyToolPathInManagedSandbox(p string) (string, error) { return VerifyToolPath(p) }

func VerifyToolPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	// Resolve reparse points/symlinks so the caller runs the real file. Fail
	// closed if resolution fails (don't fall back to an unverified path, Astra
	// A15).
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	if err := checkObject(real, dangerousFile); err != nil {
		return "", err
	}
	for dir := filepath.Dir(real); ; dir = filepath.Dir(dir) {
		if err := checkObject(dir, dangerousDir); err != nil {
			return "", err
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return real, nil
}

func checkObject(p string, dangerous uint32) error {
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read ACL of %s: %w", p, err)
	}
	owner, _, err := sd.Owner()
	if err == nil && owner != nil && !trustedSIDs[owner.String()] && !isDriveRoot(p) {
		return fmt.Errorf("%s is owned by %s, which could replace it", p, sidName(owner))
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL of %s: %w", p, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s has no DACL (everyone can write)", p)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != accessAllowedAce || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if trustedSIDs[sid.String()] {
			continue
		}
		if uint32(ace.Mask)&dangerous != 0 {
			if isDriveRoot(p) && uint32(ace.Mask)&(writeDAC|writeOwner|genericAll|fileDeleteChild) == 0 {
				// Authenticated Users may create folders at C:\ by default;
				// that cannot replace anything below a protected folder.
				continue
			}
			return fmt.Errorf("%s is writable by %s", p, sidName(sid))
		}
	}
	return nil
}

func isDriveRoot(p string) bool { return filepath.Dir(p) == p }

func sidName(s *windows.SID) string {
	acct, dom, _, err := s.LookupAccount("")
	if err != nil {
		return s.String()
	}
	if dom != "" {
		return dom + `\` + acct
	}
	return acct
}
