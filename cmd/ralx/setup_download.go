package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Harsette/ralx/internal/setupconfig"
)

func uninstallDownload() error {
	home, _ := os.UserHomeDir()
	p := filepath.Join(home, ".ralx", "install.json")
	b, e := os.ReadFile(p)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var r struct {
		Binary         string `json:"binary"`
		PathAdded      bool   `json:"path_added"`
		Profile        string `json:"profile"`
		ProfileExisted bool   `json:"profile_existed"`
		ProfileBackup  string `json:"profile_backup"`
	}
	if e := json.Unmarshal(b, &r); e != nil {
		return e
	}
	exe, _ := os.Executable()
	if !sameInstallPath(exe, r.Binary) {
		return errors.New("installer binary differs from this executable; remove the installer binary manually")
	}
	if r.PathAdded {
		if e := removeInstallPath(filepath.Dir(r.Binary)); e != nil {
			return e
		}
	}
	if r.Profile != "" {
		b, e := os.ReadFile(r.Profile)
		if e != nil {
			return e
		}
		start := bytes.Index(b, []byte("\n# RalX PATH begin\n"))
		end := bytes.Index(b, []byte("# RalX PATH end\n"))
		if start >= 0 && end >= start {
			b = append(b[:start], b[end+len("# RalX PATH end\n"):]...)
			if !r.ProfileExisted && len(b) == 0 {
				e = os.Remove(r.Profile)
			} else {
				e = setupconfig.Write(r.Profile, b, 0600)
			}
			if e != nil {
				return e
			}
		}
	}
	if r.ProfileBackup != "" {
		if r.ProfileBackup != r.Profile+".ralx-path.bak" {
			return errors.New("PATH profile backup mismatch")
		}
		if e := os.Remove(r.ProfileBackup); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	if e := removeInstalledBinary(r.Binary); e != nil {
		return e
	}
	if e := os.Remove(p); e != nil {
		return e
	}
	fmt.Println("Installer binary and added PATH entry removed (open a new terminal).")
	return nil
}
func sameInstallPath(a, b string) bool {
	aa, e := filepath.Abs(a)
	if e != nil {
		return false
	}
	bb, e := filepath.Abs(b)
	if e != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(aa), filepath.Clean(bb))
	}
	return filepath.Clean(aa) == filepath.Clean(bb)
}

func cmdInstallPath() error {
	if runtime.GOOS == "windows" {
		return errors.New("use install.ps1 on Windows")
	}
	home, _ := os.UserHomeDir()
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	bin := filepath.Dir(exe)
	profile := filepath.Join(home, ".profile")
	if strings.HasSuffix(os.Getenv("SHELL"), "zsh") {
		profile = filepath.Join(home, ".zprofile")
	} else if runtime.GOOS == "darwin" || strings.HasSuffix(os.Getenv("SHELL"), "bash") {
		// Bash reads only the first existing login profile.
		profile = filepath.Join(home, ".bash_profile")
		for _, name := range []string{".bash_profile", ".bash_login", ".profile"} {
			candidate := filepath.Join(home, name)
			if _, e := os.Stat(candidate); e == nil {
				profile = candidate
				break
			}
		}
	}
	original, e := os.ReadFile(profile)
	existed := e == nil
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if bytes.Contains(original, []byte("# RalX PATH begin")) {
		return errors.New("existing RalX PATH block kept")
	}
	quoted := "'" + strings.ReplaceAll(bin, "'", `'\''`) + "'"
	block := []byte("\n# RalX PATH begin\nexport PATH=" + quoted + ":\"$PATH\"\n# RalX PATH end\n")
	r := map[string]any{"binary": exe, "path_added": true, "profile": profile, "profile_existed": existed}
	b, _ := json.MarshalIndent(r, "", "  ")
	p := filepath.Join(home, ".ralx", "install.json")
	if _, e := os.Stat(p); e == nil {
		return errors.New("existing installer receipt kept")
	}
	if existed {
		backup := profile + ".ralx-path.bak"
		if _, e := os.Lstat(backup); !os.IsNotExist(e) {
			return errors.New("existing PATH profile backup kept")
		}
		if e := setupconfig.Write(backup, original, 0600); e != nil {
			return e
		}
		r["profile_backup"] = backup
		b, _ = json.MarshalIndent(r, "", "  ")
	}
	if e := setupconfig.Write(p, b, 0600); e != nil {
		return e
	}
	return setupconfig.Write(profile, append(original, block...), 0600)
}
