package main

// The verified release binary performs upgrades, so the two download scripts
// share one transaction and one backup format. No provider request is needed.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Harsette/ralx/internal/client"
	"github.com/Harsette/ralx/internal/setupconfig"
)

type upgradeLayout struct {
	Binary, Data, Addr, Pipe, Service string
	PID                               int
	State                             *setupState
	ServiceDefinition                 []byte `json:"-"`
	ServiceRegistry                   []byte `json:"-"`
	RegistrationPath                  string
	ExtraPaths                        []string
}
type upgradeFile struct {
	Source, Copy, SHA256 string
	Mode                 uint32
}
type upgradePermission struct {
	Path, Descriptor string
	Mode             uint32
	UID, GID         int
	Directory        bool
}
type upgradeBackup struct {
	Format                   int
	Created, Version, Target string
	Layout                   upgradeLayout
	Roots                    []string
	Files                    []upgradeFile
	Permissions              []upgradePermission
	Exports                  map[string]string
}

func installedVersion(binary string) (string, error) {
	b, e := exec.Command(binary, "version").Output()
	if e != nil {
		return "", e
	}
	v := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "ralx "))
	if v == "" || strings.ContainsAny(v, "\r\n\t ") {
		return "", errors.New("invalid RalX version response")
	}
	return v, nil
}
func sameUpgradeVersion(a, b string) bool {
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}
func checkUpgradeDirection(installed, candidate string) error {
	parse := func(v string) ([3]int, error) {
		var n [3]int
		core := strings.SplitN(strings.SplitN(strings.TrimPrefix(v, "v"), "-", 2)[0], "+", 2)[0]
		p := strings.Split(core, ".")
		if len(p) != 3 {
			return n, errors.New("version must have three numeric components")
		}
		for i := range n {
			x, e := strconv.Atoi(p[i])
			if e != nil || x < 0 {
				return n, errors.New("invalid version")
			}
			n[i] = x
		}
		return n, nil
	}
	a, e := parse(installed)
	if e != nil {
		return e
	}
	b, e := parse(candidate)
	if e != nil {
		return e
	}
	for i := range a {
		if a[i] > b[i] {
			return errors.New("installed RalX is newer; downgrade refused (use rollback for a saved snapshot)")
		}
		if a[i] < b[i] {
			return nil
		}
	}
	if !strings.Contains(installed, "-") && strings.Contains(candidate, "-") {
		return errors.New("stable RalX kept; prerelease downgrade refused")
	}
	return nil
}
func upgradeInvocation(exe string) string {
	if runtime.GOOS == "windows" {
		return "& " + quoteSetupArg(exe)
	}
	return quoteSetupArg(exe)
}
func fileDigest(p string) (string, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	_, e = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), e
}
func copyUpgradeFile(src, dst string, mode os.FileMode) error {
	f, e := os.Open(src)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = os.MkdirAll(filepath.Dir(dst), 0700); e != nil {
		return e
	}
	out, e := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, f)
	if e == nil {
		e = out.Sync()
	}
	ce := out.Close()
	if e != nil {
		return e
	}
	return ce
}
func lockUpgradeTransaction() (func(), error) {
	h, _ := os.UserHomeDir()
	dir := filepath.Join(h, "RalX-backups")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(dir, "upgrade.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = finishUpgradeLock(dir, f.Name()); e != nil {
		f.Close()
		return nil, e
	}
	ok, e := tryLockFile(f)
	if e != nil {
		f.Close()
		return nil, e
	}
	if !ok {
		f.Close()
		return nil, errors.New("another RalX upgrade or rollback is running")
	}
	return func() { _ = unlockFile(f); f.Close() }, nil
}
func upgradeRoots(l upgradeLayout, target string) []string {
	h, _ := os.UserHomeDir()
	roots := []string{l.Binary, l.Data, filepath.Join(h, ".ralx"), target}
	roots = append(roots, l.ExtraPaths...)
	if l.RegistrationPath != "" {
		roots = append(roots, l.RegistrationPath)
	}
	for _, c := range setupClients() {
		roots = append(roots, c.Path, c.Path+".ralx-setup.json", c.Path+".ralx-setup.bak", c.Path+".bak-ralx")
	}
	for _, p := range []string{filepath.Join(h, ".claude", "settings.json"), filepath.Join(os.Getenv("LOCALAPPDATA"), "hermes", "config.yaml"), filepath.Join(os.Getenv("LOCALAPPDATA"), "hermes", ".env")} {
		roots = append(roots, p, p+".bak-ralx")
	}
	if l.State != nil && l.State.Autostart != "" {
		roots = append(roots, l.State.Autostart)
	}
	if l.State == nil && l.Service == "" {
		s := setupState{Mode: "local", Exe: target, Data: l.Data, Addr: l.Addr}
		if path, _, e := userAutostart(s); e == nil {
			roots = append(roots, path)
		}
	}
	return roots
}
func makeUpgradeBackup(l upgradeLayout, target string) (string, error) {
	h, _ := os.UserHomeDir()
	dir := filepath.Join(h, "RalX-backups", "pre-v"+strings.TrimPrefix(version, "v")+"-"+time.Now().Format("20060102-150405.000000000"))
	if e := os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	if e := secureUpgradeDir(dir); e != nil {
		return "", e
	}
	v, e := installedVersion(l.Binary)
	if e != nil {
		return "", e
	}
	m := upgradeBackup{Format: 1, Created: time.Now().UTC().Format(time.RFC3339), Version: v, Target: target, Layout: l}
	seen := map[string]bool{}
	for _, root := range upgradeRoots(l, target) {
		if root == "" || seen[root] {
			continue
		}
		seen[root] = true
		m.Roots = append(m.Roots, root)
		e = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("backup refuses symlink: %s", p)
			}
			if p == l.Pipe && info.Mode()&os.ModeSocket != 0 {
				return nil
			}
			if p == filepath.Join(l.Data, "ralx.db-wal") || p == filepath.Join(l.Data, "ralx.db-shm") {
				return nil
			}
			permission, e := readUpgradePermission(p, info)
			if e != nil {
				return e
			}
			m.Permissions = append(m.Permissions, permission)
			if info.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("backup refuses special file: %s", p)
			}
			if seen["file:"+p] {
				return nil
			}
			seen["file:"+p] = true
			rel := filepath.Join("files", fmt.Sprintf("%06d", len(m.Files)))
			dest := filepath.Join(dir, rel)
			if p == filepath.Join(l.Data, "ralx.db") {
				if e = os.MkdirAll(filepath.Dir(dest), 0700); e != nil {
					return e
				}
				db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(p)+"?mode=ro&_pragma=busy_timeout(15000)")
				if err != nil {
					return err
				}
				_, e = db.Exec("VACUUM INTO '" + strings.ReplaceAll(filepath.ToSlash(dest), "'", "''") + "'")
				ce := db.Close()
				if e == nil {
					e = ce
				}
			} else {
				e = copyUpgradeFile(p, dest, 0600)
			}
			if e != nil {
				return e
			}
			hash, e := fileDigest(dest)
			if e != nil {
				return e
			}
			m.Files = append(m.Files, upgradeFile{Source: p, Copy: rel, SHA256: hash, Mode: uint32(info.Mode().Perm())})
			return nil
		})
		if e != nil {
			return "", e
		}
	}
	m.Exports = map[string]string{}
	for name, content := range map[string][]byte{"service.json": l.ServiceDefinition, "service.reg": l.ServiceRegistry} {
		if len(content) == 0 {
			continue
		}
		p := filepath.Join(dir, name)
		if e = os.WriteFile(p, content, 0600); e != nil {
			return "", e
		}
		hash, e := fileDigest(p)
		if e != nil {
			return "", e
		}
		m.Exports[name] = hash
	}
	exe, e := os.Executable()
	if e != nil {
		return "", e
	}
	rollback := filepath.Join(dir, "rollback")
	if runtime.GOOS == "windows" {
		rollback += ".exe"
	}
	if e = copyUpgradeFile(exe, rollback, 0700); e != nil {
		return "", e
	}
	hash, e := fileDigest(rollback)
	if e != nil {
		return "", e
	}
	m.Exports[filepath.Base(rollback)] = hash
	b, e := json.MarshalIndent(m, "", "  ")
	if e != nil {
		return "", e
	}
	if e = setupconfig.Write(filepath.Join(dir, "manifest.json"), b, 0600); e != nil {
		return "", e
	}
	if e = finishUpgradeBackup(dir); e != nil {
		return "", e
	}
	return dir, nil
}
func readUpgradeBackup(dir string) (upgradeBackup, error) {
	var m upgradeBackup
	b, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e != nil {
		return m, e
	}
	if e = json.Unmarshal(b, &m); e != nil {
		return m, e
	}
	if m.Format != 1 {
		return m, errors.New("unknown backup format")
	}
	for name, want := range m.Exports {
		if filepath.Base(name) != name {
			return m, errors.New("invalid backup export name")
		}
		h, e := fileDigest(filepath.Join(dir, name))
		if e != nil {
			return m, e
		}
		if h != want {
			return m, errors.New("backup export hash mismatch; nothing restored")
		}
	}
	if _, ok := m.Exports["service.json"]; ok {
		m.Layout.ServiceDefinition, e = os.ReadFile(filepath.Join(dir, "service.json"))
		if e != nil {
			return m, e
		}
	}
	if m.Layout.Service != "" && len(m.Layout.ServiceDefinition) == 0 {
		return m, errors.New("backup service definition missing; nothing restored")
	}
	for _, f := range m.Files {
		p := filepath.Join(dir, f.Copy)
		rel, e := filepath.Rel(dir, p)
		if e != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(f.Copy) {
			return m, errors.New("invalid backup file path")
		}
		h, e := fileDigest(p)
		if e != nil {
			return m, e
		}
		if h != f.SHA256 {
			return m, errors.New("backup hash mismatch; nothing restored")
		}
	}
	return m, nil
}
func stopUpgrade(ctx context.Context, l upgradeLayout) error {
	if l.Service != "" {
		return stopUpgradeSystem(ctx, l)
	}
	if l.PID != 0 {
		if os.Getenv("RALX_SETUP_SANDBOX") != "1" {
			return errors.New("PID upgrades are limited to isolated sandbox trials")
		}
		p, e := os.FindProcess(l.PID)
		if e != nil {
			return e
		}
		if e = p.Kill(); e != nil {
			return e
		}
		_, _ = p.Wait()
	} else if l.State != nil {
		if runtime.GOOS == "darwin" {
			if e := syncUserAutostart(*l.State, true); e != nil {
				return e
			}
		}
		if e := setupconfig.Write(filepath.Join(setupHome(), "stop"), []byte("stop\n"), 0600); e != nil {
			return e
		}
	} else {
		return errors.New("unknown running service; supply its registration before upgrading")
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if !setupHealthy(setupState{URL: "http://" + l.Addr}) {
			if l.State != nil {
				f, e := os.OpenFile(filepath.Join(setupHome(), "service.lock"), os.O_CREATE|os.O_RDWR, 0600)
				if e != nil {
					return e
				}
				ok, e := tryLockFile(f)
				if ok {
					_ = unlockFile(f)
				}
				f.Close()
				if e != nil {
					return e
				}
				if !ok {
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("old RalX did not stop; binary kept")
}
func restoreUpgrade(ctx context.Context, dir string) error {
	unlock, e := lockUpgradeTransaction()
	if e != nil {
		return e
	}
	defer unlock()
	m, e := readUpgradeBackup(dir)
	if e != nil {
		return e
	}
	if e = validateUpgradeSandbox(m.Layout, m.Target); e != nil {
		return e
	}
	if s, e := readSetup(); e == nil {
		if !sameInstallPath(s.Data, m.Layout.Data) || s.Addr != m.Layout.Addr || s.SystemService != m.Layout.Service {
			return errors.New("backup belongs to another RalX setup; nothing stopped or restored")
		}
		l := m.Layout
		l.State = &s
		l.PID = 0
		l.Service = s.SystemService
		if e = stopUpgrade(ctx, l); e != nil {
			return e
		}
	} else if os.IsNotExist(e) && m.Layout.Service != "" {
		if e = stopUpgrade(ctx, m.Layout); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	// Only files under the recorded install/data/config roots belong to this transaction.
	for _, root := range m.Roots {
		if root == m.Layout.Data || strings.HasSuffix(root, string(filepath.Separator)+".ralx") {
			if e = os.RemoveAll(root); e != nil {
				return e
			}
		} else {
			existed := false
			for _, f := range m.Files {
				existed = existed || sameInstallPath(f.Source, root)
			}
			if !existed {
				if e = os.Remove(root); e != nil && !os.IsNotExist(e) {
					if root != m.Target {
						return e
					}
					aside := filepath.Join(dir, "rollback-running"+filepath.Ext(root))
					if e = os.Rename(root, aside); e != nil {
						return e
					}
					_ = removeInstalledBinary(aside)
				}
			}
		}
	}
	for _, f := range m.Files {
		if e = replaceUpgradeBinaryOrFile(filepath.Join(dir, f.Copy), f.Source, os.FileMode(f.Mode)); e != nil {
			return e
		}
	}
	for _, p := range m.Permissions {
		if p.Directory {
			if e = os.MkdirAll(p.Path, 0700); e != nil {
				return e
			}
		}
	}
	for _, f := range m.Files {
		h, e := fileDigest(f.Source)
		if e != nil {
			return e
		}
		if h != f.SHA256 {
			return fmt.Errorf("restored file hash mismatch: %s", f.Source)
		}
	}
	fmt.Println("Rollback hash check: old binary and saved data are byte-identical.")
	for _, p := range m.Permissions {
		if e = restoreUpgradePermission(p); e != nil {
			return e
		}
	}
	hadTarget := false
	for _, f := range m.Files {
		hadTarget = hadTarget || sameInstallPath(f.Source, m.Target)
	}
	if !hadTarget && !sameInstallPath(m.Target, m.Layout.Binary) {
		_ = os.Remove(m.Target)
	}
	if m.Layout.Service != "" {
		if e = restoreUpgradeSystem(ctx, m.Layout); e != nil {
			return e
		}
	} else if m.Layout.State != nil {
		s := *m.Layout.State
		if e = startUserService(ctx, &s); e != nil {
			return e
		}
	}
	fmt.Println("Rollback restored RalX " + m.Version + " and the saved data. Snapshot: " + dir)
	return nil
}
func replaceUpgradeBinaryOrFile(src, dst string, mode os.FileMode) error {
	tmp := dst + ".ralx-new"
	_ = os.Remove(tmp)
	if e := copyUpgradeFile(src, tmp, mode); e != nil {
		return e
	}
	if _, e := os.Stat(dst); e == nil {
		// A still-running MCP client can keep an older image mapped. Never reuse
		// an aside filename: that image must not block a later swap or rollback.
		aside, e := os.CreateTemp(filepath.Dir(dst), ".ralx-replaced-*")
		if e != nil {
			return e
		}
		old := aside.Name()
		if e = aside.Close(); e != nil {
			return e
		}
		if e = os.Remove(old); e != nil {
			return e
		}
		if e = os.Rename(dst, old); e != nil {
			return e
		}
		if e = os.Rename(tmp, dst); e != nil {
			_ = os.Rename(old, dst)
			return e
		}
		if e := os.Remove(old); e != nil {
			_ = removeInstalledBinary(old)
		}
		return nil
	}
	return os.Rename(tmp, dst)
}
func validateUpgradeSandbox(l upgradeLayout, target string) error {
	if e := sandboxSetup(l.Addr); e != nil {
		return e
	}
	if os.Getenv("RALX_SETUP_SANDBOX") == "1" {
		h, _ := os.UserHomeDir()
		paths := append([]string{l.Binary, l.Data, target}, l.ExtraPaths...)
		if l.RegistrationPath != "" {
			paths = append(paths, l.RegistrationPath)
		}
		if l.State != nil && l.State.Autostart != "" {
			paths = append(paths, l.State.Autostart)
		}
		for _, p := range paths {
			r, e := filepath.Rel(h, p)
			if e != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
				return errors.New("sandbox upgrade paths must stay inside temporary HOME")
			}
		}
		if l.Service != "" {
			return errors.New("sandbox refuses system service changes")
		}
		if runtime.GOOS == "windows" && strings.EqualFold(l.Pipe, client.DefaultAdminPipe) {
			return errors.New("sandbox refuses the installed admin pipe")
		}
		if l.Pipe != "" && runtime.GOOS != "windows" {
			r, e := filepath.Rel(h, l.Pipe)
			if e != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
				return errors.New("sandbox refuses an admin socket outside temporary HOME")
			}
		}
	}
	return nil
}
func discoverUpgrade(target string) (upgradeLayout, error) {
	if s, e := readSetup(); e == nil {
		if s.SystemService != "" {
			l, e := discoverUpgradeSystem(s.Exe)
			if e != nil {
				return l, e
			}
			l.State = &s
			l.Binary = s.Exe
			l.Data = s.Data
			l.Addr = s.Addr
			l.Pipe = s.Pipe
			return l, nil
		}
		return upgradeLayout{Binary: s.Exe, Data: s.Data, Addr: s.Addr, Pipe: s.Pipe, Service: s.SystemService, State: &s}, nil
	} else if !os.IsNotExist(e) {
		return upgradeLayout{}, e
	}
	if p := os.Getenv("RALX_UPGRADE_LEGACY_JSON"); p != "" {
		if os.Getenv("RALX_SETUP_SANDBOX") != "1" {
			return upgradeLayout{}, errors.New("legacy JSON is for isolated trials only")
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return upgradeLayout{}, e
		}
		var l upgradeLayout
		e = json.Unmarshal(b, &l)
		return l, e
	}
	return discoverUpgradeSystem(target)
}
func cmdInstallUpgrade(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("install-upgrade", flag.ContinueOnError)
	target := fs.String("target", "", "verified release destination")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if *target == "" {
		return errors.New("--target required")
	}
	l, e := discoverUpgrade(*target)
	if errors.Is(e, os.ErrNotExist) {
		fmt.Println("fresh")
		return nil
	}
	if e != nil {
		return e
	}
	if e = validateUpgradeSandbox(l, *target); e != nil {
		return e
	}
	v, e := installedVersion(l.Binary)
	if e != nil {
		return e
	}
	if sameUpgradeVersion(v, version) {
		fmt.Println("RalX " + v + " is already installed. Kept unchanged.")
		return nil
	}
	if e = checkUpgradeDirection(v, version); e != nil {
		return e
	}
	if l.Service != "" {
		return installUpgradeSystem(ctx, l, *target)
	}
	return performUpgrade(ctx, l, *target)
}
func performUpgrade(ctx context.Context, l upgradeLayout, target string) (err error) {
	unlock, e := lockUpgradeTransaction()
	if e != nil {
		return e
	}
	defer unlock()
	// Snapshot before any stop or replacement. Setup has its own separate lock.
	dir, e := makeUpgradeBackup(l, target)
	if e != nil {
		return e
	}
	fmt.Println("Backup checked: " + dir)
	rollback := filepath.Join(dir, "rollback")
	if runtime.GOOS == "windows" {
		rollback += ".exe"
	}
	fmt.Printf("Rollback: %s rollback --backup %s\n", upgradeInvocation(rollback), quoteSetupArg(dir))
	if e = setupconfig.Write(filepath.Join(setupHome(), "last-upgrade"), []byte(dir), 0600); e != nil {
		return e
	}
	if e = stopUpgrade(ctx, l); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Upgrade incomplete. Restore the saved snapshot: ralx rollback --backup %s\n", quoteSetupArg(dir))
		}
	}()
	// A second snapshot of a stopped store is unnecessary: the online snapshot
	// already represents the exact committed restore point printed above.
	candidate, _ := os.Executable()
	if e = replaceUpgradeBinaryOrFile(candidate, target, 0755); e != nil {
		return e
	}
	// Legacy configs (including Hermes) may still invoke the former binary path.
	if !sameInstallPath(l.Binary, target) {
		if e = replaceUpgradeBinaryOrFile(candidate, l.Binary, 0755); e != nil {
			return e
		}
	}
	s := setupState{Mode: "local", Exe: target, Data: l.Data, Addr: l.Addr, URL: "http://" + l.Addr, Pipe: l.Pipe, SystemService: l.Service}
	if l.State != nil {
		s = *l.State
		s.Exe = target
		if s.Autostart != "" && s.SystemService == "" {
			oldPath, oldBytes, e := userAutostart(*l.State)
			if e != nil {
				return e
			}
			actual, e := os.ReadFile(oldPath)
			if e != nil {
				return e
			}
			if !bytes.Equal(actual, oldBytes) {
				return errors.New("autostart was edited; saved backup kept")
			}
			newPath, newBytes, e := userAutostart(s)
			if e != nil {
				return e
			}
			if newPath != oldPath {
				return errors.New("autostart location changed; saved backup kept")
			}
			if e = setupconfig.Write(newPath, newBytes, 0600); e != nil {
				return e
			}
		}
	}
	if s.Pipe == "" {
		s.Pipe = upgradeUserPipe(s.Data)
	}
	if e = saveSetup(s); e != nil {
		return e
	}
	if l.Service != "" {
		if e = startUpgradeSystem(ctx, l, target); e != nil {
			return e
		}
		deadline := time.Now().Add(20 * time.Second)
		for !setupHealthy(s) {
			if time.Now().After(deadline) {
				return errors.New("upgraded service did not become healthy")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if e = adoptUpgradeClients(ctx, l, &s); e != nil {
		return fmt.Errorf("upgrade needs attention; rollback: ralx rollback --backup %s: %w", quoteSetupArg(dir), e)
	}
	if e = saveSetup(s); e != nil {
		return e
	}
	cmd := exec.CommandContext(ctx, target, "setup", "--mode", "local", "--clients", "all", "--yes", "--data", s.Data, "--addr", s.Addr, "--no-browser")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if e = cmd.Run(); e != nil {
		return fmt.Errorf("setup failed; rollback: ralx rollback --backup %s: %w", quoteSetupArg(dir), e)
	}
	cmd = exec.CommandContext(ctx, target, "doctor")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if e = cmd.Run(); e != nil {
		return e
	}
	if e = setupconfig.Write(filepath.Join(setupHome(), "last-upgrade"), []byte(dir), 0600); e != nil {
		return e
	}
	if e = finishUpgradeOwnership(); e != nil {
		return e
	}
	fmt.Printf("RalX upgraded to %s. Accounts and identities kept. Rollback: %s rollback --backup %s\n", version, upgradeInvocation(rollback), quoteSetupArg(dir))
	return nil
}
func cmdUpgradeBackup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	target := fs.String("target", "", "installer destination")
	if e := fs.Parse(args); e != nil {
		return e
	}
	h, _ := os.UserHomeDir()
	if *target == "" {
		*target = filepath.Join(h, ".local", "bin", "ralx")
		if runtime.GOOS == "windows" {
			*target += ".exe"
		}
	}
	l, e := discoverUpgrade(*target)
	if e != nil {
		return e
	}
	if e = validateUpgradeSandbox(l, *target); e != nil {
		return e
	}
	return backupUpgradePlatform(ctx, l, *target)
}
func cmdRollback(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	dir := fs.String("backup", "", "snapshot directory")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if *dir == "" {
		b, e := os.ReadFile(filepath.Join(setupHome(), "last-upgrade"))
		if e != nil {
			return e
		}
		*dir = string(b)
	}
	return rollbackUpgradePlatform(ctx, *dir)
}
func upgradeUserPipe(data string) string {
	if runtime.GOOS != "windows" {
		return filepath.Join(setupHome(), "admin.sock")
	}
	h := sha256.Sum256([]byte(data))
	return `\\.\pipe\ralx-user-` + hex.EncodeToString(h[:8])
}
func adoptUpgradeClients(ctx context.Context, l upgradeLayout, s *setupState) error {
	if s.AgentNames == nil {
		s.AgentNames = map[string]string{}
	}
	for _, c := range setupClients() {
		b, e := os.ReadFile(c.Path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		entry, e := setupconfig.Entry(b, c)
		if e != nil {
			return e
		}
		if entry == nil {
			continue
		}
		oldcmd, _ := entry["command"].(string)
		if !sameInstallPath(oldcmd, l.Binary) && !sameInstallPath(oldcmd, s.Exe) {
			return fmt.Errorf("%s has a different RalX entry; kept", c.Name)
		}
		env, _ := entry["env"].(map[string]any)
		p, _ := env["RALX_AGENT_KEY_FILE"].(string)
		if p == "" {
			return fmt.Errorf("%s identity path missing", c.Name)
		}
		id, e := client.ReadIdentity(p)
		if e != nil {
			return e
		}
		// Never carry an identity from another hub into this upgrade.
		if id.URL != "" && id.URL != s.URL {
			return fmt.Errorf("%s identity belongs to another address", c.Name)
		}
		id.URL = s.URL
		dest := identityFile("setup-" + c.Name)
		if !sameInstallPath(p, dest) {
			if e = writeIdentity(dest, id); e != nil {
				return e
			}
		}
		s.Clients = addString(s.Clients, c.Name)
		if e = setupconfig.AdoptUpgrade(c, setupServer(*s, c.Name), l.Binary); e != nil {
			return e
		}
	}
	return nil
}
