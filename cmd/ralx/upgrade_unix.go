//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func secureUpgradeDir(path string) error { return os.Chmod(path, 0700) }
func finishUpgradeLock(dir, path string) error {
	u, g, ok := upgradeSudoUser()
	if !ok {
		return nil
	}
	if e := os.Chown(dir, u, g); e != nil {
		return e
	}
	return os.Chown(path, u, g)
}
func upgradeSudoUser() (int, int, bool) {
	if os.Geteuid() != 0 || os.Getenv("SUDO_UID") == "" {
		return 0, 0, false
	}
	u, e := strconv.Atoi(os.Getenv("SUDO_UID"))
	if e != nil {
		return 0, 0, false
	}
	g, e := strconv.Atoi(os.Getenv("SUDO_GID"))
	return u, g, e == nil
}
func finishUpgradeBackup(dir string) error {
	u, g, ok := upgradeSudoUser()
	if !ok {
		return nil
	}
	return filepath.Walk(dir, func(p string, i os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if i.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in backup")
		}
		return os.Chown(p, u, g)
	})
}
func finishUpgradeOwnership() error {
	u, g, ok := upgradeSudoUser()
	if !ok {
		return nil
	}
	h, _ := os.UserHomeDir()
	if e := filepath.Walk(filepath.Join(h, ".ralx"), func(p string, i os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if i.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in identity folder")
		}
		return os.Chown(p, u, g)
	}); e != nil {
		return e
	}
	for _, c := range setupClients() {
		for _, p := range []string{c.Path, c.Path + ".ralx-setup.json", c.Path + ".ralx-setup.bak"} {
			if e := os.Chown(p, u, g); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
	}
	return nil
}
func readUpgradePermission(path string, info os.FileInfo) (upgradePermission, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return upgradePermission{}, fmt.Errorf("file ownership unavailable")
	}
	return upgradePermission{Path: path, Mode: uint32(info.Mode().Perm()), UID: int(s.Uid), GID: int(s.Gid), Directory: info.IsDir()}, nil
}
func restoreUpgradePermission(p upgradePermission) error {
	if e := os.Chmod(p.Path, os.FileMode(p.Mode)); e != nil {
		return e
	}
	if os.Geteuid() == 0 {
		return os.Chown(p.Path, p.UID, p.GID)
	}
	return nil
}
func discoverUpgradeSystem(target string) (upgradeLayout, error) {
	if os.Getenv("RALX_SETUP_SANDBOX") == "1" {
		if _, e := os.Stat(target); e == nil {
			return upgradeLayout{}, fmt.Errorf("existing sandbox binary without setup receipt; kept")
		}
		return upgradeLayout{}, os.ErrNotExist
	}
	if runtime.GOOS == "linux" && os.Getenv("RALX_SETUP_SANDBOX") != "1" {
		out, e := exec.Command("systemctl", "show", "ralx.service", "--property=FragmentPath", "--value").Output()
		if e == nil && strings.TrimSpace(string(out)) != "" {
			path := strings.TrimSpace(string(out))
			b, e := os.ReadFile(path)
			if e != nil {
				return upgradeLayout{}, e
			}
			l, e := parseLegacySystemd(string(b))
			if e != nil {
				return l, e
			}
			l.ServiceDefinition = b
			l.RegistrationPath = path
			return l, nil
		}
	}
	// Existing user services have setup/state.json. Refuse an unregistered system
	// installation rather than risk decrypting its vault as a different OS user.
	for _, p := range []string{target, "/usr/local/bin/ralx", "/opt/ralx/ralx"} {
		if _, e := os.Stat(p); e == nil {
			return upgradeLayout{}, fmt.Errorf("existing RalX at %s has no setup receipt; system-account migration needs its service definition (kept unchanged)", p)
		}
	}
	if p, e := exec.LookPath("ralx"); e == nil {
		return upgradeLayout{}, fmt.Errorf("existing RalX at %s has no setup receipt; kept unchanged", p)
	}
	return upgradeLayout{}, os.ErrNotExist
}
func parseLegacySystemd(unit string) (upgradeLayout, error) {
	l := upgradeLayout{Data: "/var/lib/ralx", Addr: "127.0.0.1:7317", Pipe: "/run/ralx/admin.sock", Service: "systemd:ralx.service"}
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Environment=RALX_DATA=") {
			l.Data = strings.TrimPrefix(line, "Environment=RALX_DATA=")
		}
		if strings.HasPrefix(line, "ExecStart=") {
			fields := strings.Fields(strings.TrimPrefix(line, "ExecStart="))
			if len(fields) < 2 || fields[1] != "daemon" {
				return l, fmt.Errorf("unrecognized RalX systemd command; kept")
			}
			l.Binary = fields[0]
			for i := 2; i+1 < len(fields); i++ {
				switch fields[i] {
				case "--data":
					l.Data = fields[i+1]
					i++
				case "--addr":
					l.Addr = fields[i+1]
					i++
				case "--admin-pipe":
					l.Pipe = fields[i+1]
					i++
				}
			}
		}
	}
	if !filepath.IsAbs(l.Binary) || !filepath.IsAbs(l.Data) {
		return l, fmt.Errorf("unrecognized RalX systemd paths; kept")
	}
	return l, nil
}
func systemUpgradeAction(ctx context.Context, l upgradeLayout, action string) error {
	if !strings.HasPrefix(l.Service, "systemd:") {
		return fmt.Errorf("unrecognized service registration; kept")
	}
	return exec.CommandContext(ctx, "systemctl", action, strings.TrimPrefix(l.Service, "systemd:")).Run()
}
func stopUpgradeSystem(ctx context.Context, l upgradeLayout) error {
	return systemUpgradeAction(ctx, l, "stop")
}
func startUpgradeSystem(ctx context.Context, l upgradeLayout, target string) error {
	return systemUpgradeAction(ctx, l, "start")
}
func restoreUpgradeSystem(ctx context.Context, l upgradeLayout) error {
	return systemUpgradeAction(ctx, l, "start")
}
func elevateUnixUpgrade(ctx context.Context, args ...string) error {
	exe, _ := os.Executable()
	h, _ := os.UserHomeDir()
	a := append([]string{"--", "env", "HOME=" + h, exe}, args...)
	c := exec.CommandContext(ctx, "sudo", a...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}
func installUpgradeSystem(ctx context.Context, l upgradeLayout, target string) error {
	if os.Geteuid() != 0 {
		return elevateUnixUpgrade(ctx, "install-upgrade", "--target", target)
	}
	l.ExtraPaths = append(l.ExtraPaths, target)
	if e := performUpgrade(ctx, l, l.Binary); e != nil {
		return e
	}
	exe, _ := os.Executable()
	return replaceUpgradeBinaryOrFile(exe, target, 0755)
}
func rollbackUpgradePlatform(ctx context.Context, dir string) error {
	m, e := readUpgradeBackup(dir)
	if e != nil {
		return e
	}
	if m.Layout.Service != "" && os.Geteuid() != 0 {
		return elevateUnixUpgrade(ctx, "rollback", "--backup", dir)
	}
	return restoreUpgrade(ctx, filepath.Clean(dir))
}
func upgradeSystemHealthy(s setupState) bool {
	return systemUpgradeAction(context.Background(), upgradeLayout{Service: s.SystemService}, "is-active") == nil
}
func backupUpgradePlatform(ctx context.Context, l upgradeLayout, target string) error {
	if l.Service != "" && os.Geteuid() != 0 {
		return elevateUnixUpgrade(ctx, "backup", "--target", target)
	}
	dir, e := makeUpgradeBackup(l, target)
	if e == nil {
		fmt.Println("Backup checked: " + dir)
	}
	return e
}
