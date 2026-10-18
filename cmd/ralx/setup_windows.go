//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

func detachUserProcess(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000200}
}
func syncUserAutostart(_ setupState, _ bool) error { return nil }
func userAutostartEnabled(_ setupState) bool       { return true }
func userAutostart(s setupState) (string, []byte, error) {
	app := os.Getenv("APPDATA")
	if app == "" {
		return "", nil, fmt.Errorf("APPDATA missing")
	}
	// VBS hides the console; the daemon is the existing Go daemon, no new service.
	q := strings.ReplaceAll(`"`+s.Exe+`" user-service`, `"`, `""`)
	return filepath.Join(app, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "RalX-user.vbs"), []byte("CreateObject(\"WScript.Shell\").Run \"" + q + "\", 0, False\r\n"), nil
}
func removeInstallPath(bin string) error {
	if os.Getenv("RALX_SETUP_SANDBOX") == "1" {
		return nil
	}
	k, e := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	if e != nil {
		return e
	}
	defer k.Close()
	path, typ, e := k.GetStringValue("Path")
	if e != nil {
		return e
	}
	parts := strings.Split(path, ";")
	var kept []string
	for _, p := range parts {
		if !strings.EqualFold(strings.TrimRight(p, `\/`), strings.TrimRight(bin, `\/`)) {
			kept = append(kept, p)
		}
	}
	if typ == registry.EXPAND_SZ {
		return k.SetExpandStringValue("Path", strings.Join(kept, ";"))
	}
	return k.SetStringValue("Path", strings.Join(kept, ";"))
}
func removeInstalledBinary(path string) error {
	// Windows cannot unlink an executing image. This helper removes only the
	// exact installer-recorded file after this process exits, without a window.
	quoted := "'" + strings.ReplaceAll(path, "'", "''") + "'"
	c := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Milliseconds 700; Remove-Item -LiteralPath "+quoted+" -Force")
	detachUserProcess(c)
	if e := c.Start(); e != nil {
		return e
	}
	return c.Process.Release()
}
