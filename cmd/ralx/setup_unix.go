//go:build !windows

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

func detachUserProcess(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
func userAutostart(s setupState) (string, []byte, error) {
	home, _ := os.UserHomeDir()
	if strings.ContainsAny(s.Exe, "\r\n") {
		return "", nil, fmt.Errorf("binary path contains a newline")
	}
	if runtime.GOOS == "darwin" {
		esc := func(v string) string {
			v = strings.ReplaceAll(v, "&", "&amp;")
			v = strings.ReplaceAll(v, "<", "&lt;")
			return strings.ReplaceAll(v, "\"", "&quot;")
		}
		p := filepath.Join(home, "Library", "LaunchAgents", macLaunchLabel(s)+".plist")
		env := "<key>EnvironmentVariables</key><dict>"
		for _, k := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "RALX_SETUP_SANDBOX", "RALX_SETUP_ADDR"} {
			v := os.Getenv(k)
			if k == "HOME" {
				v = home
			}
			if v != "" {
				env += "<key>" + k + "</key><string>" + esc(v) + "</string>"
			}
		}
		env += "</dict>"
		log := esc(filepath.Join(setupHome(), "service.log"))
		return p, []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>%s</string><key>ProgramArguments</key><array><string>%s</string><string>user-service</string></array><key>RunAtLoad</key><true/>%s<key>StandardOutPath</key><string>%s</string><key>StandardErrorPath</key><string>%s</string></dict></plist>
`, macLaunchLabel(s), esc(s.Exe), env, log, log)), nil
	}
	if _, e := exec.LookPath("systemctl"); e == nil {
		esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%")
		return filepath.Join(home, ".config", "systemd", "user", "ralx-user.service"), []byte(fmt.Sprintf("[Unit]\nDescription=RalX per-user background service\n[Service]\nType=simple\nExecStart=\"%s\" user-service\n[Install]\nWantedBy=default.target\n", esc.Replace(s.Exe))), nil
	}
	// XDG autostart runs on desktop login without root, systemd or lingering.
	// Servers without a desktop can use the existing deploy/linux system unit.
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", "$", `\$`, "%", "%%")
	return filepath.Join(home, ".config", "autostart", "ralx-user.desktop"), []byte(fmt.Sprintf("[Desktop Entry]\nType=Application\nName=RalX\nExec=\"%s\" user-service\nTerminal=false\nX-GNOME-Autostart-enabled=true\n", esc.Replace(s.Exe))), nil
}
func removeInstallPath(_ string) error        { return nil }
func removeInstalledBinary(path string) error { return os.Remove(path) }

func userAutostartEnabled(s setupState) bool {
	if runtime.GOOS == "darwin" {
		return exec.Command("launchctl", "print", macLaunchDomain()+"/"+macLaunchLabel(s)).Run() == nil
	}
	if !strings.HasSuffix(s.Autostart, ".service") {
		return true
	}
	link := filepath.Join(filepath.Dir(s.Autostart), "default.target.wants", "ralx-user.service")
	target, e := os.Readlink(link)
	return e == nil && target == s.Autostart
}
func syncUserAutostart(s setupState, remove bool) error {
	if runtime.GOOS == "darwin" {
		domain := macLaunchDomain()
		target := domain + "/" + macLaunchLabel(s)
		loaded := exec.Command("launchctl", "print", target).Run() == nil
		if remove && !loaded || !remove && loaded {
			return nil
		}
		args := []string{"bootstrap", domain, s.Autostart}
		if remove {
			args = []string{"bootout", target}
		}
		if out, e := exec.Command("launchctl", args...).CombinedOutput(); e != nil {
			return fmt.Errorf("could not update login startup: %w: %s", e, out)
		}
		return nil
	}
	if !strings.HasSuffix(s.Autostart, ".service") {
		return nil
	}
	link := filepath.Join(filepath.Dir(s.Autostart), "default.target.wants", "ralx-user.service")
	if _, e := os.Lstat(link); e == nil {
		target, e := os.Readlink(link)
		if e != nil || target != s.Autostart {
			return fmt.Errorf("existing autostart link kept: %s", link)
		}
		if remove {
			return os.Remove(link)
		}
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	if remove {
		return nil
	}
	if e := os.MkdirAll(filepath.Dir(link), 0700); e != nil {
		return e
	}
	return os.Symlink(s.Autostart, link)
}

func macLaunchLabel(s setupState) string {
	sum := sha256.Sum256([]byte(s.Data))
	return fmt.Sprintf("com.ralveto.ralx.%x", sum[:8])
}

func macLaunchDomain() string {
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	if exec.Command("launchctl", "print", domain).Run() == nil {
		return domain
	}
	return fmt.Sprintf("user/%d", os.Getuid())
}
