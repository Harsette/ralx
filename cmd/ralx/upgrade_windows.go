//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Harsette/ralx/internal/client"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func secureUpgradeDir(path string) error {
	sid, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid.User.Sid.String() + ")")
	if e != nil {
		return e
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, sid.User.Sid, nil, dacl, nil)
}
func finishUpgradeBackup(dir string) error {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	return filepath.Walk(dir, func(p string, _ os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		return windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil)
	})
}
func finishUpgradeOwnership() error          { return nil }
func finishUpgradeLock(string, string) error { return nil }
func readUpgradePermission(path string, info os.FileInfo) (upgradePermission, error) {
	sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return upgradePermission{}, e
	}
	return upgradePermission{Path: path, Descriptor: sd.String(), Mode: uint32(info.Mode().Perm()), Directory: info.IsDir()}, nil
}
func restoreUpgradePermission(p upgradePermission) error {
	sd, e := windows.SecurityDescriptorFromString(p.Descriptor)
	if e != nil {
		return e
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	control, _, e := sd.Control()
	if e != nil {
		return e
	}
	flags := windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	if control&windows.SE_DACL_PROTECTED != 0 {
		flags = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(p.Path, windows.SE_FILE_OBJECT, windows.SECURITY_INFORMATION(flags), nil, nil, dacl, nil)
}
func discoverUpgradeSystem(target string) (upgradeLayout, error) {
	if os.Getenv("RALX_SETUP_SANDBOX") == "1" {
		if _, e := os.Stat(target); e == nil {
			return upgradeLayout{}, fmt.Errorf("existing sandbox binary without setup receipt; kept")
		}
		return upgradeLayout{}, os.ErrNotExist
	}
	m, e := readUpgradeManager()
	if e != nil {
		return upgradeLayout{}, e
	}
	defer m.Disconnect()
	s, e := openUpgradeService(m, serviceName, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if e == nil {
		defer s.Close()
		c, e := s.Config()
		if e != nil {
			return upgradeLayout{}, e
		}
		// CommandLineToArgvW preserves spaces in Program Files.
		argv, e := windows.DecomposeCommandLine(c.BinaryPathName)
		if e != nil || len(argv) == 0 {
			return upgradeLayout{}, errors.New("invalid service binary path")
		}
		b, e := json.Marshal(c)
		if e != nil {
			return upgradeLayout{}, e
		}
		var registration []byte
		if isElevated() {
			f, e := os.CreateTemp("", "ralx-service-*.reg")
			if e != nil {
				return upgradeLayout{}, e
			}
			p := f.Name()
			f.Close()
			defer os.Remove(p)
			if e = exec.Command("reg.exe", "export", `HKLM\SYSTEM\CurrentControlSet\Services\RalX`, p, "/y").Run(); e != nil {
				return upgradeLayout{}, e
			}
			registration, e = os.ReadFile(p)
			if e != nil {
				return upgradeLayout{}, e
			}
		}
		return upgradeLayout{Binary: argv[0], Data: filepath.Join(programData(), "RalX"), Addr: "127.0.0.1:7317", Pipe: client.DefaultAdminPipe, Service: serviceName, ServiceDefinition: b, ServiceRegistry: registration}, nil
	}
	if !errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return upgradeLayout{}, e
	}
	// A binary without a setup/service receipt is ambiguous. Never invent a new vault.
	for _, p := range []string{target, filepath.Join(installDir(), "ralx.exe")} {
		if _, e := os.Stat(p); e == nil {
			return upgradeLayout{}, fmt.Errorf("existing RalX at %s has no service/setup registration; kept", p)
		}
	}
	if p, e := exec.LookPath("ralx"); e == nil {
		return upgradeLayout{}, fmt.Errorf("existing RalX at %s has no service/setup registration; kept", p)
	}
	return upgradeLayout{}, os.ErrNotExist
}
func readUpgradeManager() (*mgr.Mgr, error) {
	h, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return nil, e
	}
	return &mgr.Mgr{Handle: h}, nil
}
func openUpgradeService(m *mgr.Mgr, name string, access uint32) (*mgr.Service, error) {
	n, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return nil, e
	}
	h, e := windows.OpenService(m.Handle, n, access)
	if e != nil {
		return nil, e
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}
func queryUpgradeService(name string, fn func(*mgr.Service) error) error {
	m, e := readUpgradeManager()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := openUpgradeService(m, name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if e != nil {
		return e
	}
	defer s.Close()
	return fn(s)
}
func upgradeService(name string, fn func(*mgr.Service) error) error {
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService(name)
	if e != nil {
		return e
	}
	defer s.Close()
	return fn(s)
}
func stopUpgradeSystem(ctx context.Context, l upgradeLayout) error {
	return upgradeService(l.Service, func(s *mgr.Service) error {
		status, e := s.Query()
		if e != nil {
			return e
		}
		if status.State == svc.Stopped {
			return nil
		}
		if _, e = s.Control(svc.Stop); e != nil {
			return e
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			status, e = s.Query()
			if e != nil {
				return e
			}
			if status.State == svc.Stopped {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		return errors.New("system service did not stop")
	})
}
func startUpgradeSystem(ctx context.Context, l upgradeLayout, target string) error {
	return upgradeService(l.Service, func(s *mgr.Service) error {
		c, e := s.Config()
		if e != nil {
			return e
		}
		c.BinaryPathName = "\"" + target + "\""
		if e = s.UpdateConfig(c); e != nil {
			return e
		}
		return s.Start()
	})
}
func restoreUpgradeSystem(ctx context.Context, l upgradeLayout) error {
	return upgradeService(l.Service, func(s *mgr.Service) error {
		var c mgr.Config
		if e := json.Unmarshal(l.ServiceDefinition, &c); e != nil {
			return e
		}
		if e := s.UpdateConfig(c); e != nil {
			return e
		}
		return s.Start()
	})
}
func installUpgradeSystem(ctx context.Context, l upgradeLayout, target string) error {
	if !isElevated() {
		before, _ := os.ReadFile(filepath.Join(setupHome(), "last-upgrade"))
		upgradeErr := runElevatedAndWait([]string{"install-upgrade", "--target", target})
		b, e := os.ReadFile(filepath.Join(setupHome(), "last-upgrade"))
		if upgradeErr != nil {
			if e == nil && string(b) != string(before) {
				fmt.Printf("Upgrade incomplete. Rollback: %s rollback --backup %s\n", upgradeInvocation(filepath.Join(string(b), "rollback.exe")), quoteSetupArg(string(b)))
			}
			h, _ := os.UserHomeDir()
			return fmt.Errorf("upgrade failed; read %s: %w", filepath.Join(h, "RalX-backups", "upgrade.log"), upgradeErr)
		}
		if e != nil {
			return e
		}
		fmt.Printf("RalX upgraded to %s. Accounts and identities kept. Rollback: %s rollback --backup %s\n", version, upgradeInvocation(filepath.Join(string(b), "rollback.exe")), quoteSetupArg(string(b)))
		return nil
	}
	h, _ := os.UserHomeDir()
	logDir := filepath.Join(h, "RalX-backups")
	if e := os.MkdirAll(logDir, 0700); e != nil {
		return e
	}
	lf, e := os.OpenFile(filepath.Join(logDir, "upgrade.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer lf.Close()
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = lf, lf
	defer func() { os.Stdout, os.Stderr = stdout, stderr }()
	// A privileged service must never execute a user-writable binary.
	serviceTarget := filepath.Join(installDir(), "bin", "ralx.exe")
	l.ExtraPaths = append(l.ExtraPaths, target)
	if e := performUpgrade(ctx, l, serviceTarget); e != nil {
		return e
	}
	candidate, _ := os.Executable()
	return replaceUpgradeBinaryOrFile(candidate, target, 0755)
}
func rollbackUpgradePlatform(ctx context.Context, dir string) error {
	m, e := readUpgradeBackup(dir)
	if e != nil {
		return e
	}
	if m.Layout.Service != "" && !isElevated() {
		if e := runElevatedAndWait([]string{"rollback", "--backup", dir}); e != nil {
			return e
		}
		fmt.Println("Rollback restored RalX " + m.Version + " and the saved data. Snapshot: " + dir)
		return nil
	}
	return restoreUpgrade(ctx, dir)
}
func upgradeSystemHealthy(s setupState) bool {
	return queryUpgradeService(s.SystemService, func(service *mgr.Service) error {
		c, e := service.Config()
		if e != nil {
			return e
		}
		if !strings.EqualFold(c.BinaryPathName, "\""+s.Exe+"\"") {
			return errors.New("service binary mismatch")
		}
		v, e := service.Query()
		if e == nil && v.State != svc.Running {
			return errors.New("service stopped")
		}
		return e
	}) == nil
}
func backupUpgradePlatform(ctx context.Context, l upgradeLayout, target string) error {
	if l.Service != "" && !isElevated() {
		if e := runElevatedAndWait([]string{"backup", "--target", target}); e != nil {
			return e
		}
		h, _ := os.UserHomeDir()
		b, e := os.ReadFile(filepath.Join(h, "RalX-backups", "latest-backup.txt"))
		if e != nil {
			return e
		}
		fmt.Println("Backup checked: " + string(b))
		return nil
	}
	dir, e := makeUpgradeBackup(l, target)
	if e != nil {
		return e
	}
	h, _ := os.UserHomeDir()
	return os.WriteFile(filepath.Join(h, "RalX-backups", "latest-backup.txt"), []byte(dir), 0600)
}
