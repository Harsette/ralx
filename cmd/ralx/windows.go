//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Harsette/ralx/internal/client"
	"github.com/Harsette/ralx/internal/daemon"
	"github.com/Harsette/ralx/internal/leakscan"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "RalX"

func programData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

func installDir() string {
	p := os.Getenv("ProgramFiles")
	if p == "" {
		p = `C:\Program Files`
	}
	return filepath.Join(p, "RalX")
}

func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type svcHandler struct{}

func (svcHandler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	dataDir := filepath.Join(programData(), "RalX")
	_ = os.MkdirAll(filepath.Join(dataDir, "logs"), 0o700)
	lf, _ := os.OpenFile(filepath.Join(dataDir, "logs", "ralx.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	var w io.Writer = io.Discard
	if lf != nil {
		w = lf
		defer lf.Close()
	}
	logger := log.New(w, "ralx ", log.LstdFlags)
	sid := ""
	if s, err := windows.StringToSid(serviceSID()); err == nil {
		sid = s.String()
	}
	s, err := daemon.New(daemon.Config{DataDir: dataDir, Addr: "127.0.0.1:7317", AdminPipe: client.DefaultAdminPipe, ServiceSID: sid, Version: version}, logger)
	if err != nil {
		logger.Printf("startup failed: %v", err)
		return true, 1
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				logger.Printf("serve: %v", err)
			}
			cancel()
			return true, 2
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}

func runService() {
	_ = svc.Run(serviceName, svcHandler{})
}

// serviceSID is the virtual account the service runs as.
func serviceSID() string {
	// Resolve "NT SERVICE\RalX" to its SID string.
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+serviceName)
	if err != nil {
		return ""
	}
	return sid.String()
}

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func relaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(strings.Join(quoteArgs(args), " "))
	return windows.ShellExecute(0, verb, file, params, nil, windows.SW_HIDE)
}

func quoteArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = syscall.EscapeArg(a)
	}
	return out
}

// runElevatedAndWait runs ralx with args elevated and waits for it to finish.
func runElevatedAndWait(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	ps := fmt.Sprintf("$p = Start-Process -FilePath %s -ArgumentList %s -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode",
		psQuote(exe), psQuote(strings.Join(quoteArgs(args), " ")))
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func scanProcesses(s *leakscan.Scanner) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance Win32_Process | ForEach-Object { \"$($_.ProcessId)`t$($_.CommandLine)\" }").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.IndexByte(line, '\t'); i > 0 {
			s.ScanBytes("process:"+strings.TrimSpace(line[:i]), []byte(line[i+1:]), 0)
		}
	}
}

// ---------- install ----------

// cmdInstall: run unelevated, it elevates for the system part (binary,
// service, folder permissions, agent keys), then wires up the harnesses as
// the normal user.
func cmdInstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	system := fs.Bool("system", false, "internal: the elevated half")
	home := fs.String("home", "", "internal: the installing user's profile folder")
	skipHarness := fs.Bool("no-harness", false, "don't register RalX with Claude Code, Codex and Hermes")
	_ = fs.Parse(args)
	if *system {
		return installSystem(ctx, *home)
	}
	userHome, _ := os.UserHomeDir()
	if !isElevated() {
		fmt.Println("Installing the RalX service (Windows will ask for admin permission)…")
		if err := runElevatedAndWait([]string{"admin", "install", "--system", "--home", userHome}); err != nil {
			return fmt.Errorf("elevated install failed: %w (see %s)", err, filepath.Join(userHome, ".ralx", "install.log"))
		}
	} else if err := installSystem(ctx, userHome); err != nil {
		return err
	}
	if b, err := os.ReadFile(filepath.Join(userHome, ".ralx", "install.log")); err == nil {
		os.Stdout.Write(b)
	}
	if err := waitHealthy(15 * time.Second); err != nil {
		return err
	}
	if !*skipHarness {
		if err := setupHarnesses(userHome); err != nil {
			fmt.Println("harness setup:", err)
		}
	}
	fmt.Println("✓ RalX is installed and running as its own Windows account. Next: ralx open")
	return nil
}

func waitHealthy(d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		resp, err := http.Get(client.DefaultURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("RalX service did not become healthy; check C:\\ProgramData\\RalX\\logs\\ralx.log")
}

func installSystem(ctx context.Context, userHome string) (err error) {
	logPath := filepath.Join(userHome, ".ralx", "install.log")
	_ = os.MkdirAll(filepath.Dir(logPath), 0o700)
	lf, _ := os.Create(logPath)
	logf := func(f string, a ...any) {
		if lf != nil {
			fmt.Fprintf(lf, f+"\n", a...)
		}
	}
	defer func() {
		if err != nil {
			logf("ERROR: %v", err)
		}
		if lf != nil {
			lf.Close()
		}
	}()
	if !isElevated() {
		return errors.New("must run elevated")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()

	// 1. Stop an existing service so the binary can be replaced. Whether the service
	// already exists tells us first-install vs upgrade: only a prior RalX install
	// (which needs admin) locks the data dir, so on a FIRST install any pre-existing
	// data dir is attacker-precreated and its contents are untrusted (Daru6 run6 F8).
	serviceExisted := false
	if s, err := m.OpenService(serviceName); err == nil {
		serviceExisted = true
		if st, _ := s.Query(); st.State != svc.Stopped {
			_, _ = s.Control(svc.Stop)
			for i := 0; i < 40; i++ {
				if st, _ := s.Query(); st.State == svc.Stopped {
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
		}
		s.Close()
	}

	// 2. Binary into Program Files (only admins can change it there).
	dir := installDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(dir, "ralx.exe")
	if !strings.EqualFold(filepath.Clean(exe), filepath.Clean(dst)) {
		if err := replaceFile(exe, dst); err != nil {
			return err
		}
	}
	logf("binary: %s", dst)

	// 3. Service under its own virtual account NT SERVICE\RalX.
	s, err := m.OpenService(serviceName)
	if err != nil {
		s, err = m.CreateService(serviceName, dst, mgr.Config{
			DisplayName:      "RalX vault",
			Description:      "RalX: one plug for every agent. Holds credentials agents can't read.",
			StartType:        mgr.StartAutomatic,
			ServiceStartName: `NT SERVICE\` + serviceName,
			SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
		})
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
		logf("service created")
	} else {
		cfg, _ := s.Config()
		cfg.BinaryPathName = `"` + dst + `"`
		cfg.ServiceStartName = `NT SERVICE\` + serviceName
		cfg.StartType = mgr.StartAutomatic
		if err := s.UpdateConfig(cfg); err != nil {
			logf("update config: %v", err)
		}
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 30 * time.Second}}, 86400)

	// 4. Data folder: only SYSTEM, Administrators and the RalX account.
	data := filepath.Join(programData(), "RalX")
	_, statErr := os.Stat(data)
	preExisted := statErr == nil
	// Refuse to adopt a pre-existing data root that is a reparse point
	// (junction/symlink): it could redirect the vault, or its ACLs, somewhere an
	// attacker controls (Astra A8). Fail closed rather than install into it.
	if preExisted {
		if fi, lerr := os.Lstat(data); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to install: %s already exists as a reparse point; remove it and reinstall", data)
		}
	}
	if err := os.MkdirAll(data, 0o700); err != nil {
		return err
	}
	// If the folder was pre-created (possibly with a foreign explicit ACE a
	// prepared attacker added), take ownership and reset its ACL first, so the
	// lockdown below starts from a clean DACL and no foreign explicit ACE
	// survives `/inheritance:r`. Both commands must SUCCEED: proceeding on a
	// failure would leave an unproven DACL in place (Astra A8 fail-closed).
	if preExisted {
		// /D is valid only with /R. This first pass must affect the root alone;
		// children are handled recursively after the root ACL is protected below.
		if out, terr := exec.Command("takeown", "/F", data, "/A").CombinedOutput(); terr != nil {
			return fmt.Errorf("take ownership of pre-existing %s failed (can't prove it is safe): %v: %s", data, terr, out)
		}
		if out, rerr := exec.Command("icacls", data, "/reset", "/C", "/Q").CombinedOutput(); rerr != nil {
			return fmt.Errorf("reset ACL of pre-existing %s failed: %v: %s", data, rerr, out)
		}
		// On a FIRST install, a pre-existing data dir is attacker-precreated: its
		// tools.yaml / actions.d would become trusted config (custom CLI actions with
		// a trusted interpreter + secret: env refs), and a precreated ralx.db could
		// carry an attacker passkey adminauth trusts or attacker-chosen agents. On an
		// upgrade (service already present) the dir was ACL-locked by the prior
		// install, so its vault is kept. Quarantine the untrusted set before the ACL
		// lockdown; a quarantine failure stops the install (fail closed — Astra A8 /
		// Daru6 run6 F8).
		if !serviceExisted {
			if err := quarantinePrecreated(data, logf, "tools.yaml", "actions.d", "ralx.db", "ralx.db-wal", "ralx.db-shm", "config.yaml", "passkeys"); err != nil {
				return err
			}
		}
	}
	// Lock the folder itself (no inheritance from ProgramData, which lets
	// Users read), then reset everything inside to inherit from it.
	out, err := exec.Command("icacls", data, "/inheritance:r", "/grant:r",
		"*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", `NT SERVICE\`+serviceName+":(OI)(CI)M", "/C", "/Q").CombinedOutput()
	logf("icacls folder: %s", strings.TrimSpace(string(out)))
	if err != nil {
		return fmt.Errorf("lock data folder: %v: %s", err, out)
	}
	entries, rderr := os.ReadDir(data)
	if rderr != nil {
		return fmt.Errorf("read data folder (to reset child ACLs): %w", rderr)
	}
	if len(entries) > 0 {
		// Files the service created are owned by its account; take ownership
		// (as Administrators) so their ACLs can be reset to inherit. Both steps
		// must succeed (Astra A8 fail-closed).
		if out, terr := exec.Command("takeown", "/F", data, "/R", "/A", "/D", "Y").CombinedOutput(); terr != nil {
			return fmt.Errorf("take ownership of data folder children failed: %v: %s", terr, out)
		}
		out, err = exec.Command("icacls", filepath.Join(data, "*"), "/reset", "/T", "/C", "/Q").CombinedOutput()
		logf("icacls children: %s", strings.TrimSpace(string(out)))
		if err != nil {
			return fmt.Errorf("reset data folder children: %v: %s", err, out)
		}
	}

	// 5. Start and wait.
	if err := s.Start(); err != nil && !strings.Contains(err.Error(), "already running") {
		return fmt.Errorf("start service: %w", err)
	}
	if err := waitHealthy(20 * time.Second); err != nil {
		return err
	}
	logf("service running")

	// 6. Client copy on the user's PATH (~/.local/bin). Harmless if an agent
	// modifies it: the client holds nothing secret.
	bin := filepath.Join(userHome, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err == nil {
		if err := replaceFile(dst, filepath.Join(bin, "ralx.exe")); err != nil {
			logf("client copy: %v", err)
		}
	}

	// 7. One agent key per harness.
	ac := client.NewAdmin("")
	for _, name := range []string{"claude-code", "codex", "hermes"} {
		path := filepath.Join(userHome, ".ralx", "agents", name+".key")
		if _, err := os.Stat(path); err == nil {
			continue
		}
		key, err := createAgent(ctx, ac, name, nil, nil)
		if err != nil {
			logf("agent %s: %v", name, err)
			continue
		}
		if err := writeKeyFile(path, key); err != nil {
			logf("agent %s key: %v", name, err)
			continue
		}
		logf("agent %s: key at %s", name, path)
	}
	def := filepath.Join(userHome, ".ralx", "agent.key")
	if _, err := os.Stat(def); err != nil {
		if b, err := os.ReadFile(filepath.Join(userHome, ".ralx", "agents", "claude-code.key")); err == nil {
			_ = os.WriteFile(def, b, 0o600)
		}
	}
	return nil
}

// quarantinePrecreated moves aside each named pre-existing entry in a data root,
// so attacker-prepopulated configuration, a planted vault, or planted passkeys
// can't be adopted as trusted on a first install. Only state written by the
// install (after the ACL lockdown) is trusted (Astra A8 / Daru6 F8). A rename
// failure is returned as an error so the caller aborts the install — leaving the
// untrusted entry in place would be fail-open. An Lstat error other than
// "not found" also aborts (we can't prove the entry is safe to adopt).
func quarantinePrecreated(data string, logf func(string, ...any), names ...string) error {
	stamp := time.Now().UnixNano()
	for _, name := range names {
		p := filepath.Join(data, name)
		if _, err := os.Lstat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("cannot inspect pre-existing %s to quarantine it: %w", name, err)
		}
		q := fmt.Sprintf("%s.untrusted-%d", p, stamp)
		if err := os.Rename(p, q); err != nil {
			return fmt.Errorf("could not quarantine pre-existing %s (untrusted provenance): %w", name, err)
		}
		logf("quarantined pre-existing %s (untrusted provenance) to %s", name, q)
	}
	return nil
}

// replaceFile swaps in a new copy of src at dst even while dst is running
// (an MCP client may be using it): the old file is renamed aside, which
// Windows allows for running executables, and old copies are cleaned up
// once nothing uses them.
func replaceFile(src, dst string) error {
	if err := copyFile(src, dst+".new"); err != nil {
		return err
	}
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, fmt.Sprintf("%s.old-%d", dst, time.Now().UnixNano())); err != nil {
			return fmt.Errorf("move old %s aside: %w", dst, err)
		}
	}
	if err := os.Rename(dst+".new", dst); err != nil {
		return err
	}
	if olds, _ := filepath.Glob(dst + ".old*"); len(olds) > 0 {
		for _, o := range olds {
			_ = os.Remove(o) // fails harmlessly while still in use
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func cmdUninstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "also delete the vault (all stored credentials)")
	_ = fs.Parse(args)
	if !isElevated() {
		a := []string{"admin", "uninstall"}
		if *purge {
			a = append(a, "--purge")
		}
		return runElevatedAndWait(a)
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		_, _ = s.Control(svc.Stop)
		time.Sleep(2 * time.Second)
		_ = s.Delete()
		s.Close()
	}
	if *purge {
		_ = os.RemoveAll(filepath.Join(programData(), "RalX"))
	}
	fmt.Println("RalX service removed.")
	return nil
}
