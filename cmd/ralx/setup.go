package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/Harsette/ralx/internal/client"
	"github.com/Harsette/ralx/internal/daemon"
	"github.com/Harsette/ralx/internal/mcpbridge"
	"github.com/Harsette/ralx/internal/setupconfig"
)

type setupState struct {
	Mode, URL, Data, Addr, Pipe, Exe, Autostart string
	SystemService                               string
	Clients                                     []string
	Identities                                  []string
	AgentNames                                  map[string]string
}

func setupHome() string      { h, _ := os.UserHomeDir(); return filepath.Join(h, ".ralx", "setup") }
func setupStatePath() string { return filepath.Join(setupHome(), "state.json") }
func readSetup() (setupState, error) {
	var s setupState
	b, e := os.ReadFile(setupStatePath())
	if e == nil {
		e = json.Unmarshal(b, &s)
	}
	return s, e
}
func saveSetup(s setupState) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return setupconfig.Write(setupStatePath(), b, 0600)
}

func lockUserSetup() (func(), error) {
	if e := os.MkdirAll(setupHome(), 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(setupHome(), "setup.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	ok, e := tryLockFile(f)
	if e != nil {
		f.Close()
		return nil, e
	}
	if !ok {
		f.Close()
		return nil, errors.New("another ralx setup/uninstall is running; retry when it finishes")
	}
	return func() { _ = unlockFile(f); f.Close() }, nil
}
func quoteSetupArg(s string) string {
	if runtime.GOOS == "windows" {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func openUserSetup(ctx context.Context, s setupState) error {
	if s.Mode == "cloud" {
		return mcpbridge.OpenBrowser(s.URL)
	}
	var out map[string]any
	if _, e := setupAdmin(s).JSON(ctx, "POST", "/admin/api/setup-link", map[string]any{}, &out); e != nil {
		return fmt.Errorf("start the per-user service with ralx setup first: %w", e)
	}
	u, _ := out["url"].(string)
	return mcpbridge.OpenBrowser(u)
}
func setupClients() []setupconfig.Client {
	h, _ := os.UserHomeDir()
	return setupconfig.ClientsWithAntigravity(h, os.Getenv("APPDATA"), runtime.GOOS)
}
func sandboxSetup(addr string) error {
	if os.Getenv("RALX_SETUP_SANDBOX") != "1" {
		return nil
	}
	h, _ := os.UserHomeDir()
	for _, k := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		v := os.Getenv(k)
		rel, e := filepath.Rel(h, v)
		if v == "" || e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("sandbox requires %s inside temporary HOME", k)
		}
	}
	if strings.HasSuffix(addr, ":7317") {
		return errors.New("sandbox refuses the installed RalX port 7317")
	}
	return nil
}
func setupHTTP() *http.Client {
	return &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}
func setupAdmin(s setupState) *client.Client {
	c := client.NewAdmin(s.Pipe)
	c.HTTP.Timeout = 5 * time.Second
	return c
}
func setupAgent(id client.Identity) *client.Client {
	return &client.Client{URL: id.URL, Key: id.Key, HTTP: setupHTTP()}
}
func setupHealthy(s setupState) bool {
	r, e := setupHTTP().Get(s.URL + "/healthz")
	if e != nil {
		return false
	}
	defer r.Body.Close()
	var v struct {
		OK bool `json:"ok"`
	}
	return r.StatusCode == 200 && json.NewDecoder(r.Body).Decode(&v) == nil && v.OK
}
func hasString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
func addString(ss []string, s string) []string {
	if !hasString(ss, s) {
		ss = append(ss, s)
	}
	return ss
}
func setupServer(s setupState, name string) setupconfig.Server {
	command := "mcp"
	if s.Mode == "cloud" {
		command = "cloud-mcp"
	}
	typ := ""
	if name == "claude-code" || name == "vscode" {
		typ = "stdio"
	}
	return setupconfig.Server{Command: s.Exe, Args: []string{command}, Env: map[string]string{"RALX_AGENT_KEY_FILE": identityFile("setup-" + name)}, Type: typ}
}

func cmdSetup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	mode := fs.String("mode", "", "local, cloud, or self-host")
	clients := fs.String("clients", "all", "all detected clients, or comma-separated names")
	yes := fs.Bool("yes", false, "accept the default local mode without prompts")
	remove := fs.Bool("remove", false, "restore client configs and remove setup-created identities")
	addr := fs.String("addr", envOr("RALX_SETUP_ADDR", "127.0.0.1:7317"), "local loopback address")
	data := fs.String("data", envOr("RALX_SETUP_DATA", filepath.Join(setupHome(), "data")), "per-user data directory")
	noBrowser := fs.Bool("no-browser", os.Getenv("RALX_SETUP_NO_BROWSER") == "1", "leave the browser closed")
	showConfig := fs.Bool("show-config", false, "show examples for other apps")
	cloudURL := fs.String("url", envOr("RALX_CLOUD_URL", ""), "hosted RalX origin")
	source := fs.String("source", ".", "RalX checkout for self-host deployment")
	localDeploy := fs.Bool("local", false, "self-host: run only local Wrangler and D1")
	checkDeploy := fs.Bool("check", false, "self-host: stop after local smoke checks")
	var codes multiFlag
	fs.Var(&codes, "enroll-code", "hosted single-use code: client=code (repeat per client)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("unexpected setup arguments")
	}
	if err := sandboxSetup(*addr); err != nil {
		return err
	}
	if *remove {
		return removeSetup(ctx, false)
	}
	// Select without creating local setup files. Re-read saved settings under
	// the setup lock below before applying any installation changes.
	if *mode == "" {
		if saved, err := readSetup(); err == nil {
			*mode = saved.Mode
		}
	}
	if *mode == "" {
		if *yes {
			*mode = "local"
		} else {
			fmt.Print("Where should RalX run?\n  1. This computer (default)\n  2. Self-host on your own Cloudflare\n  3. RalX Cloud (coming soon)\nChoose [1]: ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			switch strings.TrimSpace(line) {
			case "", "1":
				*mode = "local"
			case "2":
				*mode = "self-host"
			case "3":
				*mode = "coming-soon"
			default:
				return errors.New("choose 1, 2, or 3")
			}
		}
	}
	if *mode == "coming-soon" {
		fmt.Println("RalX Cloud is coming soon. Waitlist: " + launchHomepageURL())
		return nil
	}
	unlock, e := lockUserSetup()
	if e != nil {
		return e
	}
	defer unlock()
	old, oldErr := readSetup()
	if oldErr != nil && !os.IsNotExist(oldErr) {
		return oldErr
	}
	if oldErr == nil {
		provided := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })
		if !provided["mode"] {
			*mode = old.Mode
		}
		if !provided["url"] && old.Mode == "cloud" {
			*cloudURL = old.URL
		}
		if !provided["data"] && os.Getenv("RALX_SETUP_DATA") == "" {
			*data = old.Data
		}
		if !provided["addr"] && os.Getenv("RALX_SETUP_ADDR") == "" {
			*addr = old.Addr
		}
	}
	if *mode == "self-host" || *mode == "cloudflare" {
		if oldErr == nil && old.Mode != "cloud" {
			return errors.New("run ralx uninstall before changing local/cloud mode")
		}
		deployArgs := []string{"cloudflare", "--source", *source}
		if *localDeploy {
			deployArgs = append(deployArgs, "--local")
		}
		if *checkDeploy {
			deployArgs = append(deployArgs, "--check")
		}
		if *localDeploy && !*checkDeploy {
			return errors.New("setup local self-host proof requires --check; use ralx deploy cloudflare --local for a persistent preview")
		}
		if e := cmdDeploy(ctx, deployArgs); e != nil {
			return e
		}
		if *localDeploy {
			return nil
		}
		b, e := os.ReadFile(filepath.Join(*source, "cloud", "wrangler.selfhost.json"))
		if e != nil {
			return fmt.Errorf("read deployed Cloudflare origin: %w", e)
		}
		var deployed struct {
			Vars struct {
				BaseURL string `json:"BASE_URL"`
			} `json:"vars"`
		}
		if e := json.Unmarshal(b, &deployed); e != nil {
			return e
		}
		*cloudURL = deployed.Vars.BaseURL
		*mode = "cloud"
	}
	if *mode != "local" && *mode != "cloud" {
		return errors.New("--mode must be local, cloud, or self-host")
	}
	if (*localDeploy || *checkDeploy) && *mode != "self-host" && *mode != "cloudflare" {
		return errors.New("--local and --check require self-host mode")
	}
	if *mode == "cloud" && *cloudURL == "" {
		return errors.New("cloud setup requires --url https://YOUR-HOST or RALX_CLOUD_URL")
	}
	if oldErr == nil && old.Mode != *mode {
		return errors.New("run ralx uninstall before changing local/cloud mode")
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	absData, e := filepath.Abs(*data)
	if e != nil {
		return e
	}
	if os.Getenv("RALX_SETUP_SANDBOX") == "1" {
		h, _ := os.UserHomeDir()
		rel, e := filepath.Rel(h, absData)
		if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return errors.New("sandbox data directory must be inside temporary HOME")
		}
	}
	s := setupState{Mode: *mode, Exe: exe, Data: absData, Addr: *addr, URL: "http://" + *addr}
	hash := sha256.Sum256([]byte(s.Data))
	s.Pipe = filepath.Join(setupHome(), "admin.sock")
	if runtime.GOOS == "windows" {
		s.Pipe = `\\.\pipe\ralx-user-` + hex.EncodeToString(hash[:8])
	}
	if oldErr == nil {
		s.Clients = old.Clients
		s.Identities = old.Identities
		s.Autostart = old.Autostart
		s.AgentNames = old.AgentNames
		s.SystemService = old.SystemService
		s.Pipe = old.Pipe
		if old.Addr != s.Addr || old.Data != s.Data || old.Exe != s.Exe {
			return errors.New("setup address, data or binary changed; run ralx uninstall first")
		}
	}
	if s.AgentNames == nil {
		s.AgentNames = map[string]string{}
	}
	// Validate selection before starting a service or changing any client.
	selected := strings.Split(*clients, ",")
	for _, n := range selected {
		found := n == "all" || n == "none"
		for _, c := range setupClients() {
			found = found || n == c.Name
		}
		if !found {
			return fmt.Errorf("unknown client %q", n)
		}
	}
	if s.Mode == "local" {
		host, _, e := net.SplitHostPort(s.Addr)
		if e != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
			return errors.New("--addr must be loopback:port")
		}
		if oldErr != nil {
			ln, e := net.Listen("tcp", s.Addr)
			if e != nil {
				return fmt.Errorf("address already in use; use --addr 127.0.0.1:17317 (existing RalX left alone): %w", e)
			}
			ln.Close()
		}
		if e := saveSetup(s); e != nil {
			return e
		}
		if e := startUserService(ctx, &s); e != nil {
			return e
		}
		fmt.Printf("[OK] RalX is running at %s. It starts when you sign in.\n", s.URL)
	} else {
		s.URL, e = setupCloudOrigin(*cloudURL)
		if e != nil {
			return e
		}
		if oldErr == nil && old.URL != s.URL {
			return errors.New("cloud origin changed; run ralx uninstall first")
		}
		if e := saveSetup(s); e != nil {
			return e
		}
	}
	// Keep the short-lived grant only in this call. --yes never approves it.
	machineGrant := ""
	if s.Mode == "cloud" {
		if names := setupDeviceClients(s, selected, *clients, codes); len(names) > 0 {
			machineGrant, e = setupDeviceAuthorize(ctx, s, names, *noBrowser)
			if e != nil {
				return e
			}
		}
	}
	failures := 0
	for _, c := range setupClients() {
		if *clients == "none" || (*clients != "all" && !hasString(selected, c.Name)) {
			fmt.Printf("[SKIP] %-15s not selected\n", c.Name)
			continue
		}
		if (c.Name == "claude-code" && os.Getenv("CLAUDE_CONFIG_DIR") != "") || (c.Name == "codex" && os.Getenv("CODEX_HOME") != "") {
			fmt.Printf("[SKIP] %-15s custom config directory active; run ralx config %s for that profile\n", c.Name, c.Name)
			continue
		}
		detected, cliPath := setupDetected(c)
		if !detected {
			fmt.Printf("[SKIP] %-15s not installed\n", c.Name)
			continue
		}
		name := "setup-" + c.Name
		id, e := client.ReadIdentity(identityFile(name))
		if e == nil && id.URL != s.URL {
			e = errors.New("identity belongs to another RalX address")
		} else if os.IsNotExist(e) {
			var key string
			if s.Mode == "local" {
				// Revoked agent names remain reserved in the existing store. A new
				// generation gets a fresh server name while the config path stays put.
				var generation [4]byte
				if _, e = rand.Read(generation[:]); e == nil {
					serverName := name + "-" + hex.EncodeToString(generation[:])
					key, e = createAgent(ctx, setupAdmin(s), serverName, nil, nil)
					if e == nil {
						s.AgentNames[name] = serverName
					}
				}
			} else {
				key, e = setupCloudIdentity(ctx, s, c.Name, codes, machineGrant)
			}
			if e == nil {
				id = client.Identity{URL: s.URL, Key: key, KeyDigest: client.KeyDigest(key)}
				e = os.MkdirAll(agentsDir(), 0700)
				if e == nil {
					e = writeIdentity(identityFile(name), id)
				}
				if e == nil {
					s.Identities = addString(s.Identities, name)
					e = saveSetup(s)
				}
			}
		}
		if e != nil {
			fmt.Printf("[FAIL] %-15s %v; fix: ralx setup --mode %s --clients %s --yes\n", c.Name, e, s.Mode, c.Name)
			failures++
			continue
		}
		server := setupServer(s, c.Name)
		var cli func() error
		if c.Name == "claude-code" && cliPath != "" && os.Getenv("CLAUDE_CONFIG_DIR") == "" && !setupconfig.Managed(c.Path) {
			cli = func() error {
				a := []string{"mcp", "add", "-e", "RALX_AGENT_KEY_FILE=" + identityFile(name), "--scope", "user", "--transport", "stdio", "ralx", "--", s.Exe, server.Args[0]}
				out, e := exec.CommandContext(ctx, cliPath, a...).CombinedOutput()
				if e != nil {
					return fmt.Errorf("%v: %s", e, out)
				}
				return nil
			}
		}
		if e = setupconfig.Install(c, server, cli); e != nil {
			fmt.Printf("[FAIL] %-15s %v; fix: inspect %s\n", c.Name, e, c.Path)
			failures++
			continue
		}
		s.Clients = addString(s.Clients, c.Name)
		if e = saveSetup(s); e != nil {
			return e
		}
		fmt.Printf("[OK] %-15s ready\n", c.Name)
	}
	fmt.Printf("\nRestart connected clients to load RalX. Check: ralx doctor\n")
	if s.Mode == "local" {
		var out map[string]any
		if _, e := setupAdmin(s).JSON(ctx, "POST", "/admin/api/setup-link", map[string]any{}, &out); e != nil {
			return e
		}
		u, _ := out["url"].(string)
		if *noBrowser {
			fmt.Println("Run ralx open to create your passkey and connect your accounts.")
		} else {
			fmt.Println("Opening RalX to finish onboarding and connect accounts.")
			if e := mcpbridge.OpenBrowser(u); e != nil {
				fmt.Printf("Browser could not open; visit %s and run setup again.\n", s.URL)
			}
		}
	}
	if *showConfig {
		generic := setupServer(s, "other")
		generic.Env["RALX_AGENT_KEY_FILE"] = "<your enrolled identity file>"
		stdio, _ := json.MarshalIndent(map[string]any{"mcpServers": map[string]any{"ralx": generic}}, "", "  ")
		httpSnippet, _ := json.MarshalIndent(map[string]any{"servers": map[string]any{"ralx": map[string]any{"type": "http", "url": s.URL + "/mcp", "headers": map[string]string{"Authorization": "Bearer <this client's RalX agent key>"}}}}, "", "  ")
		fmt.Printf("Other clients (stdio):\n%s\nHTTP MCP (each client needs its own identity):\n%s\n", stdio, httpSnippet)
	}
	fmt.Println("Using another app? Run: ralx config <app> (or ralx config --list)")
	if failures > 0 {
		return fmt.Errorf("%d client(s) need attention; connected clients were kept", failures)
	}
	return nil
}

func setupCloudIdentity(ctx context.Context, s setupState, name string, codes []string, grant string) (string, error) {
	path := "/api/enroll"
	payload := map[string]any{"code": setupCodeFor(codes, name), "name": "setup-" + name, "client": name}
	if grant != "" && setupCodeFor(codes, name) == "" {
		path = "/device/enroll"
		payload = map[string]any{"machine_grant": grant, "client": name}
	} else if setupCodeFor(codes, name) == "" {
		return "", errors.New("browser approval required; run setup again")
	}
	c := &client.Client{URL: s.URL, HTTP: setupHTTP()}
	var out struct {
		Key string `json:"key"`
	}
	if _, e := c.JSON(ctx, "POST", path, payload, &out); e != nil {
		return "", e
	}
	if out.Key == "" {
		return "", errors.New("hosted enrollment returned no key")
	}
	return out.Key, nil
}

func startUserService(ctx context.Context, s *setupState) error {
	if s.SystemService != "" {
		if !setupHealthy(*s) {
			return errors.New("existing system service is not healthy; repair the service before setup")
		}
		return nil
	}
	if !setupHealthy(*s) {
		if e := os.MkdirAll(s.Data, 0700); e != nil {
			return e
		}
		_ = os.Remove(filepath.Join(setupHome(), "stop"))
		lf, e := os.OpenFile(filepath.Join(setupHome(), "service.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer lf.Close()
		if runtime.GOOS == "darwin" {
			if e := installUserAutostart(s); e != nil {
				return e
			}
		} else {
			cmd := exec.Command(s.Exe, "user-service")
			cmd.Stdout, cmd.Stderr = lf, lf
			detachUserProcess(cmd)
			if e := cmd.Start(); e != nil {
				return e
			}
			_ = cmd.Process.Release()
		}
		deadline := time.Now().Add(20 * time.Second)
		for !setupHealthy(*s) {
			if time.Now().After(deadline) {
				return fmt.Errorf("service did not start; read %s", lf.Name())
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	// Verify this is OUR daemon, not a different process on the same port.
	if _, e := setupAdmin(*s).JSON(ctx, "GET", "/admin/api/state", nil, nil); e != nil {
		return fmt.Errorf("private service check failed: %w", e)
	}
	return installUserAutostart(s)
}

func installUserAutostart(s *setupState) error {
	path, b, e := userAutostart(*s)
	if e != nil {
		return e
	}
	if s.Autostart != "" && s.Autostart != path {
		return errors.New("autostart path changed")
	}
	if existing, e := os.ReadFile(path); e == nil && !reflect.DeepEqual(existing, b) {
		return fmt.Errorf("existing autostart file kept: %s", path)
	}
	s.Autostart = path
	if e := saveSetup(*s); e != nil {
		return e
	}
	if e := setupconfig.Write(path, b, 0600); e != nil {
		return e
	}
	if e := syncUserAutostart(*s, false); e != nil {
		return e
	}
	return saveSetup(*s)
}

func cmdUserService(ctx context.Context) error {
	s, e := readSetup()
	if e != nil {
		return e
	}
	if s.Mode != "local" {
		return errors.New("local setup required")
	}
	if e := sandboxSetup(s.Addr); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(setupHome(), "service.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	ok, e := tryLockFile(lock)
	if e != nil {
		return e
	}
	if !ok {
		return nil
	}
	defer unlockFile(lock)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, e := os.Stat(filepath.Join(setupHome(), "stop")); e == nil {
					cancel()
					return
				}
			}
		}
	}()
	srv, e := daemon.New(daemon.Config{DataDir: s.Data, Addr: s.Addr, Dev: true, AdminPipe: s.Pipe, Version: version}, log.New(os.Stderr, "ralx-user ", log.LstdFlags))
	if e != nil {
		return e
	}
	defer srv.Close()
	return srv.Serve(ctx)
}

func removeSetup(ctx context.Context, uninstall bool) error {
	s, e := readSetup()
	if os.IsNotExist(e) {
		fmt.Println("No per-user setup to remove.")
		if uninstall {
			return uninstallDownload()
		}
		return nil
	}
	if e != nil {
		return e
	}
	if e := sandboxSetup(s.Addr); e != nil {
		return e
	}
	unlock, e := lockUserSetup()
	if e != nil {
		return e
	}
	defer unlock()
	// Receipts also cover a client CLI that failed after writing its registration.
	for _, c := range setupClients() {
		if e := setupconfig.Remove(c); e != nil {
			return fmt.Errorf("%s: %w", c.Name, e)
		}
	}
	for _, name := range s.Identities {
		if s.Mode == "local" {
			serverName := s.AgentNames[name]
			if serverName == "" {
				serverName = name
			}
			if _, e := setupAdmin(s).JSON(ctx, "POST", "/admin/api/agents/"+serverName+"/revoke", nil, nil); e != nil && e.Error() != "agent already revoked" {
				return fmt.Errorf("identity not revoked; restart setup service and retry: %w", e)
			}
		}
		// Hosted revocation requires an owner session; local files alone cannot revoke.
		if s.Mode == "cloud" {
			fmt.Printf("Revoke %s in %s (Agents).\n", name, s.URL)
		}
		if e := os.Remove(identityFile(name)); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	s.Clients = nil
	s.Identities = nil
	s.AgentNames = nil
	if e := saveSetup(s); e != nil {
		return e
	}
	if !uninstall {
		fmt.Println("Client configs restored; setup identities removed. Service kept. Stop it with ralx uninstall.")
		return nil
	}
	if s.Autostart != "" {
		path, b, e := userAutostart(s)
		if e != nil {
			return e
		}
		if path != s.Autostart {
			return errors.New("autostart receipt mismatch")
		}
		actual, e := os.ReadFile(path)
		if e == nil {
			if !reflect.DeepEqual(actual, b) {
				return errors.New("autostart file edited; kept for manual removal")
			}
			if e := syncUserAutostart(s, true); e != nil {
				return e
			}
			if e := os.Remove(path); e != nil {
				return e
			}
		} else if !os.IsNotExist(e) {
			return e
		} else if e := syncUserAutostart(s, true); e != nil {
			return e
		}
	}
	if s.Mode == "local" {
		if e := setupconfig.Write(filepath.Join(setupHome(), "stop"), []byte("stop\n"), 0600); e != nil {
			return e
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			c := setupAdmin(s)
			_, e := c.JSON(ctx, "GET", "/admin/api/state", nil, nil)
			if e != nil {
				break
			}
			if time.Now().After(deadline) {
				return errors.New("service still stopping; retry ralx uninstall")
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	if e := os.Remove(setupStatePath()); e != nil {
		return e
	}
	fmt.Println("Client configs restored. Per-user service and autostart removed. Vault data kept at " + s.Data)
	return uninstallDownload()
}

func cmdDoctor(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("usage: ralx doctor")
	}
	s, e := readSetup()
	if e != nil {
		return errors.New("setup missing; fix: ralx setup")
	}
	if e := sandboxSetup(s.Addr); e != nil {
		return e
	}
	failures := 0
	check := func(ok bool, label, fix string) {
		if ok {
			fmt.Println("✓ " + label)
		} else {
			fmt.Printf("✗ %s; fix: %s\n", label, fix)
			failures++
		}
	}
	fix := "ralx setup"
	if s.Mode == "local" {
		check(setupHealthy(s), "service up", fix)
		if s.SystemService != "" {
			check(upgradeSystemHealthy(s), "system service and protected binary", "repair the RalX system service")
		} else {
			_, e := setupAdmin(s).JSON(ctx, "GET", "/admin/api/state", nil, nil)
			check(e == nil, "private service connection", fix)
			b, e := os.ReadFile(s.Autostart)
			_, want, _ := userAutostart(s)
			check(e == nil && reflect.DeepEqual(b, want) && userAutostartEnabled(s), "autostart at login", fix)
		}
	}
	uiURL := s.URL
	if s.Mode == "local" {
		_, port, _ := net.SplitHostPort(s.Addr)
		uiURL = "http://localhost:" + port
	}
	r, e := setupHTTP().Get(uiURL + "/")
	ok := e == nil
	if r != nil {
		ok = ok && r.StatusCode == 200
		r.Body.Close()
	}
	check(ok, "UI reachable: "+uiURL, fix)
	for _, c := range setupClients() {
		if !hasString(s.Clients, c.Name) {
			detected, _ := setupDetected(c)
			fmt.Println(doctorClientHint(c.Name, detected))
			continue
		}
		b, e := os.ReadFile(c.Path)
		var got map[string]any
		if e == nil {
			got, e = setupconfig.Entry(b, c)
		}
		wantB, _ := json.Marshal(setupServer(s, c.Name))
		var want map[string]any
		_ = json.Unmarshal(wantB, &want)
		_, binErr := os.Stat(s.Exe)
		check(e == nil && binErr == nil && reflect.DeepEqual(got, want), c.Name+" config and binary", fix+" --clients "+c.Name)
		id, e := client.ReadIdentity(identityFile("setup-" + c.Name))
		var status map[string]any
		if e == nil && id.URL == s.URL {
			path := "/v1/whoami"
			if s.Mode == "cloud" {
				path = "/api/v1/whoami"
			}
			_, e = setupAgent(id).JSON(ctx, "GET", path, nil, &status)
		}
		identityFix := fix + " --clients " + c.Name
		if e != nil {
			identityFix = "ralx setup --remove; " + fix + " --clients all"
		}
		check(e == nil && id.URL == s.URL, c.Name+" identity enrolled", identityFix)
	}
	if len(s.Clients) > 0 {
		id, e := client.ReadIdentity(identityFile("setup-" + s.Clients[0]))
		if e == nil {
			var out struct {
				Connections []struct {
					Status string `json:"status"`
				} `json:"connections"`
				Connected []map[string]any `json:"connected"`
			}
			p := "/v1/connections"
			if s.Mode == "cloud" {
				p = "/api/v1/whoami"
			}
			_, e = setupAgent(id).JSON(ctx, "GET", p, nil, &out)
			healthy := e == nil
			for _, v := range out.Connections {
				healthy = healthy && (v.Status == "" || v.Status == "ok" || v.Status == "connected")
			}
			if e == nil && len(out.Connections) == 0 && len(out.Connected) == 0 {
				fmt.Println("- No accounts connected yet; next: ralx open")
			} else {
				if os.Getenv("RALX_SETUP_SANDBOX") == "1" && os.Getenv("RALX_SETUP_OFFLINE") == "1" {
					check(e == nil, "provider records readable (sandbox offline; provider status not checked)", "check the sandbox service")
				} else {
					check(healthy, "provider connection records healthy (provider access not tested)", "ralx open (reconnect the account in RalX)")
				}
			}
		}
	}
	if failures > 0 {
		return fmt.Errorf("doctor found %d problem(s)", failures)
	}
	return nil
}
