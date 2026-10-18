package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/client"
	"github.com/Harsette/ralx/internal/setupconfig"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pelletier/go-toml/v2"
)

func TestSetupSandboxJourney(t *testing.T) {
	binary := os.Getenv("RALX_TEST_BINARY")
	if binary == "" {
		t.Skip("set RALX_TEST_BINARY to a locally built binary for installer + real MCP proof")
	}
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell installer journey; run shell installer separately on Unix")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	release := filepath.Join(root, "release")
	_ = os.MkdirAll(release, 0700)
	// Preserve Go/module caches: only runtime HOME and client config variables move.
	for k, v := range map[string]string{"HOME": home, "USERPROFILE": home, "APPDATA": filepath.Join(home, "AppData", "Roaming"), "LOCALAPPDATA": filepath.Join(home, "AppData", "Local"), "RALX_SETUP_SANDBOX": "1", "RALX_AGENT_KEY": "", "RALX_AGENT_KEY_FILE": "", "RALX_URL": "", "CLAUDE_CONFIG_DIR": "", "CODEX_HOME": "", "XDG_CONFIG_HOME": filepath.Join(home, ".config")} {
		t.Setenv(k, v)
	}
	if e := os.MkdirAll(os.Getenv("LOCALAPPDATA"), 0700); e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := ln.Addr().String()
	ln.Close()
	data := filepath.Join(home, "test-data")
	t.Setenv("RALX_SETUP_ADDR", addr)
	t.Setenv("RALX_SETUP_DATA", data)
	t.Setenv("RALX_SETUP_NO_BROWSER", "1")
	cs := setupClients()
	originals := map[string][]byte{}
	for _, c := range cs {
		for _, p := range c.Detect {
			if strings.HasSuffix(p, ".json") {
				continue
			}
			if e := os.MkdirAll(p, 0700); e != nil {
				t.Fatal(e)
			}
		}
		orig := []byte("{\r\n \"" + c.Group + "\": {\"existing\": {\"command\":\"keep\"}}, \"keep\": true\r\n}\r\n")
		if c.Format == "toml" {
			orig = []byte("# keep this exact file\r\nmodel='fixture'\r\n[mcp_servers.existing]\r\ncommand='keep'\r\n")
		}
		originals[c.Name] = orig
		if e := setupconfig.Write(c.Path, orig, 0600); e != nil {
			t.Fatal(e)
		}
	}
	built, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	asset := "ralx_windows_" + runtime.GOARCH + ".exe"
	if e := os.WriteFile(filepath.Join(release, asset), built, 0700); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(built)
	if e := os.WriteFile(filepath.Join(release, "checksums.txt"), []byte(hex.EncodeToString(sum[:])+"  "+asset+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("RALX_RELEASE_BASE_URL", release)
	t.Setenv("RALX_SETUP_ARGS_JSON", `["--mode","local","--clients","all","--yes","--no-browser"]`)
	installed := filepath.Join(home, ".local", "bin", "ralx.exe")
	run := func(exe string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, exe, args...)
		b, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %v\n%s", exe, args, e, b)
		}
		return string(b)
	}
	t.Cleanup(func() {
		if _, e := os.Stat(setupStatePath()); e == nil {
			c := exec.Command(installed, "uninstall")
			_ = c.Run()
		}
	})
	// A corrupt release must fail before any binary or client config is changed.
	if e := os.WriteFile(filepath.Join(release, "checksums.txt"), []byte(strings.Repeat("0", 64)+"  "+asset+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	bad := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", filepath.Join("..", "..", "install.ps1"))
	badOut, badErr := bad.CombinedOutput()
	if badErr == nil || !strings.Contains(string(badOut), "The download check failed") {
		t.Fatalf("corrupt binary not rejected: %v %s", badErr, badOut)
	}
	if _, e := os.Stat(installed); !os.IsNotExist(e) {
		t.Fatal("corrupt binary installed")
	}
	if e := os.WriteFile(filepath.Join(release, "checksums.txt"), []byte(hex.EncodeToString(sum[:])+"  "+asset+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	t.Log("CHECKSUM: corrupt release refused before installation")
	transcript := run("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", filepath.Join("..", "..", "install.ps1"))
	if !strings.Contains(transcript, "Using another app? Run: ralx config <app> (or ralx config --list)") || strings.Contains(transcript, "Other clients (stdio)") || strings.Contains(transcript, `\u003c`) {
		t.Fatalf("setup output is not concise: %s", transcript)
	}
	t.Log("INSTALL + SETUP\n" + transcript)
	s, e := readSetup()
	if e != nil {
		t.Fatal(e)
	}
	if s.URL != "http://"+addr || s.Data != data {
		t.Fatal("sandbox address or data changed")
	}
	ids := map[string]bool{}
	for _, c := range cs {
		b, _ := os.ReadFile(c.Path)
		bak, e := os.ReadFile(setupconfig.BackupPath(c.Path))
		if e != nil || !bytes.Equal(bak, originals[c.Name]) {
			t.Fatal("backup failed", c.Name, e)
		}
		entry, e := setupconfig.Entry(b, c)
		if e != nil || entry["command"] != installed {
			t.Fatal("wrong command", c.Name, e)
		}
		id, e := client.ReadIdentity(identityFile("setup-" + c.Name))
		if e != nil || ids[id.KeyDigest] {
			t.Fatal("missing or shared identity", c.Name, e)
		}
		ids[id.KeyDigest] = true
	}
	before := map[string][]byte{}
	for _, c := range cs {
		before[c.Path], _ = os.ReadFile(c.Path)
	}
	t.Log("RERUN\n" + run(installed, "setup", "--mode", "local", "--clients", "all", "--yes", "--no-browser"))
	for _, c := range cs {
		b, _ := os.ReadFile(c.Path)
		if !bytes.Equal(b, before[c.Path]) {
			t.Fatal("non-idempotent", c.Name)
		}
	}
	t.Log("DOCTOR\n" + run(installed, "doctor"))
	// Exercise the actual Windows login launcher with only sandbox files/env.
	stopFile := filepath.Join(setupHome(), "stop")
	if e := os.WriteFile(stopFile, []byte("stop"), 0600); e != nil {
		t.Fatal(e)
	}
	deadlineStop := time.Now().Add(10 * time.Second)
	for setupHealthy(s) {
		if time.Now().After(deadlineStop) {
			t.Fatal("sandbox service did not stop for launcher proof")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e := os.Remove(stopFile); e != nil {
		t.Fatal(e)
	}
	run("wscript.exe", s.Autostart)
	deadlineStart := time.Now().Add(10 * time.Second)
	for !setupHealthy(s) {
		if time.Now().After(deadlineStart) {
			t.Fatal("sandbox Windows autostart launcher did not start service")
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Log("AUTOSTART: sandbox Windows VBS launcher restarted daemon")
	for _, name := range []string{"codex", "claude-code", "antigravity"} {
		var c setupconfig.Client
		for _, v := range cs {
			if v.Name == name {
				c = v
			}
		}
		b, _ := os.ReadFile(c.Path)
		// Parse the exact emitted TOML/JSON formats independently of the writer.
		var config map[string]any
		if name == "codex" {
			e = toml.Unmarshal(b, &config)
		} else {
			e = json.Unmarshal(b, &config)
		}
		if e != nil {
			t.Fatal(e)
		}
		entry := config[c.Group].(map[string]any)["ralx"].(map[string]any)
		args := []string{}
		switch vs := entry["args"].(type) {
		case []any:
			for _, v := range vs {
				args = append(args, v.(string))
			}
		}
		cmd := exec.Command(entry["command"].(string), args...)
		cmd.Env = os.Environ()
		for k, v := range entry["env"].(map[string]any) {
			cmd.Env = append(cmd.Env, k+"="+v.(string))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		mc := mcp.NewClient(&mcp.Implementation{Name: "setup-sandbox-proof", Version: "1"}, nil)
		sess, e := mc.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
		if e != nil {
			cancel()
			t.Fatal(name, e)
		}
		tools, e := sess.ListTools(ctx, nil)
		if e != nil || len(tools.Tools) == 0 {
			t.Fatal(name, "tools/list", e)
		}
		names := map[string]bool{}
		for _, tool := range tools.Tools {
			names[tool.Name] = true
		}
		for _, required := range []string{"browser_sign_up", "browser_sign_in", "logins_new_test", "browser_authorize"} {
			if !names[required] {
				t.Fatalf("%s setup-written config missing sign-in tool %s", name, required)
			}
		}
		t.Logf("MCP %s: all four sign-in tools advertised through setup-written config", name)
		t.Logf("MCP %s: initialize OK, tools/list OK (%d tools)", name, len(tools.Tools))
		sess.Close()
		cancel()
	}
	// A removed/revoked identity must fail the doctor's real enrollment check.
	var discarded map[string]any
	_, e = setupAdmin(s).JSON(context.Background(), "POST", "/admin/api/agents/"+s.AgentNames["setup-cursor"]+"/revoke", nil, &discarded)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(installed, "doctor")
	out, e := cmd.CombinedOutput()
	if e == nil || !strings.Contains(string(out), "✗ cursor identity enrolled") {
		t.Fatalf("doctor missed revoked identity: %v %s", e, out)
	}
	t.Log("DOCTOR revoked identity: detected with fix command")
	t.Log("REMOVE\n" + run(installed, "setup", "--remove"))
	for _, c := range cs {
		b, e := os.ReadFile(c.Path)
		if e != nil || !bytes.Equal(b, originals[c.Name]) {
			t.Fatal("remove failed byte restoration", c.Name, e)
		}
	}
	if !setupHealthy(s) {
		t.Fatal("setup --remove stopped the service")
	}
	t.Log("RECONNECT\n" + run(installed, "setup", "--mode", "local", "--clients", "all", "--yes", "--no-browser"))
	s, e = readSetup()
	if e != nil {
		t.Fatal(e)
	}
	t.Log("UNINSTALL\n" + run(installed, "uninstall"))
	for _, c := range cs {
		b, e := os.ReadFile(c.Path)
		if e != nil || !bytes.Equal(b, originals[c.Name]) {
			t.Fatal("not byte-identical", c.Name, e)
		}
		if setupconfig.Managed(c.Path) {
			t.Fatal("receipt left", c.Name)
		}
	}
	for _, name := range s.Identities {
		if _, e := os.Stat(identityFile(name)); !os.IsNotExist(e) {
			t.Fatal("identity left", name)
		}
	}
	if setupHealthy(s) {
		t.Fatal("service still running")
	}
	if _, e := os.Stat(s.Autostart); !os.IsNotExist(e) {
		t.Fatal("autostart left")
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		_, e := os.Stat(installed)
		if os.IsNotExist(e) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("installer binary not removed")
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Log("RESTORED: all 8 original files byte-identical; identities, autostart and binary removed; service stopped; data retained")
}

func TestSetupCloudComingSoon(t *testing.T) {
	home := t.TempDir()
	for k, v := range map[string]string{"HOME": home, "USERPROFILE": home, "APPDATA": filepath.Join(home, "AppData"), "LOCALAPPDATA": filepath.Join(home, "Local"), "RALX_SETUP_SANDBOX": "1", "RALX_SETUP_ADDR": "127.0.0.1:17319"} {
		t.Setenv(k, v)
	}
	if e := cmdSetup(context.Background(), []string{"--mode", "coming-soon"}); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(setupStatePath()); !os.IsNotExist(e) {
		t.Fatal("coming soon created installation", e)
	}
	if _, e := os.Stat(setupHome()); !os.IsNotExist(e) {
		t.Fatal("coming soon created setup files", e)
	}
}

func TestFreshCodexConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("RALX_SETUP_SANDBOX", "1")
	if e := os.MkdirAll(filepath.Join(home, ".codex"), 0700); e != nil {
		t.Fatal(e)
	}
	for _, c := range setupClients() {
		if c.Name != "codex" {
			continue
		}
		if detected, _ := setupDetected(c); !detected {
			t.Fatal("fresh Codex directory not detected")
		}
		if _, e := os.Stat(c.Path); !os.IsNotExist(e) {
			t.Fatal("config already exists", e)
		}
		if e := setupconfig.Install(c, setupconfig.Server{Command: "ralx", Args: []string{"mcp"}}, nil); e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(c.Path)
		if e != nil {
			t.Fatal(e)
		}
		var m map[string]any
		if e := toml.Unmarshal(b, &m); e != nil {
			t.Fatal(e)
		}
		if m["mcp_servers"].(map[string]any)["ralx"] == nil {
			t.Fatal("registration missing")
		}
		if e := setupconfig.Remove(c); e != nil {
			t.Fatal(e)
		}
		if _, e := os.Stat(c.Path); !os.IsNotExist(e) {
			t.Fatal("new config not removed", e)
		}
	}
}

func TestSetupCloudSandbox(t *testing.T) {
	binary := os.Getenv("RALX_TEST_BINARY")
	if binary == "" {
		t.Skip("set RALX_TEST_BINARY for hosted setup fixture")
	}
	home := t.TempDir()
	for k, v := range map[string]string{"HOME": home, "USERPROFILE": home, "APPDATA": filepath.Join(home, "AppData", "Roaming"), "LOCALAPPDATA": filepath.Join(home, "AppData", "Local"), "RALX_SETUP_SANDBOX": "1", "RALX_SETUP_ADDR": "127.0.0.1:17319", "RALX_SETUP_NO_BROWSER": "1", "RALX_AGENT_KEY": "", "RALX_AGENT_KEY_FILE": "", "RALX_URL": "", "CLAUDE_CONFIG_DIR": "", "CODEX_HOME": ""} {
		t.Setenv(k, v)
	}
	if e := os.MkdirAll(os.Getenv("LOCALAPPDATA"), 0700); e != nil {
		t.Fatal(e)
	}
	for _, c := range setupClients() {
		if c.Name == "codex" || c.Name == "claude-code" {
			if e := os.MkdirAll(filepath.Dir(c.Path), 0700); e != nil {
				t.Fatal(e)
			}
			if c.Name == "claude-code" {
				if e := os.MkdirAll(filepath.Join(home, ".claude"), 0700); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	keys := map[string]string{"codex": "fixture-cloud-codex-stand-in-key", "claude-code": "fixture-cloud-claude-stand-in-key"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`{}`))
			return
		case "/api/enroll":
			var b struct{ Client, Code string }
			if json.NewDecoder(r.Body).Decode(&b) != nil || b.Code != b.Client+"-code" || keys[b.Client] == "" {
				w.WriteHeader(400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"key": keys[b.Client]})
			return
		}
		auth := r.Header.Get("Authorization")
		valid := false
		for _, key := range keys {
			valid = valid || auth == "Bearer "+key
		}
		if !valid {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/api/v1/whoami" {
			w.Write([]byte(`{"agent":{"name":"fixture"},"connected":[{"slug":"fixture"}]}`))
			return
		}
		if r.URL.Path == "/mcp" {
			var req struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if json.NewDecoder(r.Body).Decode(&req) != nil {
				w.WriteHeader(400)
				return
			}
			if len(req.ID) == 0 {
				w.WriteHeader(202)
				return
			}
			var result any
			switch req.Method {
			case "initialize":
				result = map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "fixture", "version": "1"}}
			case "tools/list":
				result = map[string]any{"tools": []any{map[string]any{"name": "fixture", "description": "synthetic tool", "inputSchema": map[string]any{"type": "object"}}}}
			default:
				result = map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "setup", "--mode", "cloud", "--url", server.URL, "--clients", "codex,claude-code", "--yes", "--no-browser", "--enroll-code", "codex=codex-code", "--enroll-code", "claude-code=claude-code-code")
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("%v %s", e, out)
	}
	s, e := readSetup()
	if e != nil || s.Mode != "cloud" || s.Autostart != "" {
		t.Fatal(s, e)
	}
	// The short doctor fix must keep the saved cloud origin and mode.
	cmd = exec.CommandContext(ctx, binary, "setup", "--clients", "codex", "--no-browser")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("short repair changed installation: %v %s", err, out)
	}
	for _, name := range []string{"codex", "claude-code"} {
		cmd := exec.Command(binary, "cloud-mcp")
		cmd.Env = append(os.Environ(), "RALX_AGENT_KEY_FILE="+identityFile("setup-"+name))
		mc := mcp.NewClient(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
		sess, e := mc.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
		if e != nil {
			t.Fatal(e)
		}
		tools, e := sess.ListTools(ctx, nil)
		if e != nil || len(tools.Tools) != 1 {
			t.Fatal(e)
		}
		sess.Close()
	}
	cmd = exec.CommandContext(ctx, binary, "doctor")
	out, e = cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("cloud doctor %v %s", e, out)
	}
	cmd = exec.CommandContext(ctx, binary, "uninstall")
	out, e = cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("cloud remove %v %s", e, out)
	}
	if !strings.Contains(string(out), "Revoke setup-") {
		t.Fatal("hosted revocation reminder missing")
	}
	for _, c := range setupClients() {
		if c.Name == "codex" || c.Name == "claude-code" {
			if _, e := os.Stat(c.Path); !os.IsNotExist(e) {
				t.Fatal("cloud config left", c.Path)
			}
		}
	}
	t.Log("CLOUD FIXTURE: 2 separate enrollments; hosted stdio initialize/tools/list; doctor; clean uninstall; no local daemon")
}

func TestSetupSelfHostIntegration(t *testing.T) {
	if _, e := exec.LookPath("node"); e != nil {
		t.Fatal("self-host integration requires Node: ", e)
	}
	for _, mode := range []string{"self-host", "cloudflare", "local-check", "failed-deploy"} {
		t.Run(mode, func(t *testing.T) {
			home := t.TempDir()
			for k, v := range map[string]string{"HOME": home, "USERPROFILE": home, "APPDATA": filepath.Join(home, "AppData", "Roaming"), "LOCALAPPDATA": filepath.Join(home, "AppData", "Local"), "RALX_SETUP_SANDBOX": "1", "RALX_SETUP_NO_BROWSER": "1", "RALX_SETUP_ADDR": "127.0.0.1:17319", "RALX_CLOUD_URL": "", "RALX_AGENT_KEY_FILE": ""} {
				t.Setenv(k, v)
			}
			source := t.TempDir()
			scripts := filepath.Join(source, "cloud", "scripts")
			if e := os.MkdirAll(scripts, 0700); e != nil {
				t.Fatal(e)
			}
			script := `const fs=require('fs'),path=require('path');
const cloud=path.resolve(__dirname,'..');
fs.writeFileSync(path.join(cloud,'called.json'),JSON.stringify(process.argv.slice(2)));
fs.writeFileSync(path.join(cloud,'wrangler.selfhost.json'),JSON.stringify({vars:{BASE_URL:'https://synthetic-selfhost.example.invalid'}}));`
			if mode == "failed-deploy" {
				script = `process.exit(9);`
			}
			if e := os.WriteFile(filepath.Join(scripts, "selfhost.mjs"), []byte(strings.ReplaceAll(script, "const fs=require('fs'),path=require('path');", "import fs from 'node:fs'; import path from 'node:path'; import {fileURLToPath} from 'node:url'; const __dirname=path.dirname(fileURLToPath(import.meta.url));")), 0600); e != nil {
				t.Fatal(e)
			}
			selected := mode
			if mode == "local-check" || mode == "failed-deploy" {
				selected = "self-host"
			}
			args := []string{"--mode", selected, "--source", source, "--clients", "none", "--yes", "--no-browser", "--url", "https://wrong.example.invalid"}
			if mode == "local-check" {
				args = append(args, "--local", "--check")
			}
			e := cmdSetup(context.Background(), args)
			if mode == "failed-deploy" {
				if e == nil {
					t.Fatal("deployment failure ignored")
				}
				if _, e := os.Stat(setupStatePath()); !os.IsNotExist(e) {
					t.Fatal("failed deploy created setup state", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			called, e := os.ReadFile(filepath.Join(source, "cloud", "called.json"))
			if e != nil {
				t.Fatal(e)
			}
			if mode == "local-check" {
				if string(called) != `["--local","--check"]` {
					t.Fatal(string(called))
				}
				if _, e := os.Stat(setupStatePath()); !os.IsNotExist(e) {
					t.Fatal("local check registered clients", e)
				}
			} else {
				s, e := readSetup()
				if e != nil || s.Mode != "cloud" || s.URL != "https://synthetic-selfhost.example.invalid" || s.Autostart != "" {
					t.Fatal(s, e)
				}
				if string(called) != `[]` {
					t.Fatal(string(called))
				}
			}
		})
	}
}
