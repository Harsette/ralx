//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// setupHarnesses registers RalX with Claude Code, Codex and Hermes: an MCP
// server entry plus RALX_AGENT_KEY_FILE for each harness's shell, so the CLI
// and MCP calls from that harness use its own revocable agent key.
func setupHarnesses(home string) error {
	exe := filepath.Join(installDir(), "ralx.exe")
	keys := filepath.Join(home, ".ralx", "agents")
	var errs []string

	// Claude Code
	if claude, err := exec.LookPath("claude"); err == nil {
		key := filepath.Join(keys, "claude-code.key")
		_ = exec.Command(claude, "mcp", "remove", "ralx", "--scope", "user").Run()
		out, err := exec.Command(claude, "mcp", "add", "-e", "RALX_AGENT_KEY_FILE="+key, "--scope", "user", "--transport", "stdio", "ralx", "--", exe, "mcp").CombinedOutput()
		if err != nil {
			errs = append(errs, fmt.Sprintf("claude mcp add: %v %s", err, out))
		} else {
			fmt.Println("✓ Claude Code: MCP server 'ralx' added")
		}
		if err := setJSONEnv(filepath.Join(home, ".claude", "settings.json"), "RALX_AGENT_KEY_FILE", key); err != nil {
			errs = append(errs, "claude settings env: "+err.Error())
		}
	}

	// Codex
	if codex, err := exec.LookPath("codex"); err == nil {
		key := filepath.Join(keys, "codex.key")
		_ = exec.Command(codex, "mcp", "remove", "ralx").Run()
		out, err := exec.Command(codex, "mcp", "add", "ralx", "--env", "RALX_AGENT_KEY_FILE="+key, "--", exe, "mcp").CombinedOutput()
		if err != nil {
			errs = append(errs, fmt.Sprintf("codex mcp add: %v %s", err, out))
		} else {
			fmt.Println("✓ Codex: MCP server 'ralx' added")
		}
		if err := setTOMLShellEnv(filepath.Join(home, ".codex", "config.toml"), "RALX_AGENT_KEY_FILE", key); err != nil {
			errs = append(errs, "codex shell env: "+err.Error())
		}
	}

	// Hermes (local desktop install)
	hermesHome := filepath.Join(os.Getenv("LOCALAPPDATA"), "hermes")
	if _, err := os.Stat(filepath.Join(hermesHome, "config.yaml")); err == nil {
		key := filepath.Join(keys, "hermes.key")
		if err := setHermesMCP(filepath.Join(hermesHome, "config.yaml"), exe, key); err != nil {
			errs = append(errs, "hermes config: "+err.Error())
		} else {
			fmt.Println("✓ Hermes: MCP server 'ralx' added")
		}
		if err := setDotEnv(filepath.Join(hermesHome, ".env"), "RALX_AGENT_KEY_FILE", key); err != nil {
			errs = append(errs, "hermes env: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func backup(path string) {
	if b, err := os.ReadFile(path); err == nil {
		bak := path + ".bak-ralx"
		if _, err := os.Stat(bak); err != nil {
			_ = os.WriteFile(bak, b, 0o600)
		}
	}
}

func setJSONEnv(path, k, v string) error {
	m := map[string]any{}
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("%s is not plain JSON; add env %s manually", path, k)
		}
	}
	env, _ := m["env"].(map[string]any)
	if env == nil {
		env = map[string]any{}
	}
	if env[k] == v {
		return nil
	}
	backup(path)
	env[k] = v
	m["env"] = env
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func tomlString(s string) string { return "'" + s + "'" }

func setTOMLShellEnv(path, k, v string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(b)
	line := k + " = " + tomlString(v)
	if strings.Contains(text, line) {
		return nil
	}
	backup(path)
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) == "[shell_environment_policy.set]" {
			// drop an older RalX line in this table, then insert ours
			j := i + 1
			for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "[") {
				if strings.HasPrefix(strings.TrimSpace(lines[j]), k+" ") || strings.HasPrefix(strings.TrimSpace(lines[j]), k+"=") {
					lines = append(lines[:j], lines[j+1:]...)
					continue
				}
				j++
			}
			lines = append(lines[:i+1], append([]string{line}, lines[i+1:]...)...)
			return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600)
		}
	}
	text = strings.TrimRight(text, "\n") + "\n\n[shell_environment_policy.set]\n" + line + "\n"
	return os.WriteFile(path, []byte(text), 0o600)
}

func setHermesMCP(path, exe, key string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(b)
	if strings.Contains(text, "# >>> ralx") {
		return nil
	}
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "mcp_servers:") {
			return fmt.Errorf("config.yaml already has an mcp_servers block; add ralx under it by hand")
		}
	}
	backup(path)
	block := fmt.Sprintf("\n# >>> ralx (added by ralx admin install)\nmcp_servers:\n  ralx:\n    command: %q\n    args: [\"mcp\"]\n    env:\n      RALX_AGENT_KEY_FILE: %q\n    timeout: 300\n# <<< ralx\n", exe, key)
	return os.WriteFile(path, []byte(strings.TrimRight(text, "\n")+"\n"+block), 0o600)
}

func setDotEnv(path, k, v string) error {
	b, _ := os.ReadFile(path)
	text := string(b)
	line := k + "=" + v
	if strings.Contains(text, line) {
		return nil
	}
	backup(path)
	var keep []string
	for _, l := range strings.Split(text, "\n") {
		if !strings.HasPrefix(l, k+"=") {
			keep = append(keep, l)
		}
	}
	out := strings.TrimRight(strings.Join(keep, "\n"), "\n") + "\n" + line + "\n"
	return os.WriteFile(path, []byte(out), 0o600)
}
