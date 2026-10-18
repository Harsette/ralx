package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Harsette/ralx/internal/client"
	"github.com/Harsette/ralx/internal/mcpbridge"
)

func adminClient() *client.Client { return client.NewAdmin(os.Getenv("RALX_ADMIN_PIPE")) }

func explainPipeErr(err error) error {
	if err != nil && (strings.Contains(err.Error(), "Access is denied") || strings.Contains(err.Error(), "permission denied")) {
		return errors.New("owner commands need an elevated (Run as administrator) terminal: " + err.Error())
	}
	return err
}

func cmdAdmin(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ralx admin install|uninstall|agent|secret|google-client|setup-link|state")
	}
	switch args[0] {
	case "install":
		return cmdInstall(ctx, args[1:])
	case "uninstall":
		return cmdUninstall(ctx, args[1:])
	case "open-setup":
		return openSetup(ctx, false)
	case "state":
		var st map[string]any
		if _, err := adminClient().JSON(ctx, "GET", "/admin/api/state", nil, &st); err != nil {
			return explainPipeErr(err)
		}
		delete(st, "audit")
		printJSON(st)
		return nil
	case "audit":
		var st map[string]any
		if _, err := adminClient().JSON(ctx, "GET", "/admin/api/state", nil, &st); err != nil {
			return explainPipeErr(err)
		}
		printJSON(st["audit"])
		return nil
	case "setup-link":
		fs := flag.NewFlagSet("setup-link", flag.ExitOnError)
		reset := fs.Bool("reset", false, "remove all passkeys and start over")
		_ = fs.Parse(args[1:])
		var out map[string]any
		if _, err := adminClient().JSON(ctx, "POST", "/admin/api/setup-link", map[string]any{"reset": *reset}, &out); err != nil {
			return explainPipeErr(err)
		}
		printJSON(out)
		return nil
	case "agent":
		return cmdAdminAgent(ctx, args[1:])
	case "secret":
		return cmdAdminSecret(ctx, args[1:])
	case "google-client":
		return cmdAdminGoogleClient(ctx, args[1:])
	case "mcp":
		return cmdAdminMCP(ctx, args[1:])
	case "paste-link":
		fs := flag.NewFlagSet("paste-link", flag.ExitOnError)
		field := fs.String("field", "", "field name (default token, or value for mcp_server)")
		provider := fs.String("provider", "", "provider")
		label := fs.String("label", "", "label shown on the page")
		origin := fs.String("origin", "", "hub origin for the link (default localhost)")
		kind := fs.String("kind", "api_key", "api_key, or mcp_server to plug a downstream MCP server in (needs --meta url= and --meta header=)")
		var metas multiFlag
		fs.Var(&metas, "meta", "non-secret metadata k=v")
		pos, _ := splitFlags(fs, args[1:])
		if len(pos) != 1 {
			return errors.New("usage: ralx admin paste-link <credential-name> [--field api_key] [--label Upload-Post]\n" +
				"       ralx admin paste-link composio --kind mcp_server --label \"Composio MCP\" --meta url=https://… --meta header=x-api-key")
		}
		meta := map[string]any{}
		for _, m := range metas {
			if i := strings.IndexByte(m, '='); i > 0 {
				meta[m[:i]] = m[i+1:]
			}
		}
		var out map[string]any
		if _, err := adminClient().JSON(ctx, "POST", "/admin/api/drop", map[string]any{"name": pos[0], "field": *field, "provider": *provider, "label": *label, "kind": *kind, "meta": meta, "origin": *origin}, &out); err != nil {
			return explainPipeErr(err)
		}
		printJSON(out)
		return nil
	case "approvals":
		var st map[string]any
		if _, err := adminClient().JSON(ctx, "GET", "/admin/api/state", nil, &st); err != nil {
			return explainPipeErr(err)
		}
		printJSON(st["pending"])
		return nil
	case "deny":
		if len(args) != 2 {
			return errors.New("usage: ralx admin deny <approval-id>   (approving needs the owner's passkey in the app)")
		}
		if _, err := adminClient().JSON(ctx, "POST", "/admin/api/approvals/"+args[1]+"/deny", nil, nil); err != nil {
			return explainPipeErr(err)
		}
		fmt.Println("✓ Denied", args[1])
		return nil
	case "oauth-client":
		fs := flag.NewFlagSet("oauth-client", flag.ExitOnError)
		name := fs.String("name", "", "app name, e.g. Grok")
		redirect := fs.String("redirect", "", "comma-separated redirect URIs the app uses")
		_, _ = splitFlags(fs, args[1:])
		if *name == "" || *redirect == "" {
			return errors.New("usage: ralx admin oauth-client --name Grok --redirect https://grok.com/connectors-oauth-exchange-code/")
		}
		var out map[string]any
		if _, err := adminClient().JSON(ctx, "POST", "/admin/api/oauth-clients", map[string]any{"name": *name, "redirect_uris": splitList(*redirect)}, &out); err != nil {
			return explainPipeErr(err)
		}
		fmt.Println("✓ OAuth client created. Paste these into the app's connector settings (the secret is shown once):")
		printJSON(out)
		return nil
	case "google-default":
		fs := flag.NewFlagSet("google-default", flag.ExitOnError)
		services := fs.String("services", "", "comma-separated services this account is the default for (drive,gmail,youtube)")
		pos, _ := splitFlags(fs, args[1:])
		if len(pos) != 1 {
			return errors.New("usage: ralx admin google-default <email> [--services youtube]")
		}
		if _, err := adminClient().JSON(ctx, "POST", "/admin/api/google/default", map[string]any{"account": pos[0], "services": splitList(*services)}, nil); err != nil {
			return explainPipeErr(err)
		}
		fmt.Println("✓ Default updated.")
		return nil
	}
	return fmt.Errorf("unknown admin command %q", args[0])
}

func cmdAdminAgent(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ralx admin agent create|revoke|list")
	}
	ac := adminClient()
	switch args[0] {
	case "list":
		var st map[string]any
		if _, err := ac.JSON(ctx, "GET", "/admin/api/state", nil, &st); err != nil {
			return explainPipeErr(err)
		}
		printJSON(st["agents"])
		return nil
	case "prompt":
		var out map[string]any
		if _, err := ac.JSON(ctx, "POST", "/admin/api/enroll/code", map[string]any{}, &out); err != nil {
			return explainPipeErr(err)
		}
		fmt.Println(out["prompt"])
		return nil
	case "create":
		fs := flag.NewFlagSet("create", flag.ExitOnError)
		out := fs.String("out", "", "write the key to this file (default: print once)")
		allow := fs.String("allow", "", "comma-separated action globs this agent may use (default all)")
		deny := fs.String("deny", "", "comma-separated action globs to deny")
		pos, _ := splitFlags(fs, args[1:])
		if len(pos) != 1 {
			return errors.New("usage: ralx admin agent create <name> [--out file]")
		}
		key, err := createAgent(ctx, ac, pos[0], splitList(*allow), splitList(*deny))
		if err != nil {
			return err
		}
		if *out != "" {
			if err := writeKeyFile(*out, key); err != nil {
				return err
			}
			fmt.Printf("✓ Agent %q created; key written to %s\n", pos[0], *out)
			return nil
		}
		fmt.Printf("✓ Agent %q created. Its RalX key (shown once):\n%s\n", pos[0], key)
		return nil
	case "revoke":
		if len(args) != 2 {
			return errors.New("usage: ralx admin agent revoke <name>")
		}
		var out map[string]any
		if _, err := ac.JSON(ctx, "POST", "/admin/api/agents/"+args[1]+"/revoke", nil, &out); err != nil {
			return explainPipeErr(err)
		}
		fmt.Printf("✓ Revoked %v. Its next call will fail.\n", out["agent"])
		return nil
	}
	return errors.New("usage: ralx admin agent create|revoke|list")
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func createAgent(ctx context.Context, ac *client.Client, name string, allow, deny []string) (string, error) {
	var res map[string]any
	if _, err := ac.JSON(ctx, "POST", "/admin/api/agents", map[string]any{"name": name, "policy": map[string]any{"allow": allow, "deny": deny}}, &res); err != nil {
		return "", explainPipeErr(err)
	}
	key, _ := res["key"].(string)
	if key == "" {
		return "", errors.New("daemon returned no key")
	}
	return key, nil
}

func writeKeyFile(path, key string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(key+"\n"), 0o600)
}

// cmdAdminSecret stores a credential read from stdin (so it never appears in
// a command line, shell history or transcript).
func cmdAdminSecret(ctx context.Context, args []string) error {
	if len(args) < 2 || args[0] != "set" {
		return errors.New("usage: ralx admin secret set <name> [--field token] [--provider P] [--kind K] [--meta k=v] < value")
	}
	fs := flag.NewFlagSet("secret", flag.ExitOnError)
	field := fs.String("field", "token", "field name")
	provider := fs.String("provider", "", "provider (default: name)")
	kind := fs.String("kind", "api_key", "kind")
	label := fs.String("label", "", "label")
	var metas multiFlag
	fs.Var(&metas, "meta", "non-secret metadata k=v (repeatable)")
	pos, _ := splitFlags(fs, args[1:])
	if len(pos) != 1 {
		return errors.New("usage: ralx admin secret set <name> < value")
	}
	val, err := readSecretStdin()
	if err != nil {
		return err
	}
	meta := map[string]any{}
	for _, m := range metas {
		if i := strings.IndexByte(m, '='); i > 0 {
			meta[m[:i]] = m[i+1:]
		}
	}
	body := map[string]any{"name": pos[0], "kind": *kind, "provider": *provider, "label": *label, "meta": meta, "fields": map[string]string{*field: val}}
	if _, err := adminClient().JSON(ctx, "POST", "/admin/api/credentials", body, nil); err != nil {
		return explainPipeErr(err)
	}
	fmt.Printf("✓ Stored %s (%d characters) in the RalX vault.\n", pos[0], len(val))
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func readSecretStdin() (string, error) {
	st, _ := os.Stdin.Stat()
	if st != nil && st.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprint(os.Stderr, "Paste the value and press Enter: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", errors.New("empty value on stdin")
	}
	return v, nil
}

// cmdAdminGoogleClient imports the Desktop OAuth client JSON downloaded from
// Google Cloud Console, then deletes the downloaded file.
func cmdAdminGoogleClient(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("google-client", flag.ExitOnError)
	keep := fs.Bool("keep", false, "don't delete the JSON file after import")
	pos, _ := splitFlags(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: ralx admin google-client <client_secret.json>")
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	var j map[string]struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		ProjectID    string `json:"project_id"`
	}
	if err := json.Unmarshal(data, &j); err != nil {
		return fmt.Errorf("not a Google client JSON: %w", err)
	}
	c, ok := j["installed"]
	if !ok {
		if _, web := j["web"]; web {
			return errors.New("this is a Web client; RalX needs a Desktop app client")
		}
		return errors.New("no \"installed\" client in this JSON")
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return errors.New("client JSON is missing client_id or client_secret")
	}
	body := map[string]any{"name": "google-oauth-client", "label": "RalX Google OAuth client (" + c.ProjectID + ")",
		"meta": map[string]any{"project_id": c.ProjectID, "client_id": c.ClientID}, "fields": map[string]string{"client_id": c.ClientID, "client_secret": c.ClientSecret}}
	if _, err := adminClient().JSON(ctx, "POST", "/admin/api/credentials", body, nil); err != nil {
		return explainPipeErr(err)
	}
	if !*keep {
		_ = os.Remove(pos[0])
	}
	fmt.Printf("✓ Google OAuth client for project %s stored in the vault%s.\n", c.ProjectID, map[bool]string{true: "", false: "; the downloaded JSON was deleted"}[*keep])
	return nil
}

// cmdAdminMCP plugs another MCP server in behind RalX.
//
//	ralx admin mcp connect notion https://mcp.notion.com/mcp      (OAuth; opens the browser)
//	ralx admin mcp add composio https://... --header x-api-key    (key on stdin)
//	ralx admin mcp reload
func cmdAdminMCP(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ralx admin mcp connect <name> <url> | add <name> <url> [--header H] | reload")
	}
	ac := adminClient()
	switch args[0] {
	case "page-edits":
		if len(args) != 4 || (args[3] != "enable" && args[3] != "disable") {
			return errors.New("usage: ralx admin mcp page-edits <server> <raw update-page tool> enable|disable")
		}
		var out map[string]any
		if _, err := ac.JSON(ctx, "POST", "/admin/api/upstreams/notion-page-edits", map[string]any{"name": args[1], "tool": args[2], "enabled": args[3] == "enable"}, &out); err != nil {
			return explainPipeErr(err)
		}
		printJSON(out)
		return nil
	case "policy":
		if len(args) != 4 {
			return errors.New("usage: ralx admin mcp policy <server> <exact raw tool> <risk>")
		}
		var out map[string]any
		if _, err := ac.JSON(ctx, "POST", "/admin/api/upstreams/policy", map[string]any{"name": args[1], "tool": args[2], "risk": args[3]}, &out); err != nil {
			return explainPipeErr(err)
		}
		printJSON(out)
		return nil
	case "connect":
		if len(args) != 3 {
			return errors.New("usage: ralx admin mcp connect <name> <https url>")
		}
		var out map[string]any
		if _, err := ac.JSON(ctx, "POST", "/admin/api/upstreams/oauth", map[string]any{"name": args[1], "url": args[2]}, &out); err != nil {
			return explainPipeErr(err)
		}
		u, _ := out["auth_url"].(string)
		fmt.Println("Approve RalX in the browser:\n  " + u)
		_ = mcpbridge.OpenBrowser(u)
		return nil
	case "add":
		fs := flag.NewFlagSet("add", flag.ExitOnError)
		header := fs.String("header", "Authorization", "header that carries the key")
		pos, _ := splitFlags(fs, args[1:])
		if len(pos) != 2 {
			return errors.New("usage: ralx admin mcp add <name> <https url> [--header x-api-key] < key")
		}
		val, err := readSecretStdin()
		if err != nil {
			return err
		}
		if _, err := ac.JSON(ctx, "POST", "/admin/api/upstreams/header", map[string]any{"name": pos[0], "url": pos[1], "header": *header, "value": val}, nil); err != nil {
			return explainPipeErr(err)
		}
		fmt.Printf("✓ %s plugged in behind RalX.\n", pos[0])
		return nil
	case "reload":
		var out map[string]any
		if _, err := ac.JSON(ctx, "POST", "/admin/api/upstreams/reload", nil, &out); err != nil {
			return explainPipeErr(err)
		}
		printJSON(out)
		return nil
	}
	return errors.New("usage: ralx admin mcp connect|add|reload")
}

// ---------- open ----------

func cmdOpen(ctx context.Context, args []string) error {
	var sess map[string]any
	if _, err := client.New().JSON(ctx, "GET", "/admin/api/session", nil, &sess); err != nil {
		return err
	}
	if need, _ := sess["setup_needed"].(bool); need {
		return openSetup(ctx, true)
	}
	return mcpbridge.OpenBrowser("http://localhost:7317/")
}

// openSetup gets a one-time setup link over the admin pipe (elevating if
// needed) and opens it, so only the PC's owner can register the first passkey.
func openSetup(ctx context.Context, canElevate bool) error {
	var out map[string]any
	_, err := adminClient().JSON(ctx, "POST", "/admin/api/setup-link", map[string]any{}, &out)
	if err != nil && canElevate && strings.Contains(err.Error(), "Access is denied") {
		fmt.Println("Asking Windows for permission to create your RalX setup link…")
		return relaunchElevated([]string{"admin", "open-setup"})
	}
	if err != nil {
		return explainPipeErr(err)
	}
	u, _ := out["url"].(string)
	fmt.Println("Opening RalX to register your passkey (Windows Hello).")
	return mcpbridge.OpenBrowser(u)
}
