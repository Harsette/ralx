// Command ralx is RalX: the vault daemon, the CLI agents use, and the MCP
// server, in one binary.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Harsette/ralx/internal/client"
	"github.com/Harsette/ralx/internal/daemon"
	"github.com/Harsette/ralx/internal/leakscan"
	"github.com/Harsette/ralx/internal/mcpbridge"
)

var version = "0.1.0-dev"

const usage = `RalX: one plug for every agent.

Agent commands (use your RalX agent key; never see real credentials):
  ralx setup [--mode local|cloud|self-host] [--clients all] [--yes]
  ralx doctor                         check installation and client connections
  ralx backup                         snapshot the current installation without stopping it
  ralx rollback [--backup DIR]         restore the last upgrade snapshot
  ralx config <app> | --list           show connection config for another app
  ralx setup --remove                 restore client configs
  ralx uninstall                      restore clients and remove per-user install
  ralx enroll <code> --name N --client claude-code|codex   connect with a code from the RalX app
  ralx --agent <name> <command>       run any command as an enrolled agent
  ralx status                         who am I, what's connected
  ralx actions                        list named actions
  ralx call <action> [k=v ...] [--json '{...}'] [--wait 10m]
  ralx wait <approval-id> [--timeout 10m]
  ralx connect google [--services drive,gmail,youtube] [--no-browser]
  ralx drive upload <file> [--folder ID] [--name NAME]
  ralx drive download <file-id> <dest>
  ralx drive ls [query]
  ralx gmail search [query] [--account you@example.invalid] [--max N] | gmail read <id> [--account you@example.invalid]
  ralx gmail send --to you@example.invalid --subject S --body B    (held for approval)
  ralx youtube channel | youtube upload <file> [--title T] [--privacy private|unlisted|public]
  ralx stage <file>                   send media to RalX for a social post
  ralx social post --platforms x,linkedin --text "..." [--media file]
  ralx leakscan [path ...]            prove no RalX secret is reachable here
  ralx mcp                            run the MCP server (stdio)
  ralx open                           open the RalX app
  ralx deploy cloudflare [--source PATH] [--local] [--check] [--update]

Owner commands (elevated / admin pipe):
  ralx admin install | uninstall
  ralx admin agent create <name> [--out file] | agent revoke <name> | agent list
  ralx admin agent prompt              one-time "connect an agent" prompt (same as the app button)
  ralx admin secret set <name> [--field F] [--provider P] [--meta k=v]   (value on stdin)
  ralx admin google-client <client_secret.json>
  ralx admin setup-link [--reset]
  ralx admin state

Daemon:
  ralx daemon [--data DIR] [--addr 127.0.0.1:7317] [--dev]
`

func main() {
	if len(os.Args) < 2 {
		if isService() {
			runService()
			return
		}
		fmt.Print(usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	if a := os.Args[1]; a == "--agent" || strings.HasPrefix(a, "--agent=") {
		name, rest := strings.TrimPrefix(a, "--agent="), os.Args[2:]
		if a == "--agent" && len(rest) > 0 {
			name, rest = rest[0], rest[1:]
		}
		if err := useAgent(name); err != nil || len(rest) == 0 {
			if err == nil {
				err = errors.New("usage: ralx --agent <name> <command>")
			}
			fmt.Fprintln(os.Stderr, "ralx:", err)
			os.Exit(1)
		}
		os.Args = append([]string{os.Args[0]}, rest...)
	}
	switch os.Args[1] {
	case "setup":
		err = cmdSetup(ctx, os.Args[2:])
	case "install-upgrade":
		err = cmdInstallUpgrade(ctx, os.Args[2:])
	case "rollback":
		err = cmdRollback(ctx, os.Args[2:])
	case "backup":
		err = cmdUpgradeBackup(ctx, os.Args[2:])
	case "doctor":
		err = cmdDoctor(ctx, os.Args[2:])
	case "config":
		err = cmdConfig(os.Args[2:])
	case "uninstall":
		if len(os.Args) != 2 {
			err = errors.New("usage: ralx uninstall")
		} else {
			err = removeSetup(ctx, true)
		}
	case "deploy":
		err = cmdDeploy(ctx, os.Args[2:])
	case "user-service":
		err = cmdUserService(ctx)
	case "cloud-mcp":
		err = cmdCloudMCP(ctx)
	case "install-path":
		err = cmdInstallPath()
	case "enroll":
		err = cmdEnroll(ctx, os.Args[2:])
	case "daemon":
		err = cmdDaemon(ctx, os.Args[2:])
	case "status":
		err = cmdStatus(ctx)
	case "actions":
		err = cmdActions(ctx)
	case "call":
		err = cmdCall(ctx, os.Args[2:])
	case "wait":
		err = cmdWait(ctx, os.Args[2:])
	case "connect":
		err = cmdConnect(ctx, os.Args[2:])
	case "drive":
		err = cmdDrive(ctx, os.Args[2:])
	case "gmail":
		err = cmdGmail(ctx, os.Args[2:])
	case "youtube":
		err = cmdYouTube(ctx, os.Args[2:])
	case "stage":
		err = cmdStage(ctx, os.Args[2:])
	case "social":
		err = cmdSocial(ctx, os.Args[2:])
	case "leakscan":
		err = cmdLeakscan(ctx, os.Args[2:])
	case "mcp":
		err = mcpbridge.Run(ctx, version)
	case "open":
		if s, e := readSetup(); e == nil {
			err = openUserSetup(ctx, s)
		} else {
			err = cmdOpen(ctx, os.Args[2:])
		}
	case "admin":
		err = cmdAdmin(ctx, os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("ralx", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ralx:", err)
		os.Exit(1)
	}
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// splitFlags lets flags appear after positional args (ralx drive upload f --folder x).
func splitFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	return pos, nil
}

// ---------- daemon ----------

func cmdDaemon(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	managed := fs.Bool("managed-sandbox-tools", false, "trust the platform-provided read-only Linux namespace root (--dev only)")
	data := fs.String("data", defaultDataDir(), "data directory")
	addr := fs.String("addr", "127.0.0.1:7317", "loopback listen address")
	dev := fs.Bool("dev", false, "dev mode: run as the current user (no account boundary)")
	pipe := fs.String("admin-pipe", client.DefaultAdminPipe, "admin pipe / socket")
	_ = fs.Parse(args)
	if !strings.HasPrefix(*addr, "127.0.0.1:") && !strings.HasPrefix(*addr, "[::1]:") && !strings.HasPrefix(*addr, "localhost:") {
		return errors.New("RalX only listens on loopback")
	}
	logger := log.New(os.Stderr, "ralx ", log.LstdFlags)
	s, err := daemon.New(daemon.Config{DataDir: *data, Addr: *addr, Dev: *dev, ManagedSandboxTools: *managed, AdminPipe: *pipe, Version: version}, logger)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Serve(ctx)
}

// ---------- agent commands ----------

func cmdStatus(ctx context.Context) error {
	c := client.New()
	var who, conns map[string]any
	if _, err := c.JSON(ctx, "GET", "/v1/whoami", nil, &who); err != nil {
		return err
	}
	_, _ = c.JSON(ctx, "GET", "/v1/connections", nil, &conns)
	fmt.Printf("RalX %v at %s  |  you are agent %q\n", who["ralx"], c.URL, who["agent"])
	if list, ok := conns["connections"].([]any); ok {
		if len(list) == 0 {
			fmt.Println("Nothing connected yet. Try: ralx connect google")
		}
		for _, it := range list {
			m, _ := it.(map[string]any)
			extra := ""
			if svc, ok := m["services"].([]any); ok && len(svc) > 0 {
				var ss []string
				for _, s := range svc {
					ss = append(ss, fmt.Sprint(s))
				}
				extra = " (" + strings.Join(ss, ", ") + ")"
			}
			st := ""
			if v, ok := m["status"]; ok && v != "ok" {
				st = "  [" + fmt.Sprint(v) + "]"
			}
			fmt.Printf("  ✓ %-10v %v%s%s\n", m["provider"], m["label"], extra, st)
		}
	}
	if tools, ok := conns["tools"].([]any); ok && len(tools) > 0 {
		var ts []string
		for _, t := range tools {
			ts = append(ts, fmt.Sprint(t))
		}
		sort.Strings(ts)
		fmt.Println("  CLIs behind RalX:", strings.Join(ts, ", "))
	}
	return nil
}

func cmdActions(ctx context.Context) error {
	c := client.New()
	var out struct {
		Actions []struct {
			Name, Description, Risk, GateReason string
			Ready                               bool
			Stream                              bool
		} `json:"actions"`
	}
	if _, err := c.JSON(ctx, "GET", "/v1/actions", nil, &out); err != nil {
		return err
	}
	for _, a := range out.Actions {
		mark := "  "
		switch a.Risk {
		case "gated":
			mark = "⏸ "
		case "write":
			mark = "✎ "
		}
		ready := ""
		if !a.Ready {
			ready = "  (not connected)"
		}
		fmt.Printf("%s%-26s %s%s\n", mark, a.Name, a.Description, ready)
	}
	fmt.Println("\n⏸ = waits for the owner's approval   ✎ = writes (private)   others read-only")
	return nil
}

func parseKV(pairs []string) (map[string]any, error) {
	out := map[string]any{}
	for _, p := range pairs {
		i := strings.IndexByte(p, '=')
		if i <= 0 {
			return nil, fmt.Errorf("expected key=value, got %q", p)
		}
		k, v := p[:i], p[i+1:]
		switch {
		case v == "true" || v == "false":
			out[k] = v == "true"
		case strings.HasPrefix(v, "[") || strings.HasPrefix(v, "{"):
			var j any
			if err := json.Unmarshal([]byte(v), &j); err != nil {
				return nil, fmt.Errorf("%s: bad JSON", k)
			}
			out[k] = j
		default:
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				out[k] = n
			} else {
				out[k] = v
			}
		}
	}
	return out, nil
}

func callAndReport(ctx context.Context, action string, args map[string]any, wait time.Duration) error {
	c := client.New()
	code, out, err := c.Call(ctx, action, args)
	if err != nil {
		return err
	}
	if code == 202 {
		id, _ := out["approval_id"].(string)
		fmt.Fprintf(os.Stderr, "⏸  Held for the owner's approval: %v\n   approval id %s  |  approve at http://localhost:7317\n", out["summary"], id)
		if wait <= 0 {
			printJSON(out)
			return nil
		}
		fmt.Fprintf(os.Stderr, "   waiting up to %s…\n", wait)
		res, err := c.WaitApproval(ctx, id, wait)
		if err != nil {
			return err
		}
		printJSON(res)
		return nil
	}
	printJSON(out["result"])
	return nil
}

func cmdCall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	js := fs.String("json", "", "arguments as a JSON object")
	wait := fs.Duration("wait", 0, "if held, wait this long for approval")
	pos, err := splitFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return errors.New("usage: ralx call <action> [k=v ...] [--json '{...}']")
	}
	a, err := parseKV(pos[1:])
	if err != nil {
		return err
	}
	if *js != "" {
		if err := json.Unmarshal([]byte(*js), &a); err != nil {
			return fmt.Errorf("--json: %w", err)
		}
	}
	return callAndReport(ctx, pos[0], a, *wait)
}

func cmdWait(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("wait", flag.ExitOnError)
	timeout := fs.Duration("timeout", 10*time.Minute, "how long to wait")
	pos, _ := splitFlags(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: ralx wait <approval-id>")
	}
	res, err := client.New().WaitApproval(ctx, pos[0], *timeout)
	if err != nil {
		return err
	}
	printJSON(res)
	return nil
}

func cmdConnect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	services := fs.String("services", "drive,gmail,youtube", "comma-separated: drive,gmail,youtube")
	noBrowser := fs.Bool("no-browser", false, "print the link instead of opening the browser")
	wait := fs.Duration("wait", 5*time.Minute, "how long to wait for the consent click")
	account := fs.String("account", "", "Google account to suggest on the consent screen")
	pos, _ := splitFlags(fs, args)
	if len(pos) == 1 && pos[0] == "vercel" {
		return connectCLI(ctx, pos[0], !*noBrowser, *wait)
	}
	if len(pos) != 1 || (pos[0] != "google" && pos[0] != "gmail" && pos[0] != "drive" && pos[0] != "youtube") {
		return errors.New("usage: ralx connect google [--services drive,gmail,youtube] | ralx connect vercel")
	}
	svc := strings.Split(*services, ",")
	if pos[0] != "google" {
		svc = []string{pos[0]}
	}
	c := client.New()
	res, err := mcpbridge.ConnectGoogle(ctx, c, svc, *account, !*noBrowser, *wait, func(u string) {
		if *noBrowser {
			fmt.Println("Open this link and click Allow:\n" + u)
		} else {
			fmt.Println("Opening Google's consent page in your browser. Click Allow; RalX keeps the keys.")
		}
	})
	if err != nil {
		return err
	}
	if res["status"] == "connected" {
		fmt.Printf("✓ Connected %v (%v)\n", res["account"], res["services"])
		return nil
	}
	printJSON(res)
	return nil
}

// connectCLI runs a CLI's own login inside RalX; the user only approves in
// the browser, and the token never passes through this process.
func connectCLI(ctx context.Context, tool string, open bool, wait time.Duration) error {
	c := client.New()
	var cs map[string]any
	if _, err := c.JSON(ctx, "POST", "/v1/connect/cli/"+tool, nil, &cs); err != nil {
		return err
	}
	u, _ := cs["url"].(string)
	id, _ := cs["id"].(string)
	fmt.Println("Approve RalX in your browser:\n  " + u)
	if open {
		_ = mcpbridge.OpenBrowser(u)
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		var st map[string]any
		if _, err := c.JSON(ctx, "GET", "/v1/connect/cli/sessions/"+id, nil, &st); err != nil {
			return err
		}
		switch st["status"] {
		case "connected":
			fmt.Printf("✓ %s connected. Agents can use it through RalX; the token stays in the vault.\n", tool)
			return nil
		case "error":
			return fmt.Errorf("%s connect failed: %v", tool, st["error"])
		}
	}
	return fmt.Errorf("still waiting for the browser approval (session %s)", id)
}

func progressBar(label string) client.Progress {
	start := time.Now()
	last := time.Time{}
	return func(sent, total int64) {
		if time.Since(last) < 500*time.Millisecond && sent != total {
			return
		}
		last = time.Now()
		pct := 0.0
		if total > 0 {
			pct = float64(sent) / float64(total) * 100
		}
		rate := float64(sent) / time.Since(start).Seconds() / (1 << 20)
		fmt.Fprintf(os.Stderr, "\r%s %6.1f%%  %s / %s  %.1f MB/s   ", label, pct, human(sent), human(total), rate)
		if sent == total {
			fmt.Fprintln(os.Stderr)
		}
	}
}

func human(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func cmdDrive(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ralx drive upload|download|ls ...")
	}
	c := client.New()
	switch args[0] {
	case "upload":
		fs := flag.NewFlagSet("upload", flag.ExitOnError)
		folder := fs.String("folder", "", "Drive folder id")
		name := fs.String("name", "", "name in Drive")
		wait := fs.Duration("wait", 10*time.Minute, "if the folder is shared, wait this long for the owner's approval")
		pos, _ := splitFlags(fs, args[1:])
		if len(pos) != 1 {
			return errors.New("usage: ralx drive upload <file> [--folder ID] [--name NAME]")
		}
		t := time.Now()
		u, held, err := mcpbridge.DriveUpload(ctx, c, pos[0], *folder, *name, *wait, progressBar("uploading"))
		if err != nil {
			return err
		}
		if held != "" {
			fmt.Printf("⏸  Uploading into a shared folder waits for the owner's approval: %s\n", held)
			return nil
		}
		fmt.Fprintf(os.Stderr, "✓ Uploaded %s in %s\n", human(u.Size), time.Since(t).Round(time.Second))
		printJSON(u.Result)
		return nil
	case "download":
		if len(args) != 3 {
			return errors.New("usage: ralx drive download <file-id> <dest>")
		}
		n, err := c.Download(ctx, args[1], args[2], progressBar("downloading"))
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "✓ Downloaded %s\n", human(n))
		return nil
	case "ls":
		a := map[string]any{}
		if len(args) > 1 {
			a["q"] = strings.Join(args[1:], " ")
		}
		return callAndReport(ctx, "drive.list", a, 0)
	}
	return errors.New("usage: ralx drive upload|download|ls")
}

// gmailSearchArgs parses `gmail search` by hand: a Gmail query may itself start
// with "-" (-label:x). A flag with a missing or empty value is a usage error, so
// it never ends up in the query or silently picks the default account.
func gmailSearchArgs(args []string) (map[string]any, error) {
	callArgs := map[string]any{}
	var q []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		k, v, inline := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		if !strings.HasPrefix(a, "--") || (k != "account" && k != "max") {
			q = append(q, a)
			continue
		}
		if !inline {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--%s needs a value", k)
			}
			i++
			v = args[i]
		}
		if v == "" {
			return nil, fmt.Errorf("--%s needs a value", k)
		}
		callArgs[k] = v
	}
	if m, ok := callArgs["max"].(string); ok {
		n, err := strconv.Atoi(m)
		if err != nil {
			return nil, errors.New("--max must be a number")
		}
		callArgs["max"] = n
	}
	callArgs["q"] = strings.Join(q, " ")
	return callArgs, nil
}

// flagSet reports whether name was given on the command line, even as "".
func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

func cmdGmail(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ralx gmail search|read|send|draft")
	}
	switch args[0] {
	case "search":
		callArgs, err := gmailSearchArgs(args[1:])
		if err != nil {
			return err
		}
		return callAndReport(ctx, "gmail.search", callArgs, 0)
	case "read":
		fs := flag.NewFlagSet("read", flag.ExitOnError)
		account := fs.String("account", "", "Google account email (default: the Gmail default)")
		pos, _ := splitFlags(fs, args[1:])
		if len(pos) != 1 {
			return errors.New("usage: ralx gmail read <id> [--account you@example.com]")
		}
		callArgs := map[string]any{"id": pos[0]}
		if *account != "" {
			callArgs["account"] = *account
		} else if flagSet(fs, "account") {
			return errors.New("--account needs an email address")
		}
		return callAndReport(ctx, "gmail.read", callArgs, 0)
	case "send", "draft":
		fs := flag.NewFlagSet("send", flag.ExitOnError)
		to := fs.String("to", "", "comma-separated recipients")
		subject := fs.String("subject", "", "subject")
		body := fs.String("body", "", "body (or - for stdin)")
		wait := fs.Duration("wait", 0, "wait for approval")
		_, _ = splitFlags(fs, args[1:])
		b := *body
		if b == "-" {
			data, _ := io.ReadAll(os.Stdin)
			b = string(data)
		}
		action := "gmail." + args[0]
		return callAndReport(ctx, action, map[string]any{"to": strings.Split(*to, ","), "subject": *subject, "body": b}, *wait)
	}
	return errors.New("usage: ralx gmail search|read|send|draft")
}

func cmdYouTube(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ralx youtube channel|videos|upload")
	}
	switch args[0] {
	case "channel":
		return callAndReport(ctx, "youtube.channel", map[string]any{}, 0)
	case "videos":
		return callAndReport(ctx, "youtube.videos", map[string]any{}, 0)
	case "upload":
		fs := flag.NewFlagSet("upload", flag.ExitOnError)
		title := fs.String("title", "", "title")
		desc := fs.String("description", "", "description")
		privacy := fs.String("privacy", "private", "private|unlisted|public")
		wait := fs.Duration("wait", 30*time.Minute, "if held, wait this long for approval")
		pos, _ := splitFlags(fs, args[1:])
		if len(pos) != 1 {
			return errors.New("usage: ralx youtube upload <file> [--title T] [--privacy private]")
		}
		res, held, err := mcpbridge.YouTubeUpload(ctx, client.New(), pos[0], *title, *desc, *privacy, *wait, progressBar("uploading"))
		if err != nil {
			return err
		}
		if held != "" {
			fmt.Println("⏸  Waiting for the owner's approval:", held, "(RalX uploads the staged video once approved)")
			return nil
		}
		printJSON(res)
		return nil
	}
	return errors.New("usage: ralx youtube channel|videos|upload")
}

func cmdStage(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: ralx stage <file>")
	}
	u, err := mcpbridge.Stage(ctx, client.New(), args[0], progressBar("staging"))
	if err != nil {
		return err
	}
	printJSON(map[string]any{"media_upload_id": u.ID, "name": u.Name, "size": u.Size})
	return nil
}

func cmdSocial(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ralx social post|accounts|history|scheduled")
	}
	switch args[0] {
	case "accounts":
		return callAndReport(ctx, "social.accounts", map[string]any{}, 0)
	case "history":
		return callAndReport(ctx, "social.history", map[string]any{}, 0)
	case "scheduled":
		return callAndReport(ctx, "social.scheduled", map[string]any{}, 0)
	case "post":
		fs := flag.NewFlagSet("post", flag.ExitOnError)
		platforms := fs.String("platforms", "", "comma-separated, e.g. x,linkedin")
		text := fs.String("text", "", "post text")
		desc := fs.String("description", "", "description")
		media := fs.String("media", "", "photo or video file")
		ytPrivacy := fs.String("youtube-privacy", "", "private|unlisted|public")
		draft := fs.Bool("tiktok-draft", false, "send TikTok post to inbox as a draft")
		schedule := fs.String("schedule", "", "ISO time to schedule instead of posting now")
		wait := fs.Duration("wait", 0, "wait for approval")
		_, _ = splitFlags(fs, args[1:])
		a := map[string]any{"platforms": strings.Split(*platforms, ","), "text": *text}
		if *desc != "" {
			a["description"] = *desc
		}
		if *ytPrivacy != "" {
			a["youtube_privacy"] = *ytPrivacy
		}
		if *draft {
			a["tiktok_draft"] = true
		}
		if *schedule != "" {
			a["scheduled_date"] = *schedule
		}
		if *media != "" {
			u, err := mcpbridge.Stage(ctx, client.New(), *media, progressBar("staging"))
			if err != nil {
				return err
			}
			a["media_upload_id"] = u.ID
		}
		return callAndReport(ctx, "social.post", a, *wait)
	}
	return errors.New("usage: ralx social post|accounts|history|scheduled")
}

func cmdLeakscan(ctx context.Context, args []string) error {
	c := client.New()
	var fp struct {
		ScanKey      string                 `json:"scan_key"`
		Window       int                    `json:"window"`
		Fingerprints []leakscan.Fingerprint `json:"fingerprints"`
	}
	if _, err := c.JSON(ctx, "GET", "/v1/leakscan/fingerprints", nil, &fp); err != nil {
		return err
	}
	s := leakscan.New(fp.ScanKey, fp.Window, fp.Fingerprints)
	roots := args
	if len(roots) == 0 {
		home, _ := os.UserHomeDir()
		roots = []string{home}
		if tmp := os.TempDir(); !strings.HasPrefix(strings.ToLower(tmp), strings.ToLower(home)) {
			roots = append(roots, tmp)
		}
	}
	fmt.Fprintf(os.Stderr, "Scanning for %d RalX secrets (by hash) in %s, plus env and process command lines…\n", len(fp.Fingerprints), strings.Join(roots, ", "))
	s.ScanEnv()
	scanProcesses(s)
	t := time.Now()
	for _, r := range roots {
		s.ScanPath(r)
	}
	rep := s.Report()
	fmt.Fprintf(os.Stderr, "Scanned %d files (%s) in %s.\n", rep.FilesScanned, human(rep.BytesScanned), time.Since(t).Round(time.Second))
	printJSON(rep)
	if len(rep.Hits) > 0 {
		return fmt.Errorf("%d RalX secret leak(s) found", len(rep.Hits))
	}
	fmt.Fprintln(os.Stderr, "✓ No RalX secret found anywhere this agent can read.")
	return nil
}

func defaultDataDir() string {
	if d := os.Getenv("RALX_DATA"); d != "" {
		return d
	}
	return filepath.Join(programData(), "RalX")
}
