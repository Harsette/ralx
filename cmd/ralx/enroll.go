package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Harsette/ralx/internal/client"
)

var agentNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,40}$`)

func agentsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ralx", "agents")
}

// identityFile holds an enrolled agent's key together with its hub address
// (client.Identity). Agents made by `ralx admin install` have only a bare
// <name>.key for the default hub, which is still read.
func identityFile(name string) string { return filepath.Join(agentsDir(), name+".json") }

// agentFile is the file an agent's key is read from, or "" if none is saved.
func agentFile(name string) string {
	for _, p := range []string{identityFile(name), filepath.Join(agentsDir(), name+".key")} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// useAgent points this process at an enrolled agent's key file; the client
// takes the hub address from the same file: `ralx --agent <name> status`.
func useAgent(name string) error {
	if !agentNameRe.MatchString(name) {
		return fmt.Errorf("bad agent name %q", name)
	}
	p := agentFile(name)
	if p == "" {
		return fmt.Errorf("no key for agent %q on this computer; run `ralx enroll` first", name)
	}
	os.Setenv("RALX_AGENT_KEY_FILE", p)
	os.Unsetenv("RALX_AGENT_KEY")
	return nil
}

// agentsLockWait is how long a save waits for another enrollment's lock.
var agentsLockWait = 10 * time.Second

// lockAgents takes the agents folder lock so only one enrollment at a time
// checks a name and saves it. It is an OS lock on agents/.lock, held until
// unlock or until the process exits, so a crashed run never leaves it held.
// The file itself stays and is never deleted: only the OS lock counts.
func lockAgents() (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(agentsDir(), ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(agentsLockWait)
	for {
		ok, err := tryLockFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		if ok {
			return func() { _ = unlockFile(f); f.Close() }, nil
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, errors.New("another ralx enroll is saving an agent; try again")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// writeIdentity replaces an agent's identity file in one step: a temporary
// file in the same folder (user-only), flushed to disk, then renamed over the
// old one. A failure leaves the old identity whole.
func writeIdentity(path string, id client.Identity) error {
	b, err := json.Marshal(id)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // gone already after a successful rename
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type enrollState struct {
	ID          string `json:"id"`
	Secret      string `json:"secret"`
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	Client      string `json:"client"`
	URL         string `json:"url"`
	// KeySaved marks an approved enrollment whose key is on disk but whose MCP
	// registration has not finished; re-running retries only the registration.
	KeySaved bool `json:"key_saved,omitempty"`
	// KeyDigest is the saved key's digest; with URL it binds the retry to the
	// identity this enrollment saved.
	KeyDigest string `json:"key_sha256,omitempty"`
}

func enrollStatePath(code string) string {
	n := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(code))
	h := sha256.Sum256([]byte(n))
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ralx", "enroll", hex.EncodeToString(h[:8])+".json")
}

// cmdEnroll redeems a one-time code from the RalX home screen, waits for
// the owner's approval, saves this agent's key and registers the MCP server.
// Re-running the same command resumes waiting on the same request.
func cmdEnroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	name := fs.String("name", "", "a short lowercase name for this agent")
	clientName := fs.String("client", "", "claude-code, codex or other")
	hub := fs.String("url", "", "RalX address (default "+client.DefaultURL+")")
	wait := fs.Duration("wait", 90*time.Second, "how long to wait for approval in this run")
	scope := fs.String("mcp-scope", envOr("RALX_MCP_SCOPE", "user"), "Claude Code MCP scope: user, local or project")
	noMCP := fs.Bool("no-mcp", false, "only save the key; don't register the MCP server")
	replace := fs.Bool("replace", false, "replace an agent of the same name already saved on this computer")
	pos, err := splitFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: ralx enroll <code> --name <your-name> --client claude-code|codex")
	}
	code := pos[0]
	if *hub == "" {
		*hub = envOr("RALX_URL", client.DefaultURL)
	}
	c := client.New()
	// Enrollment never sends another agent's key, nor follows its address.
	c.URL, c.Key = strings.TrimRight(*hub, "/"), ""
	statePath := enrollStatePath(code)
	var st enrollState
	if b, err := os.ReadFile(statePath); err == nil && json.Unmarshal(b, &st) == nil && st.ID != "" {
		if st.KeySaved {
			if *clientName != "" {
				st.Client = *clientName
			}
			fmt.Printf("Agent %q is already approved; finishing the MCP setup.\n", st.Name)
			return registerAndFinish(ctx, st, statePath, *scope, *noMCP)
		}
		// Another enrollment may have saved this name since the request opened;
		// refuse before taking the key so --replace can still collect it.
		if agentFile(st.Name) != "" && !*replace {
			return fmt.Errorf("an agent called %q was saved on this computer after this request was opened; run the same command with --replace to overwrite it", st.Name)
		}
		fmt.Printf("Still waiting on request for %q (fingerprint %s).\n", st.Name, st.Fingerprint)
	} else {
		if !agentNameRe.MatchString(*name) {
			return errors.New("--name must be lowercase letters, numbers, dots or dashes, e.g. --name claude-code-ralveto")
		}
		// Refuse before the code is used: another hub's key under this name
		// would otherwise be overwritten while its saved URL stays behind.
		if agentFile(*name) != "" && !*replace {
			return fmt.Errorf("an agent called %q is already saved on this computer; pick another --name, or add --replace to overwrite it", *name)
		}
		var out map[string]any
		if _, err := c.JSON(ctx, "POST", "/v1/enroll", map[string]any{"code": code, "name": *name, "client": *clientName}, &out); err != nil {
			return err
		}
		st = enrollState{Name: *name, Client: *clientName, URL: c.URL}
		st.ID, _ = out["request_id"].(string)
		st.Secret, _ = out["secret"].(string)
		st.Fingerprint, _ = out["fingerprint"].(string)
		if st.ID == "" || st.Secret == "" {
			return errors.New("RalX did not open a request")
		}
		if err := saveEnrollState(statePath, st); err != nil {
			return err
		}
		fmt.Printf("Asked RalX to connect agent %q. Fingerprint: %s\n", st.Name, st.Fingerprint)
	}
	fmt.Print(enrollmentOwner(fmt.Sprintf("Tell the owner: \"Approve %s in RalX, fingerprint %s.\" Waiting up to %s...\n", st.Name, st.Fingerprint, *wait)))
	c.URL = st.URL
	deadline := time.Now().Add(*wait)
	for {
		var out map[string]any
		_, err := c.JSON(ctx, "GET", "/v1/enroll/"+url.PathEscape(st.ID), nil, &out, map[string]string{"X-RalX-Enroll-Secret": st.Secret})
		if err != nil {
			var ae *client.APIError
			if errors.As(err, &ae) && ae.Status == 404 {
				_ = os.Remove(statePath)
				return errors.New(enrollmentOwner("RalX no longer knows this request (it restarted or the request expired); ask the owner for a new code"))
			}
			return err
		}
		switch out["status"] {
		case "approved":
			key, _ := out["key"].(string)
			if key == "" {
				return errors.New("RalX approved the request but sent no key")
			}
			return finishEnroll(ctx, st, key, statePath, *scope, *noMCP, *replace)
		case "denied":
			_ = os.Remove(statePath)
			return errors.New(enrollmentOwner("the owner denied this request"))
		case "expired", "delivered":
			_ = os.Remove(statePath)
			return errors.New(enrollmentOwner(fmt.Sprintf("this request is %v; ask the owner for a new code", out["status"])))
		}
		if !time.Now().Before(deadline) {
			return errors.New(enrollmentOwner("still waiting for the owner's approval; run the same command again to keep waiting"))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// saveEnrollState writes the resume file. It holds the request secret, so it
// is user-only, like the key file next to it.
func saveEnrollState(statePath string, st enrollState) error {
	b, _ := json.Marshal(st)
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(statePath, b, 0o600)
}

func finishEnroll(ctx context.Context, st enrollState, key, statePath, scope string, noMCP, replace bool) error {
	keyFile := identityFile(st.Name)
	// The key and the hub it belongs to are saved together, in one file.
	if err := os.MkdirAll(agentsDir(), 0o700); err != nil {
		return fmt.Errorf("approved, but saving the key failed: %w", err)
	}
	unlock, err := lockAgents()
	if err != nil {
		return fmt.Errorf("approved, but saving the key failed: %w", err)
	}
	// The name rule is checked again here, under the lock: an enrollment that
	// finished while this one waited must not be overwritten without --replace.
	if agentFile(st.Name) != "" && !replace {
		unlock()
		_ = os.Remove(statePath)
		return errors.New(enrollmentOwner(fmt.Sprintf("approved, but an agent called %q was saved on this computer meanwhile, so this key was not saved; ask the owner for a new code and add --replace to overwrite it", st.Name)))
	}
	id := client.Identity{URL: st.URL, Key: key, KeyDigest: client.KeyDigest(key)}
	err = writeIdentity(keyFile, id)
	unlock()
	if err != nil {
		return fmt.Errorf("approved, but saving the key failed: %w", err)
	}
	fmt.Printf("✓ Approved. Agent %q key saved to %s (do not open or print it).\n", st.Name, keyFile)
	st.KeySaved, st.Secret, st.KeyDigest = true, "", id.KeyDigest
	if err := saveEnrollState(statePath, st); err != nil {
		return err
	}
	return registerAndFinish(ctx, st, statePath, scope, noMCP)
}

// registerAndFinish adds the MCP server for a saved key. On failure the
// resume file stays, so running the same command again retries only this.
func registerAndFinish(ctx context.Context, st enrollState, statePath, scope string, noMCP bool) error {
	keyFile := identityFile(st.Name)
	id, err := client.ReadIdentity(keyFile)
	if err != nil {
		_ = os.Remove(statePath)
		return errors.New(enrollmentOwner(fmt.Sprintf("the saved key for %q is gone; ask the owner for a new code", st.Name)))
	}
	if id.URL != st.URL || id.KeyDigest != st.KeyDigest {
		_ = os.Remove(statePath)
		return errors.New(enrollmentOwner(fmt.Sprintf("agent %q on this computer was replaced (it now belongs to %s) after this enrollment, so nothing was registered; finish the newer enrollment instead, or ask the owner for a new code", st.Name, id.URL)))
	}
	if !noMCP {
		if err := registerMCP(ctx, st.Client, id, keyFile, scope); err != nil {
			return fmt.Errorf("key saved, but MCP setup failed: %w\nFix that, then run the same command again to finish (add --client to change the client)", err)
		}
	}
	_ = os.Remove(statePath)
	exe, err := os.Executable()
	if err != nil {
		exe = "ralx"
	}
	fmt.Printf("Use the CLI as this agent (in PowerShell put & in front): \"%s\" --agent %s status\n", exe, st.Name)
	return nil
}

// registerMCP adds the RalX MCP server to the agent's own client, pointing at
// this agent's identity file (the MCP server takes key and address from it;
// RALX_URL is the same address, for older ralx builds).
func registerMCP(ctx context.Context, clientName string, id client.Identity, keyFile, scope string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	env := []string{"RALX_AGENT_KEY_FILE=" + keyFile}
	if id.URL != "" && id.URL != client.DefaultURL {
		env = append(env, "RALX_URL="+id.URL)
	}
	switch clientName {
	case "claude-code":
		claude, err := exec.LookPath("claude")
		if err != nil {
			return errors.New("claude not found on PATH")
		}
		_ = exec.CommandContext(ctx, claude, "mcp", "remove", "ralx", "--scope", scope).Run()
		// -e takes several values, so it must come before the other flags and
		// the server name (same order as `ralx admin install`).
		a := []string{"mcp", "add"}
		for _, e := range env {
			a = append(a, "-e", e)
		}
		a = append(a, "--scope", scope, "--transport", "stdio", "ralx", "--", exe, "mcp")
		if out, err := exec.CommandContext(ctx, claude, a...).CombinedOutput(); err != nil {
			return fmt.Errorf("claude mcp add: %v %s", err, out)
		}
		fmt.Printf("✓ Claude Code: MCP server \"ralx\" added (%s scope). New sessions see the RalX tools.\n", scope)
	case "codex":
		codex, err := exec.LookPath("codex")
		if err != nil {
			return errors.New("codex not found on PATH")
		}
		_ = exec.CommandContext(ctx, codex, "mcp", "remove", "ralx").Run()
		a := []string{"mcp", "add", "ralx"}
		for _, e := range env {
			a = append(a, "--env", e)
		}
		a = append(a, "--", exe, "mcp")
		if out, err := exec.CommandContext(ctx, codex, a...).CombinedOutput(); err != nil {
			return fmt.Errorf("codex mcp add: %v %s", err, out)
		}
		fmt.Println("✓ Codex: MCP server \"ralx\" added. New sessions see the RalX tools.")
	default:
		fmt.Printf("To add RalX as an MCP server, run %q with args [\"mcp\"] and env %s\n", exe, strings.Join(env, " "))
	}
	return nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func enrollmentOwner(message string) string {
	name := strings.TrimSpace(os.Getenv("RALX_OWNER_NAME"))
	if name == "" {
		return message
	}
	return strings.ReplaceAll(message, "the owner", name)
}
