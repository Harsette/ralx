package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/client"
)

// fakeHub answers enrollment like the daemon: redeem opens a request, the
// first poll returns approved with a synthetic key. It counts redeems.
type fakeHub struct {
	*httptest.Server
	key     string
	redeems atomic.Int32
	polls   atomic.Int32
	hold    atomic.Bool // answer "pending" until cleared
	// beforeApprove runs just before the approved answer is sent.
	beforeApprove func()
}

func newFakeHub(t *testing.T, key string) *fakeHub {
	t.Helper()
	f := &fakeHub{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		f.redeems.Add(1)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"request_id": "enr_test", "secret": "synthetic-request-secret", "fingerprint": "TEST-FPRT", "status": "pending"})
	})
	mux.HandleFunc("GET /v1/enroll/{id}", func(w http.ResponseWriter, r *http.Request) {
		if f.hold.Load() {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
			return
		}
		if f.polls.Add(1) > 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "delivered"})
			return
		}
		if f.beforeApprove != nil {
			f.beforeApprove()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "approved", "agent": "n", "key": f.key})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// enrollHome gives the test its own home folder and an empty PATH.
func enrollHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	t.Setenv("RALX_URL", "")
	t.Setenv("RALX_AGENT_KEY", "")
	t.Setenv("RALX_AGENT_KEY_FILE", "")
	t.Setenv("PATH", filepath.Join(home, "bin"))
	return home
}

// savedPair is what `ralx --agent <name>` (and so status) would use: the hub
// address and the key it would send there.
func savedPair(t *testing.T, name string) (string, string) {
	t.Helper()
	os.Unsetenv("RALX_URL")
	os.Unsetenv("RALX_AGENT_KEY_FILE")
	if err := useAgent(name); err != nil {
		t.Fatalf("--agent %s: %v", name, err)
	}
	c := client.New()
	return c.URL, c.Key
}

// fakeClaude puts a claude on PATH that records its arguments.
func fakeClaude(t *testing.T, home string) string {
	t.Helper()
	bin := filepath.Join(home, "bin")
	_ = os.MkdirAll(bin, 0o700)
	log := filepath.Join(home, "claude-args.txt")
	if runtime.GOOS == "windows" {
		_ = os.WriteFile(filepath.Join(bin, "claude.cmd"), []byte("@echo %* >> \""+log+"\"\r\n@exit /b 0\r\n"), 0o700)
	} else {
		_ = os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\necho \"$@\" >> '"+log+"'\nexit 0\n"), 0o700)
	}
	return log
}

func readTrim(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(p), err)
	}
	return strings.TrimSpace(string(b))
}

// Sol S1: enrolling the same name against a second hub must not silently
// replace the key while the saved URL still points at the first hub.
func TestEnrollRefusesToReplaceLocalIdentity(t *testing.T) {
	home := enrollHome(t)
	ctx := context.Background()
	hubB := newFakeHub(t, "ralx_synthetic_key_b")
	hubA := newFakeHub(t, "ralx_synthetic_key_a")
	if err := cmdEnroll(ctx, []string{"CODE-BBBB", "--name", "n", "--client", "other", "--url", hubB.URL, "--no-mcp"}); err != nil {
		t.Fatalf("enroll against B: %v", err)
	}
	_ = home
	err := cmdEnroll(ctx, []string{"CODE-AAAA", "--name", "n", "--client", "other", "--url", hubA.URL, "--no-mcp"})
	if err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("second enroll of the same name: %v", err)
	}
	if hubA.redeems.Load() != 0 {
		t.Fatal("refused enroll still used up the code on hub A")
	}
	if u, k := savedPair(t, "n"); u != hubB.URL || k != hubB.key {
		t.Fatal("refused enroll changed the saved identity")
	}
	if err := cmdEnroll(ctx, []string{"CODE-AAAA", "--name", "n", "--client", "other", "--url", hubA.URL, "--no-mcp", "--replace"}); err != nil {
		t.Fatalf("explicit replace: %v", err)
	}
	if u, k := savedPair(t, "n"); u != hubA.URL || k != hubA.key {
		t.Fatalf("--agent n talks to %q with the wrong key or hub, want hub A", u)
	}
}

// Sol R1: a failed MCP setup at hub A, then the name replaced by hub B, then
// A's command retried: the retry must not register B's key against A.
func TestEnrollRetryRefusesReplacedIdentity(t *testing.T) {
	home := enrollHome(t)
	ctx := context.Background()
	hubA := newFakeHub(t, "ralx_synthetic_key_r1a")
	hubB := newFakeHub(t, "ralx_synthetic_key_r1b")
	argsA := []string{"CODE-R1AA", "--name", "n", "--client", "claude-code", "--url", hubA.URL}
	if err := cmdEnroll(ctx, argsA); err == nil || !strings.Contains(err.Error(), "MCP setup failed") {
		t.Fatalf("first enroll at A: %v", err)
	}
	if err := cmdEnroll(ctx, []string{"CODE-R1BB", "--name", "n", "--client", "other", "--url", hubB.URL, "--no-mcp", "--replace"}); err != nil {
		t.Fatalf("replace with B: %v", err)
	}
	log := fakeClaude(t, home)
	err := cmdEnroll(ctx, argsA)
	if b, _ := os.ReadFile(log); strings.Contains(string(b), "mcp add") {
		t.Fatalf("retry of A registered MCP after the agent was replaced by B: %s", b)
	}
	if err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("retry of A after replace: %v", err)
	}
	if u, k := savedPair(t, "n"); u != hubB.URL || k != hubB.key {
		t.Fatal("refused retry changed the saved identity")
	}
	if _, err := os.Stat(enrollStatePath("CODE-R1AA")); !os.IsNotExist(err) {
		t.Fatalf("stale resume file kept: %v", err)
	}
}

// Sol R2: when saving a replacement fails part way, the key and the hub
// address it is used with must still belong together.
func TestEnrollFailedReplaceKeepsKeyAndURLTogether(t *testing.T) {
	enrollHome(t)
	ctx := context.Background()
	hubA := newFakeHub(t, "ralx_synthetic_key_r2a")
	hubB := newFakeHub(t, "ralx_synthetic_key_r2b")
	if err := cmdEnroll(ctx, []string{"CODE-R2AA", "--name", "n", "--client", "other", "--url", hubA.URL, "--no-mcp"}); err != nil {
		t.Fatalf("enroll at A: %v", err)
	}
	savedPair(t, "n")
	keyFile := os.Getenv("RALX_AGENT_KEY_FILE")
	if err := os.Chmod(keyFile, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(keyFile, 0o600) })
	err := cmdEnroll(ctx, []string{"CODE-R2BB", "--name", "n", "--client", "other", "--url", hubB.URL, "--no-mcp", "--replace"})
	t.Logf("replace over a read-only key file: %v", err)
	u, k := savedPair(t, "n")
	if !(u == hubA.URL && k == hubA.key) && !(u == hubB.URL && k == hubB.key) {
		t.Fatalf("after a failed replace --agent n sends the key of the other hub to %s", u)
	}
}

// Sol R3: two pending requests for one name at two hubs. Once A is saved,
// resuming B without --replace must refuse (before taking B's key), and
// --replace then still works.
func TestEnrollResumeChecksNameCollision(t *testing.T) {
	enrollHome(t)
	ctx := context.Background()
	hubA := newFakeHub(t, "ralx_synthetic_key_r3a")
	hubB := newFakeHub(t, "ralx_synthetic_key_r3b")
	hubA.hold.Store(true)
	hubB.hold.Store(true)
	argsA := []string{"CODE-R3AA", "--name", "n", "--client", "other", "--url", hubA.URL, "--no-mcp", "--wait", "0s"}
	argsB := []string{"CODE-R3BB", "--name", "n", "--client", "other", "--url", hubB.URL, "--no-mcp", "--wait", "0s"}
	for _, a := range [][]string{argsA, argsB} {
		if err := cmdEnroll(ctx, a); err == nil || !strings.Contains(err.Error(), "still waiting") {
			t.Fatalf("pending enroll: %v", err)
		}
	}
	hubA.hold.Store(false)
	if err := cmdEnroll(ctx, argsA); err != nil {
		t.Fatalf("finish A: %v", err)
	}
	hubB.hold.Store(false)
	err := cmdEnroll(ctx, argsB)
	if u, k := savedPair(t, "n"); u != hubA.URL || k != hubA.key {
		t.Fatalf("resumed B overwrote A without --replace (err %v)", err)
	}
	if err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("resumed B without --replace: %v", err)
	}
	if err := cmdEnroll(ctx, append(argsB, "--replace")); err != nil {
		t.Fatalf("resumed B with --replace: %v", err)
	}
	if u, k := savedPair(t, "n"); u != hubB.URL || k != hubB.key {
		t.Fatal("resumed B with --replace did not save B")
	}
}

// Sol R3, the race: another enrollment saves the name while this one waits
// for approval. The save, under the agents lock, must still refuse.
func TestEnrollSaveRechecksNameUnderLock(t *testing.T) {
	enrollHome(t)
	ctx := context.Background()
	hubA := newFakeHub(t, "ralx_synthetic_key_r3c")
	hubB := newFakeHub(t, "ralx_synthetic_key_r3d")
	hubB.beforeApprove = func() {
		if err := cmdEnroll(ctx, []string{"CODE-R3CC", "--name", "n", "--client", "other", "--url", hubA.URL, "--no-mcp"}); err != nil {
			t.Errorf("concurrent enroll at A: %v", err)
		}
	}
	err := cmdEnroll(ctx, []string{"CODE-R3DD", "--name", "n", "--client", "other", "--url", hubB.URL, "--no-mcp"})
	if err == nil || !strings.Contains(err.Error(), "was not saved") {
		t.Fatalf("save after a concurrent enroll: %v", err)
	}
	if u, k := savedPair(t, "n"); u != hubA.URL || k != hubA.key {
		t.Fatal("the later save overwrote the concurrent enrollment")
	}
}

// Sol R3 P2: a save must wait while another enrollment holds the agents lock,
// even when the lock file looks old, and must never delete it. Here A holds
// the lock mid check-and-save; B's save must block, then refuse once A saved.
func TestEnrollSaveWaitsForHeldLockEvenIfOld(t *testing.T) {
	home := enrollHome(t)
	ctx := context.Background()
	hubA := newFakeHub(t, "ralx_synthetic_key_p2a")
	hubB := newFakeHub(t, "ralx_synthetic_key_p2b")
	dir := filepath.Join(home, ".ralx", "agents")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockAgents() // A: name checked, not yet saved
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, ".lock")
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmdEnroll(ctx, []string{"CODE-P2BB", "--name", "n", "--client", "other", "--url", hubB.URL, "--no-mcp"})
	}()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("B saved while A held the agents lock (err %v)", err)
	case <-time.After(time.Second):
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("B removed the lock A holds: %v", err)
	}
	if err := writeIdentity(identityFile("n"), client.Identity{URL: hubA.URL, Key: hubA.key, KeyDigest: client.KeyDigest(hubA.key)}); err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "was not saved") {
		t.Fatalf("B after A saved: %v", err)
	}
	if u, k := savedPair(t, "n"); u != hubA.URL || k != hubA.key {
		t.Fatal("B overwrote A without --replace")
	}
}

// A lock file left by a process that died (no one holds it) must not block.
func TestEnrollSaveIgnoresDeadLockFile(t *testing.T) {
	home := enrollHome(t)
	dir := filepath.Join(home, ".ralx", "agents")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	hub := newFakeHub(t, "ralx_synthetic_key_dead")
	start := time.Now()
	if err := cmdEnroll(context.Background(), []string{"CODE-DEAD", "--name", "n", "--client", "other", "--url", hub.URL, "--no-mcp"}); err != nil {
		t.Fatalf("enroll with a leftover lock file: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("leftover lock file delayed the save by %s", d)
	}
	if u, k := savedPair(t, "n"); u != hub.URL || k != hub.key {
		t.Fatal("key not saved")
	}
}

// A lock held past the wait gives a clear error and saves nothing.
func TestEnrollSaveTimesOutOnHeldLock(t *testing.T) {
	home := enrollHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".ralx", "agents"), 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockAgents()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	wait := agentsLockWait
	agentsLockWait = 300 * time.Millisecond
	t.Cleanup(func() { agentsLockWait = wait })
	hub := newFakeHub(t, "ralx_synthetic_key_busy")
	err = cmdEnroll(context.Background(), []string{"CODE-BUSY", "--name", "n", "--client", "other", "--url", hub.URL, "--no-mcp"})
	if err == nil || !strings.Contains(err.Error(), "another ralx enroll") {
		t.Fatalf("save under a held lock: %v", err)
	}
	if agentFile("n") != "" {
		t.Fatal("saved a key without the lock")
	}
}

// Agents made by `ralx admin install` keep working: a bare <name>.key is the
// default hub's key, and enrolling that name still needs --replace.
func TestAgentReadsInstallKeyFile(t *testing.T) {
	home := enrollHome(t)
	dir := filepath.Join(home, ".ralx", "agents")
	if err := writeKeyFile(filepath.Join(dir, "claude-code.key"), "ralx_synthetic_install_key"); err != nil {
		t.Fatal(err)
	}
	if u, k := savedPair(t, "claude-code"); u != client.DefaultURL || k != "ralx_synthetic_install_key" {
		t.Fatalf("--agent claude-code: %q with the wrong key", u)
	}
	hub := newFakeHub(t, "ralx_synthetic_key_new")
	err := cmdEnroll(context.Background(), []string{"CODE-LLLL", "--name", "claude-code", "--client", "other", "--url", hub.URL, "--no-mcp"})
	if err == nil || !strings.Contains(err.Error(), "--replace") || hub.redeems.Load() != 0 {
		t.Fatalf("enroll over an installed agent: %v", err)
	}
	if readTrim(t, filepath.Join(dir, "claude-code.key")) != "ralx_synthetic_install_key" {
		t.Fatal("installed key file changed")
	}
}

// Sol S4: if the MCP registration fails, enroll must say so, and re-running
// the same command retries only the registration with the saved key.
func TestEnrollRetriesFailedMCPRegistration(t *testing.T) {
	home := enrollHome(t)
	ctx := context.Background()
	hub := newFakeHub(t, "ralx_synthetic_key_c")
	args := []string{"CODE-CCCC", "--name", "c", "--client", "claude-code", "--url", hub.URL}
	err := cmdEnroll(ctx, args)
	if err == nil || !strings.Contains(err.Error(), "claude") {
		t.Fatalf("missing claude reported as: %v", err)
	}
	if u, k := savedPair(t, "c"); u != hub.URL || k != hub.key {
		t.Fatal("key not saved before registration")
	}
	keyFile := os.Getenv("RALX_AGENT_KEY_FILE")
	log := fakeClaude(t, home)
	// The closing hint names this executable, not whatever ralx is first on PATH.
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	err = cmdEnroll(ctx, args)
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	if err != nil {
		t.Fatalf("retry registration: %v", err)
	}
	exe, _ := os.Executable()
	if !strings.Contains(string(out), "\""+exe+"\" --agent c status") {
		t.Fatalf("hint does not name the running executable:\n%s", out)
	}
	if hub.redeems.Load() != 1 || hub.polls.Load() != 1 {
		t.Fatalf("retry talked to the hub again: %d redeems, %d polls", hub.redeems.Load(), hub.polls.Load())
	}
	if got := readTrim(t, log); !strings.Contains(got, "mcp add") || !strings.Contains(got, keyFile) {
		t.Fatalf("claude mcp add not run with the saved key file: %s", got)
	}
	if _, err := os.Stat(enrollStatePath("CODE-CCCC")); !os.IsNotExist(err) {
		t.Fatalf("finished enrollment left its state file: %v", err)
	}
}
