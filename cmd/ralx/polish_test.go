package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func capturePolishOutput(t *testing.T, run func() error) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	err = run()
	w.Close()
	b, readErr := io.ReadAll(r)
	r.Close()
	if err != nil || readErr != nil {
		t.Fatalf("command: %v; read: %v", err, readErr)
	}
	return string(b)
}

func TestConfigExamplesAndDoctorHints(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	for _, app := range []string{"stdio", "claude-code", "vscode", "http"} {
		out := capturePolishOutput(t, func() error { return cmdConfig([]string{app}) })
		var parsed map[string]any
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, `\u003c`) || !strings.Contains(out, "<") {
			t.Fatalf("escaped placeholder: %s", out)
		}
	}
	out := capturePolishOutput(t, func() error { return cmdConfig([]string{"codex"}) })
	var parsed map[string]any
	if err := toml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}
	entry := parsed["mcp_servers"].(map[string]any)["ralx"].(map[string]any)
	if entry["command"] == nil || entry["env"] == nil {
		t.Fatalf("wrong TOML keys: %s", out)
	}
	list := capturePolishOutput(t, func() error { return cmdConfig([]string{"--list"}) })
	if !strings.Contains(list, "codex\n") || !strings.Contains(list, "http\n") {
		t.Fatal(list)
	}
	if cmdConfig([]string{"unknown-app"}) == nil {
		t.Fatal("unknown app accepted")
	}
	if got := doctorClientHint("cursor", false); got != "- cursor not installed" {
		t.Fatal(got)
	}
	if got := doctorClientHint("cursor", true); got != "- cursor not connected; fix: ralx setup --clients cursor" {
		t.Fatal(got)
	}
}

func TestEnrollmentOwnerMessage(t *testing.T) {
	t.Setenv("RALX_OWNER_NAME", "")
	if got := enrollmentOwner("Tell the owner: approve this request"); got != "Tell the owner: approve this request" {
		t.Fatal(got)
	}
	t.Setenv("RALX_OWNER_NAME", "  Taylor 100%  ")
	if got := enrollmentOwner("Tell the owner: approve this request"); got != "Tell Taylor 100%: approve this request" {
		t.Fatal(got)
	}
}

func TestDoctorShowsOnlyUsefulClientFixes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	t.Setenv("RALX_SETUP_SANDBOX", "1")
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0700); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("RalX")) }))
	defer server.Close()
	if err := saveSetup(setupState{Mode: "cloud", URL: server.URL, Addr: "127.0.0.1:17449"}); err != nil {
		t.Fatal(err)
	}
	out := capturePolishOutput(t, func() error { return cmdDoctor(context.Background(), nil) })
	if !strings.Contains(out, "✓ UI reachable") || !strings.Contains(out, "- cursor not connected; fix: ralx setup --clients cursor") {
		t.Fatal(out)
	}
	if !strings.Contains(out, "- codex not installed\n") || strings.Contains(out, "--data") || strings.Contains(out, "--clients codex") {
		t.Fatal(out)
	}
	if strings.Count(out, "\n") > 12 {
		t.Fatalf("doctor grew past a screen: %s", out)
	}
}
