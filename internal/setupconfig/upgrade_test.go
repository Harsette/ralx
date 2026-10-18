package setupconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestUpgradePreservesOtherServersAndIdentity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.toml")
	original := []byte("[mcp_servers.other]\ncommand='keep'\n[mcp_servers.ralx]\ncommand='old'\nargs=['mcp']\n[mcp_servers.ralx.env]\nRALX_AGENT_KEY_FILE='same.key'\n")
	if e := os.WriteFile(p, original, 0600); e != nil {
		t.Fatal(e)
	}
	c := Client{Name: "codex", Path: p, Group: "mcp_servers", Format: "toml"}
	s := Server{Command: "new", Args: []string{"mcp"}, Env: map[string]string{"RALX_AGENT_KEY_FILE": "same.key"}}
	if e := AdoptUpgrade(c, s, "wrong"); e == nil {
		t.Fatal("foreign entry replaced")
	}
	if e := AdoptUpgrade(c, s, "old"); e != nil {
		t.Fatal(e)
	}
	a, _ := os.ReadFile(p)
	m, e := decode(a, "toml")
	if e != nil {
		t.Fatal(e)
	}
	if m["mcp_servers"].(map[string]any)["other"].(map[string]any)["command"] != "keep" {
		t.Fatal("other server lost")
	}
	if e = AdoptUpgrade(c, s, "old"); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(p)
	if !bytes.Equal(a, b) {
		t.Fatal("second upgrade changed config")
	}
	if e = Remove(c); e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(p)
	if !bytes.Equal(b, original) {
		t.Fatal("original config not restored")
	}
}
