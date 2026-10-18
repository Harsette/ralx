package setupconfig

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixture(c Client) []byte {
	if c.Format == "toml" {
		return []byte("# existing Codex preferences\r\nmodel = \"example-model\"\r\n[mcp_servers.existing]\r\ncommand = \"other\"\r\nargs = [\"--flag\"]\r\n[mcp_servers.existing.env]\r\nKEEP = \"value\"\r\n[features]\r\nfoo = true\r\n")
	}
	if c.Name == "vscode" {
		return []byte("{\n // keep an existing server and inputs\n \"servers\": {\"existing\": {\"command\": \"other\",},},\n \"inputs\": [{\"id\": \"keep\", \"type\": \"promptString\"}],\n}\n")
	}
	return []byte("{\r\n \"preference\": \"" + c.Name + "\",\r\n \"mcpServers\": {\"existing\": {\"command\": \"other\", \"env\": {\"KEEP\": \"synthetic\"}}}\r\n}\r\n")
}
func TestConfigAllClients(t *testing.T) {
	for _, goos := range []string{"windows", "darwin", "linux"} {
		for _, c := range ClientsWithAntigravity(t.TempDir(), "", goos) {
			t.Run(goos+"/"+c.Name, func(t *testing.T) {
				orig := fixture(c)
				if e := Write(c.Path, orig, 0600); e != nil {
					t.Fatal(e)
				}
				s := Server{Command: filepath.Join(t.TempDir(), "Program Files", "ralx"), Args: []string{"mcp"}, Env: map[string]string{"RALX_AGENT_KEY_FILE": "/private/agent.json"}, Type: "stdio"}
				before, e := decode(orig, c.Format)
				if e != nil {
					t.Fatal(e)
				}
				if e := Install(c, s, nil); e != nil {
					t.Fatal(e)
				}
				bak, e := os.ReadFile(BackupPath(c.Path))
				if e != nil || !bytes.Equal(bak, orig) {
					t.Fatal("backup differs", e)
				}
				first, _ := os.ReadFile(c.Path)
				after, e := decode(first, c.Format)
				if e != nil {
					t.Fatal(e)
				}
				g := after[c.Group].(map[string]any)
				delete(g, "ralx")
				if !reflect.DeepEqual(before, after) {
					t.Fatalf("existing settings changed: %#v", after)
				}
				if e := Install(c, s, nil); e != nil {
					t.Fatal(e)
				}
				second, _ := os.ReadFile(c.Path)
				if !bytes.Equal(first, second) {
					t.Fatal("rerun changed bytes")
				}
				if e := Remove(c); e != nil {
					t.Fatal(e)
				}
				restored, _ := os.ReadFile(c.Path)
				if !bytes.Equal(orig, restored) {
					t.Fatal("original not byte-identical")
				}
				if Managed(c.Path) {
					t.Fatal("receipt left")
				}
				if _, e := os.Stat(BackupPath(c.Path)); !os.IsNotExist(e) {
					t.Fatal("backup left")
				}
			})
		}
	}
}
func TestConfigAbsentAndConcurrentChanges(t *testing.T) {
	for _, c := range ClientsWithAntigravity(t.TempDir(), "", "windows") {
		t.Run(c.Name, func(t *testing.T) {
			s := Server{Command: "ralx", Args: []string{"mcp"}, Type: "stdio"}
			if e := Install(c, s, nil); e != nil {
				t.Fatal(e)
			}
			if e := Remove(c); e != nil {
				t.Fatal(e)
			}
			if _, e := os.Stat(c.Path); !os.IsNotExist(e) {
				t.Fatal("new config not removed")
			}
			if e := Write(c.Path, fixture(c), 0600); e != nil {
				t.Fatal(e)
			}
			if e := Install(c, s, nil); e != nil {
				t.Fatal(e)
			}
			b, _ := os.ReadFile(c.Path)
			if c.Format == "toml" {
				b = append(b, []byte("\n[mcp_servers.later]\ncommand='later'\n")...)
			} else {
				m, e := decode(b, c.Format)
				if e != nil {
					t.Fatal(e)
				}
				m[c.Group].(map[string]any)["later"] = map[string]any{"command": "later"}
				b, _ = json.Marshal(m)
			}
			if e := Write(c.Path, b, 0600); e != nil {
				t.Fatal(e)
			}
			if e := Remove(c); e != nil {
				t.Fatal(e)
			}
			b, _ = os.ReadFile(c.Path)
			m, e := decode(b, c.Format)
			if e != nil {
				t.Fatal(e)
			}
			g := m[c.Group].(map[string]any)
			if g["later"] == nil || g["existing"] == nil || g["ralx"] != nil {
				t.Fatal("uninstall clobbered later changes")
			}
		})
	}
}
func TestConfigRefusesInvalidAndForeignServers(t *testing.T) {
	c := ClientsWithAntigravity(t.TempDir(), "", "windows")[0]
	for _, b := range []string{`{"mcpServers":`, `{"mcpServers": []}`, `null`, `{"mcpServers":{"ralx":{"command":"foreign"}}}`} {
		if e := Write(c.Path, []byte(b), 0600); e != nil {
			t.Fatal(e)
		}
		if e := Install(c, Server{Command: "ralx"}, nil); e == nil {
			t.Fatalf("accepted %s", b)
		}
		got, _ := os.ReadFile(c.Path)
		if string(got) != b {
			t.Fatal("invalid config overwritten")
		}
	}
}

func TestCodexTOMLMergeForms(t *testing.T) {
	for name, original := range map[string]string{
		"explicit-parent": "# keep explicit table\n[mcp_servers]\nexisting={command='other'}\n",
		"inline":          "# keep inline preferences\nmodel='example'\nmcp_servers = { existing = { command = 'other' } } # keep server comment\n",
		"dotted":          "# keep dotted preferences\nmcp_servers.existing.command = 'other'\nfeatures.fast = true\n",
		"quoted-inline":   "# keep quoted key\n'mcp_servers' = { existing = {command='other'} }\n",
	} {
		t.Run(name, func(t *testing.T) {
			c := Clients(t.TempDir(), "", "windows")[2]
			if e := Write(c.Path, []byte(original), 0600); e != nil {
				t.Fatal(e)
			}
			if e := Install(c, Server{Command: "ralx", Args: []string{"mcp"}}, nil); e != nil {
				t.Fatal(e)
			}
			got, _ := os.ReadFile(c.Path)
			after, e := decode(got, "toml")
			if e != nil {
				t.Fatalf("saved invalid TOML: %v", e)
			}
			g := after[c.Group].(map[string]any)
			if g["existing"] == nil || g["ralx"] == nil {
				t.Fatal("lost registration")
			}
			for _, line := range strings.Split(original, "\n") {
				if strings.HasPrefix(line, "#") && !bytes.Contains(got, []byte(line)) {
					t.Fatal("lost comment")
				}
			}
			if strings.Contains(original, "# keep server comment") && !bytes.Contains(got, []byte("# keep server comment")) {
				t.Fatal("lost trailing comment")
			}
			if e := Remove(c); e != nil {
				t.Fatal(e)
			}
			restored, _ := os.ReadFile(c.Path)
			if string(restored) != original {
				t.Fatal("not byte identical")
			}
		})
	}
}

func TestCodexTOMLUnsafeMergeLeavesNoChange(t *testing.T) {
	for _, original := range []string{"mcp_servers = 42\n", "mcp_servers = { ralx = 7 }\n", "[mcp_servers\n", "mcp_servers.existing='x'\nmcp_servers.existing.command='bad'\n"} {
		c := Clients(t.TempDir(), "", "windows")[2]
		if e := Write(c.Path, []byte(original), 0600); e != nil {
			t.Fatal(e)
		}
		if e := Install(c, Server{Command: "ralx"}, nil); e == nil {
			t.Fatal("accepted unsafe config")
		}
		got, _ := os.ReadFile(c.Path)
		if string(got) != original {
			t.Fatal("changed unsafe config")
		}
		if Managed(c.Path) {
			t.Fatal("created receipt for refused merge")
		}
		if _, e := os.Stat(BackupPath(c.Path)); !os.IsNotExist(e) {
			t.Fatal("created backup for refused merge")
		}
	}
}
func TestConfigRefusesChangedRalxOnRemoval(t *testing.T) {
	c := ClientsWithAntigravity(t.TempDir(), "", "windows")[0]
	if e := Install(c, Server{Command: "ralx"}, nil); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(c.Path)
	b = bytes.ReplaceAll(b, []byte(`"command": "ralx"`), []byte(`"command": "edited"`))
	if e := Write(c.Path, b, 0600); e != nil {
		t.Fatal(e)
	}
	if e := Remove(c); e == nil {
		t.Fatal("removed changed registration")
	}
	if !Managed(c.Path) {
		t.Fatal("receipt lost")
	}
}
func TestConfigJSONCStrings(t *testing.T) {
	b, e := JSONC([]byte(`{"url":"https://example.com/*keep*/",//comment
"path":"escaped\\\"//keep", "list":[1,],}`))
	if e != nil || !json.Valid(b) || !strings.Contains(string(b), "/*keep*/") {
		t.Fatal(string(b), e)
	}
}

func TestConfigCLIBackedUpBeforeInvocation(t *testing.T) {
	c := ClientsWithAntigravity(t.TempDir(), "", "windows")[0]
	orig := fixture(c)
	if e := Write(c.Path, orig, 0600); e != nil {
		t.Fatal(e)
	}
	s := Server{Command: "ralx", Args: []string{"mcp"}, Type: "stdio"}
	calls := 0
	cli := func() error {
		calls++
		bak, e := os.ReadFile(BackupPath(c.Path))
		if e != nil || !bytes.Equal(bak, orig) {
			t.Fatal("CLI called without backup")
		}
		m, _ := decode(orig, "json")
		b, _ := json.Marshal(s)
		var entry any
		_ = json.Unmarshal(b, &entry)
		m[c.Group].(map[string]any)["ralx"] = entry
		out, _ := json.Marshal(m)
		return Write(c.Path, out, 0600)
	}
	if e := Install(c, s, cli); e != nil {
		t.Fatal(e)
	}
	if e := Install(c, s, cli); e != nil {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatal("CLI was not idempotent")
	}
	if e := Remove(c); e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(c.Path)
	if !bytes.Equal(orig, got) {
		t.Fatal("CLI-backed config not restored")
	}
}

func TestAntigravityLocation(t *testing.T) {
	for _, goos := range []string{"windows", "darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			home := t.TempDir()
			find := func() Client {
				for _, c := range ClientsWithAntigravity(home, "", goos) {
					if c.Name == "antigravity" {
						return c
					}
				}
				t.Fatal("Antigravity missing")
				return Client{}
			}
			modern := filepath.Join(home, ".gemini", "config", "mcp_config.json")
			legacy := filepath.Join(home, ".gemini", "antigravity", "mcp_config.json")
			if c := find(); c.Path != modern || c.Group != "mcpServers" || c.Format != "json" {
				t.Fatal(c)
			}
			if e := Write(legacy, []byte(`{"mcpServers":{}}`), 0600); e != nil {
				t.Fatal(e)
			}
			if c := find(); c.Path != legacy {
				t.Fatal(c)
			}
			if e := Write(modern, []byte(`{"mcpServers":{}}`), 0600); e != nil {
				t.Fatal(e)
			}
			if c := find(); c.Path != modern {
				t.Fatal(c)
			}
		})
	}
}
