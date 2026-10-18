// Package setupconfig installs reversible, per-user MCP registrations.
package setupconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

type Client struct {
	Name, Path, Group, Format string
	Detect                    []string
	CLI                       string
}
type Server struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
	Type    string            `json:"type,omitempty"`
}

func Clients(home, appdata, goos string) []Client {
	if appdata == "" {
		appdata = filepath.Join(home, ".config")
	}
	desktop, code := filepath.Join(appdata, "Claude"), filepath.Join(appdata, "Code", "User")
	if goos == "darwin" {
		desktop = filepath.Join(home, "Library", "Application Support", "Claude")
		code = filepath.Join(home, "Library", "Application Support", "Code", "User")
	}
	if goos == "linux" {
		desktop = filepath.Join(home, ".config", "Claude")
		code = filepath.Join(home, ".config", "Code", "User")
	}
	windsurf := filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")
	// Current Cascade documentation moved to Devin. Keep older Windsurf installs
	// working, and use the new path when that application has been installed.
	devin := filepath.Join(home, ".config", "devin", "mcp_config.json")
	if goos == "windows" {
		devin = filepath.Join(appdata, "devin", "mcp_config.json")
	}
	if _, e := os.Stat(filepath.Dir(devin)); e == nil {
		windsurf = devin
	}
	return []Client{
		{"claude-code", filepath.Join(home, ".claude.json"), "mcpServers", "json", []string{filepath.Join(home, ".claude"), filepath.Join(home, ".claude.json")}, "claude"},
		{"claude-desktop", filepath.Join(desktop, "claude_desktop_config.json"), "mcpServers", "json", []string{desktop}, ""},
		{"codex", filepath.Join(home, ".codex", "config.toml"), "mcp_servers", "toml", []string{filepath.Join(home, ".codex")}, "codex"},
		{"cursor", filepath.Join(home, ".cursor", "mcp.json"), "mcpServers", "json", []string{filepath.Join(home, ".cursor")}, "cursor"},
		{"vscode", filepath.Join(code, "mcp.json"), "servers", "json", []string{code}, "code"},
		{"windsurf", windsurf, "mcpServers", "json", []string{filepath.Dir(windsurf)}, "windsurf"},
		{"gemini", filepath.Join(home, ".gemini", "settings.json"), "mcpServers", "json", []string{filepath.Join(home, ".gemini")}, "gemini"},
	}
}

type Receipt struct {
	Path, Group, Format string
	Existed             bool
	Original, Installed []byte
}

func receiptPath(path string) string { return path + ".ralx-setup.json" }
func BackupPath(path string) string  { return path + ".ralx-setup.bak" }

// Write refuses user symlinks and uses a same-directory rename, including on Windows.
func Write(path string, b []byte, mode os.FileMode) error {
	for p := path; ; p = filepath.Dir(p) {
		if f, e := os.Lstat(p); e == nil && f.Mode()&os.ModeSymlink != 0 && !macSystemAlias(p, f) {
			return fmt.Errorf("refusing symlink %s", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".ralx-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, path)
}

func read(path string) ([]byte, bool, error) {
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil, false, nil
	}
	return b, e == nil, e
}
func receipt(path string) (Receipt, error) {
	var r Receipt
	b, e := os.ReadFile(receiptPath(path))
	if e != nil {
		return r, e
	}
	e = json.Unmarshal(b, &r)
	if e == nil && r.Path != path {
		e = errors.New("setup receipt path mismatch")
	}
	return r, e
}

func decode(b []byte, format string) (map[string]any, error) {
	m := map[string]any{}
	if len(bytes.TrimSpace(b)) == 0 {
		return m, nil
	}
	var e error
	if format == "toml" {
		e = toml.Unmarshal(b, &m)
	} else {
		b, e = JSONC(b)
		if e == nil {
			e = json.Unmarshal(b, &m)
		}
	}
	if m == nil && e == nil {
		e = errors.New("config must be an object")
	}
	return m, e
}
func Entry(b []byte, c Client) (map[string]any, error) {
	m, e := decode(b, c.Format)
	if e != nil {
		return nil, e
	}
	group, ok := m[c.Group].(map[string]any)
	if m[c.Group] != nil && !ok {
		return nil, errors.New("MCP servers must be an object")
	}
	v, ok := group["ralx"].(map[string]any)
	if group["ralx"] != nil && !ok {
		return nil, errors.New("ralx must be an object")
	}
	return v, nil
}

// Install records the original before invoking a client CLI or writing a file.
// A foreign ralx entry is deliberately left alone rather than silently replaced.
func Install(c Client, s Server, cli func() error) error {
	b, exists, e := read(c.Path)
	if e != nil {
		return e
	}
	m, e := decode(b, c.Format)
	if e != nil {
		return e
	}
	entry, e := Entry(b, c)
	if e != nil {
		return e
	}
	wantBytes, _ := json.Marshal(s)
	var want map[string]any
	_ = json.Unmarshal(wantBytes, &want)
	r, re := receipt(c.Path)
	if re == nil {
		if reflect.DeepEqual(entry, want) {
			return nil
		}
		// A partial install can be retried, but never replace an edited entry.
		old, _ := Entry(r.Installed, c)
		if entry != nil && !reflect.DeepEqual(entry, old) {
			return errors.New("ralx entry changed outside setup; remove it manually or restore the backup")
		}
	} else {
		if !os.IsNotExist(re) {
			return re
		}
		if entry != nil {
			return errors.New("existing ralx server kept; rename it before connecting RalX")
		}
		r = Receipt{Path: c.Path, Group: c.Group, Format: c.Format, Original: b, Existed: exists}
		if _, e := os.Stat(BackupPath(c.Path)); e == nil {
			return errors.New("existing RalX backup kept; inspect it before setup")
		}
	}
	group, _ := m[c.Group].(map[string]any)
	if group == nil {
		group = map[string]any{}
		m[c.Group] = group
	}
	group["ralx"] = want
	var out []byte
	if c.Format == "toml" {
		if entry != nil {
			return errors.New("changed TOML registration: run ralx setup --remove before changing mode or binary")
		}
		block, e := toml.Marshal(map[string]any{c.Group: map[string]any{"ralx": want}})
		if e != nil {
			return e
		}
		out, e = mergeTOML(b, c.Group, want, m, block)
		if e != nil {
			return e
		}
	} else {
		out, e = json.MarshalIndent(m, "", "  ")
		out = append(out, '\n')
		if e != nil {
			return e
		}
	}
	if re != nil && exists {
		if e := Write(BackupPath(c.Path), b, 0600); e != nil {
			return e
		}
	}
	r.Installed = out
	rb, _ := json.MarshalIndent(r, "", "  ")
	if e := Write(receiptPath(c.Path), rb, 0600); e != nil {
		return e
	}
	if cli != nil {
		if e := cli(); e != nil {
			return fmt.Errorf("client CLI failed (backup kept): %w", e)
		}
		actual, e := os.ReadFile(c.Path)
		if e != nil {
			return e
		}
		got, e := Entry(actual, c)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(got, want) {
			return errors.New("client CLI did not save the expected registration")
		}
		r.Installed = actual
		rb, _ = json.MarshalIndent(r, "", "  ")
		return Write(receiptPath(c.Path), rb, 0600)
	}
	return Write(c.Path, out, 0600)
}

// Use the parser for both meaning and source positions. Ordinary tables keep
// every original byte; inline tables get an insertion inside their own braces;
// dotted keys get another root dotted key instead of an illegal table re-open.
func mergeTOML(b []byte, group string, want, expected map[string]any, block []byte) ([]byte, error) {
	wrap := func(block []byte) []byte {
		return append(append([]byte("\n# RalX setup begin\n"), block...), []byte("# RalX setup end\n")...)
	}
	valid := func(out []byte) bool {
		got, e := decode(out, "toml")
		return e == nil && reflect.DeepEqual(got, expected)
	}
	out := append(append([]byte{}, b...), wrap(block)...)
	if valid(out) {
		return out, nil
	}
	// An explicit parent table must not be re-opened by the encoder's block.
	keyBytes, e := toml.Marshal(map[string]any{group: ""})
	if e != nil {
		return nil, e
	}
	eq := bytes.IndexByte(keyBytes, '=')
	if eq < 0 {
		return nil, errors.New("cannot encode TOML key")
	}
	var fields bytes.Buffer
	if e := toml.NewEncoder(&fields).SetTablesInline(true).Encode(want); e != nil {
		return nil, e
	}
	child := append([]byte("["), bytes.TrimSpace(keyBytes[:eq])...)
	child = append(child, []byte(".ralx]\n")...)
	child = append(child, fields.Bytes()...)
	out = append(append([]byte{}, b...), wrap(child)...)
	if valid(out) {
		return out, nil
	}
	var inline bytes.Buffer
	enc := toml.NewEncoder(&inline).SetTablesInline(true)
	if e := enc.Encode(map[string]any{"ralx": want}); e != nil {
		return nil, e
	}
	entry := bytes.TrimSpace(inline.Bytes())
	p := unstable.Parser{}
	p.Reset(b)
	root := true
	for p.NextExpression() {
		n := p.Expression()
		if n.Kind == unstable.Table || n.Kind == unstable.ArrayTable {
			root = false
		}
		if !root || n.Kind != unstable.KeyValue {
			continue
		}
		key := n.Key()
		if !key.Next() || string(key.Node().Data) != group || key.Next() || n.Value().Kind != unstable.InlineTable {
			continue
		}
		pos := int(n.Value().Raw.Offset) + 1
		insert := append([]byte{}, entry...)
		if n.Value().Child() != nil {
			insert = append(insert, ',')
		}
		insert = append(insert, ' ')
		out = append(append(append([]byte{}, b[:pos]...), insert...), b[pos:]...)
		if valid(out) {
			return out, nil
		}
		return nil, errors.New("cannot safely merge inline Codex TOML; config kept unchanged")
	}
	if p.Error() != nil {
		return nil, errors.New("cannot safely parse Codex TOML; config kept unchanged")
	}
	// The parser/encoder supplies both quoted keys and values; no string rewriting.
	// Serialize a quoted dotted key using the already encoded inline entry.
	dottedKey := append(append(bytes.TrimSpace(keyBytes[:eq]), '.'), entry...)
	out = append(wrap(append(dottedKey, '\n')), b...)
	if valid(out) {
		return out, nil
	}
	return nil, errors.New("cannot safely merge Codex TOML; config kept unchanged")
}

func Remove(c Client) error {
	r, e := receipt(c.Path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	b, _, e := read(c.Path)
	if e != nil {
		return e
	}
	if bytes.Equal(b, r.Installed) {
		if r.Existed {
			e = Write(c.Path, r.Original, 0600)
		} else {
			e = os.Remove(c.Path)
		}
	} else {
		got, ge := Entry(b, c)
		installed, ie := Entry(r.Installed, c)
		if ge != nil {
			return ge
		}
		if ie != nil {
			return ie
		}
		if got != nil && !reflect.DeepEqual(got, installed) {
			return errors.New("ralx entry was edited; backup kept, remove manually")
		}
		if got != nil {
			if c.Format == "toml" {
				start := bytes.Index(b, []byte("\n# RalX setup begin\n"))
				end := bytes.Index(b, []byte("# RalX setup end\n"))
				if start < 0 || end < start {
					// An inline registration has no separate block. Parse, remove
					// only our entry and validate before replacing edited content.
					m, err := decode(b, "toml")
					if err != nil {
						return err
					}
					delete(m[c.Group].(map[string]any), "ralx")
					out, err := toml.Marshal(m)
					if err != nil {
						return err
					}
					if checked, err := decode(out, "toml"); err != nil || !reflect.DeepEqual(m, checked) {
						return errors.New("cannot safely remove Codex registration; config kept unchanged")
					}
					b = out
				} else {
					b = append(b[:start], b[end+len("# RalX setup end\n"):]...)
				}
			} else {
				m, _ := decode(b, c.Format)
				g := m[c.Group].(map[string]any)
				delete(g, "ralx")
				if len(g) == 0 {
					orig, _ := decode(r.Original, c.Format)
					if orig[c.Group] == nil {
						delete(m, c.Group)
					}
				}
				b, e = json.MarshalIndent(m, "", "  ")
				b = append(b, '\n')
			}
			if e == nil {
				e = Write(c.Path, b, 0600)
			}
		}
	}
	if e != nil {
		return e
	}
	if e = os.Remove(receiptPath(c.Path)); e != nil {
		return e
	}
	if r.Existed {
		return os.Remove(BackupPath(c.Path))
	}
	return nil
}

func Managed(path string) bool { _, e := os.Stat(receiptPath(path)); return e == nil }

// AdoptUpgrade changes only the RalX entry of a verified prior installation.
// The full original is retained for uninstall; every other client entry stays.
func AdoptUpgrade(c Client, s Server, oldBinary string) error {
	b, exists, e := read(c.Path)
	if e != nil || !exists {
		return e
	}
	entry, e := Entry(b, c)
	if e != nil {
		return e
	}
	if entry == nil {
		return nil
	}
	command, _ := entry["command"].(string)
	if filepath.Clean(command) != filepath.Clean(oldBinary) && filepath.Clean(command) != filepath.Clean(s.Command) {
		return errors.New("existing RalX belongs to another binary")
	}
	m, e := decode(b, c.Format)
	if e != nil {
		return e
	}
	wantBytes, _ := json.Marshal(s)
	var want map[string]any
	_ = json.Unmarshal(wantBytes, &want)
	if reflect.DeepEqual(entry, want) {
		return nil
	}
	r, e := receipt(c.Path)
	if os.IsNotExist(e) {
		r = Receipt{Path: c.Path, Group: c.Group, Format: c.Format, Original: b, Existed: true}
	} else if e != nil {
		return e
	}
	m[c.Group].(map[string]any)["ralx"] = want
	var out []byte
	if c.Format == "toml" {
		out, e = toml.Marshal(m)
	} else {
		out, e = json.MarshalIndent(m, "", "  ")
	}
	if e != nil {
		return e
	}
	out = append(out, '\n')
	r.Installed = out
	if e = Write(BackupPath(c.Path), r.Original, 0600); e != nil {
		return e
	}
	rb, _ := json.MarshalIndent(r, "", "  ")
	if e = Write(receiptPath(c.Path), rb, 0600); e != nil {
		return e
	}
	return Write(c.Path, out, 0600)
}

// JSONC accepts VS Code comments/trailing commas without touching string values.
func JSONC(src []byte) ([]byte, error) {
	b := bytes.TrimPrefix(append([]byte{}, src...), []byte{0xef, 0xbb, 0xbf})
	str, escape := false, false
	for i := 0; i < len(b); i++ {
		if str {
			if escape {
				escape = false
			} else if b[i] == '\\' {
				escape = true
			} else if b[i] == '"' {
				str = false
			}
			continue
		}
		if b[i] == '"' {
			str = true
			continue
		}
		if b[i] == '/' && i+1 < len(b) {
			if b[i+1] == '/' {
				for i < len(b) && b[i] != '\n' {
					b[i] = ' '
					i++
				}
			} else if b[i+1] == '*' {
				b[i], b[i+1] = ' ', ' '
				i += 2
				for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
					if b[i] != '\n' {
						b[i] = ' '
					}
					i++
				}
				if i+1 >= len(b) {
					return nil, errors.New("unterminated JSON comment")
				}
				b[i], b[i+1] = ' ', ' '
				i++
			}
		}
	}
	str, escape = false, false
	for i := 0; i < len(b); i++ {
		if str {
			if escape {
				escape = false
			} else if b[i] == '\\' {
				escape = true
			} else if b[i] == '"' {
				str = false
			}
			continue
		}
		if b[i] == '"' {
			str = true
		}
		if b[i] == ',' {
			j := i + 1
			for j < len(b) && strings.ContainsRune(" \r\n\t", rune(b[j])) {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				b[i] = ' '
			}
		}
	}
	return b, nil
}
