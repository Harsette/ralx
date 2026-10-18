package actions

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed catalog/*.yaml
var builtinCatalog embed.FS

type Registry struct {
	mu      sync.RWMutex
	actions map[string]*Action
}

func NewRegistry() *Registry { return &Registry{actions: map[string]*Action{}} }

func (r *Registry) Add(a *Action) error {
	if err := a.Compile(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.actions[a.Name]; dup {
		return fmt.Errorf("duplicate action %s", a.Name)
	}
	r.actions[a.Name] = a
	return nil
}

// ReplacePrefix swaps every action under prefix (e.g. "notion.") for a new
// set, used when an upstream MCP server's tool list is (re)loaded.
func (r *Registry) ReplacePrefix(prefix string, list []*Action) error {
	for _, a := range list {
		if err := a.Compile(); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for name := range r.actions {
		if strings.HasPrefix(name, prefix) {
			delete(r.actions, name)
		}
	}
	for _, a := range list {
		r.actions[a.Name] = a
	}
	return nil
}

func (r *Registry) Get(name string) (*Action, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.actions[name]
	return a, ok
}

func (r *Registry) List() []*Action {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Action, 0, len(r.actions))
	for _, a := range r.actions {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func parseCatalog(data []byte, src string) ([]*Action, error) {
	var list []*Action
	if err := yaml.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	return list, nil
}

// LoadBuiltin loads the CLI action catalogs compiled into the binary.
func (r *Registry) LoadBuiltin() error {
	entries, err := builtinCatalog.ReadDir("catalog")
	if err != nil {
		return err
	}
	for _, e := range entries {
		data, err := builtinCatalog.ReadFile("catalog/" + e.Name())
		if err != nil {
			return err
		}
		list, err := parseCatalog(data, e.Name())
		if err != nil {
			return err
		}
		for _, a := range list {
			if err := r.Add(a); err != nil {
				return fmt.Errorf("%s: %w", e.Name(), err)
			}
		}
	}
	return nil
}

// LoadDir loads extra catalogs from a directory only an admin can write.
func (r *Registry) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		list, err := parseCatalog(data, e.Name())
		if err != nil {
			return err
		}
		for _, a := range list {
			if err := r.Add(a); err != nil {
				return fmt.Errorf("%s: %w", e.Name(), err)
			}
		}
	}
	return nil
}

// ParseSecretRef splits "secret:github.token" into ("github", "token").
func ParseSecretRef(v string) (cred, field string, ok bool) {
	if !strings.HasPrefix(v, "secret:") {
		return "", "", false
	}
	ref := strings.TrimPrefix(v, "secret:")
	i := strings.LastIndexByte(ref, '.')
	if i <= 0 || i == len(ref)-1 {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}
