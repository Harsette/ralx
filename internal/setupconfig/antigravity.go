package setupconfig

import (
	"os"
	"path/filepath"
)

// ClientsWithAntigravity keeps Antigravity on the same reversible JSON writer.
// Antigravity 2 uses the shared .gemini/config file on all three operating systems.
func ClientsWithAntigravity(home, appdata, goos string) []Client {
	path := filepath.Join(home, ".gemini", "config", "mcp_config.json")
	legacy := filepath.Join(home, ".gemini", "antigravity", "mcp_config.json")
	if _, e := os.Stat(path); os.IsNotExist(e) {
		if _, e := os.Stat(legacy); e == nil {
			path = legacy
		}
	}
	return append(Clients(home, appdata, goos), Client{
		Name: "antigravity", Path: path, Group: "mcpServers", Format: "json",
		Detect: []string{filepath.Join(home, ".gemini", "antigravity"), filepath.Join(home, ".gemini", "antigravity-cli"), path},
		CLI:    "antigravity",
	})
}
