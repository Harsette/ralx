//go:build !windows

package daemon

import (
	"net"
	"os"
)

// listenAdmin opens a unix socket that only root and the daemon's own user
// can use (mode 0600).
func listenAdmin(path string, dev bool) (net.Listener, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return ln, nil
}

func uacWarning() string { return "" }

func defaultToolPaths() map[string][]string {
	return map[string][]string{
		"gh":       {"/usr/bin/gh"},
		"vercel":   {"/usr/bin/node", "/usr/local/lib/ralx/vercel/node_modules/vercel/dist/index.js"},
		"supabase": {"/usr/local/bin/supabase"},
		"wrangler": {"/usr/bin/node", "/usr/local/lib/ralx/wrangler/node_modules/wrangler/bin/wrangler.js"},
	}
}
