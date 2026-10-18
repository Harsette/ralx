package daemon

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/Harsette/ralx/web"
)

// uiHandler serves the embedded admin app. All data comes from the admin API
// behind a passkey session; the static files themselves hold nothing secret.
func (s *Server) uiHandler() http.Handler {
	sub, _ := fs.Sub(web.Files, "app")
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if h := r.Host; strings.HasPrefix(h, "127.0.0.1:") || strings.HasPrefix(h, "[::1]:") {
			// Passkeys are bound to a hostname; send IP visitors to localhost.
			http.Redirect(w, r, s.origin+r.URL.RequestURI(), http.StatusFound)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		files.ServeHTTP(w, r)
	})
}
