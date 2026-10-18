package browserlogin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func browserFixture(t *testing.T, handler http.HandlerFunc) (*Manager, *httptest.Server, context.Context) {
	t.Helper()
	if os.Getenv("RALX_BROWSER_TESTS") != "1" {
		t.Skip("set RALX_BROWSER_TESTS=1 under shared heavy lock")
	}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		handler(w, r)
	}))
	t.Cleanup(app.Close)
	m := New(t.TempDir(), func(b []byte) ([]byte, bool) { return b, false })
	t.Cleanup(m.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return m, app, ctx
}
