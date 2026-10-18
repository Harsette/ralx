package upstream

// Astra2 probes, inverted: each asserts the FIX (no credential leaks on a
// redirect). Fake transports, no sockets.
import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/redact"
	"github.com/Harsette/ralx/internal/secretbox"
	"github.com/Harsette/ralx/internal/store"
)

type astra2RT func(*http.Request) (*http.Response, error)

func (f astra2RT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func astra2Response(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}
func astra2Manager(t *testing.T) *Manager {
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "fixture.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(st, redact.New(), actions.NewRegistry(), "http://localhost/callback")
	t.Cleanup(func() { m.Close(); _ = st.Close() })
	return m
}

func TestAstra2ReproAuthReattachedOnRedirect(t *testing.T) {
	for _, mode := range []string{"header", "oauth"} {
		t.Run(mode, func(t *testing.T) {
			m := astra2Manager(t)
			secret := "synthetic-upstream-token-0123456789"
			_, err := m.Store.PutCredential("mcp:demo", "mcp_server", "mcp", "fixture", map[string]any{"url": "https://trusted.example/mcp", "prefix": "demo", "auth": mode, "header": "Authorization"}, map[string]string{"value": secret, "access_token": secret, "expires_at": fmt.Sprint(time.Now().Add(time.Hour).Unix())})
			if err != nil {
				t.Fatal(err)
			}
			var leaked string
			m.Transport = astra2RT(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "trusted.example" {
					res := astra2Response(r, 307, "")
					res.Header.Set("Location", "http://attacker.example/capture")
					return res, nil
				}
				if r.URL.Scheme != "http" || r.URL.Host != "attacker.example" {
					t.Fatal("unexpected destination")
				}
				leaked = r.Header.Get("Authorization")
				return nil, errors.New("stopped in fake transport")
			})
			_ = m.Load(context.Background(), "demo")
			// Fixed: the client does not follow the redirect and the credential is
			// bound to the configured origin, so nothing reaches attacker.example.
			if strings.Contains(leaked, secret) {
				t.Fatalf("credential re-attached to the redirect target (%s)", mode)
			}
		})
	}
}

func TestAstra2ReproRefreshBodyRedirect(t *testing.T) {
	m := astra2Manager(t)
	secret := "synthetic-refresh-token-0123456789"
	leaked := false
	initial := false
	m.Transport = astra2RT(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "issuer.example" {
			initial = true
			res := astra2Response(r, 307, "")
			res.Header.Set("Location", "http://attacker.example/capture")
			return res, nil
		}
		b, _ := io.ReadAll(r.Body)
		q, _ := url.ParseQuery(string(b))
		leaked = r.URL.Host == "attacker.example" && q.Get("refresh_token") == secret
		return astra2Response(r, 200, `{"access_token":"synthetic-new-access-token","expires_in":3600}`), nil
	})
	// Fixed: postToken doesn't follow the 307, so the refresh-token body is never
	// replayed to the redirect target; the redirect is reported as an error.
	_, err := m.postToken(context.Background(), "https://issuer.example/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {secret}})
	if !initial {
		t.Fatal("the initial token request never reached the endpoint (test exercises nothing)")
	}
	if leaked {
		t.Fatal("refresh token replayed to the redirect target")
	}
	if err == nil {
		t.Fatal("a redirect from the token endpoint should be an error, not followed")
	}
}
