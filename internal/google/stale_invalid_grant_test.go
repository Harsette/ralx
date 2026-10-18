package google

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Harsette/ralx/internal/redact"
	"github.com/Harsette/ralx/internal/secretbox"
	"github.com/Harsette/ralx/internal/store"
)

// R4: a refresh that started on the old refresh token and got invalid_grant
// after the owner reconnected the account must not flag the new login.
// Without the reconnect, invalid_grant still flags the account.
func TestStaleInvalidGrantKeepsReconnectedAccount(t *testing.T) {
	for _, reconnect := range []bool{true, false} {
		box, err := secretbox.New(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		s, err := store.Open(filepath.Join(t.TempDir(), "fixture.db"), box)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if _, err := s.PutCredential(ClientCredential, "oauth_client", "google", "", nil, map[string]string{"client_id": "SyntheticClientID0123456789", "client_secret": "SyntheticClientSecret0123456789"}); err != nil {
			t.Fatal(err)
		}
		const name = credPrefix + "fixture@example.invalid"
		connect := func(refresh string) {
			// The same write the OAuth callback makes.
			meta := map[string]any{"email": "fixture@example.invalid", "status": "ok", "default": true}
			if _, err := s.PutCredential(name, "oauth_token", "google", "fixture@example.invalid", meta, map[string]string{"refresh_token": refresh}); err != nil {
				t.Fatal(err)
			}
		}
		connect("SyntheticRefreshOld0123456789")
		b := NewBroker(s, redact.New(), "http://localhost/callback")
		entered, release := make(chan struct{}), make(chan struct{})
		b.HTTP.Transport = astra8Transport(func(r *http.Request) (*http.Response, error) {
			close(entered)
			<-release
			return &http.Response{StatusCode: 400, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":"invalid_grant"}`)), Request: r}, nil
		})
		done := make(chan error, 1)
		go func() { _, _, err := b.AccessToken(context.Background(), "fixture@example.invalid"); done <- err }()
		<-entered
		if reconnect {
			connect("SyntheticRefreshNew9876543210")
		}
		close(release)
		if err := <-done; err == nil {
			t.Fatal("invalid_grant returned a token")
		}
		c, err := s.GetCredential(name)
		if err != nil {
			t.Fatal(err)
		}
		if reconnect && c.Meta["status"] != "ok" {
			t.Fatalf("an old refresh's invalid_grant flagged the reconnected account: %v", c.Meta["status"])
		}
		if !reconnect && c.Meta["status"] != "reconnect_needed" {
			t.Fatalf("invalid_grant on the current login didn't flag it: %v", c.Meta["status"])
		}
	}
}
