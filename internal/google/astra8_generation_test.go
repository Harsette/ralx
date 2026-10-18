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

type astra8Transport func(*http.Request) (*http.Response, error)

func (f astra8Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAstra8FixGoogleGenerationCacheAndRefresh(t *testing.T) {
	for _, scenario := range []string{"ordinary-refresh", "replacement-during-refresh", "replacement-cached", "client-replacement-cached"} {
		t.Run(scenario, func(t *testing.T) {
			box, err := secretbox.New(make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			s, err := store.Open(filepath.Join(t.TempDir(), "fixture.db"), box)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			client, err := s.PutCredential(ClientCredential, "oauth_client", "google", "", nil, map[string]string{"client_id": "SyntheticClientID0123456789", "client_secret": "SyntheticClientSecret0123456789"})
			if err != nil {
				t.Fatal(err)
			}
			account, err := s.PutCredential("google:fixture@example.invalid", "oauth_token", "google", "", nil, map[string]string{"refresh_token": "SyntheticRefreshAccountA0123456789"})
			if err != nil {
				t.Fatal(err)
			}
			bindings := map[string]string{account.Name: store.CredentialIdentity(account), client.Name: store.CredentialIdentity(client)}
			ctx := store.WithCredentialBindings(context.Background(), bindings)
			b := NewBroker(s, redact.New(), "http://localhost/callback")
			entered, release := make(chan struct{}), make(chan struct{})
			calls := 0
			b.HTTP.Transport = astra8Transport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 && scenario == "replacement-during-refresh" {
					close(entered)
					<-release
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"access_token":"SyntheticAccessAccountA0123456789","refresh_token":"SyntheticRotatedAccountA0123456789","expires_in":3600}`)), Request: r}, nil
			})
			if scenario == "replacement-during-refresh" {
				done := make(chan error, 1)
				go func() { _, _, err := b.AccessToken(ctx, "fixture@example.invalid"); done <- err }()
				<-entered
				_, err = s.PutCredential(account.Name, "oauth_token", "google", "", nil, map[string]string{"refresh_token": "SyntheticRefreshAccountB9876543210"})
				if err != nil {
					close(release)
					<-done
					t.Fatal(err)
				}
				close(release)
				if err := <-done; err == nil {
					t.Fatal("stale refresh accepted")
				}
				fields, err := s.Secret(account.Name)
				if err != nil || fields["refresh_token"] != "SyntheticRefreshAccountB9876543210" {
					t.Fatal("stale refresh overwrote replacement")
				}
				if len(b.tokens) != 0 {
					t.Fatal("stale refresh cached")
				}
				return
			}
			tok, _, err := b.AccessToken(ctx, "fixture@example.invalid")
			if err != nil || tok == "" {
				t.Fatal("ordinary refresh failed", err)
			}
			if scenario == "replacement-cached" {
				_, err = s.PutCredential(account.Name, "oauth_token", "google", "", nil, map[string]string{"refresh_token": "SyntheticRefreshAccountB9876543210"})
			}
			if scenario == "client-replacement-cached" {
				_, err = s.PutCredential(ClientCredential, "oauth_client", "google", "", nil, map[string]string{"client_id": "SyntheticClientB9876543210", "client_secret": "SyntheticClientSecretB9876543210"})
			}
			if err != nil {
				t.Fatal(err)
			}
			tok, _, err = b.AccessToken(ctx, "fixture@example.invalid")
			if scenario == "ordinary-refresh" {
				if err != nil || tok == "" || calls != 1 {
					t.Fatal("legitimate rotation/cache lost", err)
				}
			} else if err == nil || calls != 1 {
				t.Fatal("old approval obtained cached token after replacement")
			}
		})
	}
}
