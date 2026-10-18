package social

import (
	"context"
	"github.com/Harsette/ralx/internal/redact"
	"github.com/Harsette/ralx/internal/secretbox"
	"github.com/Harsette/ralx/internal/store"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

type astra8Transport func(*http.Request) (*http.Response, error)

func (f astra8Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAstra8FixSocialAttachmentIdentity(t *testing.T) {
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(t.TempDir(), "fixture.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const key = "SyntheticSocialAccountA0123456789"
	cred, err := s.PutCredential(Credential, "api_key", "uploadpost", "", map[string]any{"profile": "fixture"}, map[string]string{"api_key": key})
	if err != nil {
		t.Fatal(err)
	}
	ctx := store.WithCredentialBindings(context.Background(), map[string]string{Credential: store.CredentialIdentity(cred)})
	c := New(s, redact.New())
	calls := 0
	c.http.Transport = astra8Transport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Authorization") != "Apikey "+key {
			t.Fatal("wrong attachment")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
	})
	if _, err := c.do(ctx, "POST", "/fixture", nil, ""); err != nil || calls != 1 {
		t.Fatal("unchanged social attachment failed", err)
	}
	if _, err := s.PutCredential(Credential, "api_key", "uploadpost", "", map[string]any{"profile": "fixture"}, map[string]string{"api_key": "SyntheticSocialAccountB9876543210"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.do(ctx, "POST", "/fixture", nil, ""); err == nil || calls != 1 {
		t.Fatal("replacement social credential dispatched")
	}
}
