// Package logins extends the existing sealed credential vault with website logins.
package logins

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/Harsette/ralx/internal/loginorigin"
	"github.com/Harsette/ralx/internal/store"
	"net/mail"
	"net/url"
	"strings"
)

const CredentialKind = "website_login"

type Login struct {
	ID         string            `json:"login_id"`
	Username   string            `json:"username"`
	Name       string            `json:"name"`
	Origin     string            `json:"origin"`
	Origins    []string          `json:"origins"`
	CreatedBy  string            `json:"created_by"`
	Kind       string            `json:"kind"`
	LastUsedAt int64             `json:"last_used_at"`
	Credential *store.Credential `json:"-"`
}

func Origin(raw string) (string, error) { return loginorigin.Normalize(raw) }
func NewTest(s *store.Store, raw, username string, clerkTest ...bool) (*Login, string, error) {
	origin, e := loginorigin.Exact(raw)
	if e != nil {
		return nil, "", e
	}
	id := store.NewID("login_")
	clerk := len(clerkTest) > 0 && clerkTest[0]
	if clerk && username != "" && !ClerkTestEmail(username) {
		return nil, "", errors.New("clerk_test requires an email with the exact +clerk_test subaddress")
	}
	if username == "" {
		username = "test-" + strings.TrimPrefix(id, "login_") + "@example.test"
		if clerk {
			username = "test-" + strings.TrimPrefix(id, "login_") + "+clerk_test@example.com"
		}
	}
	if len(username) > 254 || strings.ContainsAny(username, "\r\n\x00") {
		return nil, "", errors.New("invalid website login")
	}
	b := make([]byte, 32)
	if _, e = rand.Read(b); e != nil {
		return nil, "", errors.New("password generation failed")
	}
	password := "Rx!9" + base64.RawURLEncoding.EncodeToString(b)
	u, _ := url.Parse(origin)
	_, e = s.CreateCredential(id, CredentialKind, "website", u.Host, map[string]any{"origins": []string{origin}, "username": username, "created_by": "agent", "kind": "test", "ralx_generated": true}, map[string]string{"password": password})
	if e != nil {
		return nil, "", errors.New("could not save login")
	}
	l, e := Get(s, id)
	return l, password, e
}

// Clerk documents this exact subaddress for its reserved test email/code flow.
// Similar-looking strings and display-name addresses are ordinary accounts.
func ClerkTestEmail(username string) bool {
	a, err := mail.ParseAddress(username)
	if err != nil || a.Address != username {
		return false
	}
	i := strings.LastIndexByte(username, '@')
	return i > 0 && strings.HasSuffix(username[:i], "+clerk_test")
}
func Get(s *store.Store, id string) (*Login, error) {
	c, f, e := s.WebsiteLogin(id)
	if e != nil || c.Kind != CredentialKind {
		return nil, errors.New("login not found")
	}
	l := &Login{ID: c.Name, Credential: c, LastUsedAt: c.LastUsedAt, Username: f["username"], Name: f["name"]}
	l.CreatedBy, _ = c.Meta["created_by"].(string)
	l.Kind, _ = c.Meta["kind"].(string)
	if json.Unmarshal([]byte(f["origins"]), &l.Origins) != nil || len(l.Origins) == 0 || l.Username == "" {
		return nil, errors.New("invalid website login")
	}
	l.Origin = l.Origins[0]
	// Earlier generated logins used this fixed placeholder. Human names, even
	// that exact phrase, remain explicit names and are preserved.
	if l.Name == "" || (l.Name == "Website login" && c.Meta["source"] == "ralx_generated") {
		u, _ := url.Parse(l.Origin)
		l.Name = u.Host
	}
	return l, nil
}
func Resolve(s *store.Store, id, origin string) (*Login, error) {
	return ResolveHash(s, id, s.LoginOriginHash(origin))
}
func ResolveHash(s *store.Store, id, hash string) (*Login, error) {
	all, e := s.ListCredentials()
	if e != nil {
		return nil, errors.New("cannot list logins")
	}
	var found *Login
	for _, c := range all {
		if c.Kind != CredentialKind || (id != "" && id != c.Name) {
			continue
		}
		values, _ := c.Meta["origin_hashes"].([]any)
		for _, v := range values {
			if v != hash {
				continue
			}
			l, e := Get(s, c.Name)
			if e != nil {
				return nil, e
			}
			for _, o := range l.Origins {
				if s.LoginOriginHash(o) == hash {
					if found != nil {
						return nil, errors.New("multiple logins match; supply login_id")
					}
					l.Origin = o
					found = l
					break
				}
			}
		}
	}
	if found == nil {
		return nil, errors.New("no login for this exact origin")
	}
	return found, nil
}
func (l *Login) Automatic(origin string) bool {
	u, e := url.Parse(origin)
	if e != nil {
		return false
	}
	source, _ := l.Credential.Meta["source"].(string)
	return source == "ralx_generated" && l.Kind == "test" && l.CreatedBy == "agent" && u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
}
func Password(ctx context.Context, s *store.Store, l *Login) (string, error) {
	c, f, e := s.BoundSecret(ctx, l.ID)
	if e != nil {
		return "", errors.New("login identity changed or unavailable")
	}
	if store.CredentialIdentity(c) != store.CredentialIdentity(l.Credential) || f["password"] == "" {
		return "", errors.New("login identity changed or password unavailable")
	}
	return f["password"], nil
}
