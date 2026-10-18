package daemon

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/Harsette/ralx/internal/store"
)

// adminAuth gates everything owner-only behind a passkey (Windows Hello,
// phone, or security key). Agents can't complete a passkey ceremony, so they
// can never approve their own actions or reveal a credential.
//
// Passkeys are bound to a hostname (the WebAuthn RP ID), so there is one
// relying party per origin the hub is served on: "localhost" on the laptop,
// and e.g. "ralx.example.com" for the phone.
type adminAuth struct {
	st  *store.Store
	rps map[string]*relyingParty // rp id -> party

	mu       sync.Mutex
	sessions map[string]*adminSession
	pending  map[string]pendingCeremony
}

type relyingParty struct {
	id     string
	origin string
	wa     *webauthn.WebAuthn
}

type pendingCeremony struct {
	rp      string
	sd      *webauthn.SessionData
	created time.Time
}

// ceremonyTTL bounds how long a WebAuthn challenge is usable, enforced
// server-side regardless of the authenticator/browser timeout (Astra finding 9).
const ceremonyTTL = 2 * time.Minute

type adminSession struct {
	id       string
	rp       string
	csrf     string
	created  time.Time
	lastSeen time.Time
}

const (
	sessionCookie   = "ralx_admin"
	sessionIdle     = 30 * time.Minute
	sessionAbsolute = 12 * time.Hour
)

type adminUser struct {
	id    []byte
	creds []webauthn.Credential
}

func (u *adminUser) WebAuthnID() []byte                         { return u.id }
func (u *adminUser) WebAuthnName() string                       { return "owner" }
func (u *adminUser) WebAuthnDisplayName() string                { return ownerDisplayName() }
func (u *adminUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func rpIDOf(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func newAdminAuth(st *store.Store, origins []string) (*adminAuth, error) {
	a := &adminAuth{st: st, rps: map[string]*relyingParty{}, sessions: map[string]*adminSession{}, pending: map[string]pendingCeremony{}}
	for _, o := range origins {
		id := rpIDOf(o)
		if id == "" {
			continue
		}
		if existing, ok := a.rps[id]; ok {
			existing.wa.Config.RPOrigins = append(existing.wa.Config.RPOrigins, o)
			continue
		}
		wa, err := webauthn.New(&webauthn.Config{RPID: id, RPDisplayName: "RalX", RPOrigins: []string{o}})
		if err != nil {
			return nil, err
		}
		a.rps[id] = &relyingParty{id: id, origin: o, wa: wa}
	}
	return a, nil
}

func randID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *adminAuth) party(rp string) (*relyingParty, error) {
	p, ok := a.rps[rp]
	if !ok {
		return nil, errors.New("passkeys aren't available on this address; open RalX on localhost or its configured HTTPS address")
	}
	return p, nil
}

func (a *adminAuth) user(rp string) (*adminUser, error) {
	id := a.st.Setting("admin_user_id")
	if id == "" {
		id = randID(32)
		if err := a.st.SetSetting("admin_user_id", id); err != nil {
			return nil, err
		}
	}
	raw, _ := base64.RawURLEncoding.DecodeString(id)
	u := &adminUser{id: raw}
	pks, err := a.st.ListPasskeys()
	if err != nil {
		return nil, err
	}
	for _, p := range pks {
		if p.RPID != rp {
			continue
		}
		var c webauthn.Credential
		if json.Unmarshal(p.Credential, &c) == nil {
			u.creds = append(u.creds, c)
		}
	}
	return u, nil
}

// hasPasskeys reports whether any passkey exists for rp ("" = any rp).
func (a *adminAuth) hasPasskeys(rp string) bool {
	pks, _ := a.st.ListPasskeys()
	for _, p := range pks {
		if rp == "" || p.RPID == rp {
			return true
		}
	}
	return false
}

// ---------- sessions ----------

func (a *adminAuth) newSession(w http.ResponseWriter, rp string, secure bool) *adminSession {
	s := &adminSession{id: randID(32), rp: rp, csrf: randID(18), created: time.Now(), lastSeen: time.Now()}
	a.mu.Lock()
	a.sessions[s.id] = s
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: s.id, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionAbsolute.Seconds())})
	return s
}

func (a *adminAuth) session(r *http.Request, rp string) *adminSession {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if !ok || s.rp != rp {
		return nil
	}
	if time.Since(s.lastSeen) > sessionIdle || time.Since(s.created) > sessionAbsolute {
		delete(a.sessions, c.Value)
		return nil
	}
	s.lastSeen = time.Now()
	return s
}

func (a *adminAuth) endSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func (a *adminAuth) endAllSessions() {
	a.mu.Lock()
	a.sessions = map[string]*adminSession{}
	a.mu.Unlock()
}

// checkBrowser enforces same-origin and the CSRF header on state-changing
// admin requests from the browser.
func (a *adminAuth) checkBrowser(r *http.Request, s *adminSession, origin string) error {
	if o := r.Header.Get("Origin"); o != "" && o != origin {
		return errors.New("cross-origin request refused")
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if s == nil || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-RalX-CSRF")), []byte(s.csrf)) != 1 {
			return errors.New("missing or bad CSRF token")
		}
	}
	return nil
}

// ---------- ceremonies ----------

func (a *adminAuth) putPending(key, rp string, sd *webauthn.SessionData) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, v := range a.pending {
		if time.Since(v.created) > ceremonyTTL {
			delete(a.pending, k)
		}
	}
	a.pending[key] = pendingCeremony{rp: rp, sd: sd, created: time.Now()}
}

func (a *adminAuth) takePending(key, rp string) (*webauthn.SessionData, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.pending[key]
	delete(a.pending, key)
	if !ok || p.rp != rp || time.Since(p.created) > ceremonyTTL {
		return nil, false
	}
	return p.sd, true
}

func (a *adminAuth) beginRegistration(key, rp string) (*protocol.CredentialCreation, error) {
	p, err := a.party(rp)
	if err != nil {
		return nil, err
	}
	u, err := a.user(rp)
	if err != nil {
		return nil, err
	}
	var exclude []protocol.CredentialDescriptor
	for _, c := range u.creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, sd, err := p.wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclude),
	)
	if err != nil {
		return nil, err
	}
	a.putPending(key, rp, sd)
	return opts, nil
}

func (a *adminAuth) finishRegistration(key, rp, name string, body []byte) (*store.Passkey, error) {
	sd, ok := a.takePending(key, rp)
	if !ok {
		return nil, errors.New("registration expired; start again")
	}
	p, err := a.party(rp)
	if err != nil {
		return nil, err
	}
	u, err := a.user(rp)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return nil, err
	}
	cred, err := p.wa.CreateCredential(u, *sd, parsed)
	if err != nil {
		return nil, err
	}
	cj, _ := json.Marshal(cred)
	if name == "" {
		name = "Passkey"
	}
	return a.st.AddPasskey(name, rp, cj)
}

func (a *adminAuth) beginAssertion(key, rp string) (*protocol.CredentialAssertion, error) {
	p, err := a.party(rp)
	if err != nil {
		return nil, err
	}
	u, err := a.user(rp)
	if err != nil {
		return nil, err
	}
	if len(u.creds) == 0 {
		return nil, errors.New("no passkey registered for this address yet")
	}
	opts, sd, err := p.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, err
	}
	a.putPending(key, rp, sd)
	return opts, nil
}

// finishAssertion verifies a passkey assertion for the ceremony key (which
// binds it to one login or one specific operation).
func (a *adminAuth) finishAssertion(key, rp string, body []byte) error {
	sd, ok := a.takePending(key, rp)
	if !ok {
		return errors.New("passkey check expired; try again")
	}
	p, err := a.party(rp)
	if err != nil {
		return err
	}
	u, err := a.user(rp)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return err
	}
	cred, err := p.wa.ValidateLogin(u, *sd, parsed)
	if err != nil {
		return err
	}
	if !cred.Flags.UserVerified {
		return errors.New("user verification (Windows Hello / PIN / face) is required")
	}
	pks, _ := a.st.ListPasskeys()
	for _, pk := range pks {
		var c webauthn.Credential
		if pk.RPID == rp && json.Unmarshal(pk.Credential, &c) == nil && string(c.ID) == string(cred.ID) {
			cj, _ := json.Marshal(cred)
			_ = a.st.UpdatePasskey(pk.ID, cj)
		}
	}
	return nil
}

func ownerDisplayName() string {
	if name := strings.TrimSpace(os.Getenv("RALX_OWNER_NAME")); name != "" {
		return name
	}
	return "RalX owner"
}
