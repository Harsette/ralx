package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// OAuth state for the hub's own authorization server (the thing ChatGPT,
// Grok and Muse connectors sign in to). Tokens are stored as SHA-256 hashes.

const oauthSchema = `
CREATE TABLE IF NOT EXISTS oauth_clients (
  id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  redirect_uris TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
  hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL,            -- access | refresh
  agent_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  family TEXT NOT NULL,          -- refresh-token family for reuse detection
  resource TEXT NOT NULL DEFAULT '',
  scope TEXT NOT NULL DEFAULT '',
  expires_at INTEGER NOT NULL,
  used_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_tokens_family ON oauth_tokens(family);
CREATE INDEX IF NOT EXISTS oauth_tokens_agent ON oauth_tokens(agent_id);
CREATE TABLE IF NOT EXISTS oauth_revoked_families (
  family TEXT PRIMARY KEY,
  revoked_at INTEGER NOT NULL
);
`

func (s *Store) migrateOAuth() error {
	if _, err := s.db.Exec(oauthSchema); err != nil {
		return err
	}
	// passkeys gained an rp_id (one set of passkeys per hostname)
	_, _ = s.db.Exec(`ALTER TABLE passkeys ADD COLUMN rp_id TEXT NOT NULL DEFAULT 'localhost'`)
	return nil
}

type OAuthClient struct {
	ID           string         `json:"client_id"`
	Name         string         `json:"client_name"`
	RedirectURIs []string       `json:"redirect_uris"`
	Metadata     map[string]any `json:"metadata"`
	SecretHash   string         `json:"-"`
	CreatedAt    int64          `json:"created_at"`
	LastUsedAt   int64          `json:"last_used_at"`
}

func randToken(prefix string, n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) CountOAuthClients() int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM oauth_clients`).Scan(&n)
	return n
}

// RegisterOAuthClient stores a dynamically registered client. withSecret
// issues a client secret (returned once) for confidential clients.
func (s *Store) RegisterOAuthClient(name string, redirects []string, meta map[string]any, withSecret bool) (*OAuthClient, string, error) {
	c := &OAuthClient{ID: NewID("rxc_"), Name: name, RedirectURIs: redirects, Metadata: meta, CreatedAt: now()}
	secret := ""
	if withSecret {
		secret = randToken("rxs_", 32)
		c.SecretHash = HashToken(secret)
	}
	rj, _ := json.Marshal(redirects)
	mj, _ := json.Marshal(meta)
	_, err := s.db.Exec(`INSERT INTO oauth_clients(id,secret_hash,name,redirect_uris,metadata,created_at) VALUES(?,?,?,?,?,?)`,
		c.ID, c.SecretHash, c.Name, string(rj), string(mj), c.CreatedAt)
	return c, secret, err
}

func (s *Store) GetOAuthClient(id string) (*OAuthClient, error) {
	var c OAuthClient
	var rj, mj string
	err := s.db.QueryRow(`SELECT id,secret_hash,name,redirect_uris,metadata,created_at,last_used_at FROM oauth_clients WHERE id=?`, id).
		Scan(&c.ID, &c.SecretHash, &c.Name, &rj, &mj, &c.CreatedAt, &c.LastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(rj), &c.RedirectURIs)
	_ = json.Unmarshal([]byte(mj), &c.Metadata)
	return &c, nil
}

// TouchOAuthClient marks a client as used now.
func (s *Store) TouchOAuthClient(id string) (bool, error) {
	res, err := s.db.Exec(`UPDATE oauth_clients SET last_used_at=? WHERE id=?`, now(), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// PruneOAuthClients removes registered clients never used within maxAge.
func (s *Store) PruneOAuthClients(maxAge time.Duration) {
	_, _ = s.db.Exec(`DELETE FROM oauth_clients WHERE last_used_at=0 AND created_at<?`, time.Now().Add(-maxAge).Unix())
}

// RefreshGraceSeconds is how long a just-used refresh token may be retried.
var RefreshGraceSeconds int64 = 30

type OAuthToken struct {
	Kind      string
	AgentID   string
	ClientID  string
	Family    string
	Resource  string
	Scope     string
	ExpiresAt int64
	UsedAt    int64
}

// IssueTokens mints an access token (and refresh token) for an agent.
func (s *Store) IssueTokens(agentID, clientID, family, resource, scope string, accessTTL, refreshTTL time.Duration) (access, refresh string, err error) {
	if family == "" {
		family = NewID("fam_")
	}
	access = randToken("ralx_at_", 32)
	refresh = randToken("ralx_rt_", 32)
	t := now()
	tx, err := s.db.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	// Never issue into a family that was revoked (closes the race where a
	// refresh in flight resurrects a revoked grant).
	var rev int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM oauth_revoked_families WHERE family=?`, family).Scan(&rev); err != nil {
		return "", "", err
	}
	if rev > 0 {
		return "", "", errors.New("this connection was signed out")
	}
	ins := `INSERT INTO oauth_tokens(hash,kind,agent_id,client_id,family,resource,scope,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)`
	if _, err = tx.Exec(ins, HashToken(access), "access", agentID, clientID, family, resource, scope, t+int64(accessTTL.Seconds()), t); err != nil {
		return "", "", err
	}
	if _, err = tx.Exec(ins, HashToken(refresh), "refresh", agentID, clientID, family, resource, scope, t+int64(refreshTTL.Seconds()), t); err != nil {
		return "", "", err
	}
	_, _ = tx.Exec(`UPDATE oauth_clients SET last_used_at=? WHERE id=?`, t, clientID)
	return access, refresh, tx.Commit()
}

func (s *Store) lookupToken(raw string) (*OAuthToken, error) {
	var t OAuthToken
	err := s.db.QueryRow(`SELECT kind,agent_id,client_id,family,resource,scope,expires_at,used_at FROM oauth_tokens WHERE hash=?`, HashToken(raw)).
		Scan(&t.Kind, &t.AgentID, &t.ClientID, &t.Family, &t.Resource, &t.Scope, &t.ExpiresAt, &t.UsedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

// AuthenticateAccessToken resolves an OAuth access token to its live agent.
func (s *Store) AuthenticateAccessToken(raw string) (*Agent, *OAuthToken, error) {
	if !strings.HasPrefix(raw, "ralx_at_") {
		return nil, nil, ErrNotFound
	}
	t, err := s.lookupToken(raw)
	if err != nil || t.Kind != "access" {
		return nil, nil, ErrNotFound
	}
	if t.ExpiresAt < now() {
		return nil, nil, errors.New("token expired")
	}
	if s.familyRevoked(t.Family) {
		return nil, nil, errors.New("this connection was signed out")
	}
	a, err := s.GetAgent(t.AgentID)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	if a.RevokedAt != 0 {
		return nil, nil, errors.New("agent revoked")
	}
	if tt := now(); tt-a.LastSeenAt > 30 {
		_, _ = s.db.Exec(`UPDATE agents SET last_seen_at=? WHERE id=?`, tt, a.ID)
	}
	return a, t, nil
}

// RedeemRefresh rotates a refresh token. Reusing an already-used refresh
// token revokes the whole family (it was probably stolen).
func (s *Store) RedeemRefresh(raw, clientID string) (*OAuthToken, error) {
	t, err := s.lookupToken(raw)
	if err != nil || t.Kind != "refresh" || t.ClientID != clientID {
		return nil, ErrNotFound
	}
	if s.familyRevoked(t.Family) {
		return nil, errors.New("this connection was signed out")
	}
	if t.UsedAt != 0 {
		// A client that lost the response may retry within a short grace
		// window; later reuse means the token leaked, so the family dies.
		if now()-t.UsedAt <= RefreshGraceSeconds {
			if a, err := s.GetAgent(t.AgentID); err != nil || a.RevokedAt != 0 {
				return nil, errors.New("agent revoked")
			}
			return t, nil
		}
		s.revokeFamily(t.Family)
		return nil, errors.New("refresh token reuse detected; this connection was signed out")
	}
	if t.ExpiresAt < now() {
		return nil, errors.New("refresh token expired")
	}
	res, err := s.db.Exec(`UPDATE oauth_tokens SET used_at=? WHERE hash=? AND used_at=0`, now(), HashToken(raw))
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, errors.New("refresh token already used")
	}
	if a, err := s.GetAgent(t.AgentID); err != nil || a.RevokedAt != 0 {
		return nil, errors.New("agent revoked")
	}
	return t, nil
}

func (s *Store) familyRevoked(family string) bool {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM oauth_revoked_families WHERE family=?`, family).Scan(&n)
	return err != nil || n > 0
}

// FamilyRevoked reports whether an OAuth refresh-token family has been revoked.
// A queued action carrying a revoked family must not run (Astra N9).
func (s *Store) FamilyRevoked(family string) bool { return s.familyRevoked(family) }

// revokeFamily tombstones a family and deletes its tokens. The tombstone
// stops an in-flight refresh from re-issuing into the family afterwards. It also
// cancels the grant's still-pending approvals, including legacy ones with no
// recorded family, so revoking a grant stops work it already queued (Astra A6).
func (s *Store) revokeFamily(family string) error {
	// Commit denial first. Cleanup failure must not roll back the tombstone.
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO oauth_revoked_families(family,revoked_at) VALUES(?,?)`, family, now()); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Cancel pending approvals for every agent this family belonged to, before
	// the tokens are deleted. An empty grant_family (a pre-fix record) for the
	// same agent is cancelled too; agent-key agents have no OAuth tokens, so
	// their approvals are untouched.
	rows, err := tx.Query(`SELECT DISTINCT agent_id FROM oauth_tokens WHERE family=?`, family)
	if err == nil {
		var agentIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			agentIDs = append(agentIDs, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, id := range agentIDs {
			if _, err := tx.Exec(`UPDATE approvals SET status='denied', decided_at=?, decided_by='grant revoked'
				WHERE agent_id=? AND status IN ('pending','approved') AND (grant_family='' OR grant_family=?)`, now(), id, family); err != nil {
				return err
			}
		}
	} else {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM oauth_tokens WHERE family=?`, family); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeToken deletes a token's whole family (RFC 7009 semantics).
func (s *Store) RevokeToken(raw string) error {
	if t, err := s.lookupToken(raw); err == nil {
		return s.revokeFamily(t.Family)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

// RevokeTokenForClient revokes a token only if it belongs to clientID, so one
// client can't revoke another client's grant.
func (s *Store) RevokeTokenForClient(raw, clientID string) error {
	if t, err := s.lookupToken(raw); err == nil && t.ClientID == clientID {
		return s.revokeFamily(t.Family)
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

// RevokeAgentTokens tombstones and drops every OAuth token family of an agent.
func (s *Store) RevokeAgentTokens(agentID string) {
	rows, err := s.db.Query(`SELECT DISTINCT family FROM oauth_tokens WHERE agent_id=?`, agentID)
	if err == nil {
		var fams []string
		for rows.Next() {
			var f string
			if rows.Scan(&f) == nil {
				fams = append(fams, f)
			}
		}
		rows.Close()
		for _, f := range fams {
			s.revokeFamily(f)
		}
	}
	_, _ = s.db.Exec(`DELETE FROM oauth_tokens WHERE agent_id=?`, agentID)
}

// PruneRevokedFamilies drops tombstones well past any refresh lifetime.
func (s *Store) PruneRevokedFamilies(maxAge time.Duration) {
	_, _ = s.db.Exec(`DELETE FROM oauth_revoked_families WHERE revoked_at<?`, now()-int64(maxAge.Seconds()))
}

// PruneTokens removes expired tokens.
func (s *Store) PruneTokens() {
	_, _ = s.db.Exec(`DELETE FROM oauth_tokens WHERE expires_at<?`, now()-86400)
}
