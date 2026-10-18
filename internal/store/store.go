// Package store is RalX's single SQLite database: encrypted credentials,
// agents (hashed keys only), approvals, passkeys and the audit log.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Harsette/ralx/internal/secretbox"
	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

const schema = `
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  provider TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  meta TEXT NOT NULL DEFAULT '{}',
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  key_hash BLOB NOT NULL,
  policy TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  revoked_at INTEGER NOT NULL DEFAULT 0,
  last_seen_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  agent_name TEXT NOT NULL,
  action TEXT NOT NULL,
  args TEXT NOT NULL,
  summary TEXT NOT NULL,
  gate_reason TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  decided_at INTEGER NOT NULL DEFAULT 0,
  decided_by TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  grant_family TEXT NOT NULL DEFAULT '',
  def_digest TEXT NOT NULL DEFAULT '',
  credential_bindings TEXT NOT NULL DEFAULT '',
  origin TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS approvals_status ON approvals(status, created_at);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS passkeys (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  credential TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
`

type Store struct {
	db  *sql.DB
	box *secretbox.Box

	mu    sync.RWMutex
	cache map[string]map[string]string // credential name -> decrypted fields
}

func Open(path string, box *secretbox.Box) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	s := &Store{db: db, box: box, cache: map[string]map[string]string{}}
	if err := s.migrateOAuth(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: oauth schema: %w", err)
	}
	// Add columns to approvals created by an older binary. A duplicate-column
	// error just means the column is already there.
	_, _ = db.Exec(`ALTER TABLE approvals ADD COLUMN grant_family TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE approvals ADD COLUMN def_digest TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE approvals ADD COLUMN origin TEXT NOT NULL DEFAULT ''`)
	if _, err := db.Exec(`ALTER TABLE approvals ADD COLUMN credential_bindings TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(err.Error(), "duplicate column") {
		db.Close()
		return nil, fmt.Errorf("store: credential binding migration: %w", err)
	}
	// One-time upgrade: approvals written by a binary that didn't record a
	// provenance (origin) can't be authenticated as agent-key or OAuth, and an
	// OAuth grant revoked before this upgrade left no token rows to map them to.
	// Deny every pending/approved row with no provenance rather than ever run work
	// of unknown origin (Astra A6). Run it ONCE (guarded by a settings flag), not on
	// every Open, so a future insert path that forgets to set Origin surfaces as a
	// live bug instead of being silently denied at the next restart (Daru6 P2-6).
	if s.Setting("mig_deny_unauthenticated_origin") == "" {
		// Fail the Open if the migration can't run, and only set the one-shot flag
		// once the UPDATE actually succeeded - otherwise a failed migration would be
		// silently marked done and legacy rows would run unauthenticated (Daru6 run6).
		if _, err := s.db.Exec(`UPDATE approvals SET status='denied', decided_at=?, decided_by='upgrade: unauthenticated provenance'
			WHERE status IN ('pending','approved') AND origin=''`, now()); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: origin provenance migration: %w", err)
		}
		if err := s.SetSetting("mig_deny_unauthenticated_origin", "1"); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: origin provenance migration flag: %w", err)
		}
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func now() int64 { return time.Now().Unix() }

// NewID returns prefix + 16 lowercase base32 characters ([a-z2-7] only, so
// IDs never contain the "_" used as a separator inside agent keys).
func NewID(prefix string) string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return prefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// ---------- credentials ----------

type Credential struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`     // api_key | oauth_client | oauth_token | token
	Provider   string         `json:"provider"` // google | github | uploadpost | ...
	Label      string         `json:"label"`
	Meta       map[string]any `json:"meta"`
	Fields     []string       `json:"fields"` // names of secret fields, never values
	CreatedAt  int64          `json:"created_at"`
	UpdatedAt  int64          `json:"updated_at"`
	LastUsedAt int64          `json:"last_used_at"`
}

func credAD(id, name string) []byte { return []byte("ralx-cred:" + id + ":" + name) }

// PutCredential creates or replaces the credential called name.
func (s *Store) PutCredential(name, kind, provider, label string, meta map[string]any, fields map[string]string) (*Credential, error) {
	c, _, err := s.PutCredentialIf(name, kind, provider, label, meta, fields, nil)
	return c, err
}

// PutCredentialIf is PutCredential that writes only if match(current) returns true
// (current is nil when no credential has that name). The read, the match and the
// write are one transaction on the single DB connection, so a caller that merged an
// earlier meta can detect that another writer replaced it in between and re-merge
// instead of restoring the obsolete settings (R2-1). It returns (nil, false, nil)
// when match rejects. match must not touch the store. A nil match always writes.
func (s *Store) PutCredentialIf(name, kind, provider, label string, meta map[string]any, fields map[string]string, match func(cur *Credential) bool) (*Credential, bool, error) {
	if kind == "website_login" {
		var err error
		fields = copyFields(fields)
		if fields["name"] == "" {
			fields["name"] = label
		}
		meta, fields, err = s.prepareWebsiteLogin(name, meta, fields)
		if err != nil {
			return nil, false, err
		}
		provider, label = "website", "Website login"
	}
	if name == "" || len(fields) == 0 {
		return nil, false, errors.New("store: credential needs a name and at least one field")
	}
	if meta == nil {
		meta = map[string]any{}
	}
	meta = replacementMeta(meta)
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, false, err
	}
	plain, err := json.Marshal(fields)
	if err != nil {
		return nil, false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	cur, _, _, err := s.scanCred(tx.QueryRow(`SELECT `+credCols+` FROM credentials WHERE name=?`, name))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}
	if match != nil && !match(cur) {
		return nil, false, nil
	}
	id := NewID("cred_")
	if cur != nil {
		id = cur.ID
	}
	nonce, ct, err := s.box.Seal(plain, credAD(id, name))
	if err != nil {
		return nil, false, err
	}
	t := now()
	_, err = tx.Exec(`INSERT INTO credentials(id,name,kind,provider,label,meta,nonce,ciphertext,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, provider=excluded.provider, label=excluded.label,
		meta=excluded.meta, nonce=excluded.nonce, ciphertext=excluded.ciphertext, updated_at=excluded.updated_at`,
		id, name, kind, provider, label, string(metaJSON), nonce, ct, t, t)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	s.cache[name] = copyFields(fields)
	s.mu.Unlock()
	c, err := s.GetCredential(name)
	return c, err == nil, err
}

// CreateCredential inserts a new credential and fails if the name already
// exists. Provisioning that must be atomic create-only (a paste link, which
// must not silently overwrite an existing server) uses this instead of the
// upserting PutCredential (Astra R13).
func (s *Store) CreateCredential(name, kind, provider, label string, meta map[string]any, fields map[string]string) (*Credential, error) {
	if kind == "website_login" {
		var err error
		fields = copyFields(fields)
		if fields["name"] == "" {
			fields["name"] = label
		}
		meta, fields, err = s.prepareWebsiteLogin(name, meta, fields)
		if err != nil {
			return nil, err
		}
		provider, label = "website", "Website login"
	}
	if name == "" || len(fields) == 0 {
		return nil, errors.New("store: credential needs a name and at least one field")
	}
	if meta == nil {
		meta = map[string]any{}
	}
	meta = replacementMeta(meta)
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	id := NewID("cred_")
	nonce, ct, err := s.box.Seal(plain, credAD(id, name))
	if err != nil {
		return nil, err
	}
	t := now()
	if _, err := s.db.Exec(`INSERT INTO credentials(id,name,kind,provider,label,meta,nonce,ciphertext,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, id, name, kind, provider, label, string(metaJSON), nonce, ct, t, t); err != nil {
		return nil, fmt.Errorf("a credential named %q already exists", name)
	}
	s.mu.Lock()
	s.cache[name] = copyFields(fields)
	s.mu.Unlock()
	return s.GetCredential(name)
}

// UpdateMeta merges keys into a credential's non-secret metadata. The read and the
// write happen inside one transaction on the single DB connection, so a concurrent
// PutCredential can't interleave between them: without that, a stale metadata write
// could restore an old meta (endpoint/generation) over a replacement's ciphertext,
// mixing one version's metadata with another's key (Astra7 self-review mixed row).
func (s *Store) UpdateMeta(name string, patch map[string]any) error {
	_, err := s.UpdateMetaIf(name, nil, patch)
	return err
}

// UpdateMetaIf is UpdateMeta that writes only if match(current) returns true, in
// the same transaction as the read, so a refresh that started on an old login
// can't flag the owner's replacement (R4). A nil match always writes. match must
// not touch the store.
func (s *Store) UpdateMetaIf(name string, match func(c *Credential) bool, patch map[string]any) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}

	defer tx.Rollback()
	cur, _, _, err := s.scanCred(tx.QueryRow(`SELECT `+credCols+` FROM credentials WHERE name=?`, name))
	if err != nil {
		return false, err
	}
	if cur.Kind == "website_login" {
		return false, errors.New("replace website login through credential save")
	}
	if match != nil && !match(cur) {
		return false, nil
	}
	m := cur.Meta
	for k, v := range patch {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, _ := json.Marshal(m)
	if _, err := tx.Exec(`UPDATE credentials SET meta=?, updated_at=? WHERE name=?`, string(b), now(), name); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// UpdateFields re-encrypts the secret fields (e.g. a rotated refresh token), keeping
// fields that are not mentioned. It goes through CASFields (always-match), so the read,
// merge and write are one transaction and a stale field write can't overwrite a
// concurrent replacement or mix it with another version's metadata (Astra7 self-review).
func (s *Store) UpdateFields(name string, patch map[string]string) error {
	ok, err := s.CASFields(name, func(*Credential, map[string]string) bool { return true }, patch)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	return nil
}

// CASFields atomically re-reads the credential and, only if match(current)
// returns true, merges patch into its secret fields. The read, the match decision
// and the write all run inside one transaction on the single DB connection, so no
// other writer can interleave between them: a token refresh that calls this can't
// overwrite an owner replacement that landed after the refresh began. It returns
// (false, nil) - no write - when match rejects the current state (Astra7 refresh
// race). match must not touch the store (it would deadlock on the held connection).
func (s *Store) CASFields(name string, match func(c *Credential, fields map[string]string) bool, patch map[string]string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var c Credential
	var meta string
	var nonce, ct []byte
	row := tx.QueryRow(`SELECT `+credCols+` FROM credentials WHERE name=?`, name)
	if err := row.Scan(&c.ID, &c.Name, &c.Kind, &c.Provider, &c.Label, &meta, &nonce, &ct, &c.CreatedAt, &c.UpdatedAt, &c.LastUsedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, err
	}
	c.Meta = map[string]any{}
	_ = json.Unmarshal([]byte(meta), &c.Meta)
	// Decrypt directly from the row read inside the transaction (not via the cache,
	// which another writer may already have updated) so match sees the committed row.
	plain, err := s.box.Open(nonce, ct, credAD(c.ID, c.Name))
	if err != nil {
		return false, fmt.Errorf("store: decrypt %s: %w", c.Name, err)
	}
	fields := map[string]string{}
	if err := json.Unmarshal(plain, &fields); err != nil {
		return false, err
	}
	for k := range fields {
		c.Fields = append(c.Fields, k)
	}
	if !match(&c, copyFields(fields)) {
		return false, nil
	}
	for k, v := range patch {
		fields[k] = v
	}
	np, err := json.Marshal(fields)
	if err != nil {
		return false, err
	}
	nn, nct, err := s.box.Seal(np, credAD(c.ID, c.Name))
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(`UPDATE credentials SET nonce=?, ciphertext=?, updated_at=? WHERE id=?`, nn, nct, now(), c.ID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	s.mu.Lock()
	s.cache[name] = copyFields(fields)
	s.mu.Unlock()
	return true, nil
}

func copyFields(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (s *Store) scanCred(row interface{ Scan(...any) error }) (*Credential, []byte, []byte, error) {
	var c Credential
	var meta string
	var nonce, ct []byte
	if err := row.Scan(&c.ID, &c.Name, &c.Kind, &c.Provider, &c.Label, &meta, &nonce, &ct, &c.CreatedAt, &c.UpdatedAt, &c.LastUsedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, nil, ErrNotFound
		}
		return nil, nil, nil, err
	}
	c.Meta = map[string]any{}
	_ = json.Unmarshal([]byte(meta), &c.Meta)
	return &c, nonce, ct, nil
}

const credCols = `id,name,kind,provider,label,meta,nonce,ciphertext,created_at,updated_at,last_used_at`

func (s *Store) GetCredential(name string) (*Credential, error) {
	c, nonce, ct, err := s.scanCred(s.db.QueryRow(`SELECT `+credCols+` FROM credentials WHERE name=?`, name))
	if err != nil {
		return nil, err
	}
	fields, err := s.decrypt(c, nonce, ct)
	if err != nil {
		return nil, err
	}
	for k := range fields {
		c.Fields = append(c.Fields, k)
	}
	return c, nil
}

func (s *Store) ListCredentials() ([]*Credential, error) {
	rows, err := s.db.Query(`SELECT ` + credCols + ` FROM credentials ORDER BY provider, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Credential
	for rows.Next() {
		c, nonce, ct, err := s.scanCred(rows)
		if err != nil {
			return nil, err
		}
		if fields, err := s.decrypt(c, nonce, ct); err == nil {
			for k := range fields {
				c.Fields = append(c.Fields, k)
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) decrypt(c *Credential, nonce, ct []byte) (map[string]string, error) {
	s.mu.RLock()
	cached, ok := s.cache[c.Name]
	s.mu.RUnlock()
	if ok {
		return copyFields(cached), nil
	}
	plain, err := s.box.Open(nonce, ct, credAD(c.ID, c.Name))
	if err != nil {
		return nil, fmt.Errorf("store: decrypt %s: %w", c.Name, err)
	}
	fields := map[string]string{}
	if err := json.Unmarshal(plain, &fields); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cache[c.Name] = copyFields(fields)
	s.mu.Unlock()
	return fields, nil
}

// Secret returns the decrypted fields of a credential. Only daemon-internal
// code calls this; nothing on an agent-facing path may return its result.
func (s *Store) Secret(name string) (map[string]string, error) {
	c, nonce, ct, err := s.scanCred(s.db.QueryRow(`SELECT `+credCols+` FROM credentials WHERE name=?`, name))
	if err != nil {
		return nil, err
	}
	fields, err := s.decrypt(c, nonce, ct)
	if err != nil {
		return nil, err
	}
	_, _ = s.db.Exec(`UPDATE credentials SET last_used_at=? WHERE id=?`, now(), c.ID)
	return fields, nil
}

// SecretWithMeta returns a credential's metadata (fields names, meta map) AND its
// decrypted field values from a SINGLE row read, so a caller that authorizes on the
// metadata (e.g. http.request's allowed_hosts) and then substitutes the secret
// value uses one immutable snapshot - a concurrent replacement can't let it check
// one version's host list and send another version's key (Daru6 run6).
func (s *Store) SecretWithMeta(name string) (*Credential, map[string]string, error) {
	return s.secretWithMeta(name, true)
}

func (s *Store) secretWithMeta(name string, markUsed bool) (*Credential, map[string]string, error) {
	c, nonce, ct, err := s.scanCred(s.db.QueryRow(`SELECT `+credCols+` FROM credentials WHERE name=?`, name))
	if err != nil {
		return nil, nil, err
	}
	// Decrypt the ciphertext THIS row read returned, not the cache: scanCred reads
	// meta + nonce + ciphertext from one row version, so decrypting that exact
	// ciphertext yields fields consistent with that meta. Going through the cache
	// (which a concurrent PutCredential may already have replaced) could pair version
	// A's metadata with version B's fields, letting http.request authorize on A's
	// allow-list and then send B's key to A's host (Astra7 self-review snapshot).
	plain, err := s.box.Open(nonce, ct, credAD(c.ID, c.Name))
	if err != nil {
		return nil, nil, fmt.Errorf("store: decrypt %s: %w", c.Name, err)
	}
	fields := map[string]string{}
	if err := json.Unmarshal(plain, &fields); err != nil {
		return nil, nil, err
	}
	for k := range fields {
		c.Fields = append(c.Fields, k)
	}
	if markUsed {
		_, _ = s.db.Exec(`UPDATE credentials SET last_used_at=? WHERE id=?`, now(), c.ID)
	}
	return c, fields, nil
}

func (s *Store) DeleteCredential(name string) error {
	res, err := s.db.Exec(`DELETE FROM credentials WHERE name=?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.mu.Lock()
	delete(s.cache, name)
	s.mu.Unlock()
	return nil
}

// AllSecretValues returns every decrypted secret value, for the redactor and
// the leak scanner. Values never leave the daemon.
func (s *Store) AllSecretValues() (map[string][]string, error) {
	creds, err := s.ListCredentials()
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, c := range creds {
		fields, err := s.Secret(c.Name)
		if err != nil {
			continue
		}
		for k, v := range fields {
			// An OAuth client id is public by design (it is in every consent
			// URL); treating it as secret would only produce false alarms.
			if v != "" && SecretField(c.Kind, k) {
				out[c.Name] = append(out[c.Name], v)
			}
		}
	}
	return out, nil
}

// SecretField distinguishes explicitly public OAuth fields/bookkeeping from
// actual credential material. Generic API-key fields retain literal protection.
func SecretField(kind, field string) bool {
	if kind == "website_login" {
		return field == "password"
	}
	if field == "client_id" {
		return false
	}
	return field != "expires_at" || (kind != "mcp_server" && kind != "oauth_token")
}

// ---------- agents ----------

type Policy struct {
	Allow []string `json:"allow,omitempty"` // action globs; empty = all
	Deny  []string `json:"deny,omitempty"`
}

type Agent struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Policy     Policy `json:"policy"`
	CreatedAt  int64  `json:"created_at"`
	RevokedAt  int64  `json:"revoked_at"`
	LastSeenAt int64  `json:"last_seen_at"`
}

const keyPrefix = "ralx_"

// CreateAgent mints a new agent key. The raw key is returned once and only its
// hash is stored.
func (s *Store) CreateAgent(name string, policy Policy) (*Agent, string, error) {
	if name == "" {
		return nil, "", errors.New("agent name required")
	}
	id := NewID("agt_")
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", err
	}
	raw := keyPrefix + strings.TrimPrefix(id, "agt_") + "_" + base64.RawURLEncoding.EncodeToString(secret)
	h := sha256.Sum256([]byte(raw))
	pj, _ := json.Marshal(policy)
	if _, err := s.db.Exec(`INSERT INTO agents(id,name,key_hash,policy,created_at) VALUES(?,?,?,?,?)`, id, name, h[:], string(pj), now()); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, "", fmt.Errorf("an agent called %q already exists", name)
		}
		return nil, "", err
	}
	a, err := s.GetAgent(id)
	return a, raw, err
}

func (s *Store) scanAgent(row interface{ Scan(...any) error }) (*Agent, []byte, error) {
	var a Agent
	var pj string
	var hash []byte
	if err := row.Scan(&a.ID, &a.Name, &hash, &pj, &a.CreatedAt, &a.RevokedAt, &a.LastSeenAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	_ = json.Unmarshal([]byte(pj), &a.Policy)
	return &a, hash, nil
}

const agentCols = `id,name,key_hash,policy,created_at,revoked_at,last_seen_at`

func (s *Store) GetAgent(id string) (*Agent, error) {
	a, _, err := s.scanAgent(s.db.QueryRow(`SELECT `+agentCols+` FROM agents WHERE id=?`, id))
	return a, err
}

func (s *Store) GetAgentByName(name string) (*Agent, error) {
	a, _, err := s.scanAgent(s.db.QueryRow(`SELECT `+agentCols+` FROM agents WHERE name=?`, name))
	return a, err
}

// AuthenticateAgent resolves a raw key to a live (unrevoked) agent.
func (s *Store) AuthenticateAgent(raw string) (*Agent, error) {
	if !strings.HasPrefix(raw, keyPrefix) {
		return nil, ErrNotFound
	}
	rest := strings.TrimPrefix(raw, keyPrefix)
	i := strings.IndexByte(rest, '_')
	if i <= 0 {
		return nil, ErrNotFound
	}
	id := "agt_" + rest[:i]
	a, hash, err := s.scanAgent(s.db.QueryRow(`SELECT `+agentCols+` FROM agents WHERE id=?`, id))
	if err != nil {
		return nil, ErrNotFound
	}
	h := sha256.Sum256([]byte(raw))
	if subtle.ConstantTimeCompare(h[:], hash) != 1 {
		return nil, ErrNotFound
	}
	if a.RevokedAt != 0 {
		return nil, errors.New("agent revoked")
	}
	t := now()
	if t-a.LastSeenAt > 30 {
		_, _ = s.db.Exec(`UPDATE agents SET last_seen_at=? WHERE id=?`, t, id)
	}
	return a, nil
}

func (s *Store) ListAgents() ([]*Agent, error) {
	rows, err := s.db.Query(`SELECT ` + agentCols + ` FROM agents ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Agent
	for rows.Next() {
		a, _, err := s.scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAgent(id string) error {
	res, err := s.db.Exec(`UPDATE agents SET revoked_at=? WHERE id=? AND revoked_at=0`, now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetAgentPolicy(id string, p Policy) error {
	pj, _ := json.Marshal(p)
	_, err := s.db.Exec(`UPDATE agents SET policy=? WHERE id=?`, string(pj), id)
	return err
}

// ---------- approvals ----------

type Approval struct {
	CredentialBindings string          `json:"-"` // immutable approved credential identities
	ID                 string          `json:"id"`
	AgentID            string          `json:"agent_id"`
	AgentName          string          `json:"agent_name"`
	Action             string          `json:"action"`
	Args               json.RawMessage `json:"args"`
	Summary            string          `json:"summary"`
	GateReason         string          `json:"gate_reason"`
	Status             string          `json:"status"` // pending | approved | denied | executed | failed | expired
	CreatedAt          int64           `json:"created_at"`
	ExpiresAt          int64           `json:"expires_at"`
	DecidedAt          int64           `json:"decided_at"`
	DecidedBy          string          `json:"decided_by"`
	Result             json.RawMessage `json:"result,omitempty"`
	Error              string          `json:"error,omitempty"`
	// GrantFamily is the OAuth refresh-token family of the token that queued
	// this action (empty for an agent key). Checked at run time so a revoked
	// grant can't still execute work it queued (Astra N9).
	GrantFamily string `json:"-"`
	// DefDigest pins an upstream tool's definition at approval time, so a reload
	// that swaps the definition under the same name can't run it (Astra R7).
	DefDigest string `json:"-"`
	// Origin records how this approval was authenticated: "key" (agent key),
	// "oauth" (OAuth grant), or "" (unknown, legacy). An empty origin is never
	// trusted to run (Astra A6); callers must set it.
	Origin string `json:"-"`
}

func (s *Store) CreateApproval(a *Approval) error {
	a.ID = NewID("apr_")
	a.Status = "pending"
	a.CreatedAt = now()
	if a.ExpiresAt == 0 {
		a.ExpiresAt = a.CreatedAt + 24*3600
	}
	_, err := s.db.Exec(`INSERT INTO approvals(id,agent_id,agent_name,action,args,summary,gate_reason,status,created_at,expires_at,grant_family,def_digest,origin,credential_bindings) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.AgentID, a.AgentName, a.Action, string(a.Args), a.Summary, a.GateReason, a.Status, a.CreatedAt, a.ExpiresAt, a.GrantFamily, a.DefDigest, a.Origin, a.CredentialBindings)
	return err
}

const apprCols = `id,agent_id,agent_name,action,args,summary,gate_reason,status,created_at,expires_at,decided_at,decided_by,result,error,grant_family,def_digest,origin,credential_bindings`

func scanApproval(row interface{ Scan(...any) error }) (*Approval, error) {
	var a Approval
	var args, result string
	if err := row.Scan(&a.ID, &a.AgentID, &a.AgentName, &a.Action, &args, &a.Summary, &a.GateReason, &a.Status, &a.CreatedAt, &a.ExpiresAt, &a.DecidedAt, &a.DecidedBy, &result, &a.Error, &a.GrantFamily, &a.DefDigest, &a.Origin, &a.CredentialBindings); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	a.Args = json.RawMessage(args)
	if result != "" {
		a.Result = json.RawMessage(result)
	}
	if a.Status == "pending" && a.ExpiresAt < now() {
		a.Status = "expired"
	}
	return &a, nil
}

func (s *Store) GetApproval(id string) (*Approval, error) {
	return scanApproval(s.db.QueryRow(`SELECT `+apprCols+` FROM approvals WHERE id=?`, id))
}

func (s *Store) ListApprovals(status string, limit int) ([]*Approval, error) {
	q := `SELECT ` + apprCols + ` FROM approvals`
	var args []any
	if status != "" {
		q += ` WHERE status=?`
		args = append(args, status)
	}
	q += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DecideApproval atomically moves a pending, unexpired approval to approved or
// denied. It fails if someone already decided it, so an approval runs once.
func (s *Store) DecideApproval(id, status, by string) error {
	if status != "approved" && status != "denied" {
		return errors.New("bad decision")
	}
	res, err := s.db.Exec(`UPDATE approvals SET status=?, decided_at=?, decided_by=? WHERE id=? AND status='pending' AND expires_at>=?`, status, now(), by, id, now())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("approval is not pending (already decided or expired)")
	}
	return nil
}

// ClaimApproval atomically moves an approved action to 'executing', so only one
// caller can start it even if several arrive at once (Astra N4). It returns true
// only for the caller that won the claim.
func (s *Store) ClaimApproval(id string) (bool, error) {
	res, err := s.db.Exec(`UPDATE approvals SET status='executing' WHERE id=? AND status='approved'`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *Store) FinishApproval(id string, result json.RawMessage, errMsg string) error {
	status := "executed"
	if errMsg != "" {
		status = "failed"
	}
	_, err := s.db.Exec(`UPDATE approvals SET status=?, result=?, error=? WHERE id=?`, status, string(result), errMsg, id)
	return err
}

// ---------- audit ----------

type AuditEntry struct {
	ID         int64  `json:"id"`
	TS         int64  `json:"ts"`
	Actor      string `json:"actor"`
	Action     string `json:"action"`
	Outcome    string `json:"outcome"`
	DurationMS int64  `json:"duration_ms"`
	Detail     string `json:"detail"`
}

// Audit records one event. Callers must pass already-redacted detail.
func (s *Store) Audit(actor, action, outcome string, dur time.Duration, detail string) {
	if len(detail) > 2000 {
		detail = detail[:2000] + "…"
	}
	_, _ = s.db.Exec(`INSERT INTO audit(ts,actor,action,outcome,duration_ms,detail) VALUES(?,?,?,?,?,?)`, now(), actor, action, outcome, dur.Milliseconds(), detail)
}

func (s *Store) ListAudit(limit int) ([]*AuditEntry, error) {
	rows, err := s.db.Query(`SELECT id,ts,actor,action,outcome,duration_ms,detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Outcome, &e.DurationMS, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// ---------- passkeys ----------

type Passkey struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	RPID       string          `json:"rp_id"`
	Credential json.RawMessage `json:"-"`
	CreatedAt  int64           `json:"created_at"`
	LastUsedAt int64           `json:"last_used_at"`
}

func (s *Store) AddPasskey(name, rpID string, cred json.RawMessage) (*Passkey, error) {
	p := &Passkey{ID: NewID("pk_"), Name: name, RPID: rpID, Credential: cred, CreatedAt: now()}
	_, err := s.db.Exec(`INSERT INTO passkeys(id,name,credential,created_at,rp_id) VALUES(?,?,?,?,?)`, p.ID, p.Name, string(cred), p.CreatedAt, rpID)
	return p, err
}

func (s *Store) ListPasskeys() ([]*Passkey, error) {
	rows, err := s.db.Query(`SELECT id,name,credential,created_at,last_used_at,rp_id FROM passkeys ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Passkey
	for rows.Next() {
		var p Passkey
		var c string
		if err := rows.Scan(&p.ID, &p.Name, &c, &p.CreatedAt, &p.LastUsedAt, &p.RPID); err != nil {
			return nil, err
		}
		p.Credential = json.RawMessage(c)
		out = append(out, &p)
	}
	return out, rows.Err()
}

func (s *Store) UpdatePasskey(id string, cred json.RawMessage) error {
	_, err := s.db.Exec(`UPDATE passkeys SET credential=?, last_used_at=? WHERE id=?`, string(cred), now(), id)
	return err
}

func (s *Store) DeletePasskey(id string) error {
	_, err := s.db.Exec(`DELETE FROM passkeys WHERE id=?`, id)
	return err
}

func (s *Store) DeleteAllPasskeys() error {
	_, err := s.db.Exec(`DELETE FROM passkeys`)
	return err
}

// ---------- settings ----------

func (s *Store) Setting(k string) string {
	var v string
	_ = s.db.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&v)
	return v
}

func (s *Store) SetSetting(k, v string) error {
	_, err := s.db.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

// HashToken is used for one-time tokens (setup links) that are stored hashed.
func HashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}
