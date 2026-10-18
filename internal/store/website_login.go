package store

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/Harsette/ralx/internal/loginorigin"
)

func (s *Store) LoginOriginHash(origin string) string {
	return s.box.LookupHash("website-origin/v1", origin)
}

// WebsiteLogin reads sealed display fields without making an owner view count
// as a website login. The ordinary Secret/BoundSecret path records actual use.
func (s *Store) WebsiteLogin(name string) (*Credential, map[string]string, error) {
	c, f, e := s.secretWithMeta(name, false)
	if e != nil {
		return nil, nil, e
	}
	if c.Kind != "website_login" {
		return nil, nil, ErrNotFound
	}
	return c, f, nil
}

// The generic credential API remains the one owner save/reveal path. Website
// logins have stricter storage rules: all human text is inside the sealed fields.
func (s *Store) prepareWebsiteLogin(name string, meta map[string]any, fields map[string]string) (map[string]any, map[string]string, error) {
	invalid := errors.New("invalid website login")
	if !regexp.MustCompile(`^login_[a-z2-7]{16}$`).MatchString(name) {
		return nil, nil, invalid
	}
	f := copyFields(fields)
	for _, key := range []string{"username", "name", "notes"} {
		if v, ok := meta[key].(string); ok && f[key] == "" {
			f[key] = v
		}
	}
	origins := []string{}
	if f["origins"] != "" {
		if json.Unmarshal([]byte(f["origins"]), &origins) != nil {
			return nil, nil, invalid
		}
	} else {
		b, _ := json.Marshal(meta["origins"])
		if json.Unmarshal(b, &origins) != nil {
			return nil, nil, invalid
		}
	}
	if len(origins) == 0 || len(origins) > 16 || f["username"] == "" || len(f["username"]) > 254 || f["password"] == "" {
		return nil, nil, invalid
	}
	hashes := []string{}
	for i, o := range origins {
		n, e := loginorigin.Exact(o)
		if e != nil {
			return nil, nil, invalid
		}
		origins[i] = n
		hashes = append(hashes, s.LoginOriginHash(n))
	}
	b, _ := json.Marshal(origins)
	f["origins"] = string(b)
	kind, _ := meta["kind"].(string)
	created, _ := meta["created_by"].(string)
	if (kind != "test" && kind != "real") || (created != "agent" && created != "human") {
		return nil, nil, invalid
	}
	source := "human_saved"
	if generated, _ := meta["ralx_generated"].(bool); generated && created == "agent" && kind == "test" {
		source = "ralx_generated"
	}
	// Preserve extra owner text, encrypted, instead of silently dropping it.
	extra := map[string]any{}
	if v := f["metadata"]; v != "" {
		if json.Unmarshal([]byte(v), &extra) != nil {
			extra = map[string]any{"saved_metadata": v}
		}
	}
	if extra == nil {
		extra = map[string]any{}
	}
	for k, v := range meta {
		switch k {
		case "kind", "created_by", "ralx_generated", "source", "origin_hashes", "_approval_generation":
		default:
			extra[k] = v
		}
	}
	b, _ = json.Marshal(extra)
	f["metadata"] = string(b)
	clean := map[string]string{}
	for _, k := range []string{"password", "username", "origins", "name", "notes", "metadata"} {
		if v := f[k]; v != "" {
			clean[k] = v
		}
	}
	unknown := map[string]string{}
	for k, v := range f {
		switch k {
		case "password", "username", "origins", "name", "notes", "metadata":
		default:
			unknown[k] = v
		}
	}
	if len(unknown) > 0 {
		b, _ := json.Marshal(unknown)
		clean["extra_fields"] = string(b)
	}
	return map[string]any{"kind": kind, "created_by": created, "source": source, "origin_hashes": hashes}, clean, nil
}
