package daemon

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/store"
)

// Astra 1 & 3, Daru 2: outward catalog actions must be gated.
func TestGatedCatalogClassifications(t *testing.T) {
	h := newHarness(t)
	want := map[string]struct {
		risk, reason string
	}{
		"gh.issue.create":         {"gated", "posts"},   // Astra 1 / Daru 2
		"social.cancel_scheduled": {"gated", "deletes"}, // Astra 3
		"gh.repo.delete":          {"gated", "deletes"},
		"vercel.project.remove":   {"gated", "deletes"},
		"social.unpublish":        {"gated", "deletes"},
	}
	for name, w := range want {
		a, ok := h.s.reg.Get(name)
		if !ok {
			t.Fatalf("%s missing from catalog", name)
		}
		if string(a.Risk) != w.risk || a.GateReason != w.reason {
			t.Fatalf("%s: risk=%s reason=%s, want %s/%s", name, a.Risk, a.GateReason, w.risk, w.reason)
		}
	}
}

// Astra 1/10 & Daru 1: YouTube upload is gated unless the upload is private,
// takes a staged file id, and its approval is bound to it.
func TestYouTubeUploadGatedUnlessPrivate(t *testing.T) {
	h := newHarness(t)
	a, ok := h.s.reg.Get("youtube.upload")
	if !ok {
		t.Fatal("youtube.upload missing")
	}
	if a.Stream {
		t.Fatal("youtube.upload must no longer be a client-stream action")
	}
	priv, err := a.Validate(map[string]any{"media_upload_id": "stg_abcdef", "title": "t", "privacy": "private"})
	if err != nil {
		t.Fatalf("validate private: %v", err)
	}
	if a.IsGated(priv) {
		t.Fatal("private upload should run without approval")
	}
	pub, _ := a.Validate(map[string]any{"media_upload_id": "stg_abcdef", "title": "t", "privacy": "public"})
	if !a.IsGated(pub) {
		t.Fatal("public upload must be held for approval")
	}
	if _, err := a.Validate(map[string]any{"title": "t", "privacy": "private"}); err == nil {
		t.Fatal("youtube.upload must require a staged media_upload_id")
	}
}

// "same argv-injection tests as gh": every string param of the built-in CLI
// catalogs rejects shell metacharacters and flag injection. The test starts
// from a fully valid baseline and mutates one field at a time, so a rejection is
// attributable to the field under test and not to another required field getting
// a placeholder that doesn't match its own pattern (delta review).
func TestCatalogArgvInjectionRejected(t *testing.T) {
	h := newHarness(t)
	bad := []string{"a; rm -rf /", "--privileged", "x`whoami`", "a|b", "a\nb", "-rf", "$(id)", "a b"}
	checked := 0
	for _, a := range h.s.reg.List() {
		if a.CLI == nil {
			continue
		}
		base, ok := validBaseline(a)
		if !ok {
			continue // couldn't construct a valid baseline for this action
		}
		if _, err := a.Validate(cloneArgs(base)); err != nil {
			t.Fatalf("%s: baseline not valid: %v", a.Name, err)
		}
		for _, p := range a.Params {
			// Identifier fields carry a pattern and must reject shell
			// metacharacters and flag injection. Free-text fields (title, body)
			// are safe without a pattern because every argv element is a whole
			// placeholder, never a shell string.
			if p.Type != "string" || p.Pattern == "" {
				continue
			}
			for _, v := range bad {
				args := cloneArgs(base)
				args[p.Name] = v
				if _, err := a.Validate(args); err == nil {
					t.Errorf("%s.%s (pattern %q) accepted injection %q", a.Name, p.Name, p.Pattern, v)
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no pattern-constrained CLI params checked")
	}
}

func cloneArgs(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// validBaseline builds a valid value for every required param of a, or (nil,
// false) if no candidate matches some pattern-constrained field.
func validBaseline(a *actions.Action) (map[string]any, bool) {
	cands := []string{"abc", "abc123", "owner/name", "main", "us-east-1", "a.b-c",
		"feature/x", "v1.2.3", "repos/o/r/commits", "example.com", "x"}
	out := map[string]any{}
	for _, p := range a.Params {
		if !p.Required {
			continue
		}
		switch p.Type {
		case "integer":
			if p.Min != nil {
				out[p.Name] = *p.Min
			} else {
				out[p.Name] = float64(1)
			}
		case "boolean":
			out[p.Name] = false
		case "array":
			out[p.Name] = []any{"ok"}
		default: // string
			if len(p.Enum) > 0 {
				out[p.Name] = p.Enum[0]
				continue
			}
			if p.Pattern == "" {
				out[p.Name] = "ok"
				continue
			}
			re, err := regexp.Compile(`^(?:` + p.Pattern + `)$`)
			if err != nil {
				return nil, false
			}
			found := ""
			for _, c := range cands {
				if re.MatchString(c) {
					found = c
					break
				}
			}
			if found == "" {
				return nil, false
			}
			out[p.Name] = found
		}
	}
	return out, true
}

// Astra 6: reusing an existing broad agent for a read-only consent is refused.
func TestOAuthReadOnlyExistingAgentRejected(t *testing.T) {
	h := newHarness(t)
	// a broad (full-access) agent already exists
	if _, _, err := h.s.store.CreateAgent("dot", store.Policy{}); err != nil {
		t.Fatal(err)
	}
	if h.s.isReadOnlyAgent(mustAgent(t, h, "dot")) {
		t.Fatal("empty-allow agent must count as broad, not read-only")
	}
	// a genuinely read-only agent is recognised
	if _, _, err := h.s.store.CreateAgent("reader", store.Policy{Allow: h.s.readOnlyActions()}); err != nil {
		t.Fatal(err)
	}
	if !h.s.isReadOnlyAgent(mustAgent(t, h, "reader")) {
		t.Fatal("read-only agent not recognised")
	}
}

func mustAgent(t *testing.T, h *harness, name string) *store.Agent {
	a, err := h.s.store.GetAgentByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// Astra 7: a revoked OAuth family cannot be resurrected by an in-flight refresh.
func TestOAuthFamilyRevocationTombstone(t *testing.T) {
	h := newHarness(t)
	a, _, err := h.s.store.CreateAgent("conn", store.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	st := h.s.store
	fam := "fam_test1"
	access, refresh, err := st.IssueTokens(a.ID, "client", fam, "res", "ralx", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, e := st.AuthenticateAccessToken(access); e != nil {
		t.Fatalf("fresh access rejected: %v", e)
	}
	// client revokes (RFC 7009)
	st.RevokeToken(refresh)
	if _, _, e := st.AuthenticateAccessToken(access); e == nil {
		t.Fatal("access token still valid after revoke")
	}
	// an in-flight refresh trying to issue into the revoked family must fail
	if _, _, e := st.IssueTokens(a.ID, "client", fam, "res", "ralx", time.Hour, time.Hour); e == nil {
		t.Fatal("revoked family was resurrected by a new issue")
	}
	// and redeeming any refresh in that family is refused
	if _, e := st.RedeemRefresh(refresh, "client"); e == nil {
		t.Fatal("redeem on revoked family succeeded")
	}
}

// Astra 7 (reuse path): a reused refresh token tombstones the family too.
func TestOAuthRefreshReuseTombstones(t *testing.T) {
	h := newHarness(t)
	a, _, _ := h.s.store.CreateAgent("conn2", store.Policy{})
	st := h.s.store
	fam := "fam_test2"
	_, refresh, _ := st.IssueTokens(a.ID, "client", fam, "res", "ralx", time.Hour, time.Hour)
	if _, e := st.RedeemRefresh(refresh, "client"); e != nil {
		t.Fatalf("first redeem: %v", e)
	}
	old := store.RefreshGraceSeconds
	store.RefreshGraceSeconds = -1
	defer func() { store.RefreshGraceSeconds = old }()
	if _, e := st.RedeemRefresh(refresh, "client"); e == nil {
		t.Fatal("reused refresh accepted")
	}
	if _, _, e := st.IssueTokens(a.ID, "client", fam, "res", "ralx", time.Hour, time.Hour); e == nil {
		t.Fatal("family not tombstoned after reuse")
	}
}

// Astra 11: an OAuth access token is only valid at the origin it was issued for.
func TestMCPTokenAudienceEnforced(t *testing.T) {
	h := newHarness(t)
	h.s.hub.PublicOrigins = []string{"https://a.example", "https://b.example"}
	req := func(host string) *http.Request {
		r := httptest.NewRequest("POST", "http://"+host+"/mcp", nil)
		r.Host = host
		return r
	}
	if err := h.s.checkAudience("https://a.example/mcp", req("a.example")); err != nil {
		t.Fatalf("same-origin token rejected: %v", err)
	}
	if err := h.s.checkAudience("https://a.example/mcp", req("b.example")); err == nil {
		t.Fatal("token for a.example accepted at b.example")
	}
	if err := h.s.checkAudience("", req("a.example")); err != nil {
		t.Fatalf("agent key (no audience) rejected: %v", err)
	}
}

var _ = strings.Contains
var _ = actions.Allowed
