package daemon

// Astra 5 probes, inverted into regression tests: each asserts the FIX and fails
// if the vulnerability returns. Every value is synthetic and every outbound
// request uses an in-memory transport; no sockets are opened.
import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/store"
)

func a5Percent(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func a5Gzip(s string) []byte {
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	_, _ = z.Write([]byte(s))
	_ = z.Close()
	return b.Bytes()
}

// The 4 Daru DeepContainsSecret fail-open cases (64-run cap, depth>4, base32,
// split headers) plus the other recoverable transforms I now close. Each must be
// WITHHELD from the agent (the request is held, then approved+run through
// execHTTP, and the response must not reconstruct the secret).
func TestAstra5FixHTTPRecoverableTransformsWithheld(t *testing.T) {
	const secret = "SyntheticAstraFiveCredential0123456789"
	for _, format := range []string{"base32", "nested_base64_depth", "percent_with_invalid_escape", "split_json_reordered", "gzip_bad_checksum", "sixty_fifth_encoded_run"} {
		t.Run(format, func(t *testing.T) {
			h := newHarness(t)
			putHostCred(t, h, "svc", secret, []string{"api.example"})
			payload := ""
			decode := func(s string) string { return s }
			switch format {
			case "base32":
				payload = base32.StdEncoding.EncodeToString([]byte(secret))
				decode = func(s string) string { b, _ := base32.StdEncoding.DecodeString(s); return string(b) }
			case "nested_base64_depth":
				payload = secret
				for i := 0; i < 6; i++ {
					payload = base64.StdEncoding.EncodeToString([]byte(payload))
				}
				decode = func(s string) string {
					for i := 0; i < 6; i++ {
						b, e := base64.StdEncoding.DecodeString(s)
						if e != nil {
							return ""
						}
						s = string(b)
					}
					return s
				}
			case "percent_with_invalid_escape":
				payload = a5Percent(secret) + "%invalid"
				decode = func(s string) string { v, _ := url.QueryUnescape(strings.TrimSuffix(s, "%invalid")); return v }
			case "split_json_reordered":
				b, _ := json.Marshal(map[string]string{"z": secret[:18], "a": secret[18:]})
				payload = string(b)
				decode = func(s string) string {
					var m map[string]string
					_ = json.Unmarshal([]byte(s), &m)
					return m["z"] + m["a"]
				}
			case "gzip_bad_checksum":
				b := a5Gzip(strings.Repeat(secret, 64))
				b[len(b)-8] ^= 1
				payload = base64.StdEncoding.EncodeToString(b)
				decode = func(s string) string {
					b, _ := base64.StdEncoding.DecodeString(s)
					z, e := gzip.NewReader(bytes.NewReader(b))
					if e != nil {
						return ""
					}
					defer z.Close()
					data, _ := io.ReadAll(z)
					if len(data) < len(secret) {
						return ""
					}
					return string(data[:len(secret)])
				}
			case "sixty_fifth_encoded_run":
				payload = strings.Repeat("QUFBQUFBQUFBQUFB;", 64) + base64.StdEncoding.EncodeToString(a5Gzip(strings.Repeat(secret, 64)))
				decode = func(s string) string {
					pieces := strings.Split(s, ";")
					b, _ := base64.StdEncoding.DecodeString(pieces[len(pieces)-1])
					z, e := gzip.NewReader(bytes.NewReader(b))
					if e != nil {
						return ""
					}
					defer z.Close()
					data, _ := io.ReadAll(z)
					if len(data) < len(secret) {
						return ""
					}
					return string(data[:len(secret)])
				}
			}
			if decode(payload) != secret {
				t.Fatal("fixture does not recover exact secret")
			}
			h.s.ext = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) { return fakeResp(r, 200, payload), nil })}
			res, errStr := execHTTP(t, h, h.agent("transform"), map[string]any{"url": "https://api.example/file", "headers": []string{"Authorization: Bearer {{svc}}"}})
			if errStr != "" {
				t.Fatalf("exec: %s", errStr)
			}
			body, _ := res["body"].(string)
			if decode(body) == secret || strings.Contains(body, secret) {
				t.Fatalf("defect reproduced: credential recovered from the response (%s)", format)
			}
		})
	}
}

// Control: base64url (unpadded) and UTF-16LE ascii are both recognised and
// withheld.
func TestAstra5FixBase64urlAndUTF16Withheld(t *testing.T) {
	for _, format := range []string{"base64url_unpadded", "utf16le_ascii"} {
		t.Run(format, func(t *testing.T) {
			h := newHarness(t)
			const secret = "SyntheticAstraFiveCredential0123456789"
			putHostCred(t, h, "svc", secret, []string{"api.example"})
			payload := base64.RawURLEncoding.EncodeToString([]byte("x" + secret + "!"))
			if format == "utf16le_ascii" {
				var b []byte
				for _, c := range []byte(secret) {
					b = append(b, c, 0)
				}
				payload = string(b)
			}
			h.s.ext = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) { return fakeResp(r, 200, payload), nil })}
			res, errStr := execHTTP(t, h, h.agent("held"), map[string]any{"url": "https://api.example/file", "headers": []string{"Authorization: Bearer {{svc}}"}})
			if errStr != "" {
				t.Fatalf("exec: %s", errStr)
			}
			if body, _ := res["body"].(string); !strings.Contains(body, "withheld") {
				t.Fatalf("expected withholding (%s)", format)
			}
		})
	}
}

// Daru fail-open case #4: a secret split across two response headers is in no
// single value, so the concatenation is deep-scanned and the whole response is
// withheld.
func TestAstra5FixSecretSplitAcrossHeadersWithheld(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticSplitHeaderCredential0123456789"
	putHostCred(t, h, "svc", secret, []string{"api.example"})
	h.s.ext = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		res := fakeResp(r, 200, `{"ok":true}`)
		res.Header.Set("X-Part-A", secret[:20])
		res.Header.Set("X-Part-B", secret[20:])
		return res, nil
	})}
	res, errStr := execHTTP(t, h, h.agent("split-headers"), map[string]any{"url": "https://api.example/file", "headers": []string{"Authorization: Bearer {{svc}}"}})
	if errStr != "" {
		t.Fatalf("exec: %s", errStr)
	}
	raw, _ := json.Marshal(res)
	hdrs, _ := res["headers"].(map[string]any)
	recovered := ""
	if a, ok := hdrs["X-Part-A"].(string); ok {
		recovered += a
	}
	if b, ok := hdrs["X-Part-B"].(string); ok {
		recovered += b
	}
	if recovered == secret || bytes.Contains(raw, []byte(secret[:20])) || bytes.Contains(raw, []byte(secret[20:])) {
		t.Fatalf("defect reproduced: split-header credential survived: %s", raw)
	}
}

// Catalog surfaces: a hostile upstream must not leak a secret through a schema
// property/$defs KEY, split property titles, or hex-prefixed tool names.
func TestAstra5FixCatalogUntrustedFields(t *testing.T) {
	for _, surface := range []string{"property_key_literal", "nested_defs_key", "split_titles", "prefixed_hex_tool_names"} {
		t.Run(surface, func(t *testing.T) {
			h := newHarness(t)
			const secret = "SyntheticCatalogCredential0123456789"
			schema := map[string]any{"type": "object"}
			var tools []map[string]any
			want := []string{secret}
			switch surface {
			case "property_key_literal":
				schema["properties"] = map[string]any{secret: map[string]any{"type": "string"}}
			case "nested_defs_key":
				schema["$defs"] = map[string]any{secret: map[string]any{"type": "string"}}
			case "split_titles":
				want = []string{secret[:17], secret[17:]}
				schema["properties"] = map[string]any{"first": map[string]any{"type": "string", "title": want[0]}, "second": map[string]any{"type": "string", "title": want[1]}}
			case "prefixed_hex_tool_names":
				enc := hex.EncodeToString([]byte(secret))
				want = []string{enc[:len(enc)/2], enc[len(enc)/2:]}
				for _, p := range want {
					tools = append(tools, map[string]any{"name": "part_" + p, "inputSchema": schema})
				}
			}
			if len(tools) == 0 {
				tools = []map[string]any{{"name": "inspect", "inputSchema": schema}}
			}
			calls := 0
			h.s.up.Transport = astra2MCPTransport(tools, &calls)
			if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", secret); err != nil {
				t.Fatal(err)
			}
			r := h.do("GET", "/v1/actions", nil, bearer(h.agent("catalog")), false)
			if r.code != 200 || calls != 0 {
				t.Fatalf("status=%d calls=%d (catalog listing must not call the upstream)", r.code, calls)
			}
			for _, p := range want {
				if strings.Contains(string(r.raw), p) {
					t.Fatalf("defect reproduced: secret component advertised in the catalog (%s)", surface)
				}
			}
		})
	}
}

// A raw gzip Drive file that gunzips to a secret is withheld (gunzip is tried on
// the raw bytes too, Astra5).
func TestAstra5FixDriveRawGzipWithheld(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticDriveArchiveCredential0123456789"
	putHostCred(t, h, "svc", secret, nil)
	payload := a5Gzip(strings.Repeat(secret, 64))
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("alt") == "media" {
			return fakeResp(r, 200, string(payload)), nil
		}
		return fakeResp(r, 200, `{"name":"fixture.gz","mimeType":"application/gzip"}`), nil
	})
	r := h.do("GET", "/v1/drive/files/abcdefghijk/content", nil, bearer(h.agent("gzip-file")), false)
	if r.code != 200 {
		t.Fatalf("status %d", r.code)
	}
	if r.hdr.Get("X-RalX-Withheld") == "" {
		t.Fatal("defect reproduced: gzip Drive file was not withheld")
	}
	if z, err := gzip.NewReader(bytes.NewReader(r.raw)); err == nil {
		defer z.Close()
		if b, _ := io.ReadAll(z); bytes.Contains(b, []byte(secret)) {
			t.Fatal("defect reproduced: credential recovered from the gzip stream")
		}
	}
}

// A Drive file larger than the deep-scan cap is withheld (fail closed), not
// streamed unscanned; and a small file whose bytes reconstruct a secret is
// withheld too.
func TestAstra5FixDriveOverCapWithheld(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticDriveCapCredential0123456789"
	putHostCred(t, h, "svc", secret, nil)
	encoded := a5Percent(secret)
	payload := encoded
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("alt") == "media" {
			return fakeResp(r, 200, payload), nil
		}
		return fakeResp(r, 200, `{"name":"fixture.txt","mimeType":"text/plain"}`), nil
	})
	key := h.agent("cap-file")
	control := h.do("GET", "/v1/drive/files/abcdefghijk/content", nil, bearer(key), false)
	if control.code != 200 || control.hdr.Get("X-RalX-Withheld") != "credential" {
		t.Fatalf("small control not withheld: %d %q", control.code, control.hdr.Get("X-RalX-Withheld"))
	}
	payload = encoded + strings.Repeat("~", 16<<20)
	r := h.do("GET", "/v1/drive/files/abcdefghijk/content", nil, bearer(key), false)
	if r.code != 200 || r.hdr.Get("X-RalX-Withheld") == "" {
		t.Fatalf("defect reproduced: oversized response not withheld (status=%d withheld=%q)", r.code, r.hdr.Get("X-RalX-Withheld"))
	}
	n := len(encoded)
	if len(r.raw) < n {
		n = len(r.raw)
	}
	if recovered, _ := url.QueryUnescape(string(r.raw[:n])); recovered == secret {
		t.Fatal("defect reproduced: oversized response recovered the exact key")
	}
}

// An approved upstream isError result is deep-scanned too; a percent-encoded
// secret in the error text is withheld, not disclosed via the polled approval.
func TestAstra5FixUpstreamErrorDeepScanned(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticMCPErrorCredential0123456789"
	calls := 0
	base := astra2MCPTransport([]map[string]any{{"name": "inspect", "inputSchema": map[string]any{"type": "object"}}}, &calls)
	h.s.up.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		res, err := base.RoundTrip(r)
		if err != nil || res.StatusCode != 200 {
			return res, err
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		var msg map[string]any
		_ = json.Unmarshal(b, &msg)
		if result, ok := msg["result"].(map[string]any); ok {
			if _, ok := result["content"]; ok {
				result["isError"] = true
				result["content"] = []any{map[string]any{"type": "text", "text": a5Percent(secret)}}
			}
		}
		b, _ = json.Marshal(msg)
		res.Body = io.NopCloser(bytes.NewReader(b))
		return res, nil
	})
	if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", secret); err != nil {
		t.Fatal(err)
	}
	key := h.agent("upstream-error")
	r := h.do("POST", "/v1/actions/demo.inspect", map[string]any{"args": map[string]any{}}, bearer(key), false)
	if r.code != 202 {
		t.Fatalf("queue %d", r.code)
	}
	id := r.body["approval_id"].(string)
	if err := h.s.store.DecideApproval(id, "approved", "synthetic approved fixture"); err != nil {
		t.Fatal(err)
	}
	h.s.runApproval(id)
	r = h.do("GET", "/v1/approvals/"+id, nil, bearer(key), false)
	if r.code != 200 {
		t.Fatalf("poll %d", r.code)
	}
	e, _ := r.body["error"].(string)
	decoded, _ := url.QueryUnescape(e)
	if strings.Contains(decoded, secret) {
		t.Fatal("defect reproduced: upstream error disclosed the credential")
	}
	if calls != 1 {
		t.Fatalf("expected exactly one upstream tool call, got %d", calls)
	}
}

// A gated Google action is refused at approval creation when no account resolves
// (no-default binding), rather than binding to a later-connected account.
func TestAstra5FixGoogleApprovalUnresolvedAccountRefused(t *testing.T) {
	h := newHarness(t)
	if got := h.s.google.DefaultAccountFor("gmail"); got != "" {
		t.Fatalf("unexpected initial account: %q", got)
	}
	queued := h.do("POST", "/v1/actions/gmail.send", map[string]any{"args": map[string]any{"to": []string{"recipient@example.invalid"}, "subject": "fixture", "body": "synthetic message"}}, bearer(h.agent("astra5-unresolved")), false)
	if queued.code != 400 {
		t.Fatalf("defect reproduced: unresolved-account action was not refused: %d %s", queued.code, queued.raw)
	}
}

// A legacy approval with no provenance (origin), from a grant revoked before this
// binary's upgrade, is never run.
func TestAstra5FixLegacyApprovalRevokedBeforeUpgrade(t *testing.T) {
	h := newHarness(t)
	agent, _, err := h.s.store.CreateAgent("astra5-legacy-upgrade", store.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	at, rt, err := h.s.store.IssueTokens(agent.ID, "synthetic-client", "", h.s.origin+"/mcp", "ralx", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.s.store.AuthenticateAccessToken(at); err != nil {
		t.Fatal(err)
	}
	h.s.store.RevokeToken(rt)
	// A pre-fix empty-provenance (origin="") legacy approval, inserted after the
	// revocation so it isn't caught by the revoke-cancel path.
	ap := &store.Approval{AgentID: agent.ID, AgentName: agent.Name, Action: "test.danger", Summary: "Delete repo", GateReason: "deletes", Args: json.RawMessage(`{"thing":"repo"}`)}
	if err := h.s.store.CreateApproval(ap); err != nil {
		t.Fatal(err)
	}
	if r := h.do("GET", "/v1/whoami", nil, bearer(at), false); r.code != 401 {
		t.Fatalf("revoked auth=%d", r.code)
	}
	if err := h.s.store.DecideApproval(ap.ID, "approved", "synthetic owner"); err != nil {
		t.Fatal(err)
	}
	h.s.runApproval(ap.ID)
	got, _ := h.s.store.GetApproval(ap.ID)
	if got.Status == "executed" {
		t.Fatal("defect reproduced: legacy empty-provenance approval executed")
	}
}

// The Drive audience is bound to a canonical fingerprint, not a display string:
// a changed audience (domain / shared-drive member / unowned-folder member) is
// refused at completion even though the display summary is unchanged.
func TestAstra5FixDriveRecipientFingerprint(t *testing.T) {
	// API-faithful fixtures (Daru6 P1-2): files.get returns only metadata (no
	// `permissions`); the audience is served by permissions.list. A change to the
	// audience after approval must refuse the upload.
	for _, kind := range []string{"domain", "shared-drive", "unowned-folder"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t)
			recipient := "alice.example.invalid"
			permLists, uploads := 0, 0
			seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
				switch r.Method {
				case "GET":
					if strings.Contains(r.URL.Path, "/permissions") {
						permLists++
						perm := `{"type":"user","role":"reader","emailAddress":"` + recipient + `"}`
						if kind == "domain" {
							perm = `{"type":"domain","role":"reader","domain":"` + recipient + `"}`
						}
						return fakeResp(r, 200, `{"permissions":[`+perm+`]}`), nil
					}
					// files.get: metadata only, as real Drive returns it.
					body := `{"name":"F","shared":true,"ownedByMe":true}`
					if kind == "shared-drive" {
						body = `{"name":"F","driveId":"drive-1"}`
					} else if kind == "unowned-folder" {
						body = `{"name":"F","shared":true,"ownedByMe":false}`
					}
					return fakeResp(r, 200, body), nil
				case "POST":
					res := fakeResp(r, 200, "")
					res.Header.Set("Location", "https://www.googleapis.com/upload/session/fixture")
					return res, nil
				case "PUT":
					data, _ := io.ReadAll(r.Body)
					if string(data) != "GOOD" {
						t.Fatalf("bytes=%q", data)
					}
					uploads++
					return fakeResp(r, 200, `{"id":"fixture-result"}`), nil
				}
				t.Fatalf("unexpected fake method %s", r.Method)
				return nil, nil
			})
			key := h.agent("astra5-recipients")
			agent := mustAgent(t, h, "astra5-recipients")
			file, err := h.s.staging.start(agent.ID, "fixture.txt", "text/plain", 4)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = h.s.staging.put(file.ID, agent.ID, 0, 4, strings.NewReader("GOOD")); err != nil {
				t.Fatal(err)
			}
			queued := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "account": "test@x", "parent_id": "fixturefolder123", "media_upload_id": file.ID}, bearer(key), false)
			if queued.code != 202 || permLists != 1 {
				t.Fatalf("queue: %d permLists=%d %s", queued.code, permLists, queued.raw)
			}
			id := queued.body["approval_id"].(string)
			if err := h.s.store.DecideApproval(id, "approved", "synthetic owner"); err != nil {
				t.Fatal(err)
			}
			recipient = "bob.example.invalid" // audience changes after approval
			done := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "approval_id": id}, bearer(key), false)
			if done.code == 200 || uploads != 0 {
				t.Fatalf("defect reproduced: %s audience change not refused (status=%d uploads=%d)", kind, done.code, uploads)
			}
			if permLists != 2 {
				t.Fatalf("expected a completion-time permissions.list recheck, got %d", permLists)
			}
		})
	}
}

// Replacing the upstream account/header changes the approval digest, and the old
// approval no longer executes (auth/account bound into the digest).
func TestAstra5FixUpstreamApprovalAuthReplacement(t *testing.T) {
	h := newHarness(t)
	calls := 0
	base := astra2MCPTransport([]map[string]any{{"name": "dispatch", "inputSchema": map[string]any{"type": "object"}}}, &calls)
	var used string
	h.s.up.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		before := calls
		res, err := base.RoundTrip(r)
		if calls > before {
			used = r.Header.Get("X-Other-Key")
		}
		return res, err
	})
	if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", "synthetic-account-a-0123456789"); err != nil {
		t.Fatal(err)
	}
	r := h.do("POST", "/v1/actions/demo.dispatch", map[string]any{"args": map[string]any{"record": "approved"}}, bearer(h.agent("astra5-auth-swap")), false)
	if r.code != 202 {
		t.Fatalf("queue: %d %s", r.code, r.raw)
	}
	id := r.body["approval_id"].(string)
	ap, _ := h.s.store.GetApproval(id)
	if ap.DefDigest == "" {
		t.Fatal("missing digest")
	}
	if err := h.s.store.DecideApproval(id, "approved", "synthetic owner"); err != nil {
		t.Fatal(err)
	}
	if err := h.s.store.UpdateMeta("mcp:demo", map[string]any{"header": "X-Other-Key", "gen": "regenerated"}); err != nil {
		t.Fatal(err)
	}
	if err := h.s.store.UpdateFields("mcp:demo", map[string]string{"value": "synthetic-account-b-0123456789"}); err != nil {
		t.Fatal(err)
	}
	if err := h.s.up.Load(context.Background(), "demo"); err != nil {
		t.Fatal(err)
	}
	a, _ := h.s.reg.Get("demo.dispatch")
	if a.DefDigest == ap.DefDigest {
		t.Fatal("defect reproduced: identity change did not invalidate the digest")
	}
	h.s.runApproval(id)
	got, _ := h.s.store.GetApproval(id)
	if got.Status == "executed" || calls != 0 || used == "synthetic-account-b-0123456789" {
		t.Fatalf("defect reproduced: old approval ran under the replacement account (status=%s calls=%d)", got.Status, calls)
	}
}

// A lazy reconnect that loads a changed origin does not silently dispatch the
// approved call there; it returns to authorization.
func TestAstra5FixUpstreamApprovalReconnect(t *testing.T) {
	h := newHarness(t)
	calls := 0
	base := astra2MCPTransport([]map[string]any{{"name": "dispatch", "inputSchema": map[string]any{"type": "object"}}}, &calls)
	var host string
	h.s.up.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		before := calls
		res, err := base.RoundTrip(r)
		if calls > before {
			host = r.URL.Host
		}
		return res, err
	})
	if err := h.s.up.AddHeaderServer("demo", "https://first.example/mcp", "X-Key", "synthetic-reconnect-key-0123456789"); err != nil {
		t.Fatal(err)
	}
	r := h.do("POST", "/v1/actions/demo.dispatch", map[string]any{"args": map[string]any{"record": "approved"}}, bearer(h.agent("astra5-reconnect")), false)
	if r.code != 202 {
		t.Fatalf("queue: %d %s", r.code, r.raw)
	}
	id := r.body["approval_id"].(string)
	if err := h.s.store.DecideApproval(id, "approved", "synthetic owner"); err != nil {
		t.Fatal(err)
	}
	ap, _ := h.s.store.GetApproval(id)
	// Model a missing session with the last known definition still advertised,
	// then the persisted endpoint changed to a new origin.
	h.s.up.Close()
	if err := h.s.store.UpdateMeta("mcp:demo", map[string]any{"url": "https://second.example/mcp"}); err != nil {
		t.Fatal(err)
	}
	h.s.runApproval(id)
	got, _ := h.s.store.GetApproval(id)
	if got.Status == "executed" || host == "second.example" {
		t.Fatalf("defect reproduced: reconnect dispatched to the changed origin (status=%s host=%s)", got.Status, host)
	}
	// Prove the reconnect path was actually reached: the lazy Load rebuilt the
	// registry action for the new origin, so its digest now differs from the one the
	// approval was pinned to (which is why dispatch was refused).
	newAction, ok := h.s.reg.Get("demo.dispatch")
	if !ok || newAction.DefDigest == ap.DefDigest {
		t.Fatalf("reconnect not reached: registry digest unchanged (%v)", ok)
	}
}

// A credential-bound GET/HEAD whose path, matrix parameter or encoded query
// selects an effect is now HELD for approval, not executed.
func TestAstra5FixHTTPPathEffectsHeld(t *testing.T) {
	for _, tc := range []struct{ name, method, suffix string }{
		{"path_get", "GET", "/items/1/delete"},
		{"matrix_get", "GET", "/items/1;action=delete"},
		{"encoded_query_get", "GET", "/items/1%3Faction=delete"},
		{"path_head", "HEAD", "/items/1/delete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			putHostCred(t, h, "svc", "synthetic-transport-review-key-0123456789", []string{"api.example"})
			deleted := false
			h.s.ext = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
				deleted = r.Header.Get("Authorization") != "" &&
					(strings.HasSuffix(r.URL.Path, "/delete") || strings.Contains(r.URL.Path, "action=delete"))
				return fakeResp(r, 200, `{"deleted":true}`), nil
			})}
			r := h.do("POST", "/v1/actions/http.request", map[string]any{"args": map[string]any{
				"method": tc.method, "url": "https://api.example" + tc.suffix,
				"headers": []string{"Authorization: Bearer {{svc}}"},
			}}, bearer(h.agent("path-effect")), false)
			if r.code != 202 {
				t.Fatalf("defect reproduced: %s %s was not held (status=%d)", tc.method, tc.suffix, r.code)
			}
			if deleted {
				t.Fatal("defect reproduced: request reached the endpoint without approval")
			}
		})
	}
}
