package daemon

// Daru6 probes, inverted: each asserts the FIX. Synthetic values, in-memory
// transports, no sockets.
import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func daru6Bomb(secret string) string {
	var b bytes.Buffer
	z, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	chunk := make([]byte, 1<<20)
	for i := 0; i < 65; i++ {
		_, _ = z.Write(chunk)
	}
	_, _ = z.Write([]byte(secret))
	_ = z.Close()
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func daru6Recover(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	z, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return ""
	}
	out, _ := io.ReadAll(z)
	return strings.TrimLeft(string(out), "\x00")
}

// An approved upstream tool returns base64(gzip(65 MiB zeros + its own header
// key)). The inflate budget / cap makes DeepContainsSecret withhold it, so the
// agent can't recover the key from the approval poll (Daru6 P0-1 end to end).
func TestDaru6FixUpstreamGzipBombWithheld(t *testing.T) {
	h := newHarness(t)
	const secret = "SyntheticDaruSixUpstreamKey0123456789"
	payload := daru6Bomb(secret)
	if daru6Recover(payload) != secret {
		t.Fatal("fixture does not recover secret")
	}
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
				result["content"] = []any{map[string]any{"type": "text", "text": payload}}
			}
		}
		b, _ = json.Marshal(msg)
		res.Body = io.NopCloser(bytes.NewReader(b))
		return res, nil
	})
	if err := h.s.up.AddHeaderServer("demo", "https://mcp.example/mcp", "X-Key", secret); err != nil {
		t.Fatal(err)
	}
	key := h.agent("daru6-bomb")
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
	var found string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if daru6Recover(x) == secret {
				found = secret
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(r.body)
	if found != "" {
		t.Fatal("defect reproduced: agent recovered the upstream header key from the gzip bomb")
	}
}

// The Drive audience fingerprint uses permissions.list (the real API), so a
// membership change after approval is caught even for a shared-drive item (whose
// files.get returns no `permissions`) or an item the caller can't share (Daru6 P1-2).
func TestDaru6FixDriveFingerprintUsesPermissionsList(t *testing.T) {
	for _, kind := range []string{"shared-drive", "unowned-no-share-capability"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t)
			member := "alice.example.invalid"
			permLists, uploads := 0, 0
			seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
				switch r.Method {
				case "GET":
					if strings.Contains(r.URL.Path, "/permissions") {
						permLists++
						return fakeResp(r, 200, `{"permissions":[{"type":"user","role":"reader","emailAddress":"`+member+`"}]}`), nil
					}
					body := `{"name":"Team","driveId":"drive-1"}`
					if kind != "shared-drive" {
						body = `{"name":"Team","shared":true,"ownedByMe":false}`
					}
					return fakeResp(r, 200, body), nil
				case "POST":
					res := fakeResp(r, 200, "")
					res.Header.Set("Location", "https://www.googleapis.com/upload/session/fixture")
					return res, nil
				case "PUT":
					_, _ = io.ReadAll(r.Body)
					uploads++
					return fakeResp(r, 200, `{"id":"fixture-result"}`), nil
				}
				return fakeResp(r, 500, ""), nil
			})
			key := h.agent("daru6-drive")
			agent := mustAgent(t, h, "daru6-drive")
			file, err := h.s.staging.start(agent.ID, "fixture.txt", "text/plain", 4)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = h.s.staging.put(file.ID, agent.ID, 0, 4, strings.NewReader("GOOD")); err != nil {
				t.Fatal(err)
			}
			q := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "account": "test@x", "parent_id": "teamfolder123", "media_upload_id": file.ID}, bearer(key), false)
			if q.code != 202 {
				t.Fatalf("queue %d %s", q.code, q.raw)
			}
			id := q.body["approval_id"].(string)
			if err := h.s.store.DecideApproval(id, "approved", "synthetic owner"); err != nil {
				t.Fatal(err)
			}
			member = "external-bob.example.invalid" // membership changes after approval
			done := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "approval_id": id}, bearer(key), false)
			if uploads != 0 || done.code == 200 {
				t.Fatalf("defect reproduced: %s audience change not refused (status=%d uploads=%d permLists=%d)", kind, done.code, uploads, permLists)
			}
			if permLists != 2 {
				t.Fatalf("expected queue + recheck permissions.list calls, got %d", permLists)
			}
		})
	}
}

// Self-review P1: a change to a permission's `view` (metadata-only -> content
// access) between approval and recheck changes the fingerprint and is refused;
// and an unresolved/empty permission set is refused at queue (fail closed).
func TestDaru6FixDriveViewAndEmptyAudience(t *testing.T) {
	t.Run("view-change-refused", func(t *testing.T) {
		h := newHarness(t)
		view := "published" // metadata-only at approval
		uploads := 0
		seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
			switch r.Method {
			case "GET":
				if strings.Contains(r.URL.Path, "/permissions") {
					// Honour the fields mask like real Drive: only return `view` if the
					// request actually asked for it. If the code forgets to request it,
					// p.View is empty both times and the change is missed (regression guard).
					viewField := ""
					if strings.Contains(r.URL.RawQuery, "view") {
						viewField = `,"view":"` + view + `"`
					}
					return fakeResp(r, 200, `{"permissions":[{"type":"user","role":"reader","emailAddress":"alice@example.invalid"`+viewField+`}]}`), nil
				}
				return fakeResp(r, 200, `{"name":"F","shared":true,"ownedByMe":true}`), nil
			case "POST":
				res := fakeResp(r, 200, "")
				res.Header.Set("Location", "https://www.googleapis.com/upload/session/fixture")
				return res, nil
			case "PUT":
				_, _ = io.ReadAll(r.Body)
				uploads++
				return fakeResp(r, 200, `{"id":"x"}`), nil
			}
			return fakeResp(r, 500, ""), nil
		})
		key := h.agent("daru6-view")
		agent := mustAgent(t, h, "daru6-view")
		file, _ := h.s.staging.start(agent.ID, "f.txt", "text/plain", 4)
		_, _ = h.s.staging.put(file.ID, agent.ID, 0, 4, strings.NewReader("GOOD"))
		q := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "account": "test@x", "parent_id": "folder123", "media_upload_id": file.ID}, bearer(key), false)
		if q.code != 202 {
			t.Fatalf("queue %d %s", q.code, q.raw)
		}
		id := q.body["approval_id"].(string)
		if err := h.s.store.DecideApproval(id, "approved", "synthetic owner"); err != nil {
			t.Fatal(err)
		}
		view = "" // same reader gains full content access
		done := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "approval_id": id}, bearer(key), false)
		if uploads != 0 || done.code == 200 {
			t.Fatalf("defect: view change not refused (status=%d uploads=%d)", done.code, uploads)
		}
	})
	t.Run("empty-audience-refused", func(t *testing.T) {
		h := newHarness(t)
		seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
			switch r.Method {
			case "GET":
				if strings.Contains(r.URL.Path, "/permissions") {
					return fakeResp(r, 200, `{"permissions":[]}`), nil // unresolved audience
				}
				return fakeResp(r, 200, `{"name":"F","driveId":"drive-1"}`), nil
			}
			return fakeResp(r, 500, ""), nil
		})
		key := h.agent("daru6-empty")
		agent := mustAgent(t, h, "daru6-empty")
		file, _ := h.s.staging.start(agent.ID, "f.txt", "text/plain", 4)
		_, _ = h.s.staging.put(file.ID, agent.ID, 0, 4, strings.NewReader("GOOD"))
		q := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "account": "test@x", "parent_id": "folder123", "media_upload_id": file.ID}, bearer(key), false)
		if q.code == 202 {
			t.Fatalf("defect: empty/unresolved audience was queued instead of refused: %s", q.raw)
		}
	})
	t.Run("grantee-id-change-refused", func(t *testing.T) {
		// Same email, different unique grantee id (a reassigned address / new principal)
		// must change the fingerprint and be refused (Daru6 self-review P1).
		h := newHarness(t)
		id := "perm-alice-1"
		uploads := 0
		seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
			switch r.Method {
			case "GET":
				if strings.Contains(r.URL.Path, "/permissions") {
					return fakeResp(r, 200, `{"permissions":[{"type":"user","role":"reader","emailAddress":"alice@example.invalid","id":"`+id+`"}]}`), nil
				}
				return fakeResp(r, 200, `{"name":"F","shared":true,"ownedByMe":true}`), nil
			case "POST":
				res := fakeResp(r, 200, "")
				res.Header.Set("Location", "https://www.googleapis.com/upload/session/fixture")
				return res, nil
			case "PUT":
				_, _ = io.ReadAll(r.Body)
				uploads++
				return fakeResp(r, 200, `{"id":"x"}`), nil
			}
			return fakeResp(r, 500, ""), nil
		})
		key := h.agent("daru6-id")
		agent := mustAgent(t, h, "daru6-id")
		file, _ := h.s.staging.start(agent.ID, "f.txt", "text/plain", 4)
		_, _ = h.s.staging.put(file.ID, agent.ID, 0, 4, strings.NewReader("GOOD"))
		q := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "account": "test@x", "parent_id": "folder123", "media_upload_id": file.ID}, bearer(key), false)
		if q.code != 202 {
			t.Fatalf("queue %d %s", q.code, q.raw)
		}
		idApr := q.body["approval_id"].(string)
		if err := h.s.store.DecideApproval(idApr, "approved", "synthetic owner"); err != nil {
			t.Fatal(err)
		}
		id = "perm-mallory-2" // different principal, same email
		done := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "approval_id": idApr}, bearer(key), false)
		if uploads != 0 || done.code == 200 {
			t.Fatalf("defect: grantee id change not refused (status=%d uploads=%d)", done.code, uploads)
		}
	})
	t.Run("empty-later-page-refused", func(t *testing.T) {
		h := newHarness(t)
		seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
			switch r.Method {
			case "GET":
				if strings.Contains(r.URL.Path, "/permissions") {
					if strings.Contains(r.URL.RawQuery, "pageToken=") {
						return fakeResp(r, 200, ``), nil // empty later page (unread continuation)
					}
					return fakeResp(r, 200, `{"permissions":[{"type":"user","role":"reader","emailAddress":"alice@example.invalid"}],"nextPageToken":"p2"}`), nil
				}
				return fakeResp(r, 200, `{"name":"F","driveId":"drive-1"}`), nil
			}
			return fakeResp(r, 500, ""), nil
		})
		key := h.agent("daru6-page2")
		agent := mustAgent(t, h, "daru6-page2")
		file, _ := h.s.staging.start(agent.ID, "f.txt", "text/plain", 4)
		_, _ = h.s.staging.put(file.ID, agent.ID, 0, 4, strings.NewReader("GOOD"))
		q := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "account": "test@x", "parent_id": "folder123", "media_upload_id": file.ID}, bearer(key), false)
		if q.code == 202 {
			t.Fatalf("defect: an empty continuation page was treated as a clean end-of-list: %s", q.raw)
		}
	})
}
