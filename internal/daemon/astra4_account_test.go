package daemon

// Astra4 probes, inverted: each asserts the FIX. Offline, synthetic, no sockets.
import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Harsette/ralx/internal/store"
)

func TestAstra4ReproNamedGoogleApprovalChangesDefaultAccount(t *testing.T) {
	cases := []struct {
		action, service string
		args            map[string]any
	}{
		{"gmail.send", "gmail", map[string]any{"to": []string{"recipient@example.invalid"}, "subject": "fixture", "body": "synthetic message"}},
		{"drive.trash", "drive", map[string]any{"file_id": "fixturefile123"}},
		{"drive.share", "drive", map[string]any{"file_id": "fixturefile123", "email": "recipient@example.invalid"}},
		{"drive.create_folder", "drive", map[string]any{"name": "fixture", "parent_id": "fixturefolder123"}},
		{"youtube.upload", "youtube", map[string]any{"title": "fixture", "privacy": "public"}},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			h := newHarness(t)
			var calls []string
			seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
				calls = append(calls, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
				if tc.action == "youtube.upload" && r.Method == "POST" {
					res := fakeResp(r, 200, "")
					res.Header.Set("Location", "https://www.googleapis.com/upload/session/fixture")
					return res, nil
				}
				return fakeResp(r, 200, `{"id":"fixture-result"}`), nil
			})
			base := h.s.google.HTTP.Transport
			h.s.google.HTTP.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "oauth2.googleapis.com" {
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if r.Form.Get("refresh_token") == "astra4-synthetic-account-b-refresh" {
						return fakeResp(r, 200, `{"access_token":"astra4-synthetic-account-b-access","expires_in":3600}`), nil
					}
					return fakeResp(r, 200, `{"access_token":"astra4-synthetic-account-a-access","expires_in":3600}`), nil
				}
				return base.RoundTrip(r)
			})
			if _, err := h.s.store.PutCredential("google:other@x", "oauth_token", "google", "other@x", map[string]any{"email": "other@x", "status": "ok"}, map[string]string{"refresh_token": "astra4-synthetic-account-b-refresh"}); err != nil {
				t.Fatal(err)
			}
			key := h.agent("astra4-account")
			if tc.action == "youtube.upload" {
				a := mustAgent(t, h, "astra4-account")
				f, err := h.s.staging.start(a.ID, "fixture.mp4", "video/mp4", 4)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := h.s.staging.put(f.ID, a.ID, 0, 4, strings.NewReader("GOOD")); err != nil {
					t.Fatal(err)
				}
				tc.args["media_upload_id"] = f.ID
			}
			if got := h.s.google.DefaultAccountFor(tc.service); got != "test@x" {
				t.Fatalf("initial default = %q", got)
			}
			r := h.do("POST", "/v1/actions/"+tc.action, map[string]any{"args": tc.args}, bearer(key), false)
			if r.code != 202 || len(calls) != 0 {
				t.Fatalf("queue: code=%d calls=%v", r.code, calls)
			}
			id := r.body["approval_id"].(string)
			ap, err := h.s.store.GetApproval(id)
			if err != nil {
				t.Fatal(err)
			}
			var approved map[string]any
			if err := json.Unmarshal(ap.Args, &approved); err != nil {
				t.Fatal(err)
			}
			// Fixed: the account is resolved and bound at approval time.
			if approved["account"] != "test@x" {
				t.Fatalf("approved account not bound to A: %v", approved["account"])
			}
			if err := h.s.store.DecideApproval(id, "approved", "synthetic owner"); err != nil {
				t.Fatal(err)
			}
			// Change the default to B after approval; the bound account A must win.
			if err := h.s.google.SetDefaultFor("other@x", []string{tc.service}); err != nil {
				t.Fatal(err)
			}
			h.s.runApproval(id)
			ap, err = h.s.store.GetApproval(id)
			if err != nil || ap.Status != "executed" || len(calls) == 0 {
				t.Fatalf("execution: approval=%#v calls=%v error=%v", ap, calls, err)
			}
			for _, call := range calls {
				if strings.Contains(call, "Bearer astra4-synthetic-account-b-access") {
					t.Fatalf("executed with the changed default account B: %s", call)
				}
				if !strings.HasSuffix(call, "Bearer astra4-synthetic-account-a-access") {
					t.Fatalf("call did not use the bound account A: %s", call)
				}
			}
		})
	}
}

func TestAstra4ReproDriveChunkIgnoresNarrowedPolicy(t *testing.T) {
	h := newHarness(t)
	puts := 0
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			res := fakeResp(r, 200, "")
			res.Header.Set("Location", "https://www.googleapis.com/upload/session/fixture")
			return res, nil
		}
		if r.Method == "PUT" {
			data, err := io.ReadAll(r.Body)
			if err != nil || string(data) != "GOOD" {
				t.Fatalf("unexpected bytes %q, error %v", data, err)
			}
			puts++
			return fakeResp(r, 200, `{"id":"fixture-result"}`), nil
		}
		t.Fatalf("unexpected fake request %s", r.Method)
		return nil, nil
	})
	key := h.agent("astra4-policy")
	r := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "name": "fixture", "size": 4}, bearer(key), false)
	if r.code != 200 {
		t.Fatalf("start: %d %s", r.code, r.raw)
	}
	id := r.body["upload_id"].(string)
	a := mustAgent(t, h, "astra4-policy")
	if err := h.s.store.SetAgentPolicy(a.ID, store.Policy{Deny: []string{"drive.upload"}}); err != nil {
		t.Fatal(err)
	}
	denied := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "name": "fixture", "size": 4}, bearer(key), false)
	if denied.code != 403 {
		t.Fatalf("new upload should prove deny active: %d", denied.code)
	}
	req := httptest.NewRequest("PUT", "http://localhost:7399/v1/uploads/"+id, strings.NewReader("GOOD"))
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-RalX-Offset", "0")
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, req)
	// Fixed: the chunk re-checks the narrowed policy, so the in-flight upload is
	// refused too, not just new starts.
	if w.Code != 403 || puts != 0 {
		t.Fatalf("chunk should be refused after drive.upload was denied: status=%d uploads=%d", w.Code, puts)
	}
}

func TestAstra4ReproApprovedDriveUploadIgnoresChangedRecipients(t *testing.T) {
	h := newHarness(t)
	recipient := "alice@example.invalid"
	lookups, uploads := 0, 0
	var sentTo string
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		switch r.Method {
		case "GET":
			if strings.Contains(r.URL.Path, "/permissions") {
				lookups++ // count permissions.list (the real audience source)
				return fakeResp(r, 200, `{"permissions":[{"type":"user","role":"reader","emailAddress":"`+recipient+`"}]}`), nil
			}
			return fakeResp(r, 200, `{"name":"F","shared":true,"ownedByMe":true}`), nil
		case "POST":
			res := fakeResp(r, 200, "")
			res.Header.Set("Location", "https://www.googleapis.com/upload/session/fixture")
			return res, nil
		case "PUT":
			data, err := io.ReadAll(r.Body)
			if err != nil || string(data) != "GOOD" {
				t.Fatalf("unexpected staged bytes %q, error %v", data, err)
			}
			uploads++
			sentTo = recipient
			return fakeResp(r, 200, `{"id":"fixture-result"}`), nil
		}
		t.Fatalf("unexpected fake method %s", r.Method)
		return nil, nil
	})
	key := h.agent("astra4-recipients")
	a := mustAgent(t, h, "astra4-recipients")
	f, err := h.s.staging.start(a.ID, "fixture.txt", "text/plain", 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.staging.put(f.ID, a.ID, 0, 4, strings.NewReader("GOOD")); err != nil {
		t.Fatal(err)
	}
	r := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "account": "test@x", "parent_id": "fixturefolder123", "media_upload_id": f.ID}, bearer(key), false)
	if r.code != 202 || lookups != 1 {
		t.Fatalf("queue: status=%d lookups=%d", r.code, lookups)
	}
	id := r.body["approval_id"].(string)
	ap, err := h.s.store.GetApproval(id)
	if err != nil || !strings.Contains(ap.Summary, "alice@example.invalid") {
		t.Fatalf("approval failed to show original recipient: %#v %v", ap, err)
	}
	// Real setup, challenge and software passkey assertion through the handler.
	h.setupPasskey()
	approved := h.do("POST", "/admin/api/approvals/"+id+"/approve", map[string]any{"assertion": h.stepUp("approve:" + id)}, h.browser(), false)
	if approved.code != 200 {
		t.Fatalf("passkey approval: %d %s", approved.code, approved.raw)
	}
	recipient = "bob@example.invalid"
	done := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "approval_id": id}, bearer(key), false)
	// Fixed: finish rechecks the destination recipients (a 2nd lookup); since they
	// changed Alice->Bob it is refused and nothing is uploaded.
	if done.code == 200 {
		t.Fatalf("upload finished despite changed recipients: %s", done.raw)
	}
	if uploads != 0 {
		t.Fatalf("bytes uploaded despite changed recipients: %d", uploads)
	}
	if lookups != 2 {
		t.Fatalf("recipients were not rechecked at finish: lookups=%d", lookups)
	}
	_ = sentTo
}
