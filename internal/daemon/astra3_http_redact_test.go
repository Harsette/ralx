package daemon

// Astra3 probes, inverted: each asserts the FIX.
// Every credential is synthetic and every outbound request uses a fake transport.
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAstra3ReproHTTPReadExemptionOverrideBody(t *testing.T) {
	// Two independent cases, so removing EITHER gate (body OR query) fails a test.
	cases := []struct {
		name string
		args map[string]any
	}{
		{"body_only", map[string]any{"method": "GET", "url": "https://api.example/items/1",
			"headers": []string{"Authorization: Bearer {{svc}}"}, "body": "private=synthetic-internal-data"}},
		{"query_only", map[string]any{"method": "GET", "url": "https://api.example/items/1?_method=DELETE",
			"headers": []string{"Authorization: Bearer {{svc}}"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			putHostCred(t, h, "svc", "synthetic-http-credential-0123456789", []string{"api.example"})
			var called bool
			h.s.ext = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
				called = true
				return fakeResp(r, 200, `{ "deleted": true }`), nil
			})}
			r := h.do("POST", "/v1/actions/http.request", map[string]any{"args": tc.args}, bearer(h.agent("http-"+tc.name)), false)
			// Fixed: a read carrying a body, or a query string, is held and never
			// reaches the provider without approval.
			if r.code != 202 {
				t.Fatalf("%s read should be held: %d %s", tc.name, r.code, r.raw)
			}
			if called {
				t.Fatalf("%s request reached the provider without approval", tc.name)
			}
		})
	}
}

func astra3WrappedSecret(secret string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("X", 30) + secret + "\n"))
	return encoded[:60] + "\n" + encoded[60:]
}

func TestAstra3ReproWrappedEncodedResponse(t *testing.T) {
	h := newHarness(t)
	secret := "synthetic-wrapped-value-0123456789"
	putHostCred(t, h, "svc", secret, []string{"api.example"})
	wrapper, _ := json.Marshal(map[string]string{"encoding": "base64", "content": astra3WrappedSecret(secret)})
	h.s.ext = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		return fakeResp(r, 200, string(wrapper)), nil
	})}
	// http.request is held for approval (Astra A10 gate-all); run it through the
	// approval path, which exercises the same response redaction.
	res, errStr := execHTTP(t, h, h.agent("wrapped"), map[string]any{
		"url": "https://api.example/file", "headers": []string{"Authorization: Bearer {{svc}}"},
	})
	if errStr != "" {
		t.Fatalf("call failed: %s", errStr)
	}
	// Fixed: the response reconstructs the secret under a line-wrapped base64, so
	// it is withheld whole — the agent can recover nothing.
	raw, _ := json.Marshal(res)
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("raw secret leaked in the response")
	}
	body, _ := res["body"].(string)
	var content map[string]string
	if err := json.Unmarshal([]byte(body), &content); err == nil {
		if decoded, derr := base64.StdEncoding.DecodeString(content["content"]); derr == nil && bytes.Contains(decoded, []byte(secret)) {
			t.Fatal("wrapped secret still recoverable from the response")
		}
	}
}

func TestAstra3ReproEncodedDriveDownload(t *testing.T) {
	h := newHarness(t)
	secret := "synthetic-drive-value-0123456789"
	putHostCred(t, h, "svc", secret, nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("X" + secret + "\n"))
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("alt") == "media" {
			return fakeResp(r, 200, encoded), nil
		}
		return fakeResp(r, 200, `{"name":"fixture.txt","mimeType":"text/plain"}`), nil
	})
	r := h.do("GET", "/v1/drive/files/abcdefghijk/content", nil, bearer(h.agent("encoded-drive")), false)
	if r.code != 200 {
		t.Fatalf("download failed: %d", r.code)
	}
	// Fixed: the Drive stream's encoded container that decodes to a vault secret
	// is scrubbed, so it isn't recoverable.
	if decoded, err := base64.StdEncoding.DecodeString(string(r.raw)); err == nil && bytes.Contains(decoded, []byte(secret)) {
		t.Fatal("encoded Drive secret still recoverable")
	}
	if bytes.Contains(r.raw, []byte(secret)) {
		t.Fatal("raw secret leaked in the Drive stream")
	}
}

func TestAstra3ReproGoogleUploadResultLeak(t *testing.T) {
	h := newHarness(t)
	secret := "synthetic-result-credential-0123456789"
	putHostCred(t, h, "svc", secret, nil)
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			res := fakeResp(r, 200, "")
			res.Header.Set("Location", "https://upload.example/session")
			return res, nil
		}
		return fakeResp(r, 200, `{"id":"file","name":"`+secret+`"}`), nil
	})
	key := h.agent("upload-result")
	r := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "name": "fixture", "size": 1}, bearer(key), false)
	id, _ := r.body["upload_id"].(string)
	if r.code != 200 || id == "" {
		t.Fatal("could not start synthetic upload")
	}
	req := httptest.NewRequest("PUT", "http://localhost:7399/v1/uploads/"+id, strings.NewReader("A"))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-RalX-Offset", "0")
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, req)
	// Fixed: the upload result is redacted on the PUT response and on the cached
	// GET status.
	if w.Code != 200 {
		t.Fatalf("chunk upload failed: %d", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), []byte(secret)) {
		t.Fatal("upload result leaked the secret on the PUT response")
	}
	status := h.do("GET", "/v1/uploads/"+id, nil, bearer(key), false)
	if status.code != 200 {
		t.Fatalf("status check should succeed: %d %s", status.code, status.raw)
	}
	if bytes.Contains(status.raw, []byte(secret)) {
		t.Fatal("cached upload status leaked the secret")
	}
}

func TestAstra3ReproGoogleSessionURLCredentialEgress(t *testing.T) {
	h := newHarness(t)
	var captured string
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			res := fakeResp(r, 200, "")
			res.Header.Set("Location", "https://attacker.example/session")
			return res, nil
		}
		if r.URL.Host == "attacker.example" {
			captured = r.Header.Get("Authorization")
		}
		return fakeResp(r, 200, `{"id":"file"}`), nil
	})
	// Prove the host binding itself (not just the scheme): with the host check on,
	// an https Location on a non-googleapis host is rejected at StartUpload, so the
	// bearer is never sent there and no chunk is ever uploaded.
	h.s.google.TrustAnyUploadHost = false
	u, err := h.s.google.StartUpload(context.Background(), "drive", "test@x", "fixture", 1, "text/plain", map[string]any{"name": "fixture"})
	if err == nil {
		// Should not happen; if it did, prove the bearer still never egresses.
		if _, perr := h.s.google.PutChunk(context.Background(), u.ID, "fixture", 0, 1, strings.NewReader("A")); perr == nil {
			t.Fatal("an attacker-controlled upload Location was accepted and a chunk was sent")
		}
		t.Fatal("an attacker-controlled upload Location was accepted")
	}
	if captured != "" {
		t.Fatal("bearer was sent to the supplied upload location")
	}
}

func TestAstra3ReproGoogleRefreshRedirect(t *testing.T) {
	h := newHarness(t)
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) { return fakeResp(r, 200, `{}`), nil })
	clientSecret := "synthetic-client-secret-0123456789"
	refresh := "synthetic-refresh-token-0123456789"
	if err := h.s.store.UpdateFields("google-oauth-client", map[string]string{"client_secret": clientSecret}); err != nil {
		t.Fatal(err)
	}
	if err := h.s.store.UpdateFields("google:test@x", map[string]string{"refresh_token": refresh}); err != nil {
		t.Fatal(err)
	}
	var captured url.Values
	// Preserve the broker's default redirect policy; replace only network I/O.
	h.s.google.HTTP.Transport = rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "oauth2.googleapis.com" {
			res := fakeResp(r, 307, "")
			res.Header.Set("Location", "http://attacker.example/token")
			return res, nil
		}
		b, _ := io.ReadAll(r.Body)
		captured, _ = url.ParseQuery(string(b))
		return fakeResp(r, 200, `{"access_token":"synthetic-access","expires_in":3600}`), nil
	})
	// Fixed: the token client doesn't follow the 307, so the refresh token and
	// client secret are never replayed to the redirect target.
	if _, _, err := h.s.google.AccessToken(context.Background(), "test@x"); err == nil {
		t.Fatal("the token endpoint redirect was followed")
	}
	if captured.Get("refresh_token") == refresh || captured.Get("client_secret") == clientSecret {
		t.Fatal("token form was replayed to the redirect target")
	}
}
