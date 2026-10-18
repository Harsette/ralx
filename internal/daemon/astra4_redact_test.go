package daemon

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAstra4ReproRecoverableEncodedResponses(t *testing.T) {
	secret := "SyntheticResponseCredential0123456789"
	for _, format := range []string{"percent_all_bytes", "gzip_base64", "split_json", "pem_crlf"} {
		t.Run(format, func(t *testing.T) {
			h := newHarness(t)
			putHostCred(t, h, "svc", secret, []string{"api.example"})
			payload := ""
			expected := secret
			decode := func(s string) (string, error) { return s, nil }
			switch format {
			case "percent_all_bytes":
				for _, b := range []byte(secret) {
					payload += fmt.Sprintf("%%%02X", b)
				}
				decode = url.QueryUnescape
			case "gzip_base64":
				var b bytes.Buffer
				w := gzip.NewWriter(&b)
				// Repetition forces compressed DEFLATE blocks; a tiny one-off
				// string may be stored verbatim inside gzip and caught incidentally.
				_, _ = w.Write([]byte(strings.Repeat(secret, 64)))
				_ = w.Close()
				payload = base64.StdEncoding.EncodeToString(b.Bytes())
				decode = func(s string) (string, error) {
					b, e := base64.StdEncoding.DecodeString(s)
					if e != nil {
						return "", e
					}
					r, e := gzip.NewReader(bytes.NewReader(b))
					if e != nil {
						return "", e
					}
					defer r.Close()
					out, e := io.ReadAll(r)
					if e != nil {
						return "", e
					}
					if string(out) != strings.Repeat(secret, 64) {
						return "", fmt.Errorf("decompressed bytes changed")
					}
					return string(out[:len(secret)]), nil
				}
			case "split_json":
				b, _ := json.Marshal(map[string]string{"first": secret[:18], "second": secret[18:]})
				payload = string(b)
				decode = func(s string) (string, error) {
					var m map[string]string
					e := json.Unmarshal([]byte(s), &m)
					return m["first"] + m["second"], e
				}
			case "pem_crlf":
				// Synthetic PEM-shaped value, not a real private key.
				expected = "-----BEGIN PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("synthetic-key-material", 8))) + "\n-----END PRIVATE KEY-----"
				putHostCred(t, h, "pem", expected, nil)
				payload = strings.ReplaceAll(expected, "\n", "\r\n")
				decode = func(s string) (string, error) { return strings.ReplaceAll(s, "\r\n", "\n"), nil }
			}
			h.s.ext = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) { return fakeResp(r, 200, payload), nil })}
			// http.request is held for approval (Astra A10 gate-all); run it through
			// the approval path, which exercises the same response redaction.
			res, errStr := execHTTP(t, h, h.agent("encoded"), map[string]any{"url": "https://api.example/fixture", "headers": []string{"Authorization: Bearer {{svc}}"}})
			if errStr != "" {
				t.Fatalf("call: %s", errStr)
			}
			// Fixed: the response reconstructs the credential under this transform,
			// so it is withheld whole and nothing decodes back to the secret.
			body, _ := res["body"].(string)
			recovered, _ := decode(body)
			if recovered == expected {
				t.Fatalf("secret recovered from the response (%s)", format)
			}
		})
	}
}

func TestAstra4ReproDriveEncodedFlushBoundary(t *testing.T) {
	h := newHarness(t)
	secret := "SyntheticStreamCredential0123456789"
	putHostCred(t, h, "svc", secret, nil)
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("X", 790000) + secret + "\n"))
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("alt") == "media" {
			return fakeResp(r, 200, encoded), nil
		}
		return fakeResp(r, 200, `{"name":"fixture.b64","mimeType":"text/plain"}`), nil
	})
	r := h.do("GET", "/v1/drive/files/abcdefghijk/content", nil, bearer(h.agent("stream-boundary")), false)
	if r.code != 200 {
		t.Fatalf("download: %d", r.code)
	}
	// Fixed: the file is buffered and deep-scanned before release; since it
	// reconstructs the secret it is withheld, so it no longer base64-decodes to it.
	if recovered, e := base64.StdEncoding.DecodeString(string(r.raw)); e == nil && bytes.Contains(recovered, []byte(secret)) {
		t.Fatal("encoded Drive stream still reconstructs the secret")
	}
	if bytes.Contains(r.raw, []byte(secret)) {
		t.Fatal("raw secret leaked in the Drive stream")
	}
}

func TestAstra4ReproHTTPAllowedHostEffectfulGet(t *testing.T) {
	h := newHarness(t)
	putHostCred(t, h, "svc", "synthetic-http-selector-key-0123456789", []string{"api.example"})
	deleted := false
	h.s.ext = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		deleted = r.Method == "GET" && r.URL.Query().Get("action") == "delete" && r.Header.Get("Authorization") != ""
		return fakeResp(r, 200, `{"deleted":true}`), nil
	})}
	r := h.do("POST", "/v1/actions/http.request", map[string]any{"args": map[string]any{"url": "https://api.example/items/1?action=delete", "headers": []string{"Authorization: Bearer {{svc}}"}}}, bearer(h.agent("get-selector")), false)
	// Fixed: a GET carrying a query string is held for approval (a query can be an
	// effectful selector), so it never reaches the endpoint unapproved.
	if r.code != 202 {
		t.Fatalf("effectful-query GET should be held: %d %s", r.code, r.raw)
	}
	if deleted {
		t.Fatal("effectful GET reached the endpoint without approval")
	}
}
