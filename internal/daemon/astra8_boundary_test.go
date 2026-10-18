package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/actions"
	"github.com/Harsette/ralx/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAstra8FixSerializedBoundary(t *testing.T) {
	for _, kind := range []string{"json", "callback", "header", "sse-split", "sse-multiline", "sse-incomplete", "safe-stream", "safe-binary"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t)
			const secret = "SyntheticBoundaryCredential0123456789"
			h.s.red.Add("fixture", secret)
			w := httptest.NewRecorder()
			handler := h.s.agentOutput(http.HandlerFunc(func(out http.ResponseWriter, _ *http.Request) {
				switch kind {
				case "json":
					out.Header().Set("Content-Type", "application/json")
					_, _ = out.Write([]byte(`{"result":"` + secret + `","ok":true}`))
				case "callback":
					_, _ = out.Write([]byte("<title>" + secret + "</title>ordinary callback"))
				case "header":
					out.Header().Set("X-Fixture", secret)
					_, _ = out.Write([]byte("ordinary"))
				case "safe-binary":
					out.Header().Set("Content-Type", "application/octet-stream")
					_, _ = out.Write([]byte{0, 1, 2, 3, 255})
				default:
					out.Header().Set("Content-Type", "text/event-stream")
					if kind == "safe-stream" {
						_, _ = out.Write([]byte("data: {\"ok\":true}\n\n"))
						out.(http.Flusher).Flush()
						if w.Body.Len() == 0 {
							t.Fatal("complete frame did not stream")
						}
						_, _ = out.Write([]byte("data: {\"next\":true}\r\n\r\n"))
						return
					}
					_, _ = out.Write([]byte("data: " + secret[:17]))
					out.(http.Flusher).Flush()
					if w.Body.Len() != 0 {
						t.Fatal("partial SSE frame released")
					}
					if kind == "sse-incomplete" {
						return
					}
					if kind == "sse-multiline" {
						_, _ = out.Write([]byte("\ndata: "))
					}
					_, _ = out.Write([]byte(secret[17:] + "\n\n"))
				}
			}))
			handler.ServeHTTP(w, httptest.NewRequest("GET", "http://localhost/fixture", nil))
			if strings.Contains(w.Body.String()+w.Header().Get("X-Fixture"), secret) {
				t.Fatal("serialized boundary leaked")
			}
			if kind == "json" && !json.Valid(w.Body.Bytes()) {
				t.Fatal("rewritten JSON invalid")
			}
			if kind == "safe-stream" && !strings.Contains(w.Body.String(), `"next":true`) {
				t.Fatal("second legitimate event lost")
			}
			if kind == "safe-binary" && string(w.Body.Bytes()) != string([]byte{0, 1, 2, 3, 255}) {
				t.Fatal("ordinary binary changed")
			}
		})
	}
}

func TestAstra8FixMCPMetadataAndErrors(t *testing.T) {
	l := newLiveHub(t)
	const secret = "SyntheticSDKMetadataCredential0123456789"
	l.s.red.Add("fixture", secret)
	l.s.cfg.Version = secret
	_ = l.s.reg.Add(&actions.Action{Name: "fixture.read", Risk: actions.Read, Description: secret, Native: func(context.Context, actions.Env, map[string]any) (any, error) {
		return map[string]any{"ok": true}, nil
	}})
	_, key, err := l.s.store.CreateAgent("fixture", store.Policy{Allow: []string{"fixture.read"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "synthetic", Version: "1"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: l.ip + "/mcp", HTTPClient: &http.Client{Transport: bearerRT{tok: key}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tools)
	if strings.Contains(string(b), secret) || !strings.Contains(string(b), "fixture_read") {
		t.Fatal("SDK catalog leaked or legitimate tool lost")
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "fixture_read", Arguments: map[string]any{}})
	if err != nil || !strings.Contains(textOf(res), `"ok": true`) {
		t.Fatal("legitimate MCP call failed", err)
	}
	h := newHarness(t)
	h.s.red.Add("fixture", secret)
	res, err = h.s.mcpTool(func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return nil, errors.New(secret)
	})(ctx, nil)
	b, _ = json.Marshal(res)
	if err != nil || strings.Contains(string(b), secret) || !res.IsError {
		t.Fatal("MCP Go error bypassed boundary")
	}
}

func TestAstra8FixShortAndWhitespaceCredentials(t *testing.T) {
	for _, secret := range []string{"!", "p4ssXYZ", "p4ssXYZ8", "  raw fixture value  ", "A\tB"} {
		t.Run(secret, func(t *testing.T) {
			h := newHarness(t)
			h.s.red.Add("fixture", secret)
			w := httptest.NewRecorder()
			h.s.writeJSONAgent(w, 200, map[string]any{"echo": secret})
			if !json.Valid(w.Body.Bytes()) || strings.Contains(w.Body.String(), secret) {
				t.Fatal("literal supported credential released or JSON damaged")
			}
			w = httptest.NewRecorder()
			h.s.writeJSONAgent(w, 200, map[string]any{"ok": true})
			if !json.Valid(w.Body.Bytes()) || !strings.Contains(w.Body.String(), `"ok":true`) {
				t.Fatal("benign control lost")
			}
		})
	}
}

func TestAstra8FixHTTPApprovalLegitimateAndAttachmentRace(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "replace-at-attachment"}[replace], func(t *testing.T) {
			h := newHarness(t)
			const secret = "SyntheticApprovedCredential0123456789"
			putHostCred(t, h, "svc", secret, []string{"api.example"})
			calls := 0
			h.s.ext = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("X-Key") != secret {
					t.Fatal("wrong credential")
				}
				return fakeResp(r, 200, `{"ok":true}`), nil
			})}
			id := astra6Approve(t, h, h.agent("fixture"), "http.request", map[string]any{"method": "POST", "url": "https://api.example/path", "headers": []string{"X-Key: {{svc.token}}"}})
			if replace {
				a, _ := h.s.reg.Get("http.request")
				original := a.Native
				a.Native = func(ctx context.Context, e actions.Env, args map[string]any) (any, error) {
					// Runs after runApproval's precheck and before the shared snapshot read.
					putHostCred(t, h, "svc", "SyntheticReplacementCredential987654321", []string{"api.example"})
					return original(ctx, e, args)
				}
			}
			h.s.runApproval(id)
			ap, err := h.s.store.GetApproval(id)
			if err != nil {
				t.Fatal(err)
			}
			if replace {
				if calls != 0 || ap.Status != "failed" {
					t.Fatal("attachment race dispatched")
				}
			} else if calls != 1 || ap.Status != "executed" {
				t.Fatal("unchanged approval failed")
			}
		})
	}
}

func TestAstra8FixShortSerializedDrive(t *testing.T) {
	h := newHarness(t)
	const secret = "A\tB"
	putHostCred(t, h, "svc", secret, nil)
	seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("alt") == "media" {
			return fakeResp(r, 200, `["A\tB"]`), nil
		}
		return fakeResp(r, 200, `{"name":"ordinary","mimeType":"application/json"}`), nil
	})
	res := h.do("GET", "/v1/drive/files/abcdefghijk/content", nil, bearer(h.agent("short-drive")), false)
	var echoed []string
	if json.Unmarshal(res.raw, &echoed) == nil && len(echoed) > 0 && echoed[0] == secret {
		t.Fatal("download released a short JSON-escaped secret")
	}
}

func TestAstra8FixPublicExpiryBookkeeping(t *testing.T) {
	h := newHarness(t)
	// Existing OAuth bookkeeping after a 401 must not become a short credential
	// during startup registration. Test the actual AllSecretValues feed.
	if _, err := h.s.store.PutCredential("mcp:expiry", "mcp_server", "mcp", "", nil, map[string]string{"access_token": "SyntheticExpiryAccess0123456789", "expires_at": "0"}); err != nil {
		t.Fatal(err)
	}
	all, err := h.s.store.AllSecretValues()
	if err != nil {
		t.Fatal(err)
	}
	h.s.red.Replace(all)
	h.s.cfg.Version = "0.1.0-dev"
	res := h.do("GET", "/healthz", nil, nil, false)
	if !strings.Contains(string(res.raw), `"ok":true`) {
		t.Fatal("public bookkeeping blocked benign startup output")
	}
	if h.s.red.ShortLiteral("0") {
		t.Fatal("expiry bookkeeping registered as credential")
	}
}

func TestAstra8FixApprovedDriveUploadReplacement(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "replaced"}[replace], func(t *testing.T) {
			h := newHarness(t)
			uploads := 0
			seedGoogle(t, h, func(r *http.Request) (*http.Response, error) {
				switch r.Method {
				case "GET":
					if strings.Contains(r.URL.Path, "/permissions") {
						return fakeResp(r, 200, `{"permissions":[{"type":"user","role":"reader","emailAddress":"recipient@example.invalid"}]}`), nil
					}
					return fakeResp(r, 200, `{"name":"fixture","shared":true,"ownedByMe":true}`), nil
				case "POST":
					res := fakeResp(r, 200, "")
					res.Header.Set("Location", "https://www.googleapis.com/upload/session/fixture")
					return res, nil
				case "PUT":
					uploads++
					return fakeResp(r, 200, `{"id":"fixture-result"}`), nil
				}
				return nil, errors.New("unexpected fake method")
			})
			key := h.agent("drive-binding")
			agent := mustAgent(t, h, "drive-binding")
			file, err := h.s.staging.start(agent.ID, "fixture.txt", "text/plain", 4)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.s.staging.put(file.ID, agent.ID, 0, 4, strings.NewReader("GOOD")); err != nil {
				t.Fatal(err)
			}
			queued := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "account": "test@x", "parent_id": "fixturefolder123", "media_upload_id": file.ID}, bearer(key), false)
			if queued.code != 202 {
				t.Fatal("shared upload not held", string(queued.raw))
			}
			id := queued.body["approval_id"].(string)
			if err := h.s.store.DecideApproval(id, "approved", "synthetic owner"); err != nil {
				t.Fatal(err)
			}
			if replace {
				if _, err := h.s.store.PutCredential("google:test@x", "oauth_token", "google", "test@x", map[string]any{"email": "test@x"}, map[string]string{"refresh_token": "SyntheticReplacementGoogle9876543210"}); err != nil {
					t.Fatal(err)
				}
			}
			result := h.do("POST", "/v1/uploads", map[string]any{"target": "drive", "approval_id": id}, bearer(key), false)
			if replace {
				if result.code == 200 || uploads != 0 {
					t.Fatal("replaced shared-upload account dispatched")
				}
			} else if result.code != 200 || uploads != 1 {
				t.Fatal("unchanged shared upload failed", string(result.raw))
			}
		})
	}
}
