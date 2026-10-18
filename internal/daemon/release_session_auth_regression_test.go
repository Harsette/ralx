package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/browserlogin"
	"github.com/Harsette/ralx/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type reviewR3Bearer struct{ key, scheme string }

func (b reviewR3Bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header.Set("Authorization", b.scheme+b.key)
	return http.DefaultTransport.RoundTrip(copy)
}

func TestRCProbeReviewR3MCPAuthScheme(t *testing.T) {
	if os.Getenv("RALX_BROWSER_TESTS") != "1" {
		t.Skip("browser fixtures need heavy lock")
	}
	const token = "SyntheticReviewMCPToken-42"
	l := newLiveHub(t)
	agent, key, err := l.s.store.CreateAgent("review-session-owner", store.Policy{Allow: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/signin" {
			fmt.Fprint(w, `<form method="post" action="/account"><input name="username"><input type="password"><button>Sign in</button></form>`)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: token, HttpOnly: true, Path: "/"})
		fmt.Fprint(w, `<h1 id="account">Account</h1>`)
	}))
	defer app.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	signed, _ := l.s.browser.SignIn(ctx, agent.ID, browserlogin.Request{Origin: app.URL, URL: app.URL + "/signin", SuccessSelector: "#account"}, "fixture@example.test", "SyntheticMCPPassword-42")
	if signed.Status != "signed_in" {
		t.Fatal(signed)
	}
	approval := &store.Approval{AgentID: agent.ID, AgentName: agent.Name, Action: "test.fixture", Args: json.RawMessage(`{}`), Summary: "Synthetic stored result", Origin: "key"}
	if err = l.s.store.CreateApproval(approval); err != nil {
		t.Fatal(err)
	}
	result, _ := json.Marshal(map[string]string{"reflected_cookie": token})
	if err = l.s.store.FinishApproval(approval.ID, result, ""); err != nil {
		t.Fatal(err)
	}
	for _, scheme := range []string{"Bearer ", "bearer ", "BEARER ", "Bearer\t"} {
		t.Run(strings.TrimSpace(scheme), func(t *testing.T) {
			client := mcp.NewClient(&mcp.Implementation{Name: "review-r3", Version: "1"}, nil)
			session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: l.ip + "/mcp", HTTPClient: &http.Client{Transport: reviewR3Bearer{key, scheme}}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			out, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "ralx_approval", Arguments: map[string]any{"approval_id": approval.ID}})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(out)
			t.Logf("scheme=%q token_leaked=%v", scheme, strings.Contains(string(raw), token))
			if strings.Contains(string(raw), token) {
				t.Errorf("owning agent received observed session token through valid alternate Bearer syntax: %s", raw)
			}
		})
	}
}
