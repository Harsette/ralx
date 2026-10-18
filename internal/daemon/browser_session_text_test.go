package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Harsette/ralx/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestBrowserAccountTextScrubsObservedSessionValues(t *testing.T) {
	if os.Getenv("RALX_BROWSER_TESTS") != "1" {
		t.Skip("set RALX_BROWSER_TESTS=1 under shared heavy lock")
	}
	values := []string{"SyntheticHttpOnlySession-42", "SyntheticLocalStorageToken-42", "SyntheticSessionStorageToken-42", "SyntheticRotatedHttpOnly-42"}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/signup":
			if r.Method == "POST" {
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: values[0], HttpOnly: true, Path: "/"})
				http.Redirect(w, r, "/account", 303)
				return
			}
			fmt.Fprint(w, `<form method="post"><input name="username"><input type="password"><button>Sign up</button></form>`)
		case "/rotate":
			http.SetCookie(w, &http.Cookie{Name: "rotated", Value: values[3], HttpOnly: true, Path: "/"})
			fmt.Fprint(w, values[3])
		default:
			fmt.Fprintf(w, `<h1>Account</h1><div id="tokens">%s %s %s %s</div><script>localStorage.setItem('access_token',%s);sessionStorage.setItem('refresh_token',%s);setTimeout(async()=>{const r=await fetch('/rotate');document.querySelector('#tokens').append(' '+await r.text());window.ready=true},800)</script>`, values[0], values[1], values[2], base64.StdEncoding.EncodeToString([]byte(values[0])), quotedFixture(values[1]), quotedFixture(values[2]))
		}
	}))
	defer app.Close()
	l := newLiveHub(t)
	agent, key, e := l.s.store.CreateAgent("session-text", store.Policy{Allow: []string{"browser.*", "logins.*"}})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "session-text", Version: "1"}, nil)
	session, e := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: l.ip + "/mcp", HTTPClient: &http.Client{Transport: bearerRT{tok: key}}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	call := func(name string, args map[string]any) map[string]any {
		t.Helper()
		res, e := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if e != nil {
			t.Fatal(e)
		}
		out := map[string]any{}
		for _, c := range res.Content {
			if x, ok := c.(*mcp.TextContent); ok {
				json.Unmarshal([]byte(x.Text), &out)
			}
		}
		return out
	}
	created := call("logins_new_test", map[string]any{"origin": app.URL})
	signed := call("browser_sign_up", map[string]any{"login_id": created["login_id"], "url": app.URL + "/signup"})
	if signed["status"] != "signed_in" {
		t.Fatalf("signup: %v", signed)
	}
	time.Sleep(time.Second) // Rotate after session export, before the account read.
	out := call("browser_account_text", map[string]any{"login_id": created["login_id"]})
	raw, _ := json.Marshal(out)
	for _, v := range append(values, base64.StdEncoding.EncodeToString([]byte(values[0]))) {
		if strings.Contains(string(raw), v) {
			t.Fatalf("observed session value entered MCP text: %s", v)
		}
	}
	if out["status"] != "signed_in" || !strings.Contains(fmt.Sprint(out["text"]), "Account") {
		t.Fatalf("lost account text control: %v", out)
	}
	state, e := os.ReadFile(signed["session_file"].(string))
	if e != nil || !strings.Contains(string(state), values[0]) {
		t.Fatal("session file no longer usable")
	}
	// Every ordinary result uses the same output scrubber, including rotated values.
	scrubbed, _ := l.s.agentScrub([]byte(values[3]), agent.ID)
	if strings.Contains(string(scrubbed), values[3]) {
		t.Fatal("session value missing from output scrubber")
	}
	again := call("browser_sign_up", map[string]any{"login_id": created["login_id"], "url": app.URL + "/signup"})
	if again["status"] != "signed_in" {
		t.Fatalf("registered cookies broke a later session export: %v", again)
	}
}
