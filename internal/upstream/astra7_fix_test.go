package upstream

// Astra 7 probe, inverted: an in-flight OAuth refresh of connection A must NOT
// overwrite an owner replacement (B) that lands mid-refresh, and the refreshed A
// credential must never reach B's host. Synthetic values, fake transport; no sockets.
import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAstra7FixRefreshDoesNotOverwriteReplacement(t *testing.T) {
	m := astra2Manager(t)
	const aAccess = "SyntheticRefreshedAccountACredential012345"
	const aRefresh = "SyntheticAccountARefreshCredential012345"
	const bAccess = "SyntheticAccountBCredential9876543210"
	const bRefresh = "SyntheticAccountBRefreshCredential987654"
	oldMeta := map[string]any{"url": "https://first.example/mcp", "auth": "oauth", "gen": "generation-a", "client_id": "synthetic-a", "token_endpoint": "https://first.example/token", "resource": "https://first.example/mcp"}
	_, err := m.Store.PutCredential("mcp:demo", "mcp_server", "mcp", "fixture", oldMeta, map[string]string{"access_token": "SyntheticExpiredCredential0123456789", "refresh_token": aRefresh, "expires_at": "0"})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := m.Store.GetCredential("mcp:demo")
	af, _ := m.Store.Secret("mcp:demo")
	// The old session's authRT is pinned to A's connection-generation fingerprint.
	oldRT := &authRT{m: m, name: "demo", conf: confOf(c), genfp: connGen(c, af)}
	tokenCalls := 0
	sentToSecond := ""
	m.Transport = astra2RT(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			tokenCalls++
			if r.URL.Host != "first.example" {
				t.Fatal("refresh hit the wrong token endpoint")
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.PostForm.Get("refresh_token") != aRefresh {
				t.Fatal("refresh did not use A's refresh token")
			}
			// Owner reconnect completes while A's refresh request is in flight.
			newMeta := map[string]any{"url": "https://second.example/mcp", "auth": "oauth", "gen": "generation-b", "client_id": "synthetic-b", "token_endpoint": "https://second.example/token", "resource": "https://second.example/mcp"}
			if _, err := m.Store.PutCredential("mcp:demo", "mcp_server", "mcp", "replacement", newMeta, map[string]string{"access_token": bAccess, "refresh_token": bRefresh, "expires_at": fmt.Sprint(time.Now().Add(time.Hour).Unix())}); err != nil {
				t.Fatal(err)
			}
			return astra2Response(r, 200, `{"access_token":"`+aAccess+`","refresh_token":"`+aRefresh+`","expires_in":3600}`), nil
		}
		if r.URL.Host == "second.example" {
			sentToSecond = r.Header.Get("Authorization")
		}
		return astra2Response(r, 200, "{}"), nil
	})
	req, _ := http.NewRequest("POST", "https://first.example/mcp", strings.NewReader("{}"))
	// The refresh runs once, then the atomic CAS refuses to overwrite B, so RoundTrip
	// returns an error rather than attaching A's refreshed token.
	if res, _ := oldRT.RoundTrip(req); res != nil {
		res.Body.Close()
	}
	if tokenCalls != 1 {
		t.Fatalf("expected exactly one refresh, got %d", tokenCalls)
	}
	current, fields, err := m.Store.SecretWithMeta("mcp:demo")
	if err != nil {
		t.Fatal(err)
	}
	if confOf(current).Gen != "generation-b" || fields["access_token"] != bAccess {
		t.Fatalf("defect reproduced: A's refresh overwrote B's replacement (gen=%s access=%q)", confOf(current).Gen, fields["access_token"])
	}
	// A fresh session for B attaches B's OWN token to second.example — never A's.
	newRT := &authRT{m: m, name: "demo", conf: confOf(current), genfp: connGen(current, fields)}
	req2, _ := http.NewRequest("POST", "https://second.example/mcp", strings.NewReader("{}"))
	res2, err := newRT.RoundTrip(req2)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if sentToSecond == "Bearer "+aAccess {
		t.Fatal("defect reproduced: A's refreshed credential leaked to second.example")
	}
	if sentToSecond != "Bearer "+bAccess {
		t.Fatalf("expected B's own token at second.example, got %q", sentToSecond)
	}
}
