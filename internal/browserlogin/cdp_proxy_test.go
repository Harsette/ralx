package browserlogin

import (
	"fmt"
	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedCDPCapability(t *testing.T) {
	m, app, ctx := browserFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<form method="post"><input type="password"></form>`)
	})
	r := Request{Origin: app.URL, URL: app.URL, Field: "password"}
	got, _ := m.Fill(ctx, "fixture-agent", r, "SyntheticPipePassword-42")
	if got.Status != "filled" {
		t.Fatalf("fill: %+v", got)
	}
	u, err := url.Parse(got.CDPEndpoint)
	if err != nil || u.Scheme != "ws" || !strings.HasPrefix(u.Path, "/devtools/browser/") || len(strings.TrimPrefix(u.Path, "/devtools/browser/")) != 32 {
		t.Fatal("managed CDP must use a 128-bit capability websocket")
	}
	s, err := m.session("fixture-agent", r)
	if err != nil {
		t.Fatal(err)
	}
	args, err := chromedp.CallBrowser(s.ctx, cdpbrowser.GetBrowserCommandLine, cdp.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	pipe := false
	for _, arg := range args.Arguments {
		if arg == "--remote-debugging-pipe" {
			pipe = true
		}
		if strings.HasPrefix(arg, "--remote-debugging-port") {
			t.Fatal("Chrome exposes debugging TCP")
		}
	}
	if !pipe {
		t.Fatal("Chrome is not controlled through a pipe")
	}
	for _, path := range []string{"/", "/json/version", "/devtools/browser/00000000000000000000000000000000"} {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+u.Host+path, nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "c3ludGhldGljLWtleS00Mg==")
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("unauthorized CDP %s: %d", path, resp.StatusCode)
		}
	}
	module, err := filepath.Abs("../../tmp/proof-browser/node_modules/playwright-core")
	if err != nil {
		t.Fatal(err)
	}
	script := `const {chromium}=require(process.argv[1]);(async()=>{const b=await chromium.connectOverCDP(process.argv[2]);const ps=b.contexts().flatMap(c=>c.pages());if(!ps.length)throw Error('no signed-in browser');const page=ps.find(p=>p.url()===new URL(process.argv[3]).href);if(!page||!await page.locator('input[type=password]').count())throw Error('wrong page');await b.close()})().catch(e=>{console.error(String(e.message).replace(/ws:\/\/\S+/g,'<cdp-capability>'));process.exit(1)})`
	cmd := exec.CommandContext(ctx, "node", "-e", script, module, got.CDPEndpoint, app.URL)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("connectOverCDP: %v %s", e, b)
	}
	m.Close()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+u.Host+u.Path, nil)
	if resp, e := http.DefaultClient.Do(req); e == nil {
		resp.Body.Close()
		t.Fatal("closed session capability remains live")
	}
}
