package daemon

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Agent enrollment by pasted prompt: the owner mints a one-time code, an agent
// redeems it into a pending request, and only an owner approval releases a key.

func (h *harness) mintEnrollCode() (code, prompt string) {
	h.t.Helper()
	r := h.do("POST", "/admin/api/enroll/code", map[string]any{}, nil, true)
	if r.code != 200 {
		h.t.Fatalf("mint code: %d %s", r.code, r.raw)
	}
	code, _ = r.body["code"].(string)
	prompt, _ = r.body["prompt"].(string)
	if code == "" || prompt == "" {
		h.t.Fatalf("mint code: missing code or prompt: %s", r.raw)
	}
	return code, prompt
}

func (h *harness) redeem(code, name string) resp {
	h.t.Helper()
	return h.do("POST", "/v1/enroll", map[string]any{"code": code, "name": name, "client": "claude-code"}, nil, false)
}

func (h *harness) poll(id, secret string) resp {
	h.t.Helper()
	return h.do("GET", "/v1/enroll/"+id, nil, map[string]string{"X-RalX-Enroll-Secret": secret}, false)
}

// doFrom sends one request from a chosen peer address (no cookie, no pipe).
func (h *harness) doFrom(remote, method, path string, body any) resp {
	h.t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, "http://localhost:7399"+path, bytes.NewReader(b))
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	out := resp{code: rec.Code, raw: rec.Body.Bytes(), hdr: rec.Header()}
	_ = json.Unmarshal(out.raw, &out.body)
	return out
}

func pendingEnrollment(t *testing.T, h *harness, id string) map[string]any {
	t.Helper()
	r := h.do("GET", "/admin/api/state", nil, nil, true)
	list, _ := r.body["enrollments"].([]any)
	for _, it := range list {
		m, _ := it.(map[string]any)
		if m["id"] == id {
			return m
		}
	}
	return nil
}

func TestEnrollApproveDeliversKeyOnce(t *testing.T) {
	h := newHarness(t)
	h.setupPasskey()
	code, prompt := h.mintEnrollCode()
	if !strings.Contains(prompt, code) {
		t.Fatalf("prompt does not carry the code:\n%s", prompt)
	}
	if strings.Contains(prompt, "ralx_") || strings.ContainsRune(prompt, '—') {
		t.Fatalf("prompt carries a key shape or an em dash:\n%s", prompt)
	}
	r := h.redeem(strings.ToLower(code), "claude-test")
	if r.code != 201 {
		t.Fatalf("redeem: %d %s", r.code, r.raw)
	}
	id, _ := r.body["request_id"].(string)
	secret, _ := r.body["secret"].(string)
	fp, _ := r.body["fingerprint"].(string)
	if id == "" || secret == "" || len(fp) != 9 {
		t.Fatalf("redeem body: %s", r.raw)
	}
	// The owner sees the name and the same fingerprint, never the secret.
	pe := pendingEnrollment(t, h, id)
	if pe == nil || pe["name"] != "claude-test" || pe["fingerprint"] != fp {
		t.Fatalf("owner state missing request: %v", pe)
	}
	if st := h.do("GET", "/admin/api/state", nil, nil, true); strings.Contains(string(st.raw), secret) {
		t.Fatal("owner state leaks the request secret")
	}
	// Before approval the agent gets nothing.
	if p := h.poll(id, secret); p.code != 200 || p.body["status"] != "pending" || p.body["key"] != nil {
		t.Fatalf("pending poll: %d %s", p.code, p.raw)
	}
	// Approval needs a passkey bound to this request.
	if a := h.do("POST", "/admin/api/enroll/"+id+"/approve", map[string]any{}, h.browser(), false); a.code != 403 {
		t.Fatalf("approve without passkey: %d %s", a.code, a.raw)
	}
	wrong := h.stepUp("enroll.approve:someoneelse")
	if a := h.do("POST", "/admin/api/enroll/"+id+"/approve", map[string]any{"assertion": wrong}, h.browser(), false); a.code != 403 {
		t.Fatalf("approve with another op's passkey: %d %s", a.code, a.raw)
	}
	if p := h.poll(id, secret); p.body["status"] != "pending" {
		t.Fatalf("not pending after refused approvals: %s", p.raw)
	}
	as := h.stepUp("enroll.approve:" + id)
	if a := h.do("POST", "/admin/api/enroll/"+id+"/approve", map[string]any{"assertion": as}, h.browser(), false); a.code != 200 {
		t.Fatalf("approve: %d %s", a.code, a.raw)
	}
	// Wrong secret learns nothing.
	if p := h.poll(id, secret+"x"); p.code != 404 || p.body["key"] != nil {
		t.Fatalf("wrong secret poll: %d %s", p.code, p.raw)
	}
	p := h.poll(id, secret)
	key, _ := p.body["key"].(string)
	if p.code != 200 || p.body["status"] != "approved" || !strings.HasPrefix(key, "ralx_") {
		t.Fatalf("approved poll: %d %s", p.code, p.raw)
	}
	if w := h.do("GET", "/v1/whoami", nil, bearer(key), false); w.code != 200 || w.body["agent"] != "claude-test" {
		t.Fatalf("enrolled key: %d %s", w.code, w.raw)
	}
	// The key is handed over once.
	if p := h.poll(id, secret); p.body["key"] != nil || p.body["status"] != "delivered" {
		t.Fatalf("second pickup: %d %s", p.code, p.raw)
	}
	if pendingEnrollment(t, h, id) != nil {
		t.Fatal("delivered request still listed as pending")
	}
}

// The redeem handler reads the request after the lock is released, while the
// owner may already be approving it. redeem must hand back its own copy, so a
// later approval can't change (or race on) what the agent is told (Sol F-b).
func TestEnrollRedeemReturnsSnapshot(t *testing.T) {
	e := newEnrollments()
	code, _, _ := e.mint()
	req, _, err := e.redeem(code, "snap", "codex")
	if err != nil {
		t.Fatal(err)
	}
	status, expires := req.Status, req.expires
	if _, err := e.decide(req.ID, "approved"); err != nil {
		t.Fatal(err)
	}
	if req.Status != status || !req.expires.Equal(expires) {
		t.Fatalf("an approval changed the redeemed request under the handler: %s -> %s", status, req.Status)
	}
}

func TestEnrollCodeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	code, _ := h.mintEnrollCode()
	if r := h.redeem(code, "first"); r.code != 201 {
		t.Fatalf("first redeem: %d %s", r.code, r.raw)
	}
	if r := h.redeem(code, "second"); r.code != 403 || r.body["request_id"] != nil {
		t.Fatalf("code reused: %d %s", r.code, r.raw)
	}
}

func TestEnrollNewCodeReplacesOld(t *testing.T) {
	h := newHarness(t)
	old, _ := h.mintEnrollCode()
	fresh, _ := h.mintEnrollCode()
	if r := h.redeem(old, "old"); r.code != 403 {
		t.Fatalf("replaced code still works: %d %s", r.code, r.raw)
	}
	if r := h.redeem(fresh, "fresh"); r.code != 201 {
		t.Fatalf("fresh code: %d %s", r.code, r.raw)
	}
}

func TestEnrollCodeExpires(t *testing.T) {
	h := newHarness(t)
	code, _ := h.mintEnrollCode()
	t0 := time.Now()
	h.s.enroll.now = func() time.Time { return t0.Add(16 * time.Minute) }
	if r := h.redeem(code, "late"); r.code != 403 {
		t.Fatalf("expired code accepted: %d %s", r.code, r.raw)
	}
}

func TestEnrollPendingRequestExpires(t *testing.T) {
	h := newHarness(t)
	code, _ := h.mintEnrollCode()
	r := h.redeem(code, "slow")
	id, secret := r.body["request_id"].(string), r.body["secret"].(string)
	t0 := time.Now()
	h.s.enroll.now = func() time.Time { return t0.Add(16 * time.Minute) }
	if p := h.poll(id, secret); p.body["status"] != "expired" || p.body["key"] != nil {
		t.Fatalf("stale request: %d %s", p.code, p.raw)
	}
	if a := h.do("POST", "/admin/api/enroll/"+id+"/approve", map[string]any{}, nil, true); a.code != 409 {
		t.Fatalf("approved an expired request: %d %s", a.code, a.raw)
	}
	if p := h.poll(id, secret); p.body["key"] != nil {
		t.Fatalf("expired request released a key: %s", p.raw)
	}
}

func TestEnrollWrongCodeAndRateLimit(t *testing.T) {
	h := newHarness(t)
	code, _ := h.mintEnrollCode()
	for i := 0; i < enrollMaxFailures; i++ {
		if r := h.redeem("WRNG-C0DE", "guess"); r.code != 403 {
			t.Fatalf("wrong code %d: %d %s", i, r.code, r.raw)
		}
	}
	if r := h.redeem("WRNG-C0DE", "guess"); r.code != 429 {
		t.Fatalf("guessing not rate limited: %d %s", r.code, r.raw)
	}
	// While limited, even the right code is refused, so guessing can't continue.
	if r := h.redeem(code, "guess"); r.code != 429 {
		t.Fatalf("right code during lockout: %d %s", r.code, r.raw)
	}
	// After the window the right code still works (it was not consumed).
	t0 := time.Now()
	h.s.enroll.now = func() time.Time { return t0.Add(enrollFailWindow + time.Second) }
	if r := h.redeem(code, "patient"); r.code != 201 {
		t.Fatalf("right code after window: %d %s", r.code, r.raw)
	}
}

func TestEnrollDeniedGetsNothing(t *testing.T) {
	h := newHarness(t)
	h.setupPasskey()
	code, _ := h.mintEnrollCode()
	r := h.redeem(code, "nope")
	id, secret := r.body["request_id"].(string), r.body["secret"].(string)
	if d := h.do("POST", "/admin/api/enroll/"+id+"/deny", map[string]any{}, h.browser(), false); d.code != 200 {
		t.Fatalf("deny: %d %s", d.code, d.raw)
	}
	if p := h.poll(id, secret); p.body["status"] != "denied" || p.body["key"] != nil {
		t.Fatalf("denied poll: %d %s", p.code, p.raw)
	}
	as := h.stepUp("enroll.approve:" + id)
	if a := h.do("POST", "/admin/api/enroll/"+id+"/approve", map[string]any{"assertion": as}, h.browser(), false); a.code != 409 {
		t.Fatalf("approved after deny: %d %s", a.code, a.raw)
	}
	if p := h.poll(id, secret); p.body["key"] != nil {
		t.Fatalf("denied request released a key: %s", p.raw)
	}
	if _, err := h.s.store.GetAgentByName("nope"); err == nil {
		t.Fatal("denied request created an agent")
	}
}

func TestEnrollNeedsOwner(t *testing.T) {
	h := newHarness(t)
	// Without an owner session nothing can mint a code or decide a request.
	if r := h.do("POST", "/admin/api/enroll/code", map[string]any{}, h.browser(), false); r.code != 401 {
		t.Fatalf("mint without owner: %d %s", r.code, r.raw)
	}
	code, _ := h.mintEnrollCode()
	r := h.redeem(code, "sneaky")
	id := r.body["request_id"].(string)
	// An agent key is not owner auth either.
	key := h.agent("other")
	if a := h.do("POST", "/admin/api/enroll/"+id+"/approve", map[string]any{}, bearer(key), false); a.code != 401 {
		t.Fatalf("approve with agent key: %d %s", a.code, a.raw)
	}
	if pe := pendingEnrollment(t, h, id); pe == nil {
		t.Fatal("request vanished")
	}
}

func TestEnrollRejectsBadNameWithoutUsingCode(t *testing.T) {
	h := newHarness(t)
	h.agent("taken")
	code, _ := h.mintEnrollCode()
	if r := h.redeem(code, "Bad Name!"); r.code != 400 {
		t.Fatalf("bad name: %d %s", r.code, r.raw)
	}
	if r := h.redeem(code, "taken"); r.code != 409 {
		t.Fatalf("taken name: %d %s", r.code, r.raw)
	}
	if r := h.redeem(code, "fine-name"); r.code != 201 {
		t.Fatalf("code was used up by a rejected name: %d %s", r.code, r.raw)
	}
}

func TestEnrollRefusedFromPublicPeer(t *testing.T) {
	h := newHarness(t)
	code, _ := h.mintEnrollCode()
	req := map[string]any{"code": code, "name": "remote"}
	r := h.doFrom("203.0.113.9:4444", "POST", "/v1/enroll", req)
	if r.code != 403 {
		t.Fatalf("public peer redeemed a code: %d %s", r.code, r.raw)
	}
	if r := h.redeem(code, "local"); r.code != 201 {
		t.Fatalf("local after refused remote: %d %s", r.code, r.raw)
	}
}

// sendEnroll sends one enrollment request with a chosen peer, Host and headers.
func (h *harness) sendEnroll(remote, host, method, path string, body any, hdr map[string]string) resp {
	h.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "http://"+host+path, rd)
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	out := resp{code: rec.Code, raw: rec.Body.Bytes(), hdr: rec.Header()}
	_ = json.Unmarshal(out.raw, &out.body)
	return out
}

// Sol S2: a LAN or tailnet peer (private address) must not redeem or poll, and
// neither may a loopback peer naming a non-loopback Host.
func TestEnrollRefusedFromPrivatePeerOrHost(t *testing.T) {
	h := newHarness(t)
	code, _ := h.mintEnrollCode()
	body := map[string]any{"code": code, "name": "lan", "client": "codex"}
	for _, c := range []struct{ remote, host string }{
		{"192.168.1.20:4444", "localhost:7399"},
		{"100.101.102.103:4444", "localhost:7399"},
		{"127.0.0.1:4444", "192.168.1.5:7399"},
		{"127.0.0.1:4444", "ralx.tailnet.example:7399"},
	} {
		if r := h.sendEnroll(c.remote, c.host, "POST", "/v1/enroll", body, nil); r.code != 403 || r.body["request_id"] != nil {
			t.Fatalf("redeem from %s Host %s: %d %s", c.remote, c.host, r.code, r.raw)
		}
	}
	r := h.redeem(code, "local")
	if r.code != 201 {
		t.Fatalf("local after refused peers: %d %s", r.code, r.raw)
	}
	id, secret := r.body["request_id"].(string), r.body["secret"].(string)
	hdr := map[string]string{"X-RalX-Enroll-Secret": secret}
	if p := h.sendEnroll("192.168.1.20:4444", "localhost:7399", "GET", "/v1/enroll/"+id, nil, hdr); p.code != 403 {
		t.Fatalf("poll from LAN peer: %d %s", p.code, p.raw)
	}
	for _, host := range []string{"127.0.0.1:7399", "[::1]:7399"} {
		if p := h.sendEnroll("[::1]:4444", host, "GET", "/v1/enroll/"+id, nil, hdr); p.code != 200 {
			t.Fatalf("loopback poll via %s: %d %s", host, p.code, p.raw)
		}
	}
}

// Sol S3: a web page can POST text/plain JSON cross-origin. Browser requests
// must be refused before the code is checked, so they can't burn the guessing
// limit and lock out the real code.
func TestEnrollRefusesBrowserRequests(t *testing.T) {
	h := newHarness(t)
	code, _ := h.mintEnrollCode()
	evil := map[string]string{"Origin": "https://evil.example", "Content-Type": "text/plain"}
	for i := 0; i < enrollMaxFailures+1; i++ {
		r := h.sendEnroll("127.0.0.1:4444", "localhost:7399", "POST", "/v1/enroll",
			map[string]any{"code": "WRNG-C0DE", "name": "evil"}, evil)
		if r.code != 403 || !strings.Contains(string(r.raw), "browser") {
			t.Fatalf("browser redeem %d: %d %s", i, r.code, r.raw)
		}
	}
	fetch := map[string]string{"Sec-Fetch-Site": "cross-site"}
	if r := h.sendEnroll("127.0.0.1:4444", "localhost:7399", "POST", "/v1/enroll",
		map[string]any{"code": code, "name": "evil"}, fetch); r.code != 403 || r.body["request_id"] != nil {
		t.Fatalf("Sec-Fetch-Site redeem: %d %s", r.code, r.raw)
	}
	r := h.redeem(code, "real")
	if r.code != 201 {
		t.Fatalf("real code locked out by browser guesses: %d %s", r.code, r.raw)
	}
	id, secret := r.body["request_id"].(string), r.body["secret"].(string)
	if p := h.sendEnroll("127.0.0.1:4444", "localhost:7399", "GET", "/v1/enroll/"+id, nil,
		map[string]string{"X-RalX-Enroll-Secret": secret, "Origin": "https://evil.example"}); p.code != 403 {
		t.Fatalf("browser poll: %d %s", p.code, p.raw)
	}
}
