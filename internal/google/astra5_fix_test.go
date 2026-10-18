package google

import "testing"

// Control: a resumable upload Location must be HTTPS, carry no userinfo, use no
// non-443 port, and sit on a googleapis host — http, userinfo, an alternate port,
// an unrelated/IDN/trailing-dot host are all rejected; case and an explicit :443
// are accepted (Astra A14). The broad *.googleapis.com suffix remains accepted
// (documented accepted-risk hardening in STATUS; no attacker origin shown).
func TestAstra5HeldUploadLocationParsing(t *testing.T) {
	b := &Broker{}
	for _, raw := range []string{
		"http://www.googleapis.com/upload/session", "https://user:pass@www.googleapis.com/upload/session",
		"https://www.googleapis.com:444/upload/session", "https://www.googleapis.com.evil.test/upload/session",
		"https://www.googleapis.com./upload/session", "https://www.googⅼeapis.com/upload/session",
	} {
		if err := b.checkUploadURL(raw); err == nil {
			t.Fatalf("unacceptable location accepted: %s", raw)
		}
	}
	for _, raw := range []string{"https://WWW.GOOGLEAPIS.COM/upload/session", "https://www.googleapis.com:443/upload/session"} {
		if err := b.checkUploadURL(raw); err != nil {
			t.Fatalf("valid spelling rejected: %s: %v", raw, err)
		}
	}
}
