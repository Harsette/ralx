package redact

// Astra 6 run 6 probes, inverted / kept as controls. Synthetic values only.
import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

// Control: content nested past the depth limit fails closed (withheld).
func TestAstra6HeldDepthLimitFailsClosed(t *testing.T) {
	r := New()
	r.Add("fixture", "SyntheticDepthKey0123456789")
	s := "ordinary-content-without-the-registered-value"
	for i := 0; i < 12; i++ {
		s = base64.StdEncoding.EncodeToString([]byte(s))
	}
	if !r.DeepContainsSecret(s) {
		t.Fatal("depth limit did not fail closed")
	}
}

// F3a: a prose word + space + a standalone base64(gzip(secret)) token is withheld —
// the per-token scan catches the framed blob the greedy run regex merges/breaks.
func TestAstra6FixEncodedRunFramingWithheld(t *testing.T) {
	r := New()
	const secret = "SyntheticFramedCredential0123456789"
	r.Add("fixture", secret)
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	_, _ = z.Write([]byte(strings.Repeat(secret, 64)))
	_ = z.Close()
	payload := "metadataisordinary " + base64.StdEncoding.EncodeToString(b.Bytes())
	if !r.DeepContainsSecret(payload) {
		t.Fatal("framed standalone base64-gzip credential was not withheld")
	}
}

// Whole-path self-review: a secret split across two JSON object KEYS (values are
// numbers) is caught — the key walk now reconstructs across keys.
func TestAstra6FixSplitAcrossJSONKeysWithheld(t *testing.T) {
	const secret = "SyntheticKeySplitCredential012345"
	r := New()
	r.Add("fixture", secret)
	payload := `{"` + secret[:16] + `":0,"` + secret[16:] + `":0}`
	if !r.DeepContainsSecret(payload) {
		t.Fatal("secret split across JSON keys was not withheld")
	}
}

// Whole-path self-review: a secret encoded as a decimal-byte number array is
// caught (numbers appear in the serialized JSON text).
func TestAstra6FixNumericArrayWithheld(t *testing.T) {
	const secret = "SyntheticNumericArrayCredential0"
	r := New()
	r.Add("fixture", secret)
	var nums []string
	for _, c := range []byte(secret) {
		nums = append(nums, itoaByte(c))
	}
	payload := `{"x":[` + strings.Join(nums, ",") + `]}`
	if !r.DeepContainsSecret(payload) {
		t.Fatal("decimal-byte number array was not withheld")
	}
}

func itoaByte(b byte) string {
	if b == 0 {
		return "0"
	}
	var d []byte
	for b > 0 {
		d = append([]byte{'0' + b%10}, d...)
		b /= 10
	}
	return string(d)
}
