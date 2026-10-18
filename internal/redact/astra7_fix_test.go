package redact

// Astra 7 probes, inverted (Fix*) / kept as controls (Held*). Synthetic values only.
import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

func astra7Encoded(t *testing.T) (string, string) {
	t.Helper()
	const secret = "SyntheticFramedCredential0123456789"
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	_, _ = z.Write([]byte(strings.Repeat(secret, 64)))
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return secret, base64.StdEncoding.EncodeToString(b.Bytes())
}

// Inverted Astra7ReproPunctuationFramedGzip: a standalone base64(gzip(secret)) token
// framed by prose and ANY delimiter — a space, or the punctuation Daru named
// (, ; | :) with or without a trailing period — must now be WITHHELD, because the
// per-token scan tokenises on punctuation as well as whitespace.
func TestAstra7FixPunctuationFramedGzipWithheld(t *testing.T) {
	secret, enc := astra7Encoded(t)
	r := New()
	r.Add("fixture", secret)
	for _, frame := range []string{
		"metadataisordinary " + enc + ".",
		"metadataisordinary " + enc,
		"metadataisordinary," + enc,
		"metadataisordinary;" + enc + ";",
		"metadataisordinary|" + enc + "|next",
		"metadataisordinary:" + enc + ":tail",
		"prefixword " + enc + ", trailing",
	} {
		if !r.DeepContainsSecret(frame) {
			t.Fatalf("defect reproduced: punctuation-framed credential not withheld: %q", frame[:20])
		}
	}
}

// Control (Held): every standalone encoding spelling + newline/tab wrapping of the
// same gzip blob stays withheld.
func TestAstra7HeldStandaloneEncodingVariants(t *testing.T) {
	secret, enc := astra7Encoded(t)
	data, _ := base64.StdEncoding.DecodeString(enc)
	r := New()
	r.Add("fixture", secret)
	cases := map[string]string{
		"space":             "metadataisordinary " + enc,
		"url-padded":        "metadataisordinary " + base64.URLEncoding.EncodeToString(data),
		"url-unpadded":      "metadataisordinary " + base64.RawURLEncoding.EncodeToString(data),
		"standard-unpadded": "metadataisordinary " + base64.RawStdEncoding.EncodeToString(data),
		"newline":           enc[:40] + "\n" + enc[40:],
		"tab":               enc[:40] + "\t" + enc[40:],
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if !r.DeepContainsSecret(payload) {
				t.Fatal("variant not withheld")
			}
		})
	}
}

// Inverted Astra7ReproPairScanCap: padding a detected two-part split with 256 ordinary
// strings must NOT turn it "safe" — above the pairwise budget AnyOrderingContainsSecret
// fails CLOSED.
func TestAstra7FixPairScanCapFailsClosed(t *testing.T) {
	const secret = "SyntheticPairCapCredential0123456789"
	r := New()
	r.Add("fixture", secret)
	parts := make([]string, 258)
	for i := range parts {
		parts[i] = "ordinary"
	}
	parts[256], parts[257] = secret[:18], secret[18:]
	if !r.AnyOrderingContainsSecret(parts[256:]) {
		t.Fatal("two-part positive control failed")
	}
	if !r.AnyOrderingContainsSecret(parts) {
		t.Fatal("defect reproduced: large padded entry passed instead of failing closed")
	}
}
