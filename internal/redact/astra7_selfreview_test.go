package redact

// Astra 7 self-review regressions (inverted). Synthetic values only.
import (
	"encoding/base64"
	"testing"
)

// A secret split with one half in a field KEY and the other in a DIFFERENT field's
// VALUE (placed non-adjacently so the group joins miss it) must be withheld by the
// bounded key/value pairwise.
func TestAstra7SelfReviewKeyValueSplitWithheld(t *testing.T) {
	const secret = "QWERTYUIOPASDFGH"
	r := New()
	r.Add("fixture", secret)
	payload := `{"` + secret[:8] + `":0,"z":"` + secret[8:] + `"}`
	if !r.DeepContainsSecret(payload) {
		t.Fatal("defect reproduced: secret split across a key and a different value was not withheld")
	}
}

// A base64 secret wrapped at a narrow column width (every line shorter than the token
// minimum) must be withheld by the whole-input wrap-strip decode.
func TestAstra7SelfReviewShortWrapWithheld(t *testing.T) {
	const secret = "QWERTYUIOPASDFGH"
	r := New()
	r.Add("fixture", secret)
	enc := base64.StdEncoding.EncodeToString([]byte(secret))
	wrapped := enc[:8] + "\n" + enc[8:16] + "\n" + enc[16:]
	if !r.DeepContainsSecret(wrapped) {
		t.Fatal("defect reproduced: short-column-wrapped base64 secret was not withheld")
	}
}

// A base64 blob framed by a `-` delimiter ("note-<b64>") — which the base64url-aware
// matcher absorbs — must be withheld by the standard-alphabet matcher.
func TestAstra7SelfReviewDashFramedWithheld(t *testing.T) {
	const secret = "QWERTYUIOPASDFGH"
	r := New()
	r.Add("fixture", secret)
	enc := base64.StdEncoding.EncodeToString([]byte("!" + secret))
	for _, payload := range []string{"note-" + enc, "x_" + enc, "a-b-" + enc} {
		if !r.DeepContainsSecret(payload) {
			t.Fatalf("defect reproduced: dash/underscore-framed base64 not withheld: %q", payload[:8])
		}
	}
}
