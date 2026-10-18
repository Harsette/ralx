package redact

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Retained original trigger inverted: cap exhaustion must withhold.
// This reuses the existing plain key/value split; no new encoding is explored.
func TestAstra8FixDeepPairCapFailsClosed(t *testing.T) {
	const secret = "QWERTYUIOPASDFGH"
	r := New()
	r.Add("synthetic", secret)
	fixture := map[string]any{secret[:8]: 0, "z": secret[8:]}
	b, _ := json.Marshal(fixture)
	if !r.DeepContainsSecret(string(b)) {
		t.Fatal("small positive control was not detected")
	}
	for i := 0; i < 260; i++ {
		fixture[fmt.Sprintf("padding_%03d", i)] = "ordinary"
	}
	b, _ = json.Marshal(fixture)
	if !r.DeepContainsSecret(string(b)) {
		t.Fatal("oversized union was released")
	}
	t.Log("same plain key/value split: detected below cap; withheld with 260 padding fields")
}

// Distinct-pair inspection must still test two occurrences of an equal half;
// unrelated middle content prevents the existing forward/reverse joins winning.
func TestAstra8FixRepeatedPairInspectionControls(t *testing.T) {
	r := New()
	r.Add("fixture", "QWERTYQWERTY")
	for _, tc := range []struct {
		parts  []string
		unsafe bool
	}{
		{[]string{"QWERTY", "ordinary", "QWERTY"}, true},
		{[]string{"QWERTY", "ordinary"}, false},
		{strings.Fields(strings.Repeat("ordinary ", 129)), true},
	} {
		b, _ := json.Marshal(tc.parts)
		if got := r.DeepContainsSecret(string(b)); got != tc.unsafe {
			t.Fatalf("repeated-part control got %v, want %v", got, tc.unsafe)
		}
	}
}

func TestAstra8FixNULDecodedOutputControls(t *testing.T) {
	const secret = "SyntheticNULCredential0123456789"
	r := New()
	r.Add("fixture", secret)
	if r.DeepContainsSecret(strings.Repeat("\x00", 1<<20)) {
		t.Fatal("benign NUL-only bytes withheld")
	}
	if !r.DeepContainsSecret(strings.Repeat("\x00", maxScanInput+1)) {
		t.Fatal("oversized NUL-only bytes bypassed the original scan limit")
	}
	r.Add("binary", strings.Repeat("\x00", 8))
	if !r.DeepContainsSecret(strings.Repeat("\x00", 16)) {
		t.Fatal("registered NUL-only credential bypassed literal check")
	}
	r = New()
	r.Add("fixture", secret)
	var encoded strings.Builder
	for _, c := range []byte(secret) {
		fmt.Fprintf(&encoded, "%d,", c)
	}
	if !r.DeepContainsSecret(strings.Repeat("0,", 1<<16) + encoded.String()) {
		t.Fatal("decimal NUL prefix hid a non-NUL secret tail")
	}
	var interleaved strings.Builder
	for _, c := range []byte(secret) {
		interleaved.WriteByte(c)
		interleaved.WriteByte(0)
	}
	if !r.DeepContainsSecret(interleaved.String()) {
		t.Fatal("NUL-interleaved credential no longer detected")
	}
}

func TestAstra8HeldCatalogPairCap(t *testing.T) {
	r := New()
	r.Add("synthetic", "QWERTYUIOPASDFGH")
	parts := make([]string, 257)
	for i := range parts {
		parts[i] = "ordinary"
	}
	if !r.AnyOrderingContainsSecret(parts) {
		t.Fatal("catalog cap failed open")
	}
	t.Log("catalog API withholds 257 ordinary parts even without a secret match")
}

func TestAstra8FixDecodeBudgetAndLegitimateControl(t *testing.T) {
	r := New()
	r.Add("synthetic", "QWERTYUIOPASDFGH")
	if r.DeepContainsSecret(`{"ok":"ordinary"}`) {
		t.Fatal("small benign JSON withheld")
	}
	// At 129 union parts recursive pair decoding was abandoned, even below the
	// cheap-pair cap. Large benign content must withhold too: a budget isn't proof.
	v := map[string]any{}
	for i := 0; i < 130; i++ {
		v[fmt.Sprintf("field_%03d", i)] = i
	}
	b, _ := json.Marshal(v)
	if !r.DeepContainsSecret(string(b)) {
		t.Fatal("recursive pair budget failed open")
	}
}
