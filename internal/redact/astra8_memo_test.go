package redact

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestAstra8FixMemoGzipAndCapacity(t *testing.T) {
	const secret = "SyntheticMemoCredential0123456789"
	payload := "ordinary safe payload"
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	input := compressed.String()
	sc := &scan{raws: []string{secret}, budget: maxInflateBytes}
	if sc.hit(input, 0) {
		t.Fatal("benign gzip withheld")
	}
	spent := int64(maxInflateBytes) - sc.budget
	before := sc.budget
	if spent < int64(len(payload)) || sc.hit(input, 0) || before-sc.budget != spent {
		t.Fatal("gzip memo did not preserve charged decompression work")
	}
	sc.budget = int64(len(payload) - 1)
	if !sc.hit(input, 0) {
		t.Fatal("warm gzip memo bypassed decompression budget")
	}
	sc = &scan{raws: []string{secret}, budget: maxInflateBytes}
	for i := 0; i < maxScanMemoEntries+8; i++ {
		if sc.hit(fmt.Sprintf("ordinary[%d]", i), 0) {
			t.Fatal("ordinary cache-capacity control withheld")
		}
	}
	if len(sc.clean) > maxScanMemoEntries || sc.memoBytes > maxScanMemoBytes {
		t.Fatal("memo exceeded bounded retained state")
	}
	if !sc.hit(base64.StdEncoding.EncodeToString([]byte(secret)), 0) {
		t.Fatal("memo admission limit skipped secret inspection")
	}
	if sc.hit("benign?", 0) {
		t.Fatal("memo admission limit withheld benign output")
	}
}

func TestAstra8FixMemoBudgetAndLimits(t *testing.T) {
	const secret = "SyntheticMemoCredential0123456789"
	input := strings.Repeat("0,", 8)
	sc := &scan{raws: []string{secret}, budget: maxInflateBytes}
	if sc.hit(input, 0) {
		t.Fatal("benign decimal NUL output withheld")
	}
	if _, ok := sc.clean[scanMemoKey{s: input, depth: 0}]; !ok {
		t.Fatal("control did not warm the completed negative subtree")
	}
	// Decimal output is eight bytes but uncharged. A false-only cache that
	// ignores the remaining budget would incorrectly release this second scan.
	sc.budget = 4
	if !sc.hit(input, 0) {
		t.Fatal("memo reuse bypassed the byte-list budget")
	}
	sc.budget = 0
	if !sc.hit(input, 0) {
		t.Fatal("memo reuse bypassed exhausted budget")
	}
	sc.budget = maxInflateBytes
	if !sc.hit(input, maxDeepDepth+1) {
		t.Fatal("memo reuse bypassed the depth cap")
	}
}

func TestAstra8FixMemoCostAndIsolation(t *testing.T) {
	const secret = "SyntheticMemoCredential0123456789"
	input := base64.StdEncoding.EncodeToString([]byte("ordinary binary material"))
	sc := &scan{raws: []string{secret}, budget: maxInflateBytes}
	if sc.hit(input, 0) {
		t.Fatal("benign encoded output withheld")
	}
	spent := int64(maxInflateBytes) - sc.budget
	if spent <= 0 {
		t.Fatal("encoded control consumed no decode budget")
	}
	before := sc.budget
	if sc.hit(input, 0) || before-sc.budget != spent {
		t.Fatal("completed negative reuse did not replay its original budget cost")
	}
	sc.budget = spent
	if !sc.hit(input, 0) {
		t.Fatal("encoded memo bypassed budget exhaustion")
	}
	r := New()
	r.Add("fixture", secret)
	if r.DeepContainsSecret("ordinary future credential") {
		t.Fatal("ordinary output withheld")
	}
	r.Add("replacement", "ordinary future credential")
	if !r.DeepContainsSecret("ordinary future credential") {
		t.Fatal("negative memo survived registration in a later scan")
	}
}

func TestAstra8FixRegexAndFoldCompatibility(t *testing.T) {
	const secret = "SyntheticMemoCredential0123456789"
	r := New()
	r.Add("fixture", secret)
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	var wrapped strings.Builder
	for i := 0; i < len(encoded); i += 8 {
		end := i + 8
		if end > len(encoded) {
			end = len(encoded)
		}
		wrapped.WriteString(encoded[i:end])
		wrapped.WriteByte('\n')
	}
	for _, input := range []string{"note," + encoded + ".", wrapped.String(), strings.Repeat("0,", 16) + encoded} {
		if !r.DeepContainsSecret(input) {
			t.Fatal("regex preflight lost framed, narrow-wrapped or mixed secret")
		}
	}
	if r.DeepContainsSecret(strings.Repeat("0,", 16)) {
		t.Fatal("ordinary decimal output withheld")
	}
	if got := foldAlnum("\u212A-A09\x00\xffB"); got != "ka09b" {
		t.Fatalf("Unicode-to-ASCII/invalid-byte normalization changed: %q", got)
	}
}
