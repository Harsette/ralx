package redact

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCatalogModeRetainsNormalCapsAndTransforms(t *testing.T) {
	r := New()
	const secret = "SyntheticCatalogModeCredential012345"
	r.Add("fixture", secret)
	benign, _ := json.Marshal(strings.Fields(strings.Repeat("ordinary ", 200)))
	if r.DeepContainsCatalogSecret(string(benign)) {
		t.Fatal("repeated catalog withheld")
	}
	if !r.DeepContainsSecret(string(benign)) {
		t.Fatal("normal result occurrence cap changed")
	}
	numbers := make([]int, len(secret[18:]))
	for i, b := range []byte(secret[18:]) {
		numbers[i] = int(b)
	}
	for _, v := range []any{
		[]string{secret[:18], "ordinary", secret[18:]},
		map[string]any{secret[:18]: "ordinary", "z": secret[18:]},
		map[string]any{"first": secret[:18], "numeric": numbers},
		map[string]any{"encoded": base64.StdEncoding.EncodeToString(daru6Gzip(0, secret))},
	} {
		b, _ := json.Marshal(v)
		if !r.DeepContainsCatalogSecret(string(b)) {
			t.Fatal("split/encoded catalog credential released")
		}
	}
	r.Add("equal", "QWERTYQWERTY")
	b, _ := json.Marshal([]string{"QWERTY", "ordinary", "QWERTY"})
	if !r.DeepContainsCatalogSecret(string(b)) {
		t.Fatal("equal half pair released")
	}
}

func TestCatalogModeBudgetControls(t *testing.T) {
	r := New()
	r.Add("fixture", "SyntheticCatalogBudgetCredential012345")
	unique := make([]string, 513)
	for i := range unique {
		unique[i] = fmt.Sprintf("ordinary_%03d", i)
	}
	for _, v := range []any{unique, make([]string, maxCatalogJSONParts+1), strings.Repeat("x", (1<<20)+1)} {
		b, _ := json.Marshal(v)
		if !r.DeepContainsCatalogSecret(string(b)) {
			t.Fatal("catalog budget exhausted without withholding")
		}
	}
	compressed := daru6Gzip(2, "ordinary")
	sc := &scan{catalog: true, budget: maxCatalogInflate}
	if out, over := sc.gunzip(string(compressed)); !over || out != "" {
		t.Fatal("catalog gzip allocation cap changed")
	}
	sc = &scan{catalog: true, raws: []string{"SyntheticBudgetCredential012345"}, budget: 1}
	if !sc.hit(base64.StdEncoding.EncodeToString(daru6Gzip(0, "ordinary")), 0) {
		t.Fatal("catalog transform budget failed open")
	}
}

func TestComplexCatalogEntryRetainsSplitTransforms(t *testing.T) {
	const secret = "SyntheticComplexCatalogCredential012345"
	r := New()
	r.Add("fixture", secret)
	padding := strings.Fields(strings.Repeat("ordinary ", 200))
	numeric := make([]int, len(secret[18:]))
	for i, b := range []byte(secret[18:]) {
		numeric[i] = int(b)
	}
	control, _ := json.Marshal(map[string]any{"padding": padding, "payload": "ordinary"})
	if r.DeepContainsCatalogSecret(string(control)) || !r.DeepContainsSecret(string(control)) {
		t.Fatal("complex catalog control did not distinguish ordinary result cap")
	}
	for _, payload := range []any{
		map[string]any{secret[:18]: "ordinary", "other": secret[18:]},
		map[string]any{"first": secret[:18], "numbers": numeric},
		base64.StdEncoding.EncodeToString(daru6Gzip(0, secret)),
	} {
		b, _ := json.Marshal(map[string]any{"padding": padding, "payload": payload})
		if !r.DeepContainsCatalogSecret(string(b)) {
			t.Fatal("complex catalog credential released")
		}
	}
	r.Add("equal", "QWERTYQWERTY")
	b, _ := json.Marshal(map[string]any{"padding": padding, "payload": []string{"QWERTY", "ordinary", "QWERTY"}})
	if !r.DeepContainsCatalogSecret(string(b)) {
		t.Fatal("complex equal-half split released")
	}
}

func TestCatalogMemoKeepsBudgetAndCapacityChecks(t *testing.T) {
	const secret = "SyntheticCatalogMemoCredential012345"
	sc := &scan{catalog: true, raws: []string{secret}, budget: maxCatalogInflate}
	input := strings.Repeat("0,", 8)
	if sc.hit(input, 0) {
		t.Fatal("ordinary byte-list withheld")
	}
	sc.budget = 4
	if !sc.hit(input, 0) {
		t.Fatal("catalog memo bypassed byte-list budget")
	}
	sc.budget = maxCatalogInflate
	if !sc.hit(input, maxDeepDepth+1) {
		t.Fatal("catalog memo bypassed depth cap")
	}
	for i := 0; i < maxCatalogMemoEntries+8; i++ {
		if sc.hit(fmt.Sprintf("ordinary[%d]", i), 0) {
			t.Fatal("ordinary capacity control withheld")
		}
	}
	if len(sc.clean) > maxCatalogMemoEntries || sc.memoBytes > maxCatalogMemoBytes {
		t.Fatal("catalog memo exceeded bounded state")
	}
	if !sc.hit(strings.ToLower(secret), 0) || !sc.hit(base64.StdEncoding.EncodeToString([]byte(secret)), 0) {
		t.Fatal("full memo skipped credential inspection")
	}
}
