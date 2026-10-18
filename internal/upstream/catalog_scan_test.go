package upstream

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Harsette/ralx/internal/redact"
)

func TestCatalogRepeatedPartsAndSplitControls(t *testing.T) {
	red := redact.New()
	const secret = "SyntheticCatalogCredential0123456789"
	red.Add("fixture", secret)
	parts := make([]string, 396)
	for i := range parts {
		parts[i] = "ordinary"
	}
	if catalogContainsSecret(red, parts) {
		t.Fatal("repeated benign catalog withheld")
	}
	parts[2], parts[395] = secret[:18], secret[18:]
	if !catalogContainsSecret(red, parts) {
		t.Fatal("cross-tool split released")
	}
	const half = "SyntheticEqualHalf012345"
	red.Add("equal", half+half)
	if catalogContainsSecret(red, []string{half}) {
		t.Fatal("single half control withheld")
	}
	if !catalogContainsSecret(red, []string{half, "ordinary", half}) {
		t.Fatal("equal-half split released")
	}
	if !red.AnyOrderingContainsSecret(make([]string, 257)) {
		t.Fatal("generic occurrence cap changed")
	}
}

func TestCatalogScanBudgetControls(t *testing.T) {
	red := redact.New()
	for _, tc := range []struct {
		name  string
		parts []string
	}{
		{"raw parts", make([]string, maxCatalogParts+1)},
		{"raw bytes", []string{strings.Repeat("x", maxCatalogBytes+1)}},
		{"repeated bytes", []string{strings.Repeat("x", maxCatalogBytes/2+1), strings.Repeat("x", maxCatalogBytes/2+1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !catalogContainsSecret(red, tc.parts) {
				t.Fatal("budget exhausted without withholding")
			}
		})
	}
	unique := make([]string, maxCatalogUniqueParts+1)
	for i := range unique {
		unique[i] = fmt.Sprintf("ordinary%d", i)
	}
	if !catalogContainsSecret(red, unique) {
		t.Fatal("distinct pair budget exhausted without withholding")
	}
}

func TestCatalogDistinctAllowanceKeepsAllPairs(t *testing.T) {
	red := redact.New()
	const secret = "SyntheticLargeDistinctCatalogCredential012345"
	red.Add("fixture", secret)
	parts := make([]string, 280)
	for i := range parts {
		parts[i] = fmt.Sprintf("ordinary_%03d", i)
	}
	if catalogContainsSecret(red, parts) {
		t.Fatal("measured distinct catalog control withheld")
	}
	if !red.AnyOrderingContainsSecret(parts) {
		t.Fatal("generic pair cap changed")
	}
	parts[267], parts[279] = secret[:21], secret[21:]
	if !catalogContainsSecret(red, parts) {
		t.Fatal("split beyond original generic pair cap released")
	}
}
