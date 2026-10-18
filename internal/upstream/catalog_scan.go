package upstream

import "github.com/Harsette/ralx/internal/redact"

const (
	maxCatalogParts       = 8192
	maxCatalogBytes       = 1 << 20
	maxCatalogUniqueParts = 512
)

// Diagnostics expose sizes only, never names, fragments or credential values.
func catalogSizes(parts []string) (raw, distinct, bytes int) {
	seen := map[string]bool{}
	for i, p := range parts {
		if i >= maxCatalogParts {
			break
		}
		if len(p) > maxCatalogBytes-bytes {
			bytes = maxCatalogBytes + 1
			break
		}
		seen[p] = true
		bytes += len(p)
		if len(seen) > 512 {
			break
		}
	}
	return len(parts), len(seen), bytes
}

// Catalogs repeat schema keywords and the static tool description. Scan the
// same singleton/pair set as before, once per exact distinct string. Equal
// halves still need p+p when the original catalog contained p twice. Only
// sanitized catalog entries/lists use this; ordinary result caps remain strict.
func catalogContainsSecret(red *redact.Redactor, parts []string) bool {
	if len(parts) > maxCatalogParts {
		return true
	}
	remaining := maxCatalogBytes
	counts := map[string]int{}
	unique := make([]string, 0)
	for _, p := range parts {
		if len(p) > remaining {
			return true
		}
		remaining -= len(p)
		if counts[p] == 0 {
			unique = append(unique, p)
			if len(unique) > maxCatalogUniqueParts {
				return true
			}
		}
		if counts[p] < 2 {
			counts[p]++
		}
	}
	if red.AnyOrderingContainsCatalogSecret(unique) {
		return true
	}
	for _, p := range unique {
		if counts[p] == 2 && red.DeepContainsSecret(p+p) {
			return true
		}
	}
	return false
}
