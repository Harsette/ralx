// Package redact scrubs secrets out of anything RalX returns to an agent or
// writes to its audit log: every known vault value, every live access token,
// and common token shapes as a backstop.
package redact

import (
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

type Redactor struct {
	mu      sync.RWMutex
	values  map[string]string // secret value -> label
	sorted  []string          // longest first, so substrings don't win
	raws    []string          // the raw secret plaintexts, for decode-and-scan
	rawSeen map[string]bool   // dedup: a repeated Add of one value adds one raw entry
}

func New() *Redactor { return &Redactor{values: map[string]string{}, rawSeen: map[string]bool{}} }

// minLen is the floor for substring replacement and encoded-token heuristics.
// Short exact literals are retained and cause public output to be withheld.
const minLen = 8

// Add registers a secret value under a label such as "google:refresh_token",
// together with its common encodings (base64, hex, URL-encoded), so a copy of
// the secret that reaches an agent encoded is scrubbed too (Astra finding 5).
func (r *Redactor) Add(label, value string) {
	if value == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(value) >= minLen {
		r.addLocked(value, label)
	}
	// Dedup: registering the same value many times must not grow the raw list the
	// deep scan walks on every call (Astra5/Daru6 P2-5).
	if !r.rawSeen[value] {
		r.rawSeen[value] = true
		r.raws = append(r.raws, value)
	}
	forms := map[string]string{
		"b64":    base64.StdEncoding.EncodeToString([]byte(value)),
		"b64url": base64.RawURLEncoding.EncodeToString([]byte(value)),
		"hex":    hex.EncodeToString([]byte(value)),
		"url":    url.QueryEscape(value),
	}
	// The JSON-escaped form matches how the value appears once a result is
	// marshaled (e.g. < becomes <, " becomes \"), which is what reaches
	// an agent (Astra finding 1).
	if jb, err := jsonMarshal(value); err == nil && len(jb) >= 2 {
		forms["json"] = string(jb[1 : len(jb)-1])
	}
	for enc, form := range forms {
		if form != value {
			r.addLocked(form, label+":"+enc)
		}
	}
}

// ShortLiteral reports a supported short credential literally present in output.
// Withhold these responses rather than replacing single bytes in JSON syntax.
// Encoding heuristics keep their existing floor; this check preserves whitespace.
func (r *Redactor) ShortLiteral(s string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, raw := range r.raws {
		if len(raw) < minLen {
			if strings.Contains(s, raw) {
				return true
			}
			// JSON is a direct output representation, including control bytes that
			// cannot appear literally in its serialized string contents.
			b, err := json.Marshal(raw)
			if err == nil && len(b) > 2 && strings.Contains(s, string(b[1:len(b)-1])) {
				return true
			}
		}
	}
	return false
}

func (r *Redactor) addLocked(value, label string) {
	if len(value) < minLen {
		return
	}
	if _, ok := r.values[value]; ok {
		return
	}
	r.values[value] = label
	r.sorted = append(r.sorted, value)
	sort.Slice(r.sorted, func(i, j int) bool { return len(r.sorted[i]) > len(r.sorted[j]) })
}

// Replace drops all registered values and registers the given set.
func (r *Redactor) Replace(all map[string][]string) {
	r.mu.Lock()
	r.values = map[string]string{}
	r.sorted = nil
	r.raws = nil
	r.rawSeen = map[string]bool{}
	r.mu.Unlock()
	for label, vs := range all {
		for _, v := range vs {
			r.Add(label, v)
		}
	}
}

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`ya29\.[0-9A-Za-z_\-\.]{20,}`),                                         // Google access token
	regexp.MustCompile(`1//0[0-9A-Za-z_\-]{20,}`),                                             // Google refresh token
	regexp.MustCompile(`GOCSPX-[0-9A-Za-z_\-]{20,}`),                                          // Google OAuth client secret
	regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{30,}`),                                          // GitHub tokens
	regexp.MustCompile(`github_pat_[0-9A-Za-z_]{40,}`),                                        // GitHub fine-grained PAT
	regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`),                                              // OpenAI/Anthropic-style keys
	regexp.MustCompile(`xox[abprs]-[0-9A-Za-z\-]{10,}`),                                       // Slack
	regexp.MustCompile(`sbp_[0-9a-f]{30,}`),                                                   // Supabase PAT
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}`),                                 // bearer headers
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`), // JWTs
}

// String returns s with every secret replaced by [REDACTED:label].
func (r *Redactor) String(s string) string {
	if s == "" {
		return s
	}
	r.mu.RLock()
	for _, v := range r.sorted {
		if strings.Contains(s, v) {
			s = strings.ReplaceAll(s, v, "[REDACTED:"+r.values[v]+"]")
		}
	}
	r.mu.RUnlock()
	for _, p := range patterns {
		s = p.ReplaceAllString(s, "[REDACTED:token]")
	}
	return r.scanEncoded(s)
}

// encodedRun matches a long base64/base64url/base32/hex token that might wrap a
// secret at an arbitrary offset (so the pre-registered exact encodings miss it
// because of alignment or surrounding bytes). It tolerates base64 split across
// lines by whitespace or by literal \n / \r escape sequences (Astra R4), so a
// 60-column-wrapped or JSON-escaped blob is still caught. Up to six trailing
// "=" are captured so base32 padding (which can be longer than base64's) is kept
// with its run (Astra5 base32 fail-open).
var encodedRun = regexp.MustCompile(`[A-Za-z0-9+/_\-]{16,}(?:(?:\s|\\[rn])+[A-Za-z0-9+/_\-]{2,})*={0,6}`)

// wrapStripper removes the whitespace and literal \r / \n escapes that wrap a
// base64 blob, so it can be decoded as one piece.
var wrapStripper = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", "\\n", "", "\\r", "")

// standaloneTokens matches maximal runs of base64/base64url/base32/hex characters
// (optional trailing padding). It decodes a standalone encoded blob framed by
// prose and ANY delimiter — a space, a newline, or punctuation ("note <blob>." or
// "note,<blob>;") — on its own. The greedy encodedRun merges a prose word across a
// single space into the following token and breaks its alignment, and
// whitespace-only tokenisation leaves trailing punctuation stuck to the token so
// it won't decode (Daru6 F3a / Astra7 punctuation-framed).
// The {11,} minimum catches the base64 of an 8-byte secret (minLen), so a short
// credential encoded as a standalone token is still decoded (Astra7 self-review short
// encoding). decodeCandidates only flags a run that actually decodes to a registered
// secret, so the lower floor adds decode attempts but never a false withhold.
// With standard=true, `-` and `_` delimit rather than join a run, catching a blob
// framed by either character (Astra7 self-review dash/underscore framing).
// These are exactly the ordered, greedy matches of
// [A-Za-z0-9+/_\-]{11,}={0,6} or [A-Za-z0-9+/]{11,}={0,6}. Their alphabets are
// ASCII-only, so Unicode and invalid UTF-8 bytes are separators in both cases.
func standaloneTokens(s string, standard bool) []string {
	var out []string
	alphabet := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || !standard && (c == '_' || c == '-')
	}
	for i := 0; i < len(s); {
		if !alphabet(s[i]) {
			i++
			continue
		}
		start := i
		for i < len(s) && alphabet(s[i]) {
			i++
		}
		if i-start < 11 {
			continue
		}
		for padding := 0; padding < 6 && i < len(s) && s[i] == '='; padding++ {
			i++
		}
		out = append(out, s[start:i])
	}
	return out
}

// scanEncoded decodes base64/hex runs in s and, if a decoded run contains a
// known raw secret, replaces the whole run. This catches a secret hidden inside
// a larger (possibly line-wrapped) encoded blob, which fixed-form registration
// can't (Astra finding 5 / R4).
func (r *Redactor) scanEncoded(s string) string {
	r.mu.RLock()
	raws := r.raws
	r.mu.RUnlock()
	if len(raws) == 0 || s == "" {
		return s
	}
	return encodedRun.ReplaceAllStringFunc(s, func(run string) string {
		clean := wrapStripper.Replace(run)
		for _, dec := range decodeCandidates(clean) {
			for _, raw := range raws {
				if len(raw) >= minLen && strings.Contains(dec, raw) {
					return "[REDACTED:encoded]"
				}
			}
		}
		return run
	})
}

// SecretInNormalized reports whether an identifier, reduced to lowercase
// alphanumerics, contains a registered secret reduced the same way. Upstream tool
// names are lowercased and have punctuation folded to "_" before registration, so
// a hostile name that is a stored key in a different case or with dashes would
// otherwise slip the exact-substring check (Astra R2 / Daru4): normalization must
// not turn a rejected name into an accepted one.
func (r *Redactor) SecretInNormalized(name string) bool {
	n := foldAlnum(name)
	if len(n) < minLen {
		return false
	}
	r.mu.RLock()
	raws := r.raws
	r.mu.RUnlock()
	for _, raw := range raws {
		if rn := foldAlnum(raw); len(rn) >= minLen && strings.Contains(n, rn) {
			return true
		}
	}
	return false
}

// foldAlnum lowercases s and drops every non-alphanumeric rune.
func foldAlnum(s string) string {
	var b strings.Builder
	lower := strings.ToLower(s)
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// maxDeepDepth bounds how many nested transforms DeepContainsSecret follows.
// Reaching it is fail-closed (withhold): content nested deeper than this is
// almost certainly a crafted encoding, and passing it through unscanned is the
// Astra5 depth fail-open. Ordinary output stops recursing long before this,
// because each level needs a real decode (random bytes stop matching).
const maxDeepDepth = 10

// DeepContainsSecret reports whether s, under common reversible transforms,
// contains a registered secret. A caller uses it to WITHHOLD a passthrough
// response whole, because a secret hidden by percent-encoding, gzip, line
// wrapping, base32 or splitting across JSON fields can't be rewritten in place
// and a blacklist of forms can't be trusted to catch every one (Astra A2/A5).
// Transforms tried: folded (lowercase alphanumerics, catches case/punct/CRLF and
// NUL-interleaved UTF-16), raw substring, tolerant percent-decode, raw gzip, the
// concatenation of JSON string VALUES in document order, and every base64 /
// base64url / base32 / hex run decoded recursively (gunzipped when it is gzip).
// Scan limits. Over-size input and over-budget decompression fail CLOSED
// (withhold): a decompression bomb, or input larger than we will scan, must not
// slip a secret through unscanned, and the total decompressed work per scan is
// bounded so a crafted response can't burn CPU (Daru6 P0-1/P1-3).
const (
	maxScanInput            = 64 << 20 // a string this large at any depth is withheld, not released
	maxInflateBytes         = 64 << 20 // total bytes gunzip may produce across one scan
	maxCatalogInput         = 1 << 20
	maxCatalogInflate       = 256 << 20
	maxCatalogJSONParts     = 8192
	maxCatalogDistinctParts = 512
)

// scan carries the registered secrets and the remaining decompression budget
// through a single DeepContainsSecret call.
type scan struct {
	raws    []string
	budget  int64
	catalog bool
	// Same immutable secret snapshot, normalized once rather than per pair.
	foldedRaws []string
	// Completed negative subtrees are reusable only with their original budget
	// cost and enough budget for every uncharged byte-list output check.
	clean        map[scanMemoKey]scanMemo
	memoBytes    int
	largestInput int
}

type scanMemoKey struct {
	s     string
	depth int
}

type scanMemo struct{ spent, required int64 }

const (
	maxScanMemoEntries = 256
	maxScanMemoInput   = 2048
	maxScanMemoBytes   = 256 << 10
	// Generated catalogs revisit many more identical decoded fragments. Cache
	// admission changes work only: every reuse still recharges the original cost.
	maxCatalogMemoEntries = 32768
	maxCatalogMemoBytes   = 32 << 20
)

func (r *Redactor) DeepContainsSecret(s string) bool {
	return r.deepContainsSecret(s, false)
}

// DeepContainsCatalogSecret retains every recursive/transform check, but permits
// repeated JSON keywords in a generated tool list. It is only for catalog exits;
// ordinary results keep the original occurrence cap.
func (r *Redactor) DeepContainsCatalogSecret(s string) bool {
	return r.deepContainsSecret(s, true)
}

func (r *Redactor) deepContainsSecret(s string, catalog bool) bool {
	r.mu.RLock()
	raws := r.raws
	r.mu.RUnlock()
	if len(raws) == 0 || s == "" {
		return false
	}
	budget := int64(maxInflateBytes)
	if catalog {
		budget = maxCatalogInflate
	}
	sc := &scan{raws: raws, budget: budget, catalog: catalog}
	for _, raw := range raws {
		sc.foldedRaws = append(sc.foldedRaws, foldAlnum(raw))
	}
	return sc.hit(s, 0)
}

// maxPairParts bounds the O(n^2) pairwise cross-check in AnyOrderingContainsSecret.
// ABOVE it the function fails CLOSED (withhold) instead of silently skipping the
// cross-check, so a caller can't defeat split detection by padding its input with
// ordinary strings (Astra7 256-part fail-open). A legitimate agent-facing structure
// with more than this many distinct string parts is withheld; see core/decisions.md.
const maxPairParts = 256

// AnyOrderingContainsSecret reports whether any of the parts individually, or the
// parts joined (every ordered pair) with no separator, reconstructs a registered
// secret. Callers pass the strings of an agent-facing structure — including object
// KEYS, which the JSON value scan skips — so a secret split across schema property
// names/keys and values is caught (Daru6 run6 F2). Above maxPairParts it fails
// closed. An arbitrary N-way permutation remains the documented accepted risk.
func (r *Redactor) AnyOrderingContainsSecret(parts []string) bool {
	return r.anyOrderingContainsSecret(parts, maxPairParts)
}

// Catalogs have a separately bounded distinct-fragment allowance. Every
// singleton/pair still uses the unchanged ordinary deep scan and its budgets.
func (r *Redactor) AnyOrderingContainsCatalogSecret(parts []string) bool {
	return r.anyOrderingContainsSecret(parts, maxCatalogDistinctParts)
}

func (r *Redactor) anyOrderingContainsSecret(parts []string, limit int) bool {
	// Fail closed above the pairwise budget: we cannot afford the O(n^2) cross-check,
	// and passing a large entry whose split we didn't fully check is the fail-open
	// Astra7 flagged. Checked FIRST so a padded input is withheld, not scanned-partial.
	if len(parts) > limit {
		return true
	}
	for _, p := range parts {
		if r.DeepContainsSecret(p) {
			return true
		}
	}
	// Every ordered PAIR concatenation: a 2-part split (e.g. two schema property
	// names that are the two halves of a key) is caught regardless of the other
	// strings that would sort between them.
	for i := 0; i < len(parts); i++ {
		for j := 0; j < len(parts); j++ {
			if i == j {
				continue
			}
			if r.DeepContainsSecret(parts[i] + parts[j]) {
				return true
			}
		}
	}
	return false
}

func (sc *scan) hit(s string, depth int) (unsafe bool) {
	if s == "" {
		return false
	}
	// Over-size input or spent inflate budget: we can't fully scan it, so withhold
	// rather than release it unscanned (Daru6 P0-1/P1-3 fail closed).
	if len(s) > maxScanInput || sc.budget <= 0 || (sc.catalog && len(s) > maxCatalogInput) {
		return true
	}
	if depth > maxDeepDepth {
		return true // too deeply nested to follow: fail closed (Astra5)
	}
	if len(s) > sc.largestInput {
		sc.largestInput = len(s)
	}
	key := scanMemoKey{s: s, depth: depth}
	if memo, ok := sc.clean[key]; ok && sc.budget >= memo.required {
		sc.budget -= memo.spent
		return false
	}
	startBudget := sc.budget
	defer func() {
		maxEntries, maxBytes := maxScanMemoEntries, maxScanMemoBytes
		if sc.catalog {
			maxEntries, maxBytes = maxCatalogMemoEntries, maxCatalogMemoBytes
		}
		if unsafe || len(s) > maxScanMemoInput || len(sc.clean) >= maxEntries || sc.memoBytes+len(s) > maxBytes {
			return
		}
		if _, exists := sc.clean[key]; exists {
			return
		}
		spent := startBudget - sc.budget
		// All charged prefixes are <= spent; uncharged hex/decimal outputs are
		// no larger than a visited input. This conservative requirement preserves
		// their budget checks as well as the charged decode/gzip cost on reuse.
		required := spent + int64(sc.largestInput) + 1
		if startBudget < required {
			return
		}
		if sc.clean == nil {
			sc.clean = make(map[scanMemoKey]scanMemo)
		}
		key.s = strings.Clone(s) // a small substring must not pin a huge backing input
		sc.clean[key] = scanMemo{spent: spent, required: required}
		sc.memoBytes += len(s)
	}()
	// Literal checks precede transforms, including for a registered binary value.
	for _, raw := range sc.raws {
		if strings.Contains(s, raw) {
			return true
		}
	}
	// Byte-list/gzip decoding can produce long NUL-only strings. After literal
	// checks these cannot contain alphanumerics, an encoded token, JSON, escapes or
	// gzip magic. Avoid repeatedly parsing that same non-text result. Mixed/NUL-
	// interleaved text still follows every transform below; size/depth/budget caps
	// were checked above and remain fail closed.
	if strings.Count(s, "\x00") == len(s) {
		return false
	}
	// Folded comparison catches case, punctuation, CRLF, and ASCII in UTF-16.
	folded := foldAlnum(s)
	for i, raw := range sc.raws {
		rn := ""
		if len(sc.foldedRaws) == len(sc.raws) {
			rn = sc.foldedRaws[i]
		} else {
			rn = foldAlnum(raw)
		}
		if len(rn) >= minLen && strings.Contains(folded, rn) {
			return true
		}
	}
	// percent-decoded form (tolerant of a trailing invalid escape — Astra5).
	if dec := percentDecodeTolerant(s); dec != "" && dec != s {
		if sc.hit(dec, depth+1) {
			return true
		}
	}
	// \xNN / \uNNNN escapes, with surrounding literal text preserved, so a mix like
	// "\x41BCDEFGH" reconstructs "ABCDEFGH" (Daru6 self-review P0).
	if dec := escapeDecode(s); dec != "" && dec != s {
		if sc.hit(dec, depth+1) {
			return true
		}
	}
	// Separated byte-list encodings: hex tokens with any separators (colon/space/
	// \x/\u) and decimal byte codes (Daru6 P2-4). Each run is decoded independently,
	// so unrelated surrounding tokens can't discard the whole scan; parsing is
	// incremental and budget-bounded so a huge list can't amplify memory (Daru6 P0/P1).
	if dec, over := sc.hexByteListDecode(s); over {
		return true
	} else if dec != "" && dec != s {
		if sc.hit(dec, depth+1) {
			return true
		}
	}
	if dec, over := sc.decimalListDecode(s); over {
		return true
	} else if dec != "" && dec != s {
		if sc.hit(dec, depth+1) {
			return true
		}
	}
	// raw gzip stream (e.g. a Drive .gz whose bytes gunzip to a secret).
	if g, over := sc.gunzip(s); over {
		return true
	} else if g != "" && g != s {
		if sc.hit(g, depth+1) {
			return true
		}
	}
	// JSON string VALUES and object KEYS, each joined forward and reversed, so a
	// secret split across two field values OR across two property NAMES (keys, which
	// the value walk alone would skip) is caught whichever order the agent reassembles
	// it (Astra5, Daru6 run6 F2/split-keys).
	if keys, vals := jsonStrings(s); len(keys)+len(vals) > 0 {
		for _, group := range [][]string{vals, keys} {
			if len(group) < 2 {
				continue
			}
			if cat := strings.Join(group, ""); cat != s && sc.hit(cat, depth+1) {
				return true
			}
			rev := make([]string, len(group))
			for i, v := range group {
				rev[len(group)-1-i] = v
			}
			if cat := strings.Join(rev, ""); cat != s && sc.hit(cat, depth+1) {
				return true
			}
		}
		// Scan each individual field string on its own too, so a single VALUE that is a
		// short-column-wrapped or otherwise encoded blob gets its own wrap-strip/decode
		// (the whole-document strip leaves JSON punctuation in and can't decode it) — Astra7
		// self-review wrapped-value-inside-JSON. decodeAndScan also catches a short encoded
		// value below the token-matcher minimum.
		for _, group := range [][]string{vals, keys} {
			for _, v := range group {
				if v == s {
					continue
				}
				if sc.budget <= 0 {
					return true
				}
				if sc.hit(v, depth+1) || (len(v) >= minLen && sc.decodeAndScan(v, depth)) {
					return true
				}
			}
		}
		// Ordered-pair check over the UNION of keys, values AND any decimal/hex byte-list
		// decoded from the document: a 2-fragment split with the halves in non-adjacent
		// fields (key+value, value+value, or a numeric array + a string) is placed
		// non-adjacently by the group joins, so only a pairwise check catches it, and the
		// pair itself may be ENCODED so it must be DECODED (Astra7 self-review key/value and
		// numeric/string splits). sc.hit does the decode; we bound its O(n^2) cost with a
		// decode cap. An unperformed pair/decode check is unsafe, never a clean result.
		union := append(append([]string(nil), keys...), vals...)
		if dec, over := sc.decimalListDecode(s); over {
			return true
		} else if dec != "" {
			union = append(union, dec)
		}
		if dec, over := sc.hexByteListDecode(s); over {
			return true
		} else if dec != "" {
			union = append(union, dec)
		}
		if (!sc.catalog && len(union) > 128) || (sc.catalog && len(union) > maxCatalogJSONParts) {
			return true // recursive pair inspection budget exhausted: fail closed
		}
		if sc.catalog {
			remaining := maxCatalogInput
			for _, part := range union {
				if len(part) > remaining {
					return true
				}
				remaining -= len(part)
			}
		}
		// Repeated schema keys/values produce identical pair inputs. Inspect each
		// distinct ordered pair once, preserving multiplicity for two equal halves.
		// The original part cap above applies BEFORE deduplication.
		counts := make(map[string]int, len(union))
		parts := make([]string, 0, len(union))
		for _, part := range union {
			if counts[part] == 0 {
				parts = append(parts, part)
				if sc.catalog && len(parts) > maxCatalogDistinctParts {
					return true
				}
			}
			counts[part]++
		}
		if n := len(parts); len(union) > 1 {
			for i := 0; i < n; i++ {
				for j := 0; j < n; j++ {
					if i == j && counts[parts[i]] < 2 {
						continue
					}
					if sc.hit(parts[i]+parts[j], depth+1) {
						return true
					}
				}
			}
		}
	}
	// Every base64/base32/hex run, decoded (and gunzipped). All runs are scanned
	// (no count cap), but the inflate budget bounds the total work (Astra5/Daru6).
	maxRun := encodedPrefixLength(s)
	var runs []string
	if maxRun >= 16 {
		runs = encodedRun.FindAllString(s, -1)
	}
	for _, run := range runs {
		if sc.budget <= 0 {
			return true
		}
		clean := wrapStripper.Replace(run)
		if sc.decodeAndScan(clean, depth) {
			return true
		}
	}
	// Each maximal base64/base32/hex-alphabet run on its own: the greedy encodedRun
	// regex can merge a preceding prose word into a following standalone token across a
	// single space and break the decode, and whitespace-only tokenisation leaves
	// trailing punctuation stuck to the token so it won't decode ("note <blob>." or
	// "note,<blob>;" — Daru6 run6 F3a / Astra7 punctuation-framed). The per-run scan
	// above still handles line-wrapped (whitespace-joined) blobs; this handles framed
	// standalone ones regardless of the surrounding delimiter.
	for _, standard := range [2]bool{false, true} {
		if maxRun < 11 {
			break // neither matcher can have an initial token this short
		}
		for _, tok := range standaloneTokens(s, standard) {
			if sc.budget <= 0 {
				return true
			}
			if sc.decodeAndScan(tok, depth) {
				return true
			}
		}
	}
	// A base64/hex blob wrapped at a narrow column width has every line shorter than
	// the token minimum, so neither matcher above anchors on it. Strip all wrapping
	// (whitespace + literal \r/\n escapes) from the whole input and decode that as one
	// piece, so e.g. an 8-column-wrapped base64 secret is still caught (Astra7 self-review
	// short line-wrap). For mixed text this merges unrelated tokens into a string that
	// fails to decode, so it is harmless beyond the (budget-bounded) decode attempt.
	if stripped := wrapStripper.Replace(s); stripped != s && len(stripped) >= 16 {
		if sc.budget <= 0 {
			return true
		}
		if sc.decodeAndScan(stripped, depth) {
			return true
		}
	}
	return false
}

// Every encoded matcher needs an initial contiguous ASCII alphabet run. Stop
// once the largest minimum (16) is met; below it only provably-empty regex passes
// are skipped. Whole-input narrow-wrap decoding still runs independently.
func encodedPrefixLength(s string) int {
	longest, run := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '_' || c == '-' {
			run++
			if run > longest {
				longest = run
				if longest == 16 {
					return longest
				}
			}
		} else {
			run = 0
		}
	}
	return longest
}

// decodeAndScan decodes one candidate run (base64/base32/hex, then gunzip) and
// recursively scans each decoding, charging the shared budget.
func (sc *scan) decodeAndScan(run string, depth int) bool {
	for _, d := range decodeCandidates(run) {
		sc.budget -= int64(len(d))
		if sc.budget <= 0 {
			return true
		}
		if sc.hit(d, depth+1) {
			return true
		}
		if g, over := sc.gunzip(d); over {
			return true
		} else if g != "" && sc.hit(g, depth+1) {
			return true
		}
	}
	return false
}

// hexByteListDecode reconstructs bytes from separated hex tokens in s (e.g.
// "41:42", "41 42", "\x41\x42", "AB"). Each maximal hex run is decoded
// independently, so an unrelated prefix/suffix token (even a lone hex digit) can't
// discard the rest (Daru6 P0). It parses in one pass and caps output at the scan's
// remaining budget, withholding (over=true) if exceeded (Daru6 P1).
func (sc *scan) hexByteListDecode(s string) (out string, over bool) {
	var b strings.Builder
	var run []byte
	flush := func() bool {
		if len(run) >= 2 && len(run)%2 == 0 {
			for i := 0; i+1 < len(run); i += 2 {
				h, _ := unhexByte(run[i])
				l, _ := unhexByte(run[i+1])
				b.WriteByte(h<<4 | l)
			}
		}
		run = run[:0]
		return int64(b.Len()) <= sc.budget
	}
	for i := 0; i < len(s); i++ {
		if _, ok := unhexByte(s[i]); ok {
			run = append(run, s[i])
			continue
		}
		if !flush() {
			return "", true
		}
	}
	if !flush() {
		return "", true
	}
	if b.Len() < minLen {
		return "", false
	}
	return b.String(), false
}

// decimalListDecode reconstructs bytes from a separator-delimited list of decimal
// byte codes (e.g. "83,121,110"). Out-of-range tokens are skipped (not aborted),
// so a trailing junk value can't discard the rest (Daru6 P0). One pass, output
// capped at the scan budget (Daru6 P1).
func (sc *scan) decimalListDecode(s string) (out string, over bool) {
	var b strings.Builder
	n, has, bad := 0, false, false
	flush := func() bool {
		if has && !bad {
			b.WriteByte(byte(n))
		}
		n, has, bad = 0, false, false
		return int64(b.Len()) <= sc.budget
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= '0' && c <= '9' {
			has = true
			// Accept leading zeros ("0090" == 90); a token is bad only if its VALUE
			// exceeds a byte, not by digit count (Daru6 self-review P0).
			if !bad {
				n = n*10 + int(c-'0')
				if n > 255 {
					bad = true
				}
			}
			continue
		}
		if !flush() {
			return "", true
		}
	}
	if !flush() {
		return "", true
	}
	if b.Len() < minLen {
		return "", false
	}
	return b.String(), false
}

// percentDecodeTolerant decodes every valid %XX escape in s and leaves any
// invalid escape (e.g. a trailing "%zz" or "%") literal, returning "" if there
// was no "%" to decode. Unlike url.QueryUnescape it never fails whole, so a
// hostile trailing escape can't suppress the scan (Astra5).
func percentDecodeTolerant(s string) string {
	if !strings.ContainsRune(s, '%') {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if h1, ok1 := unhexByte(s[i+1]); ok1 {
				if h2, ok2 := unhexByte(s[i+2]); ok2 {
					b.WriteByte(h1<<4 | h2)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// escapeDecode replaces \xNN and \uNNNN escapes with their byte/rune, leaving all
// surrounding literal text in place, so a mix of escaped and literal characters
// ("\x41BCDEFGH") is reconstructed ("ABCDEFGH"). Returns "" if there were no such
// escapes (Daru6 self-review).
func escapeDecode(s string) string {
	if !strings.Contains(s, `\x`) && !strings.Contains(s, `\u`) {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			if s[i+1] == 'x' && i+3 < len(s) {
				if h, ok1 := unhexByte(s[i+2]); ok1 {
					if l, ok2 := unhexByte(s[i+3]); ok2 {
						b.WriteByte(h<<4 | l)
						i += 4
						continue
					}
				}
			}
			if s[i+1] == 'u' && i+5 < len(s) {
				if r, ok := parseHex4(s[i+2 : i+6]); ok {
					b.WriteRune(rune(r))
					i += 6
					continue
				}
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func parseHex4(s string) (int, bool) {
	n := 0
	for i := 0; i < 4; i++ {
		d, ok := unhexByte(s[i])
		if !ok {
			return 0, false
		}
		n = n<<4 | int(d)
	}
	return n, true
}

func unhexByte(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// jsonStringValues parses s as JSON and returns its string VALUES in document
// order (object keys excluded); nil if s is not JSON. The caller joins them in
// forward and reverse order, so a secret split across reordered fields is caught.
// jsonStrings parses s as JSON and returns its object KEYS and string VALUES as two
// document-order lists; nil, nil if s is not JSON. The caller joins each list
// forward and reversed, so a secret split across two field values OR across two
// property names (keys) is caught (Astra5, Daru6 run6 split-keys).
func jsonStrings(s string) (keys, vals []string) {
	t := strings.TrimSpace(s)
	if t == "" || (t[0] != '{' && t[0] != '[') {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(s))
	// Each object frame alternates key, value; array frames are all values.
	type frame struct {
		isObj     bool
		expectKey bool
	}
	var stack []frame
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, frame{isObj: true, expectKey: true})
			case '[':
				stack = append(stack, frame{isObj: false})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				if n := len(stack); n > 0 && stack[n-1].isObj && !stack[n-1].expectKey {
					stack[n-1].expectKey = true // the nested value just closed
				}
			}
		case string:
			if n := len(stack); n > 0 && stack[n-1].isObj {
				if stack[n-1].expectKey {
					keys = append(keys, v)
					stack[n-1].expectKey = false
				} else {
					vals = append(vals, v)
					stack[n-1].expectKey = true
				}
			} else {
				vals = append(vals, v)
			}
		default: // number, bool, null
			if n := len(stack); n > 0 && stack[n-1].isObj && !stack[n-1].expectKey {
				stack[n-1].expectKey = true
			}
		}
	}
	return keys, vals
}

// gunzip decompresses s if it is gzip, charging the scan's inflate budget. It
// tolerates a bad trailing checksum (returning what decompressed so far), but if
// the stream would exceed the remaining budget (or the per-scan size) it returns
// over=true so the caller WITHHOLDS — scanning a truncated output would miss a
// secret placed past the cap, which is the decompression-bomb fail-open (Daru6
// P0-1), and the budget bounds total decode work (Daru6 P1-3).
func (sc *scan) gunzip(s string) (out string, over bool) {
	if len(s) < 2 || s[0] != 0x1f || s[1] != 0x8b {
		return "", false
	}
	zr, err := gzip.NewReader(strings.NewReader(s))
	if err != nil {
		// The gzip magic matched but Go's header parser refused it (e.g. an
		// over-long FNAME field Go rejects but other decompressors accept). We can't
		// prove it's harmless — withhold rather than pass it through (Daru6 self-review).
		return "", true
	}
	defer zr.Close()
	limit := sc.budget
	if limit > maxScanInput {
		limit = maxScanInput
	}
	if sc.catalog && limit > maxCatalogInput {
		limit = maxCatalogInput
	}
	buf, rerr := io.ReadAll(io.LimitReader(zr, limit+1))
	if int64(len(buf)) > limit {
		return "", true // would exceed the budget/size: withhold rather than truncate-and-miss
	}
	// Any read error after the gzip signature was recognised (bad checksum, a
	// truncated or multistream member we couldn't fully read) means we can't be sure
	// we scanned everything the agent could decompress — withhold (Daru6 P0).
	if rerr != nil {
		return "", true
	}
	sc.budget -= int64(len(buf))
	return string(buf), false
}

// decodeCandidates returns the plausible, DISTINCT decodings of an encoded run
// (base64 in its four spellings, base32, and hex). Deduplicating matters because
// the four base64 spellings often decode an unpadded run to the same bytes, and
// scanning identical subtrees four times is wasted work (Daru6 self-review).
func decodeCandidates(run string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(b []byte, err error) {
		if err == nil && len(b) > 0 && !seen[string(b)] {
			seen[string(b)] = true
			out = append(out, string(b))
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(run)
		add(b, err)
	}
	// base32 (upper-cased, padding stripped): a secret base32-encoded would
	// otherwise slip every base64/hex decoder (Astra5).
	if up := strings.ToUpper(strings.TrimRight(run, "=")); len(up) >= 16 {
		b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(up)
		add(b, err)
	}
	if len(run)%2 == 0 {
		b, err := hex.DecodeString(run)
		add(b, err)
	}
	return out
}

func (r *Redactor) Bytes(b []byte) []byte { return []byte(r.String(string(b))) }

// maxLen is the length of the longest registered secret (0 if none).
func (r *Redactor) maxLen() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.sorted) == 0 {
		return 0
	}
	return len(r.sorted[0])
}

// Writer streams data through the redactor to dst, scrubbing any registered
// secret even when it is split across writes. Used for Drive downloads so a
// file containing a known RalX secret can't be streamed out verbatim (Astra
// finding 10). It does not apply the shape patterns (which would corrupt
// binary files); it replaces only exact known secret values.
type Writer struct {
	r     *Redactor
	dst   io.Writer
	carry []byte
	keep  int
}

func (r *Redactor) NewWriter(dst io.Writer) *Writer {
	keep := r.maxLen()
	return &Writer{r: r, dst: dst, keep: keep}
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.keep == 0 { // no secrets registered: pass through
		return w.dst.Write(p)
	}
	w.carry = append(w.carry, p...)
	// Emit everything that cannot be the prefix of a secret still being
	// assembled: keep the last (keep-1) bytes back, but never cut through a
	// value that straddles that boundary.
	if len(w.carry) > 1<<20+w.keep {
		if err := w.flush(false); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (w *Writer) flush(final bool) error {
	data := w.carry
	safe := len(data)
	if !final {
		safe = len(data) - (w.keep - 1)
		if safe < 0 {
			safe = 0
		}
	}
	w.r.mu.RLock()
	// Don't emit past the start of any known value that reaches into the
	// retained tail.
	if !final {
		for _, v := range w.r.sorted {
			idx := 0
			for {
				j := indexFrom(data, v, idx)
				if j < 0 {
					break
				}
				if j < safe && j+len(v) > safe {
					safe = j
				}
				idx = j + 1
			}
		}
	}
	out := redactBytes(data[:safe], w.r)
	w.r.mu.RUnlock()
	// Also scrub an encoded blob that decodes to a known secret (e.g. a Drive
	// file whose bytes are base64 around a vault secret). Only runs that decode
	// to a registered secret are touched, so ordinary bytes are unaffected
	// (Astra R4). A run split across flush boundaries is a documented residual.
	out = []byte(w.r.scanEncoded(string(out)))
	if _, err := w.dst.Write(out); err != nil {
		return err
	}
	w.carry = append([]byte(nil), data[safe:]...)
	return nil
}

func (w *Writer) Close() error {
	if w.keep == 0 {
		return nil
	}
	return w.flush(true)
}

func indexFrom(b []byte, sub string, from int) int {
	if from >= len(b) {
		return -1
	}
	i := strings.Index(string(b[from:]), sub)
	if i < 0 {
		return -1
	}
	return from + i
}

// redactBytes replaces exact known values in b (caller holds the read lock).
func redactBytes(b []byte, r *Redactor) []byte {
	s := string(b)
	for _, v := range r.sorted {
		if strings.Contains(s, v) {
			s = strings.ReplaceAll(s, v, "[REDACTED:"+r.values[v]+"]")
		}
	}
	return []byte(s)
}
