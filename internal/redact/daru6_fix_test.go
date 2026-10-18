package redact

// Daru6 probes, inverted: each asserts the FIX. Synthetic values only; no sockets.
import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

const daru6Secret = "SyntheticDaruSixCredential0123456789"

func daru6Red() *Redactor {
	r := New()
	r.Add("svc:token", daru6Secret)
	return r
}

func daru6Gzip(prefixMiB int, tail string) []byte {
	var b bytes.Buffer
	z, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	chunk := make([]byte, 1<<20)
	for i := 0; i < prefixMiB; i++ {
		_, _ = z.Write(chunk)
	}
	_, _ = z.Write([]byte(tail))
	_ = z.Close()
	return b.Bytes()
}

// A gzip stream whose secret sits past the decompress cap is WITHHELD (we no
// longer scan a truncated prefix and miss it) — raw and base64 (Daru6 P0-1).
func TestDaru6FixGzipPastDecompressCapWithheld(t *testing.T) {
	r := daru6Red()
	raw := daru6Gzip(65, daru6Secret)
	if !r.DeepContainsSecret(string(raw)) {
		t.Fatal("raw gzip past the cap was not withheld")
	}
	if !r.DeepContainsSecret(base64.StdEncoding.EncodeToString(raw)) {
		t.Fatal("base64(gzip) past the cap was not withheld")
	}
}

// Control: a secret well under the cap is still caught.
func TestDaru6HeldGzipUnderCap(t *testing.T) {
	r := daru6Red()
	if !r.DeepContainsSecret(base64.StdEncoding.EncodeToString(daru6Gzip(1, daru6Secret))) {
		t.Fatal("under-cap gzip not caught")
	}
}

// Over-size input is withheld, not released unscanned (Daru6 P0-1).
func TestDaru6FixOversizeInputWithheld(t *testing.T) {
	r := daru6Red()
	s := strings.Repeat("a", 64<<20) + daru6Secret
	if !r.DeepContainsSecret(s) {
		t.Fatal("over-size input was not withheld")
	}
}

// Separated-byte-list text encodings are now decoded and withheld (Daru6 P2-4).
func TestDaru6FixCommonTextEncodingsClosed(t *testing.T) {
	r := daru6Red()
	var colon, xesc, uesc, dec []string
	for _, c := range []byte(daru6Secret) {
		colon = append(colon, fmt.Sprintf("%02x", c))
		xesc = append(xesc, fmt.Sprintf(`\x%02x`, c))
		uesc = append(uesc, fmt.Sprintf(`\u%04x`, c))
		dec = append(dec, fmt.Sprint(int(c)))
	}
	cases := map[string]string{
		"colon_hex":     strings.Join(colon, ":"),
		"space_hex":     strings.Join(colon, " "),
		"x_escape":      strings.Join(xesc, ""),
		"u_escape_text": "msg=" + strings.Join(uesc, ""),
		"decimal_csv":   strings.Join(dec, ","),
	}
	for name, payload := range cases {
		if !r.DeepContainsSecret(payload) {
			t.Fatalf("%s passed through unredacted", name)
		}
	}
}

// Registering one value many times adds exactly one raw entry (Daru6 P2-5).
func TestDaru6FixDuplicateRegistrationDeduped(t *testing.T) {
	r := New()
	for i := 0; i < 50; i++ {
		r.Add("fixture", daru6Secret)
	}
	if len(r.raws) != 1 {
		t.Fatalf("expected 1 raw entry after 50 identical Adds, got %d", len(r.raws))
	}
}

// The inflate budget bounds decode work: many gzip runs no longer burn CPU
// (Daru6 P1-3). The old path took 35s; budgeted it is well under 5s.
func TestDaru6FixManyGzipRunsBounded(t *testing.T) {
	r := daru6Red()
	// Each run is a >budget bomb (70 MiB of zeros), so the first one overflows the
	// inflate budget and the scan withholds immediately instead of inflating all 16
	// (~1 GiB, ~35 s unbounded). Threshold is generous for slow/shared CI runners;
	// the point is "bounded, not 16×", not a precise time.
	one := base64.StdEncoding.EncodeToString(daru6Gzip(70, "x"))
	s := strings.Repeat(one+";", 16)
	start := time.Now()
	_ = r.DeepContainsSecret(s)
	if el := time.Since(start); el >= 25*time.Second {
		t.Fatalf("scan took %s (>=25s): inflate budget not enforced", el)
	}
}

// Self-review P0: an unrelated leading hex digit or a trailing out-of-range decimal
// token must not discard the rest of the byte-list decode.
func TestDaru6FixByteListLocalRuns(t *testing.T) {
	r := daru6Red()
	var hexTok, decTok []string
	for _, c := range []byte(daru6Secret) {
		hexTok = append(hexTok, fmt.Sprintf("%02x", c))
		decTok = append(decTok, fmt.Sprint(int(c)))
	}
	if !r.DeepContainsSecret("a:" + strings.Join(hexTok, ":")) {
		t.Fatal("hex byte-list with a leading lone hex digit was not withheld")
	}
	if !r.DeepContainsSecret(strings.Join(decTok, ",") + ",999") {
		t.Fatal("decimal byte-list with a trailing out-of-range token was not withheld")
	}
}

// Self-review P0: a gzip whose first member has a bad checksum (so decompression
// stops) followed by a valid member containing the secret must be withheld — a
// read error after the gzip signature now fails closed.
func TestDaru6FixGzipMultistreamBadMemberWithheld(t *testing.T) {
	r := daru6Red()
	var m1 bytes.Buffer
	zw1 := gzip.NewWriter(&m1)
	_ = zw1.Close() // empty first member
	bad := m1.Bytes()
	bad[len(bad)-8] ^= 1 // corrupt member 1's checksum
	var m2 bytes.Buffer
	zw2 := gzip.NewWriter(&m2)
	_, _ = zw2.Write([]byte(daru6Secret))
	_ = zw2.Close()
	stream := append(append([]byte(nil), bad...), m2.Bytes()...)
	if !r.DeepContainsSecret(string(stream)) {
		t.Fatal("multistream gzip with a bad first member was not withheld")
	}
}

// Self-review P1: a huge decimal list must not amplify memory or burn CPU; the
// incremental parser + budget keep it fast.
func TestDaru6FixDecimalAmplificationBounded(t *testing.T) {
	r := daru6Red()
	s := strings.Repeat("0,", 8<<20) // 8M tokens
	start := time.Now()
	_ = r.DeepContainsSecret(s)
	if el := time.Since(start); el >= 25*time.Second {
		t.Fatalf("decimal scan took %s (>=25s): not incrementally bounded", el)
	}
}

// Self-review-2 P0: a gzip whose magic matches but whose header Go's reader
// rejects (another decompressor might accept it) must be withheld, not passed
// through. A truncated FEXTRA header makes gzip.NewReader fail.
func TestDaru6FixGzipBadHeaderWithheld(t *testing.T) {
	r := daru6Red()
	bad := []byte{0x1f, 0x8b, 0x08, 0x04, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff} // FEXTRA, XLEN=0xffff, no data
	if !r.DeepContainsSecret(string(bad)) {
		t.Fatal("a gzip-magic blob Go's header parser rejects was not withheld")
	}
}

// Self-review-3 P0: a mix of an escape and literal text ("\x53yntheticDaru…")
// reconstructs the secret; the escape is decoded with the literal tail preserved.
func TestDaru6FixMixedEscapeCaught(t *testing.T) {
	r := daru6Red()
	xmix := fmt.Sprintf(`\x%02x`, daru6Secret[0]) + daru6Secret[1:]
	if !r.DeepContainsSecret(xmix) {
		t.Fatal(`\xNN + literal tail was not withheld`)
	}
	umix := fmt.Sprintf(`\u%04x`, daru6Secret[0]) + daru6Secret[1:]
	if !r.DeepContainsSecret(umix) {
		t.Fatal(`\uNNNN + literal tail was not withheld`)
	}
}

// Self-review-2 P0: zero-padded decimal byte codes ("0090" == 90) are decoded;
// a token is invalid only if its VALUE exceeds a byte, not by digit count.
func TestDaru6FixZeroPaddedDecimalCaught(t *testing.T) {
	r := daru6Red()
	var toks []string
	for _, c := range []byte(daru6Secret) {
		toks = append(toks, fmt.Sprintf("%04d", int(c))) // 4-digit zero-padded
	}
	if !r.DeepContainsSecret(strings.Join(toks, ",")) {
		t.Fatal("zero-padded decimal byte list was not withheld")
	}
}
