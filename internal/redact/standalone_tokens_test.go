package redact

import (
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var standaloneTokenReferences = [2]*regexp.Regexp{
	regexp.MustCompile(`[A-Za-z0-9+/_\-]{11,}={0,6}`),
	regexp.MustCompile(`[A-Za-z0-9+/]{11,}={0,6}`),
}

func checkStandaloneTokens(t testing.TB, s string) {
	t.Helper()
	var wantBoth, gotBoth []string
	for pass, re := range standaloneTokenReferences {
		want := re.FindAllString(s, -1)
		got := standaloneTokens(s, pass == 1)
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("standard=%v input=%q: got %q, want %q", pass == 1, s, got, want)
		}
		wantBoth = append(wantBoth, want...)
		gotBoth = append(gotBoth, got...)
	}
	if !reflect.DeepEqual(wantBoth, gotBoth) {
		t.Fatalf("two-pass order or multiplicity differs for %q", s)
	}
}

func TestStandaloneTokensMatchRegex(t *testing.T) {
	separators := []string{"", " ", "\t", "\n", "\r\n", `\r\n`, ".", ",", "_", "-", "=", "=======", "é", "中", "😀", "\u00a0", "\u2028", "\x00", string([]byte{0xff, 0xfe})}
	for n := 0; n <= 20; n++ {
		for padding := 0; padding <= 9; padding++ {
			for _, sep := range separators {
				run := strings.Repeat("A", n) + strings.Repeat("=", padding)
				checkStandaloneTokens(t, run)
				checkStandaloneTokens(t, "!"+run+sep+strings.Repeat("b", 11)+"=======")
				checkStandaloneTokens(t, strings.Repeat("c", 12)+sep+run+"!")
			}
		}
	}
	for _, s := range []string{
		"", "!", "中文", string([]byte{0xff, 0xfe, 0, 0x80}),
		strings.Repeat("x", 100000) + "=======",
		"ABCDEFGHIJK_abcdefghijk-12345678901",
		"ABCDEFGHIJK=ABCDEFGHIJK", "ABCDEFGHIJKABCDEFGHIJK", "ABCDEFGHIJK!ABCDEFGHIJK",
	} {
		checkStandaloneTokens(t, s)
	}
	rng := rand.New(rand.NewSource(537))
	alphabet := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-")
	for n := 0; n < 5000; n++ {
		var b strings.Builder
		for j, runs := 0, 1+rng.Intn(12); j < runs; j++ {
			for k, size := 0, rng.Intn(60); k < size; k++ {
				b.WriteByte(alphabet[rng.Intn(len(alphabet))])
			}
			b.WriteString(strings.Repeat("=", rng.Intn(10)))
			b.WriteString(separators[rng.Intn(len(separators))])
		}
		checkStandaloneTokens(t, b.String())
	}
	for n := 0; n < 2000; n++ {
		b := make([]byte, rng.Intn(256))
		_, _ = rng.Read(b)
		checkStandaloneTokens(t, string(b))
	}
}

func FuzzStandaloneTokensMatchRegex(f *testing.F) {
	for _, s := range []string{"", "ABCDEFGHIJK=======abcdefghijkl", "ABCDEFGHIJK_abcdefghijk-12345678901", "éABCDEFGHIJK😀abcdefghijkl", string([]byte{0xff, 0xfe})} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { checkStandaloneTokens(t, s) })
}
