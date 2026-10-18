// Package leakscan searches everything an agent can reach (files, its own
// environment, other processes' command lines) for RalX's secrets without
// knowing them: the daemon hands out per-scan HMAC fingerprints of fixed-width
// windows of each secret, and the scanner HMACs candidate windows of what it
// reads. The window is wide enough (and secrets short enough are dropped) that
// the fingerprints are not a brute-force oracle, and the per-scan key stops
// precomputation or cross-scan correlation. It also flags well-known token
// shapes sitting in plaintext.
package leakscan

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

type Fingerprint struct {
	Label  string   `json:"label"`
	Hashes []string `json:"hashes"`
}

type Hit struct {
	Where  string `json:"where"`  // file path or "env:NAME" / "process:PID"
	Secret string `json:"secret"` // RalX credential label that matched
	Offset int64  `json:"offset"`
}

type ShapeHit struct {
	Where string `json:"where"`
	Kind  string `json:"kind"`
}

type Report struct {
	FilesScanned int64      `json:"files_scanned"`
	BytesScanned int64      `json:"bytes_scanned"`
	Hits         []Hit      `json:"ralx_secret_hits"`
	Shapes       []ShapeHit `json:"plaintext_token_shapes"`
	Skipped      int64      `json:"skipped"`
}

type Scanner struct {
	key     []byte
	window  int
	set     map[[32]byte]string // HMAC(window-bytes) -> label
	MaxFile int64
	mu      sync.Mutex
	rep     Report
	shapes  map[string]bool
}

var shapeRes = map[string]*regexp.Regexp{
	"google_access_token":  regexp.MustCompile(`ya29\.[0-9A-Za-z_\-]{30,}`),
	"google_refresh_token": regexp.MustCompile(`1//0[0-9A-Za-z_\-]{30,}`),
	"google_client_secret": regexp.MustCompile(`GOCSPX-[0-9A-Za-z_\-]{20,}`),
	"github_token":         regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36}`),
	"github_pat":           regexp.MustCompile(`github_pat_[0-9A-Za-z_]{60,}`),
}

func New(keyHex string, window int, fps []Fingerprint) *Scanner {
	key, _ := hex.DecodeString(keyHex)
	if window < 8 {
		window = 24
	}
	s := &Scanner{key: key, window: window, set: map[[32]byte]string{}, MaxFile: 64 << 20, shapes: map[string]bool{}}
	for _, f := range fps {
		for _, h := range f.Hashes {
			b, err := hex.DecodeString(h)
			if err != nil || len(b) != 32 {
				continue
			}
			var k [32]byte
			copy(k[:], b)
			s.set[k] = f.Label
		}
	}
	return s
}

// delimiters never occur inside the secrets RalX holds, so windows that
// contain one are skipped without hashing (a big speed-up on prose/code).
var delim = func() [256]bool {
	var t [256]bool
	for _, c := range " \t\r\n\"'`<>,;(){}[]\\|" {
		t[c] = true
	}
	return t
}()

// ScanBytes checks one buffer; where names the source.
func (s *Scanner) ScanBytes(where string, data []byte, base int64) {
	if len(s.set) > 0 {
		win := s.window
		mac := hmac.New(sha256.New, s.key)
		var sum [32]byte
		run := 0 // length of the current delimiter-free run
		for i := 0; i < len(data); i++ {
			if delim[data[i]] {
				run = 0
				continue
			}
			run++
			if run >= win {
				start := i - win + 1
				mac.Reset()
				mac.Write(data[start : i+1])
				mac.Sum(sum[:0])
				if label, ok := s.set[sum]; ok {
					s.mu.Lock()
					s.rep.Hits = append(s.rep.Hits, Hit{Where: where, Secret: label, Offset: base + int64(start)})
					s.mu.Unlock()
				}
			}
		}
	}
	for kind, re := range shapeRes {
		if re.Match(data) {
			key := where + "|" + kind
			s.mu.Lock()
			if !s.shapes[key] {
				s.shapes[key] = true
				s.rep.Shapes = append(s.rep.Shapes, ShapeHit{Where: where, Kind: kind})
			}
			s.mu.Unlock()
		}
	}
}

var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "__pycache__": true, ".venv": true, "venv": true,
	"go": false, "Cache": true, "Code Cache": true, "GPUCache": true, "ShaderCache": true,
	"WinSxS": true, "$Recycle.Bin": true,
}

var skipExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".mp4": true, ".mov": true, ".mkv": true,
	".mp3": true, ".wav": true, ".zip": true, ".7z": true, ".gz": true, ".exe": true, ".dll": true, ".msi": true,
	".iso": true, ".pdf": true, ".ttf": true, ".woff": true, ".woff2": true, ".psd": true, ".blend": true,
}

// ScanPath walks root and scans regular files up to MaxFile bytes.
func (s *Scanner) ScanPath(root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			s.mu.Lock()
			s.rep.Skipped++
			s.mu.Unlock()
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && p != root {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || skipExt[strings.ToLower(filepath.Ext(p))] {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > s.MaxFile || info.Size() == 0 {
			return nil
		}
		s.scanFile(p)
		return nil
	})
}

func (s *Scanner) scanFile(p string) {
	f, err := os.Open(p)
	if err != nil {
		s.mu.Lock()
		s.rep.Skipped++
		s.mu.Unlock()
		return
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	buf := make([]byte, 4<<20)
	overlap := 64
	var base int64
	carry := 0
	for {
		n, err := io.ReadFull(r, buf[carry:])
		total := carry + n
		if total > 0 {
			s.ScanBytes(p, buf[:total], base)
			s.mu.Lock()
			s.rep.BytesScanned += int64(n)
			s.mu.Unlock()
		}
		if err != nil {
			break
		}
		keep := overlap
		if keep > total {
			keep = total
		}
		copy(buf, buf[total-keep:total])
		base += int64(total - keep)
		carry = keep
	}
	s.mu.Lock()
	s.rep.FilesScanned++
	s.mu.Unlock()
}

// ScanEnv checks this process's environment (which an agent inherits).
func (s *Scanner) ScanEnv() {
	for _, kv := range os.Environ() {
		name := kv
		if i := strings.IndexByte(kv, '='); i > 0 {
			name = kv[:i]
		}
		s.ScanBytes("env:"+name, []byte(kv), 0)
	}
}

func (s *Scanner) Report() Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rep
	// de-duplicate overlapping-window hits on the same secret+place
	seen := map[string]bool{}
	var hits []Hit
	for _, h := range r.Hits {
		k := h.Where + "|" + h.Secret
		if !seen[k] {
			seen[k] = true
			hits = append(hits, h)
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Where < hits[j].Where })
	r.Hits = hits
	sort.Slice(r.Shapes, func(i, j int) bool { return r.Shapes[i].Where < r.Shapes[j].Where })
	return r
}
