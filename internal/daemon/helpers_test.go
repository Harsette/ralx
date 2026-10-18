package daemon

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// bytesInDir reports whether needle appears in any file under dir.
func bytesInDir(t *testing.T, dir, needle string) bool {
	t.Helper()
	found := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err == nil && bytes.Contains(b, []byte(needle)) {
			t.Logf("found in %s", p)
			found = true
		}
		return nil
	})
	return found
}
