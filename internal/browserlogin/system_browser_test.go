package browserlogin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemBrowserIgnoresAgentPATH(t *testing.T) {
	fake := t.TempDir()
	for _, name := range []string{"chrome", "chrome.exe", "msedge", "msedge.exe", "google-chrome"} {
		if e := os.WriteFile(filepath.Join(fake, name), []byte("not a browser"), 0700); e != nil {
			t.Fatal(e)
		}
	}
	t.Setenv("PATH", fake)
	p, e := systemBrowser(false)
	if e != nil {
		t.Skip("no system Chrome/Edge installed")
	}
	if !filepath.IsAbs(p) || filepath.Dir(p) == fake {
		t.Fatal("agent PATH selected as privileged browser")
	}
}
