package browserlogin

import (
	"path/filepath"
	"testing"
)

func TestMacBrowserCandidates(t *testing.T) {
	home := t.TempDir()
	chrome, edge := macBrowserCandidates(home)
	if len(chrome) != 8 || len(edge) != 2 {
		t.Fatalf("missing browser locations: %v %v", chrome, edge)
	}
	for i, root := range []string{"/Applications", filepath.Join(home, "Applications")} {
		for j, bundle := range []string{"Google Chrome.app/Contents/MacOS/Google Chrome", "Chromium.app/Contents/MacOS/Chromium", "Brave Browser.app/Contents/MacOS/Brave Browser", "Arc.app/Contents/MacOS/Arc"} {
			if chrome[i*4+j] != filepath.Join(root, bundle) {
				t.Fatalf("browser missing from %s: %s", root, bundle)
			}
		}
		if edge[i] != filepath.Join(root, "Microsoft Edge.app/Contents/MacOS/Microsoft Edge") {
			t.Fatal("Edge missing")
		}
	}
}
