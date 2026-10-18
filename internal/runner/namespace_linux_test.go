//go:build linux

package runner

import "testing"

func TestNamespaceRootTrustIsExplicitAndNarrow(t *testing.T) {
	if namespaceDirectoryOwner("/", 65534, 1000, false) {
		t.Fatal("default trusts namespace root")
	}
	for _, p := range []string{"/tmp", "/workspace", "/untrusted", "/tmp/tool"} {
		if namespaceDirectoryOwner(p, 65534, 1000, true) {
			t.Fatalf("trusted %s", p)
		}
	}
}

func TestSingleUserNamespaceOwner(t *testing.T) {
	for _, tc := range []struct {
		name, mapping, overflow string
		uid                     uint32
		self                    int
		want                    bool
	}{
		{"cloud", "1000 0 1\n", "65534\n", 65534, 1000, true},
		{"custom overflow", "1000 1000 1", "65533", 65533, 1000, true},
		{"initial namespace", "0 0 4294967295", "65534", 65534, 1000, false},
		{"mapped nobody", "65534 1000 1", "65534", 65534, 65534, false},
		{"root mapped", "0 1000 1", "65534", 65534, 0, false},
		{"other owner", "1000 0 1", "65534", 1001, 1000, false},
		{"multiple users", "1000 0 1\n65534 65534 1", "65534", 65534, 1000, false},
		{"range", "1000 0 2", "65534", 65534, 1000, false},
		{"wrong self", "1001 0 1", "65534", 65534, 1000, false},
		{"malformed map", "1000 x 1", "65534", 65534, 1000, false},
		{"missing map", "", "65534", 65534, 1000, false},
		{"invalid overflow", "1000 0 1", "", 65534, 1000, false},
		{"unmapped parent", "1000 4294967295 1", "65534", 65534, 1000, false},
		{"extra fields", "1000 0 1 4", "65534", 65534, 1000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := singleUserNamespaceOwner(tc.uid, tc.self, tc.mapping, tc.overflow); got != tc.want {
				t.Fatalf("accepted=%v, want %v", got, tc.want)
			}
		})
	}
}
