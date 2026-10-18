//go:build linux

package runner

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// An explicitly trusted managed sandbox may supply a read-only root whose
// owner is unmapped. Never extend this trust to /tmp, another directory or a
// regular file: an ordinary outside user could own those and replace entries.
func namespaceDirectoryOwner(path string, uid uint32, self int, trustedSandbox bool) bool {
	if !trustedSandbox || path != "/" {
		return false
	}
	var fs unix.Statfs_t
	if unix.Statfs(path, &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 {
		return false
	}
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false
	}
	overflow, err := os.ReadFile("/proc/sys/kernel/overflowuid")
	if err != nil {
		return false
	}
	return singleUserNamespaceOwner(uid, self, string(uidMap), string(overflow))
}

func singleUserNamespaceOwner(uid uint32, self int, uidMap, overflow string) bool {
	o, err := strconv.ParseUint(strings.TrimSpace(overflow), 10, 32)
	if err != nil || uint64(uid) != o || self < 0 || uint64(self) == o {
		return false
	}
	lines := strings.Split(strings.TrimSpace(uidMap), "\n")
	if len(lines) != 1 {
		return false
	}
	fields := strings.Fields(lines[0])
	if len(fields) != 3 {
		return false
	}
	var ids [3]uint64
	for i, field := range fields {
		ids[i], err = strconv.ParseUint(field, 10, 32)
		if err != nil || ids[i] == 1<<32-1 {
			return false
		}
	}
	// Require exactly the daemon UID, with neither root nor overflowuid mapped.
	return ids[0] == uint64(self) && ids[0] != 0 && ids[2] == 1
}
