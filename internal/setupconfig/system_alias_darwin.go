package setupconfig

import (
	"os"
	"path/filepath"
	"syscall"
)

// macOS ships these root-owned links. Do not accept user-created aliases or
// resolve arbitrary links: configs, backups and receipts must stay together.
func macSystemAlias(path string, info os.FileInfo) bool {
	if path != "/var" && path != "/tmp" && path != "/etc" {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	target, err := os.Readlink(path)
	if err != nil {
		return false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join("/", target)
	}
	return filepath.Clean(target) == "/private"+path
}
