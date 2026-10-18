//go:build !windows

package browserlogin

import "os"

func PrivateDir(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	return os.Chmod(path, 0700)
}
func PrivateFile(path string) error { return os.Chmod(path, 0600) }
