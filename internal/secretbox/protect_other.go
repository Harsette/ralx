//go:build !windows

package secretbox

// On Linux/macOS the daemon runs as a dedicated user and the key file is 0600
// inside a 0700 directory owned by that user; the file mode is the protection.
func protect(plain []byte) ([]byte, error) { return append([]byte(nil), plain...), nil }

func unprotect(blob []byte) ([]byte, error) { return append([]byte(nil), blob...), nil }
