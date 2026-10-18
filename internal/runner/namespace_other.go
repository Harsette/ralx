//go:build !linux && !windows

package runner

func namespaceDirectoryOwner(string, uint32, int, bool) bool { return false }
