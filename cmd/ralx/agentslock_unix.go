//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

// tryLockFile takes an exclusive flock on f without waiting; false means
// another open file holds it. The kernel drops it when the file closes or
// the process exits.
func tryLockFile(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
