//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Harsette/ralx/internal/leakscan"
)

func programData() string { return "/var/lib" }

func isService() bool { return false }

func runService() {}

func relaunchElevated(args []string) error {
	return errors.New("run this with sudo")
}

func scanProcesses(s *leakscan.Scanner) {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline")); err == nil {
			s.ScanBytes("process:"+e.Name(), []byte(strings.ReplaceAll(string(b), "\x00", " ")), 0)
		}
		if b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "environ")); err == nil {
			s.ScanBytes("process-env:"+e.Name(), b, 0)
		}
	}
}

func cmdInstall(ctx context.Context, args []string) error {
	return errors.New("on Linux, install with deploy/linux/install.sh (systemd unit + dedicated ralx user)")
}

func cmdUninstall(ctx context.Context, args []string) error {
	return errors.New("on Linux: systemctl disable --now ralx && userdel ralx")
}

func setupHarnesses(home string) error { return nil }
