//go:build !windows

package daemon

import (
	"os/exec"
	"testing"
)

func containProofProcess(t *testing.T, cmd *exec.Cmd) func() { return func() { cmd.Process.Kill() } }
