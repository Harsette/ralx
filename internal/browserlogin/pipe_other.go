//go:build !windows

package browserlogin

import (
	"os"
	"os/exec"
)

func browserPipes(cmd *exec.Cmd, childRead, childWrite, parentRead, parentWrite *os.File) error {
	cmd.ExtraFiles = []*os.File{childRead, childWrite}
	return nil
}
