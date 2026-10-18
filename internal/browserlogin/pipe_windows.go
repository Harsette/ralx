//go:build windows

package browserlogin

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func browserPipes(cmd *exec.Cmd, childRead, childWrite, parentRead, parentWrite *os.File) error {
	for _, f := range []*os.File{parentRead, parentWrite} {
		if e := syscall.SetHandleInformation(syscall.Handle(f.Fd()), syscall.HANDLE_FLAG_INHERIT, 0); e != nil {
			return e
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(childRead.Fd()), syscall.Handle(childWrite.Fd())}}
	cmd.Args = append(cmd.Args[:1], append([]string{fmt.Sprintf("--remote-debugging-io-pipes=%d,%d", childRead.Fd(), childWrite.Fd())}, cmd.Args[1:]...)...)
	return nil
}
