//go:build windows

package runner

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

// afterStart puts the child in a job object that kills the whole process
// tree when RalX closes the job (on exit, timeout or cancel).
func afterStart(cmd *exec.Cmd) func() {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return func() {}
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, _ = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		_ = windows.AssignProcessToJobObject(job, h)
		windows.CloseHandle(h)
	}
	return func() { windows.CloseHandle(job) }
}
