//go:build windows

package daemon

import (
	"golang.org/x/sys/windows"
	"os/exec"
	"testing"
	"time"
	"unsafe"
)

// The job contains only the daemon this test just started and its descendants.
func containProofProcess(t *testing.T, cmd *exec.Cmd) func() {
	t.Helper()
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		cmd.Process.Kill()
		t.Fatal(e)
	}
	fail := func(e error) { windows.CloseHandle(job); cmd.Process.Kill(); t.Fatal(e) }
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
		fail(e)
	}
	process, e := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if e != nil {
		fail(e)
	}
	e = windows.AssignProcessToJobObject(job, process)
	windows.CloseHandle(process)
	if e != nil {
		fail(e)
	}
	return func() {
		windows.TerminateJobObject(job, 1)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var info struct {
				TotalUser, TotalKernel, PeriodUser, PeriodKernel                 int64
				PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses uint32
			}
			if e := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); e == nil && info.ActiveProcesses == 0 {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		windows.CloseHandle(job)
	}
}
