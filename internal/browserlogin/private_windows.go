//go:build windows

package browserlogin

import (
	"golang.org/x/sys/windows"
	"os"
	"os/user"
)

func protect(path string) error {
	u, e := user.Current()
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + u.Uid + ")")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func PrivateDir(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	return protect(path)
}
func PrivateFile(path string) error { return protect(path) }
