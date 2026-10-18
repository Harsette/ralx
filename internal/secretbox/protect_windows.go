//go:build windows

package secretbox

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPI in the daemon account's own user scope: only the RalX service account
// (or someone who already controls the machine) can unwrap the master key.
func protect(plain []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var out windows.DataBlob
	desc, _ := windows.UTF16PtrFromString("RalX vault master key")
	if err := windows.CryptProtectData(&in, desc, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func unprotect(blob []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
