package agent

import (
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

func ProtectCredential(plain []byte) ([]byte, error) {
	if len(plain) == 0 || len(plain) > 4096 {
		return nil, errors.New("invalid credential size")
	}
	input := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, errors.New("credential protection failed")
	}
	runtime.KeepAlive(plain)
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	if output.Data == nil || output.Size > 16384 {
		return nil, errors.New("invalid protected blob")
	}
	return append([]byte(nil), unsafe.Slice(output.Data, int(output.Size))...), nil
}
func UnprotectCredential(blob []byte) ([]byte, error) {
	if len(blob) == 0 || len(blob) > 16384 {
		return nil, errors.New("invalid protected credential size")
	}
	input := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, errors.New("credential unprotection failed")
	}
	runtime.KeepAlive(blob)
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	if output.Data == nil || output.Size > 4096 {
		return nil, errors.New("invalid credential output")
	}
	memory := unsafe.Slice(output.Data, int(output.Size))
	plain := append([]byte(nil), memory...)
	clear(memory)
	return plain, nil
}
