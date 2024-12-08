package preprocessor

import (
	"path/filepath"
	"syscall"
)

func loadPreprocessor() (uintptr, error) {
	abs, err := filepath.Abs("../protector_lib/target/release/protector_lib.dll")
	if err != nil {
		return uintptr(0x0), err
	}

	handle, err := syscall.LoadLibrary(abs)
	return uintptr(handle), err
}

func closeLibrary(handle uintptr) error {
	return syscall.FreeLibrary(syscall.Handle(handle))
}
