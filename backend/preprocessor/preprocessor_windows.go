package preprocessor

import (
	"path/filepath"
	"syscall"
)

func loadPreprocessor() (uintptr, error) {
	abs, err := filepath.Abs("../preprocessor/target/release/armorshield_preprocessor.dll")
	if err != nil {
		return uintptr(0x0), err
	}

	handle, err := syscall.LoadLibrary(abs)
	return uintptr(handle), err
}

func closeLibrary(handle uintptr) error {
	return syscall.FreeLibrary(syscall.Handle(handle))
}
