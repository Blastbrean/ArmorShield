package preprocessor

import "syscall"

func loadPreprocessor() (uintptr, error) {
	handle, err := syscall.LoadLibrary("../protector_lib/target/release/protector_lib.dll")
	return uintptr(handle), err
}

func closeLibrary(handle uintptr) error {
	return syscall.FreeLibrary(syscall.Handle(handle))
}
