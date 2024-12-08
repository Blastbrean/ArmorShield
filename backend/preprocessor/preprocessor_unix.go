//go:build darwin || freebsd || linux

package preprocessor

import (
	"path/filepath"

	"github.com/ebitengine/purego"
)

func loadPreprocessor() (uintptr, error) {
	abs, err := filepath.Abs("../protector_lib/target/release/protector_lib.so")
	if err != nil {
		return uintptr(0x0), err
	}

	return purego.Dlopen(abs, purego.RTLD_NOW|purego.RTLD_GLOBAL)
}

func closeLibrary(handle uintptr) error {
	return purego.Dlclose(handle)
}
