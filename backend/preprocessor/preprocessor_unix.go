//go:build darwin || freebsd || linux

package preprocessor

import "github.com/ebitengine/purego"

func loadPreprocessor() (uintptr, error) {
	return purego.Dlopen("../protector_lib/target/release/protector_lib.so", purego.RTLD_NOW|purego.RTLD_GLOBAL)
}

func closeLibrary(handle uintptr) error {
	return purego.Dlclose(handle)
}
