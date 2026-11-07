//go:build linux && veer_kfuncs

package app

import (
	"os"
	"path/filepath"
	"testing"
)

// The name matches the optional-kernel-module CI filter (TestOptionalKernelModule.*).
func TestOptionalKernelModuleEmbeddedSourceExtracts(t *testing.T) {
	source, ok := kernelHelperEmbeddedSource()
	if !ok {
		t.Fatal("veer_kfuncs builds must embed the module source")
	}
	dir := t.TempDir()
	if err := extractKernelHelperSource(source, dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Kbuild", "Makefile", "build.sh", "veer_kfuncs.c"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Size() == 0 {
			t.Fatalf("extracted %s: %v", name, err)
		}
	}
}
