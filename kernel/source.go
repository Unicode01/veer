// Package kernel embeds the optional veer_kfuncs helper source. Binaries
// built with -tags veer_kfuncs carry it so `veer kfuncs build` can rebuild the
// module for a new kernel from exactly the source this binary's probes expect.
//
// This file lives above veer_kfuncs/ on purpose: Go rejects a package
// directory that also holds .c files when cgo is enabled.
package kernel

import (
	"embed"
	"io/fs"
)

//go:embed veer_kfuncs/Kbuild veer_kfuncs/Makefile veer_kfuncs/build.sh veer_kfuncs/veer_kfuncs.c
var helperFiles embed.FS

// HelperSource returns the files kbuild needs plus the shared build script,
// rooted at the module directory.
func HelperSource() fs.FS {
	source, err := fs.Sub(helperFiles, "veer_kfuncs")
	if err != nil {
		panic(err)
	}
	return source
}
