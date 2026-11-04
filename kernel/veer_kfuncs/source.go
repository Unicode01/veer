// Package veerkfuncs embeds the optional kernel helper source. Binaries built
// with -tags veer_kfuncs carry it so `veer kfuncs build` can rebuild the module
// for a new kernel from exactly the source this binary's probes expect.
package veerkfuncs

import "embed"

// Source holds the files kbuild needs plus the shared build script.
//
//go:embed Kbuild Makefile build.sh veer_kfuncs.c
var Source embed.FS
