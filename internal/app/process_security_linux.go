//go:build linux

package app

import "golang.org/x/sys/unix"

func applySecureProcessUmask() {
	unix.Umask(0o077)
}
