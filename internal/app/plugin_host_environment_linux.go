//go:build linux

package app

import (
	"bytes"

	"golang.org/x/sys/unix"
)

func currentPluginKernelRelease() string {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return ""
	}
	raw := make([]byte, 0, len(uname.Release))
	for _, value := range uname.Release {
		if value == 0 {
			break
		}
		raw = append(raw, byte(value))
	}
	return string(bytes.TrimSpace(raw))
}
