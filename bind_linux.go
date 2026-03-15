//go:build linux

package main

import (
	"syscall"
)

func controlBindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var err error
		c.Control(func(fd uintptr) {
			err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		})
		return err
	}
}
