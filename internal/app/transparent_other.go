//go:build !linux

package app

import (
	"net"
	"syscall"
)

func controlTransparent(_ net.IP, _ string) func(network, address string, c syscall.RawConn) error {
	return nil
}

func transparentSupported() bool {
	return false
}
