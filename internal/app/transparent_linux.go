//go:build linux

package app

import (
	"net"
	"syscall"
)

const ipTransparent = 19 // IP_TRANSPARENT

// controlTransparent returns a control function that sets IP_TRANSPARENT on the socket,
// allowing bind to a non-local IP address (the original client IP).
func controlTransparent(clientIP net.IP, outIface string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var err error
		c.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, ipTransparent, 1)
			if err != nil {
				return
			}
			if outIface != "" {
				_ = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, outIface)
			}
		})
		return err
	}
}

// transparentSupported returns true on Linux.
func transparentSupported() bool {
	return true
}
