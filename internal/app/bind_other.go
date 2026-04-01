//go:build !linux

package app

import "syscall"

func controlBindToDevice(_ string) func(network, address string, c syscall.RawConn) error {
	return nil
}
