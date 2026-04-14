//go:build !linux

package app

func shouldPreserveUserspaceWorkersOnClose() bool {
	return false
}
