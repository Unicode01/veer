//go:build !linux

package app

func newManagedNetworkRuntime() managedNetworkRuntime {
	return nil
}

func managedNetworkPreserveStateOnClose() bool {
	return false
}
