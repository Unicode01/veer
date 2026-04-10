//go:build !linux

package app

import "fmt"

func persistManagedNetworkBridge(item ManagedNetwork) (managedNetworkPersistBridgeResult, error) {
	_ = item
	return managedNetworkPersistBridgeResult{}, fmt.Errorf("managed network bridge persistence is supported only on linux hosts")
}
