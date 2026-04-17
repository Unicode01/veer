//go:build !linux

package managednet

import "fmt"

func PersistBridge(item ManagedNetwork) (PersistBridgeResult, error) {
	_ = item
	return PersistBridgeResult{}, fmt.Errorf("managed network bridge persistence is supported only on linux hosts")
}
