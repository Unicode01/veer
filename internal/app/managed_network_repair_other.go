//go:build !linux

package app

func repairManagedNetworkHostState(items []ManagedNetwork) (managedNetworkRepairResult, error) {
	return managedNetworkRepairResult{}, nil
}

func loadManagedNetworkPVEBridgeBindings() ([]managedNetworkPVEBridgeBinding, error) {
	return nil, nil
}
