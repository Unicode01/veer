//go:build !linux

package managednet

import "github.com/vishvananda/netlink"

func RepairHostState(items []ManagedNetwork, opts RepairOptions) (RepairResult, error) {
	return RepairResult{}, nil
}

func LoadPVEBridgeBindings(opts RepairOptions) ([]PVEBridgeBinding, error) {
	return nil, nil
}

func LoadPVEGuestNICs(opts RepairOptions) ([]PVEGuestNIC, error) {
	return nil, nil
}

func LoadPVEConfigsFromGlobs(patterns []string) (map[string]string, error) {
	return nil, nil
}

func RepairPVEBridgeLinks(networks map[string]ManagedNetwork, bindings []PVEBridgeBinding, ops RepairLinkOps) (RepairResult, error) {
	return RepairResult{}, nil
}

func EnsureGuestLinkAttached(link netlink.Link, bridge netlink.Link, ops RepairLinkOps) (bool, error) {
	return false, nil
}
