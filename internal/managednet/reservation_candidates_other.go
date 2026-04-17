//go:build !linux

package managednet

import "github.com/vishvananda/netlink"

func DiscoverReservationCandidates(networks []ManagedNetwork, reservations []ManagedNetworkReservation, opts CandidateDiscoveryOptions) ([]ReservationCandidate, error) {
	return []ReservationCandidate{}, nil
}

func DiscoverReservationFDBMACs(networks []ManagedNetwork, infos []InterfaceInfo) ([]DiscoveredMAC, error) {
	return []DiscoveredMAC{}, nil
}

func DiscoverReservationObservedIPv4s(discovered []DiscoveredMAC, networks []ManagedNetwork) (map[string][]string, error) {
	return nil, nil
}

func CollectObservedIPv4sForNetwork(network ManagedNetwork, bridgeIndex int, memberIndexes map[int]struct{}, hostMACs map[string]struct{}, interestedMACs map[string]struct{}, neighbors []netlink.Neigh) map[string][]string {
	return nil
}
