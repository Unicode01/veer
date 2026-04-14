//go:build linux

package app

func canSkipManagedNetworkAddrReload(managedNetworks []ManagedNetwork, reservations []ManagedNetworkReservation) bool {
	if len(managedNetworks) == 0 {
		return true
	}

	reservationsByNetwork := make(map[int64][]ManagedNetworkReservation)
	for _, item := range reservations {
		if item.ManagedNetworkID <= 0 {
			continue
		}
		reservationsByNetwork[item.ManagedNetworkID] = append(reservationsByNetwork[item.ManagedNetworkID], item)
	}

	for _, network := range managedNetworks {
		network = normalizeManagedNetwork(network)
		if !network.Enabled || !network.IPv4Enabled {
			continue
		}
		plan, err := buildManagedNetworkIPv4Plan(network, reservationsByNetwork[network.ID])
		if err != nil {
			return false
		}
		link, addr, err := linuxManagedNetworkIPv4AddressFromSpec(plan.AddressSpec)
		if err != nil {
			return false
		}
		present, err := linuxManagedNetworkHasIPv4Address(link, addr)
		if err != nil || !present {
			return false
		}
	}

	return true
}
