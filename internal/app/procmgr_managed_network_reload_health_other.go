//go:build !linux

package app

func canSkipManagedNetworkAddrReload(managedNetworks []ManagedNetwork, reservations []ManagedNetworkReservation) bool {
	return true
}
