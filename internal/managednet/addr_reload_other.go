//go:build !linux

package managednet

func CanSkipAddrReload(managedNetworks []ManagedNetwork, reservations []ManagedNetworkReservation) bool {
	_ = managedNetworks
	_ = reservations
	return true
}
