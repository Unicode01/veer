//go:build !linux

package app

func discoverManagedNetworkReservationCandidates(networks []ManagedNetwork, reservations []ManagedNetworkReservation) ([]ManagedNetworkReservationCandidate, error) {
	return []ManagedNetworkReservationCandidate{}, nil
}
