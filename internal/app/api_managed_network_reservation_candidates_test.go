package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleListManagedNetworkReservationCandidatesUsesLoaderOverride(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadManagedNetworkReservationCandidatesForTests
	loadManagedNetworkReservationCandidatesForTests = func(networks []ManagedNetwork, reservations []ManagedNetworkReservation) ([]ManagedNetworkReservationCandidate, error) {
		return []ManagedNetworkReservationCandidate{{
			ManagedNetworkID:     2,
			ManagedNetworkName:   "vm100-lan",
			ManagedNetworkBridge: "vmbr10",
			ChildInterface:       "tap100i0",
			MACAddress:           "aa:bb:cc:dd:ee:ff",
			SuggestedIPv4:        "10.0.0.10",
			IPv4Candidates:       []string{"10.0.0.10", "10.0.0.11"},
			Status:               managedNetworkReservationCandidateStatusAvailable,
		}}, nil
	}
	defer func() {
		loadManagedNetworkReservationCandidatesForTests = oldLoad
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/managed-network-reservation-candidates", nil)
	w := httptest.NewRecorder()

	handleListManagedNetworkReservationCandidates(w, req, db)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []ManagedNetworkReservationCandidate
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp) != 1 || resp[0].ChildInterface != "tap100i0" || resp[0].SuggestedIPv4 != "10.0.0.10" {
		t.Fatalf("resp = %+v, want one discovered candidate", resp)
	}
	if len(resp[0].IPv4Candidates) != 2 || resp[0].IPv4Candidates[1] != "10.0.0.11" {
		t.Fatalf("resp[0].IPv4Candidates = %#v, want two preserved ipv4 candidates", resp[0].IPv4Candidates)
	}
}
