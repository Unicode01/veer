package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagedNetworkReservationPersistsInDBAndDeletesWithManagedNetwork(t *testing.T) {
	db := openTestDB(t)

	managedNetworkID, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:        "lab",
		Bridge:      "vmbr0",
		IPv4Enabled: true,
		IPv4CIDR:    "192.0.2.1/24",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	input := ManagedNetworkReservation{
		ManagedNetworkID: managedNetworkID,
		MACAddress:       "aa:bb:cc:dd:ee:ff",
		IPv4Address:      "192.0.2.10",
		Remark:           "vm100",
	}
	id, err := dbAddManagedNetworkReservation(db, &input)
	if err != nil {
		t.Fatalf("dbAddManagedNetworkReservation() error = %v", err)
	}

	item, err := dbGetManagedNetworkReservation(db, id)
	if err != nil {
		t.Fatalf("dbGetManagedNetworkReservation() error = %v", err)
	}
	if item.ManagedNetworkID != managedNetworkID || item.MACAddress != input.MACAddress || item.IPv4Address != input.IPv4Address {
		t.Fatalf("item = %+v, want persisted managed network reservation", item)
	}

	if err := dbDeleteManagedNetwork(db, managedNetworkID); err != nil {
		t.Fatalf("dbDeleteManagedNetwork(%d) error = %v", managedNetworkID, err)
	}
	if _, err := dbGetManagedNetworkReservation(db, id); err == nil {
		t.Fatalf("dbGetManagedNetworkReservation(%d) succeeded after managed network delete", id)
	}
}

func TestHandleListManagedNetworkReservationsIncludesManagedNetworkDetails(t *testing.T) {
	db := openTestDB(t)

	managedNetworkID, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:        "lab",
		Bridge:      "vmbr0",
		IPv4Enabled: true,
		IPv4CIDR:    "192.0.2.1/24",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}
	if _, err := dbAddManagedNetworkReservation(db, &ManagedNetworkReservation{
		ManagedNetworkID: managedNetworkID,
		MACAddress:       "aa:bb:cc:dd:ee:ff",
		IPv4Address:      "192.0.2.10",
		Remark:           "vm100",
	}); err != nil {
		t.Fatalf("dbAddManagedNetworkReservation() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/managed-network-reservations", nil)
	w := httptest.NewRecorder()

	handleListManagedNetworkReservations(w, req, db)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var items []ManagedNetworkReservationStatus
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if items[0].ManagedNetworkName != "lab" || items[0].ManagedNetworkBridge != "vmbr0" {
		t.Fatalf("item = %+v, want managed network details", items[0])
	}
}

func TestHandleAddManagedNetworkReservationValidationErrorIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPost, "/api/managed-network-reservations", ManagedNetworkReservation{})
	w := httptest.NewRecorder()

	handleAddManagedNetworkReservation(w, req, db, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "create", "managed_network_id", "is required")
}

func TestHandleUpdateManagedNetworkReservationNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPut, "/api/managed-network-reservations", ManagedNetworkReservation{
		ID:               404,
		ManagedNetworkID: 1,
		MACAddress:       "aa:bb:cc:dd:ee:ff",
		IPv4Address:      "192.0.2.10",
	})
	w := httptest.NewRecorder()

	handleUpdateManagedNetworkReservation(w, req, db, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "update", "id", "managed network reservation not found")
}

func TestHandleDeleteManagedNetworkReservationNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodDelete, "/api/managed-network-reservations?id=404", nil)
	w := httptest.NewRecorder()

	handleDeleteManagedNetworkReservation(w, req, db, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "delete", "id", "managed network reservation not found")
}

func TestLoadManagedNetworkReservationCandidatesUsesEnabledNetworkScope(t *testing.T) {
	db := openTestDB(t)

	enabledID, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:        "enabled",
		Bridge:      "vmbr0",
		IPv4Enabled: true,
		IPv4CIDR:    "192.0.2.1/24",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("dbAddManagedNetwork(enabled) error = %v", err)
	}
	disabledID, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:        "disabled",
		Bridge:      "vmbr1",
		IPv4Enabled: true,
		IPv4CIDR:    "192.0.3.1/24",
		Enabled:     false,
	})
	if err != nil {
		t.Fatalf("dbAddManagedNetwork(disabled) error = %v", err)
	}
	if _, err := dbAddManagedNetworkReservation(db, &ManagedNetworkReservation{
		ManagedNetworkID: enabledID,
		MACAddress:       "aa:bb:cc:dd:ee:01",
		IPv4Address:      "192.0.2.10",
	}); err != nil {
		t.Fatalf("dbAddManagedNetworkReservation(enabled) error = %v", err)
	}
	if _, err := dbAddManagedNetworkReservation(db, &ManagedNetworkReservation{
		ManagedNetworkID: disabledID,
		MACAddress:       "aa:bb:cc:dd:ee:02",
		IPv4Address:      "192.0.3.10",
	}); err != nil {
		t.Fatalf("dbAddManagedNetworkReservation(disabled) error = %v", err)
	}

	oldLoad := loadManagedNetworkReservationCandidatesForTests
	var (
		gotNetworks     []ManagedNetwork
		gotReservations []ManagedNetworkReservation
	)
	loadManagedNetworkReservationCandidatesForTests = func(networks []ManagedNetwork, reservations []ManagedNetworkReservation) ([]ManagedNetworkReservationCandidate, error) {
		gotNetworks = append([]ManagedNetwork(nil), networks...)
		gotReservations = append([]ManagedNetworkReservation(nil), reservations...)
		return []ManagedNetworkReservationCandidate{}, nil
	}
	defer func() {
		loadManagedNetworkReservationCandidatesForTests = oldLoad
	}()

	items, err := loadManagedNetworkReservationCandidates(db)
	if err != nil {
		t.Fatalf("loadManagedNetworkReservationCandidates() error = %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("len(items) = %d, want 0 from test loader", len(items))
	}
	if len(gotNetworks) != 1 || gotNetworks[0].ID != enabledID {
		t.Fatalf("gotNetworks = %+v, want only enabled managed network #%d", gotNetworks, enabledID)
	}
	if len(gotReservations) != 1 || gotReservations[0].ManagedNetworkID != enabledID {
		t.Fatalf("gotReservations = %+v, want only reservations for enabled managed network #%d", gotReservations, enabledID)
	}
}
