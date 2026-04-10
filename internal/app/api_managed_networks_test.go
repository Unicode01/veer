package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"
)

type fakeManagedNetworkRuntime struct {
	reconcileCalls   int
	lastItems        []ManagedNetwork
	lastReservations []ManagedNetworkReservation
	reconcileErr     error
	statuses         map[int64]managedNetworkRuntimeStatus
}

func (rt *fakeManagedNetworkRuntime) Reconcile(items []ManagedNetwork, reservations []ManagedNetworkReservation) error {
	rt.reconcileCalls++
	rt.lastItems = append([]ManagedNetwork(nil), items...)
	rt.lastReservations = append([]ManagedNetworkReservation(nil), reservations...)
	return rt.reconcileErr
}

func (rt *fakeManagedNetworkRuntime) SnapshotStatus() map[int64]managedNetworkRuntimeStatus {
	if len(rt.statuses) == 0 {
		return nil
	}
	out := make(map[int64]managedNetworkRuntimeStatus, len(rt.statuses))
	for id, status := range rt.statuses {
		out[id] = status
	}
	return out
}

func (rt *fakeManagedNetworkRuntime) Close() error {
	return nil
}

func TestManagedNetworkPersistsInDB(t *testing.T) {
	db := openTestDB(t)

	input := ManagedNetwork{
		Name:                "vmbr0 managed",
		BridgeMode:          managedNetworkBridgeModeCreate,
		Bridge:              "vmbr0",
		BridgeMTU:           9000,
		BridgeVLANAware:     true,
		UplinkInterface:     "eno1",
		IPv4Enabled:         true,
		IPv4CIDR:            "192.0.2.1/24",
		IPv4Gateway:         "192.0.2.1",
		IPv4PoolStart:       "192.0.2.100",
		IPv4PoolEnd:         "192.0.2.200",
		IPv4DNSServers:      "1.1.1.1,8.8.8.8",
		IPv6Enabled:         true,
		IPv6ParentInterface: "vmbr0",
		IPv6ParentPrefix:    "2001:db8::/64",
		IPv6AssignmentMode:  "prefix_64",
		AutoEgressNAT:       true,
		Remark:              "lab",
		Enabled:             true,
	}
	id, err := dbAddManagedNetwork(db, &input)
	if err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	item, err := dbGetManagedNetwork(db, id)
	if err != nil {
		t.Fatalf("dbGetManagedNetwork() error = %v", err)
	}
	if item.Name != input.Name || item.BridgeMode != input.BridgeMode || item.Bridge != input.Bridge || item.IPv6AssignmentMode != managedNetworkIPv6AssignmentModePrefix64 {
		t.Fatalf("item = %+v, want persisted managed network", item)
	}
	if item.BridgeMTU != 9000 || !item.BridgeVLANAware {
		t.Fatalf("bridge config = %+v, want mtu=9000 vlan-aware=true", item)
	}
	if !item.IPv4Enabled || !item.IPv6Enabled || !item.AutoEgressNAT || !item.Enabled {
		t.Fatalf("bool fields = %+v, want true values preserved", item)
	}
}

func TestManagedNetworkExistingBridgeIgnoresCreateOnlyBridgeConfig(t *testing.T) {
	db := openTestDB(t)

	input := ManagedNetwork{
		Name:            "vmbr1 existing",
		BridgeMode:      managedNetworkBridgeModeExisting,
		Bridge:          "vmbr1",
		BridgeMTU:       9000,
		BridgeVLANAware: true,
		Enabled:         true,
	}
	id, err := dbAddManagedNetwork(db, &input)
	if err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	item, err := dbGetManagedNetwork(db, id)
	if err != nil {
		t.Fatalf("dbGetManagedNetwork() error = %v", err)
	}
	if item.BridgeMode != managedNetworkBridgeModeExisting {
		t.Fatalf("BridgeMode = %q, want %q", item.BridgeMode, managedNetworkBridgeModeExisting)
	}
	if item.BridgeMTU != 0 || item.BridgeVLANAware {
		t.Fatalf("bridge config = %+v, want existing bridge to keep zero-value managed config", item)
	}
}

func TestHandleListManagedNetworksReturnsSortedItems(t *testing.T) {
	db := openTestDB(t)

	secondID, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:    "second",
		Bridge:  "vmbr1",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed second managed network: %v", err)
	}
	firstID, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:    "first",
		Bridge:  "vmbr0",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed first managed network: %v", err)
	}
	if !(firstID > 0 && secondID > 0) {
		t.Fatalf("unexpected ids: first=%d second=%d", firstID, secondID)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/managed-networks", nil)
	w := httptest.NewRecorder()

	handleListManagedNetworks(w, req, db, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var items []ManagedNetworkStatus
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(items))
	}
	if items[0].ID != secondID || items[1].ID != firstID {
		t.Fatalf("items ids = [%d %d], want [%d %d]", items[0].ID, items[1].ID, secondID, firstID)
	}
}

func TestHandleListManagedNetworksIncludesDerivedPreview(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadInterfaceInfosForManagedNetworkPreviewTests
	loadInterfaceInfosForManagedNetworkPreviewTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "eno1", Kind: "device"},
			{Name: "vmbr0", Kind: "bridge"},
			{Name: "tap100i0", Parent: "vmbr0", Kind: "tap"},
			{Name: "tap101i0", Parent: "vmbr0", Kind: "tap"},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForManagedNetworkPreviewTests = oldLoad
	}()

	_, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:                "lab",
		Bridge:              "vmbr0",
		UplinkInterface:     "eno1",
		IPv6Enabled:         true,
		IPv6ParentInterface: "vmbr0",
		IPv6ParentPrefix:    "2001:db8:100::/64",
		IPv6AssignmentMode:  managedNetworkIPv6AssignmentModeSingle128,
		AutoEgressNAT:       true,
		Enabled:             true,
	})
	if err != nil {
		t.Fatalf("seed managed network: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/managed-networks", nil)
	w := httptest.NewRecorder()

	handleListManagedNetworks(w, req, db, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var items []ManagedNetworkStatus
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if items[0].ChildInterfaceCount != 2 {
		t.Fatalf("ChildInterfaceCount = %d, want 2", items[0].ChildInterfaceCount)
	}
	if !reflect.DeepEqual(items[0].ChildInterfaces, []string{"tap100i0", "tap101i0"}) {
		t.Fatalf("ChildInterfaces = %v, want [tap100i0 tap101i0]", items[0].ChildInterfaces)
	}
	if items[0].GeneratedIPv6AssignmentCount != 2 {
		t.Fatalf("GeneratedIPv6AssignmentCount = %d, want 2", items[0].GeneratedIPv6AssignmentCount)
	}
	if !items[0].GeneratedEgressNAT {
		t.Fatalf("GeneratedEgressNAT = %v, want true", items[0].GeneratedEgressNAT)
	}
	if len(items[0].PreviewWarnings) != 0 {
		t.Fatalf("PreviewWarnings = %v, want none", items[0].PreviewWarnings)
	}
}

func TestHandleListManagedNetworksMarksRepairRecommended(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadInterfaceInfosForManagedNetworkPreviewTests
	loadInterfaceInfosForManagedNetworkPreviewTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "eno1", Kind: "device"},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForManagedNetworkPreviewTests = oldLoad
	}()

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:    "lab",
		Bridge:  "vmbr1",
		Enabled: true,
	}); err != nil {
		t.Fatalf("seed managed network: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/managed-networks", nil)
	w := httptest.NewRecorder()

	handleListManagedNetworks(w, req, db, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var items []ManagedNetworkStatus
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if !items[0].RepairRecommended {
		t.Fatalf("RepairRecommended = %v, want true", items[0].RepairRecommended)
	}
	if !sliceContainsString(items[0].RepairIssues, "bridge vmbr1 is missing from current host interfaces") {
		t.Fatalf("RepairIssues = %v, want missing bridge issue", items[0].RepairIssues)
	}
}

func TestHandleListManagedNetworksIncludesRuntimeStatus(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadInterfaceInfosForManagedNetworkPreviewTests
	loadInterfaceInfosForManagedNetworkPreviewTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "eno1", Kind: "device"},
			{Name: "vmbr0", Kind: "bridge"},
			{Name: "tap100i0", Parent: "vmbr0", Kind: "tap"},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForManagedNetworkPreviewTests = oldLoad
	}()

	id, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:                "lab",
		Bridge:              "vmbr0",
		UplinkInterface:     "eno1",
		IPv4Enabled:         true,
		IPv4CIDR:            "192.0.2.1/24",
		IPv6Enabled:         true,
		IPv6ParentInterface: "vmbr0",
		IPv6ParentPrefix:    "2001:db8:100::/64",
		IPv6AssignmentMode:  managedNetworkIPv6AssignmentModeSingle128,
		Enabled:             true,
	})
	if err != nil {
		t.Fatalf("seed managed network: %v", err)
	}
	if _, err := dbAddManagedNetworkReservation(db, &ManagedNetworkReservation{
		ManagedNetworkID: id,
		MACAddress:       "02:00:00:00:00:01",
		IPv4Address:      "192.0.2.10",
		Remark:           "reserved",
	}); err != nil {
		t.Fatalf("seed managed network reservation: %v", err)
	}

	pm := &ProcessManager{
		managedNetworkRuntime: &fakeManagedNetworkRuntime{
			statuses: map[int64]managedNetworkRuntimeStatus{
				id: {
					RuntimeStatus:    "running",
					RuntimeDetail:    "dhcpv4 listener active",
					DHCPv4ReplyCount: 4,
				},
			},
		},
		ipv6Runtime: &fakeIPv6AssignmentRuntime{
			stats: map[int64]ipv6AssignmentRuntimeStats{
				managedNetworkSyntheticID("ipv6", id, "tap100i0"): {
					RuntimeStatus:        "draining",
					RuntimeDetail:        "waiting for router advertisement refresh",
					RAAdvertisementCount: 9,
					DHCPv6ReplyCount:     2,
				},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/managed-networks", nil)
	w := httptest.NewRecorder()

	handleListManagedNetworks(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var items []ManagedNetworkStatus
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if items[0].ReservationCount != 1 {
		t.Fatalf("ReservationCount = %d, want 1", items[0].ReservationCount)
	}
	if items[0].IPv4RuntimeStatus != "running" || items[0].IPv4RuntimeDetail != "dhcpv4 listener active" || items[0].IPv4DHCPv4ReplyCount != 4 {
		t.Fatalf("ipv4 runtime = %+v, want merged ipv4 runtime fields", items[0])
	}
	if items[0].IPv6RuntimeStatus != "draining" || items[0].IPv6RuntimeDetail != "assignment #"+strconv.FormatInt(managedNetworkSyntheticID("ipv6", id, "tap100i0"), 10)+": waiting for router advertisement refresh" {
		t.Fatalf("ipv6 runtime = %+v, want aggregated ipv6 runtime fields", items[0])
	}
	if items[0].IPv6RAAdvertisementCount != 9 || items[0].IPv6DHCPv6ReplyCount != 2 {
		t.Fatalf("ipv6 counts = %+v, want merged ipv6 counters", items[0])
	}
}

func TestAggregateManagedNetworkIPv6RuntimeStatusPreservesAssignmentOrder(t *testing.T) {
	t.Parallel()

	status, detail, raCount, dhcpCount := aggregateManagedNetworkIPv6RuntimeStatus(
		[]int64{10, 2, 30},
		map[int64]ipv6AssignmentRuntimeStats{
			10: {
				RuntimeStatus:        "running",
				RuntimeDetail:        "router advertisement active",
				RAAdvertisementCount: 3,
			},
			2: {
				RuntimeStatus:    "draining",
				RuntimeDetail:    "waiting for parent route",
				DHCPv6ReplyCount: 7,
			},
		},
	)
	if status != "draining" {
		t.Fatalf("status = %q, want draining", status)
	}
	if detail != "assignment #10: router advertisement active; assignment #2: waiting for parent route; assignment #30: waiting for runtime apply" {
		t.Fatalf("detail = %q, want assignment-ordered runtime details", detail)
	}
	if raCount != 3 || dhcpCount != 7 {
		t.Fatalf("counts = (%d, %d), want (3, 7)", raCount, dhcpCount)
	}
}

func TestHandleAddManagedNetworkValidationErrorIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPost, "/api/managed-networks", ManagedNetwork{})
	w := httptest.NewRecorder()

	handleAddManagedNetwork(w, req, db, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "create", "name", "is required")
}

func TestHandleAddManagedNetworkRejectsMissingExistingBridge(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadHostNetworkInterfacesForManagedNetworkTests
	loadHostNetworkInterfacesForManagedNetworkTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{{Name: "vmbr0", Kind: "bridge"}}, nil
	}
	defer func() {
		loadHostNetworkInterfacesForManagedNetworkTests = oldLoad
	}()

	req := newJSONRequest(t, http.MethodPost, "/api/managed-networks", ManagedNetwork{
		Name:       "lab",
		BridgeMode: managedNetworkBridgeModeExisting,
		Bridge:     "vmbr9",
	})
	w := httptest.NewRecorder()

	handleAddManagedNetwork(w, req, db, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "create", "bridge", "bridge interface does not exist on this host")
}

func TestHandleAddManagedNetworkRejectsInvalidBridgeMTU(t *testing.T) {
	db := openTestDB(t)

	req := newJSONRequest(t, http.MethodPost, "/api/managed-networks", ManagedNetwork{
		Name:       "lab",
		BridgeMode: managedNetworkBridgeModeCreate,
		Bridge:     "vmbr9",
		BridgeMTU:  70000,
	})
	w := httptest.NewRecorder()

	handleAddManagedNetwork(w, req, db, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "create", "bridge_mtu", "bridge_mtu must be between 0 and 65535")
}

func TestHandleUpdateManagedNetworkNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPut, "/api/managed-networks", ManagedNetwork{
		ID:                 404,
		Name:               "managed",
		Bridge:             "vmbr0",
		IPv6AssignmentMode: managedNetworkIPv6AssignmentModeSingle128,
	})
	w := httptest.NewRecorder()

	handleUpdateManagedNetwork(w, req, db, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "update", "id", "managed network not found")
}

func TestHandleDeleteManagedNetworkNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodDelete, "/api/managed-networks?id=404", nil)
	w := httptest.NewRecorder()

	handleDeleteManagedNetwork(w, req, db, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "delete", "id", "managed network not found")
}

func TestHandleToggleManagedNetworkNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPost, "/api/managed-networks/toggle?id=404", nil)
	w := httptest.NewRecorder()

	handleToggleManagedNetwork(w, req, db, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "toggle", "id", "managed network not found")
}

func TestHandleToggleManagedNetworkFlipsEnabledState(t *testing.T) {
	db := openTestDB(t)

	id, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:    "managed",
		Bridge:  "vmbr0",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed managed network: %v", err)
	}

	req := newJSONRequest(t, http.MethodPost, "/api/managed-networks/toggle?id="+strconv.FormatInt(id, 10), nil)
	w := httptest.NewRecorder()

	handleToggleManagedNetwork(w, req, db, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	item, err := dbGetManagedNetwork(db, id)
	if err != nil {
		t.Fatalf("dbGetManagedNetwork(%d) error = %v", id, err)
	}
	if item.Enabled {
		t.Fatalf("item.Enabled = %v, want false after toggle", item.Enabled)
	}
}

func TestHandlePersistManagedNetworkBridgeConvertsNetworkToExistingMode(t *testing.T) {
	db := openTestDB(t)

	id, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:            "managed",
		BridgeMode:      managedNetworkBridgeModeCreate,
		Bridge:          "vmbr7",
		BridgeMTU:       9000,
		BridgeVLANAware: true,
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("seed managed network: %v", err)
	}

	oldPersist := persistManagedNetworkBridgeForTests
	persistManagedNetworkBridgeForTests = func(item ManagedNetwork) (managedNetworkPersistBridgeResult, error) {
		if item.ID != id || item.Bridge != "vmbr7" || item.BridgeMode != managedNetworkBridgeModeCreate {
			t.Fatalf("persist hook item = %+v, want create-mode vmbr7 network", item)
		}
		return managedNetworkPersistBridgeResult{
			Status:         "persisted",
			Bridge:         "vmbr7",
			InterfacesPath: managedNetworkHostInterfacesConfigPath,
			BackupPath:     managedNetworkHostInterfacesConfigPath + ".forward.bak.test",
		}, nil
	}
	defer func() {
		persistManagedNetworkBridgeForTests = oldPersist
	}()

	req := newJSONRequest(t, http.MethodPost, "/api/managed-networks/persist-bridge?id="+strconv.FormatInt(id, 10), nil)
	w := httptest.NewRecorder()

	handlePersistManagedNetworkBridge(w, req, db, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp managedNetworkPersistBridgeResult
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if resp.Status != "persisted" || resp.Bridge != "vmbr7" {
		t.Fatalf("response = %+v, want persisted vmbr7 result", resp)
	}

	item, err := dbGetManagedNetwork(db, id)
	if err != nil {
		t.Fatalf("dbGetManagedNetwork(%d) error = %v", id, err)
	}
	if item.BridgeMode != managedNetworkBridgeModeExisting {
		t.Fatalf("BridgeMode = %q, want %q", item.BridgeMode, managedNetworkBridgeModeExisting)
	}
	if item.BridgeMTU != 0 || item.BridgeVLANAware {
		t.Fatalf("bridge config = %+v, want existing-mode zero values", item)
	}
}

func TestHandlePersistManagedNetworkBridgeRejectsExistingMode(t *testing.T) {
	db := openTestDB(t)

	id, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:       "managed",
		BridgeMode: managedNetworkBridgeModeExisting,
		Bridge:     "vmbr7",
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("seed managed network: %v", err)
	}

	req := newJSONRequest(t, http.MethodPost, "/api/managed-networks/persist-bridge?id="+strconv.FormatInt(id, 10), nil)
	w := httptest.NewRecorder()

	handlePersistManagedNetworkBridge(w, req, db, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "persist", "bridge_mode", "managed network bridge persistence requires create mode")
}

func TestHandlePersistManagedNetworkBridgeNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPost, "/api/managed-networks/persist-bridge?id=404", nil)
	w := httptest.NewRecorder()

	handlePersistManagedNetworkBridge(w, req, db, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "persist", "id", "managed network not found")
}

func TestHandleReloadManagedNetworkRuntimeQueuesRedistribute(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/managed-networks/reload-runtime", nil)
	w := httptest.NewRecorder()
	pm := &ProcessManager{}

	handleReloadManagedNetworkRuntime(w, req, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if !pm.redistributePending {
		t.Fatal("redistributePending = false, want true after reload request")
	}
	var resp ManagedNetworkRuntimeReloadResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if resp.Status != "fallback" {
		t.Fatalf("Status = %q, want fallback", resp.Status)
	}
	if resp.Error != "managed network runtime reload requires database/config context" {
		t.Fatalf("Error = %q, want missing context fallback", resp.Error)
	}
	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if status.LastRequestSource != "manual" {
		t.Fatalf("LastRequestSource = %q, want manual", status.LastRequestSource)
	}
	if status.LastResult != "fallback" {
		t.Fatalf("LastResult = %q, want fallback", status.LastResult)
	}
	if status.LastError != "managed network runtime reload requires database/config context" {
		t.Fatalf("LastError = %q, want missing context fallback", status.LastError)
	}
	if status.LastStartedAt.IsZero() || status.LastCompletedAt.IsZero() {
		t.Fatalf("reload timestamps = started:%v completed:%v, want both recorded", status.LastStartedAt, status.LastCompletedAt)
	}
}

func TestHandleReloadManagedNetworkRuntimeRunsTargetedReloadWhenContextAvailable(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "eno1", Kind: "device"},
			{Name: "vmbr1", Kind: "bridge"},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:            "lab",
		BridgeMode:      managedNetworkBridgeModeCreate,
		Bridge:          "vmbr1",
		UplinkInterface: "eno1",
		IPv4Enabled:     true,
		IPv4CIDR:        "192.0.2.1/24",
		Enabled:         true,
	}); err != nil {
		t.Fatalf("seed managed network: %v", err)
	}

	fakeManagedRuntime := &fakeManagedNetworkRuntime{}
	fakeIPv6Runtime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		db:                    db,
		cfg:                   &Config{DefaultEngine: ruleEngineAuto},
		managedNetworkRuntime: fakeManagedRuntime,
		ipv6Runtime:           fakeIPv6Runtime,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/managed-networks/reload-runtime", nil)
	w := httptest.NewRecorder()

	handleReloadManagedNetworkRuntime(w, req, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if pm.redistributePending {
		t.Fatal("redistributePending = true, want targeted reload without queueing full redistribute")
	}
	var resp ManagedNetworkRuntimeReloadResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if resp.Status != "success" {
		t.Fatalf("Status = %q, want success", resp.Status)
	}
	if resp.Error != "" {
		t.Fatalf("Error = %q, want empty", resp.Error)
	}
	if fakeManagedRuntime.reconcileCalls != 1 {
		t.Fatalf("managed network reconcileCalls = %d, want 1", fakeManagedRuntime.reconcileCalls)
	}
	if len(fakeManagedRuntime.lastItems) != 1 {
		t.Fatalf("managed network items = %d, want 1", len(fakeManagedRuntime.lastItems))
	}
	if fakeIPv6Runtime.reconcileCalls != 1 {
		t.Fatalf("ipv6 reconcileCalls = %d, want 1", fakeIPv6Runtime.reconcileCalls)
	}
	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if status.LastRequestSource != "manual" {
		t.Fatalf("LastRequestSource = %q, want manual", status.LastRequestSource)
	}
	if status.LastResult != "success" {
		t.Fatalf("LastResult = %q, want success", status.LastResult)
	}
	if status.LastCompletedAt.IsZero() {
		t.Fatal("LastCompletedAt = zero, want completed timestamp")
	}
}

func TestHandleReloadManagedNetworkRuntimeRecordsPartialResultOnRuntimeError(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "eno1", Kind: "device"},
			{Name: "vmbr1", Kind: "bridge"},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:            "lab",
		BridgeMode:      managedNetworkBridgeModeCreate,
		Bridge:          "vmbr1",
		UplinkInterface: "eno1",
		IPv4Enabled:     true,
		IPv4CIDR:        "192.0.2.1/24",
		Enabled:         true,
	}); err != nil {
		t.Fatalf("seed managed network: %v", err)
	}

	fakeManagedRuntime := &fakeManagedNetworkRuntime{}
	fakeIPv6Runtime := &fakeIPv6AssignmentRuntime{reconcileErr: errors.New("apply failed")}
	pm := &ProcessManager{
		db:                    db,
		cfg:                   &Config{DefaultEngine: ruleEngineAuto},
		managedNetworkRuntime: fakeManagedRuntime,
		ipv6Runtime:           fakeIPv6Runtime,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/managed-networks/reload-runtime", nil)
	w := httptest.NewRecorder()

	handleReloadManagedNetworkRuntime(w, req, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if pm.redistributePending {
		t.Fatal("redistributePending = true, want targeted reload without queueing full redistribute")
	}
	var resp ManagedNetworkRuntimeReloadResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if resp.Status != "partial" {
		t.Fatalf("Status = %q, want partial", resp.Status)
	}
	if resp.Error != "ipv6 assignment runtime reconcile: apply failed" {
		t.Fatalf("Error = %q, want ipv6 assignment runtime reconcile failure", resp.Error)
	}
	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if status.LastResult != "partial" {
		t.Fatalf("LastResult = %q, want partial", status.LastResult)
	}
	if status.LastError != "ipv6 assignment runtime reconcile: apply failed" {
		t.Fatalf("LastError = %q, want ipv6 assignment runtime reconcile failure", status.LastError)
	}
	if status.LastAppliedSummary == "" {
		t.Fatal("LastAppliedSummary = empty, want targeted reload summary")
	}
}

func TestHandleReloadManagedNetworkRuntimeRecordsPartialResultOnIPv6AssignmentLoadError(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "eno1", Kind: "device"},
			{Name: "vmbr1", Kind: "bridge"},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	oldLoadIPv6Assignments := loadIPv6AssignmentsForManagedNetworkReload
	loadIPv6AssignmentsForManagedNetworkReload = func(db sqlRuleStore) ([]IPv6Assignment, error) {
		return nil, errors.New("load failed")
	}
	defer func() {
		loadIPv6AssignmentsForManagedNetworkReload = oldLoadIPv6Assignments
	}()

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:            "lab",
		BridgeMode:      managedNetworkBridgeModeCreate,
		Bridge:          "vmbr1",
		UplinkInterface: "eno1",
		IPv4Enabled:     true,
		IPv4CIDR:        "192.0.2.1/24",
		Enabled:         true,
	}); err != nil {
		t.Fatalf("seed managed network: %v", err)
	}

	fakeManagedRuntime := &fakeManagedNetworkRuntime{}
	fakeIPv6Runtime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		db:                    db,
		cfg:                   &Config{DefaultEngine: ruleEngineAuto},
		managedNetworkRuntime: fakeManagedRuntime,
		ipv6Runtime:           fakeIPv6Runtime,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/managed-networks/reload-runtime", nil)
	w := httptest.NewRecorder()

	handleReloadManagedNetworkRuntime(w, req, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if pm.redistributePending {
		t.Fatal("redistributePending = true, want targeted reload without queueing full redistribute")
	}
	var resp ManagedNetworkRuntimeReloadResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if resp.Status != "partial" {
		t.Fatalf("Status = %q, want partial", resp.Status)
	}
	if resp.Error != "load ipv6 assignments: load failed" {
		t.Fatalf("Error = %q, want ipv6 assignment load failure", resp.Error)
	}
	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if status.LastResult != "partial" {
		t.Fatalf("LastResult = %q, want partial", status.LastResult)
	}
	if status.LastError != "load ipv6 assignments: load failed" {
		t.Fatalf("LastError = %q, want ipv6 assignment load failure", status.LastError)
	}
	if fakeIPv6Runtime.reconcileCalls != 0 {
		t.Fatalf("ipv6 reconcileCalls = %d, want 0 when assignments fail to load", fakeIPv6Runtime.reconcileCalls)
	}
}

func TestHandleRepairManagedNetworkRuntimeRepairsHostStateBeforeTargetedReload(t *testing.T) {
	db := openTestDB(t)

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:            "lab",
		BridgeMode:      managedNetworkBridgeModeCreate,
		Bridge:          "vmbr1",
		UplinkInterface: "eno1",
		IPv4Enabled:     true,
		IPv4CIDR:        "192.0.2.1/24",
		Enabled:         true,
	}); err != nil {
		t.Fatalf("seed managed network: %v", err)
	}

	oldRepair := repairManagedNetworkHostStateForTests
	var repaired []ManagedNetwork
	repairManagedNetworkHostStateForTests = func(items []ManagedNetwork) (managedNetworkRepairResult, error) {
		repaired = append([]ManagedNetwork(nil), items...)
		return managedNetworkRepairResult{
			Bridges:    []string{"vmbr1"},
			GuestLinks: []string{"fwpr100p0->vmbr1"},
		}, nil
	}
	defer func() {
		repairManagedNetworkHostStateForTests = oldRepair
	}()

	fakeManagedRuntime := &fakeManagedNetworkRuntime{}
	fakeIPv6Runtime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		db:                    db,
		cfg:                   &Config{DefaultEngine: ruleEngineAuto},
		managedNetworkRuntime: fakeManagedRuntime,
		ipv6Runtime:           fakeIPv6Runtime,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/managed-networks/repair", nil)
	w := httptest.NewRecorder()

	handleRepairManagedNetworkRuntime(w, req, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp ManagedNetworkRepairResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if resp.Status != "queued" {
		t.Fatalf("Status = %q, want queued", resp.Status)
	}
	if !reflect.DeepEqual(resp.Bridges, []string{"vmbr1"}) {
		t.Fatalf("Bridges = %v, want [vmbr1]", resp.Bridges)
	}
	if !reflect.DeepEqual(resp.GuestLinks, []string{"fwpr100p0->vmbr1"}) {
		t.Fatalf("GuestLinks = %v, want [fwpr100p0->vmbr1]", resp.GuestLinks)
	}
	if len(repaired) != 1 || repaired[0].Bridge != "vmbr1" {
		t.Fatalf("repaired = %+v, want managed network for vmbr1", repaired)
	}
	if fakeManagedRuntime.reconcileCalls != 1 {
		t.Fatalf("managed network reconcileCalls = %d, want 1", fakeManagedRuntime.reconcileCalls)
	}
	if fakeIPv6Runtime.reconcileCalls != 1 {
		t.Fatalf("ipv6 reconcileCalls = %d, want 1", fakeIPv6Runtime.reconcileCalls)
	}
}

func TestHandleRepairManagedNetworkRuntimeReturnsPartialWhenRepairPartiallySucceeds(t *testing.T) {
	db := openTestDB(t)

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:            "lab",
		BridgeMode:      managedNetworkBridgeModeCreate,
		Bridge:          "vmbr1",
		UplinkInterface: "eno1",
		IPv4Enabled:     true,
		IPv4CIDR:        "192.0.2.1/24",
		Enabled:         true,
	}); err != nil {
		t.Fatalf("seed managed network: %v", err)
	}

	oldRepair := repairManagedNetworkHostStateForTests
	repairManagedNetworkHostStateForTests = func(items []ManagedNetwork) (managedNetworkRepairResult, error) {
		return managedNetworkRepairResult{
			Bridges:    []string{"vmbr1"},
			GuestLinks: []string{"fwpr100p0->vmbr1"},
		}, errors.New("repair guest links: permission denied")
	}
	defer func() {
		repairManagedNetworkHostStateForTests = oldRepair
	}()

	fakeManagedRuntime := &fakeManagedNetworkRuntime{}
	fakeIPv6Runtime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		db:                    db,
		cfg:                   &Config{DefaultEngine: ruleEngineAuto},
		managedNetworkRuntime: fakeManagedRuntime,
		ipv6Runtime:           fakeIPv6Runtime,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/managed-networks/repair", nil)
	w := httptest.NewRecorder()

	handleRepairManagedNetworkRuntime(w, req, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp ManagedNetworkRepairResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if resp.Status != "partial" {
		t.Fatalf("Status = %q, want partial", resp.Status)
	}
	if !reflect.DeepEqual(resp.Bridges, []string{"vmbr1"}) {
		t.Fatalf("Bridges = %v, want [vmbr1]", resp.Bridges)
	}
	if !reflect.DeepEqual(resp.GuestLinks, []string{"fwpr100p0->vmbr1"}) {
		t.Fatalf("GuestLinks = %v, want [fwpr100p0->vmbr1]", resp.GuestLinks)
	}
	if resp.Error != "repair guest links: permission denied" {
		t.Fatalf("Error = %q, want partial repair error", resp.Error)
	}
	if fakeManagedRuntime.reconcileCalls != 1 {
		t.Fatalf("managed network reconcileCalls = %d, want 1", fakeManagedRuntime.reconcileCalls)
	}
	if fakeIPv6Runtime.reconcileCalls != 1 {
		t.Fatalf("ipv6 reconcileCalls = %d, want 1", fakeIPv6Runtime.reconcileCalls)
	}
}

func sliceContainsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestHandleManagedNetworkRuntimeReloadStatusReturnsSnapshot(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/managed-networks/runtime-status", nil)
	w := httptest.NewRecorder()
	now := time.Now().UTC().Truncate(time.Second)
	pm := &ProcessManager{
		managedRuntimeReloadPending:            true,
		managedRuntimeReloadDueAt:              now.Add(2 * time.Second),
		managedRuntimeReloadLastRequestedAt:    now,
		managedRuntimeReloadLastRequestSource:  "link_change",
		managedRuntimeReloadLastRequestSummary: "tap100i0,vmbr1",
		managedRuntimeReloadLastStartedAt:      now.Add(3 * time.Second),
		managedRuntimeReloadLastCompletedAt:    now.Add(4 * time.Second),
		managedRuntimeReloadLastResult:         "success",
		managedRuntimeReloadLastAppliedSummary: "networks=1 bridges=vmbr1",
	}

	handleManagedNetworkRuntimeReloadStatus(w, req, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var status ManagedNetworkRuntimeReloadStatus
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if !status.Pending {
		t.Fatal("Pending = false, want true")
	}
	if status.LastRequestSource != "link_change" {
		t.Fatalf("LastRequestSource = %q, want link_change", status.LastRequestSource)
	}
	if status.LastRequestSummary != "tap100i0,vmbr1" {
		t.Fatalf("LastRequestSummary = %q, want tap100i0,vmbr1", status.LastRequestSummary)
	}
	if status.LastAppliedSummary != "networks=1 bridges=vmbr1" {
		t.Fatalf("LastAppliedSummary = %q, want networks=1 bridges=vmbr1", status.LastAppliedSummary)
	}
}

func TestHandleDeleteManagedNetworkRemovesRow(t *testing.T) {
	db := openTestDB(t)

	id, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:    "managed",
		Bridge:  "vmbr0",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed managed network: %v", err)
	}

	req := newJSONRequest(t, http.MethodDelete, "/api/managed-networks?id="+strconv.FormatInt(id, 10), nil)
	w := httptest.NewRecorder()

	handleDeleteManagedNetwork(w, req, db, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	if _, err := dbGetManagedNetwork(db, id); err == nil {
		t.Fatalf("dbGetManagedNetwork(%d) succeeded after delete, want not found", id)
	}
}
