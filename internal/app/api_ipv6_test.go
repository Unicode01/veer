package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestHandleAddIPv6AssignmentValidationErrorIncludesIssues(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{}, nil
	}
	defer func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	}()

	req := newJSONRequest(t, http.MethodPost, "/api/ipv6-assignments", IPv6Assignment{})
	w := httptest.NewRecorder()

	handleAddIPv6Assignment(w, req, db, &ProcessManager{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "create", "parent_interface", "is required")
}

func TestHandleListIPv6AssignmentsIncludesRuntimeStats(t *testing.T) {
	db := openTestDB(t)

	firstID, err := dbAddIPv6Assignment(db, &IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8::/64",
		AssignedPrefix:  "2001:db8::10/128",
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("seed first assignment: %v", err)
	}
	secondID, err := dbAddIPv6Assignment(db, &IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i1",
		ParentPrefix:    "2001:db8::/64",
		AssignedPrefix:  "2001:db8:1::/64",
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("seed second assignment: %v", err)
	}

	pm := &ProcessManager{
		ipv6Runtime: &fakeIPv6AssignmentRuntime{
			stats: map[int64]ipv6AssignmentRuntimeStats{
				firstID: {
					RAAdvertisementCount: 7,
					DHCPv6ReplyCount:     3,
					RuntimeStatus:        "running",
					RuntimeDetail:        "dhcpv6 listener active",
				},
				secondID: {
					RAAdvertisementCount: 11,
					RuntimeStatus:        "error",
					RuntimeDetail:        "router advertiser failed",
				},
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/ipv6-assignments", nil)
	w := httptest.NewRecorder()

	handleListIPv6Assignments(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var items []IPv6Assignment
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(items))
	}
	if items[0].ID != firstID || items[0].RAAdvertisementCount != 7 || items[0].DHCPv6ReplyCount != 3 ||
		items[0].RuntimeStatus != "running" || items[0].RuntimeDetail != "dhcpv6 listener active" {
		t.Fatalf("items[0] = %+v, want merged /128 runtime stats", items[0])
	}
	if items[1].ID != secondID || items[1].RAAdvertisementCount != 11 || items[1].DHCPv6ReplyCount != 0 ||
		items[1].RuntimeStatus != "error" || items[1].RuntimeDetail != "router advertiser failed" {
		t.Fatalf("items[1] = %+v, want merged /64 runtime stats", items[1])
	}
}

func TestHandleListIPv6AssignmentsRebasesCurrentHostPrefixes(t *testing.T) {
	db := openTestDB(t)

	id, err := dbAddIPv6Assignment(db, &IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8:100::/64",
		AssignedPrefix:  "2001:db8:100::1234/128",
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{
			{
				Name: "vmbr0",
				Addresses: []HostInterfaceAddress{
					{Family: ipFamilyIPv6, IP: "2001:db8:200::1", CIDR: "2001:db8:200::/64", PrefixLen: 64},
				},
			},
			{Name: "tap100i0"},
		}, nil
	}
	defer func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/ipv6-assignments", nil)
	w := httptest.NewRecorder()

	handleListIPv6Assignments(w, req, db, &ProcessManager{})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var items []IPv6Assignment
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if items[0].ID != id {
		t.Fatalf("items[0].ID = %d, want %d", items[0].ID, id)
	}
	if items[0].ParentPrefix != "2001:db8:200::/64" {
		t.Fatalf("items[0].ParentPrefix = %q, want 2001:db8:200::/64", items[0].ParentPrefix)
	}
	if items[0].AssignedPrefix != "2001:db8:200::1234/128" {
		t.Fatalf("items[0].AssignedPrefix = %q, want 2001:db8:200::1234/128", items[0].AssignedPrefix)
	}
	if items[0].Address != "2001:db8:200::1234" {
		t.Fatalf("items[0].Address = %q, want 2001:db8:200::1234", items[0].Address)
	}
	if items[0].PrefixLen != 128 {
		t.Fatalf("items[0].PrefixLen = %d, want 128", items[0].PrefixLen)
	}
}

func TestHandleAddIPv6AssignmentPersistsCanonicalItem(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{
			{
				Name: "vmbr0",
				Addresses: []HostInterfaceAddress{
					{Family: ipFamilyIPv6, IP: "2001:db8:100::10", CIDR: "2001:db8:100::/48", PrefixLen: 48},
				},
			},
			{
				Name: "tap100i0",
			},
		}, nil
	}
	defer func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	}()

	req := newJSONRequest(t, http.MethodPost, "/api/ipv6-assignments", IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8:100:abcd::1/48",
		AssignedPrefix:  "2001:db8:100:1::1234/64",
		Remark:          "vm100",
		Enabled:         true,
	})
	w := httptest.NewRecorder()
	pm := &ProcessManager{}

	handleAddIPv6Assignment(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if !pm.redistributePending {
		t.Fatal("redistributePending = false, want true after successful create")
	}

	var item IPv6Assignment
	if err := json.Unmarshal(w.Body.Bytes(), &item); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if item.ID <= 0 {
		t.Fatalf("id = %d, want > 0", item.ID)
	}
	if item.ParentPrefix != "2001:db8:100::/48" {
		t.Fatalf("parent_prefix = %q, want %q", item.ParentPrefix, "2001:db8:100::/48")
	}
	if item.AssignedPrefix != "2001:db8:100:1::/64" {
		t.Fatalf("assigned_prefix = %q, want %q", item.AssignedPrefix, "2001:db8:100:1::/64")
	}
	if item.Address != "2001:db8:100:1::" {
		t.Fatalf("address = %q, want %q", item.Address, "2001:db8:100:1::")
	}
	if item.PrefixLen != 64 {
		t.Fatalf("prefix_len = %d, want 64", item.PrefixLen)
	}

	stored, err := dbGetIPv6Assignment(db, item.ID)
	if err != nil {
		t.Fatalf("dbGetIPv6Assignment() error = %v", err)
	}
	if stored.AssignedPrefix != "2001:db8:100:1::/64" || stored.TargetInterface != "tap100i0" {
		t.Fatalf("stored = %+v, want canonical persisted item", stored)
	}
}

func TestHandleAddIPv6AssignmentAcceptsLegacySingleAddressInput(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{
			{
				Name: "vmbr0",
				Addresses: []HostInterfaceAddress{
					{Family: ipFamilyIPv6, IP: "2001:db8::10", CIDR: "2001:db8::/64", PrefixLen: 64},
				},
			},
			{Name: "tap100i0"},
		}, nil
	}
	defer func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	}()

	req := newJSONRequest(t, http.MethodPost, "/api/ipv6-assignments", IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8::beef/64",
		Address:         "2001:db8::1234",
		PrefixLen:       128,
		Remark:          "vm100",
		Enabled:         true,
	})
	w := httptest.NewRecorder()

	handleAddIPv6Assignment(w, req, db, &ProcessManager{})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var item IPv6Assignment
	if err := json.Unmarshal(w.Body.Bytes(), &item); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if item.AssignedPrefix != "2001:db8::1234/128" {
		t.Fatalf("assigned_prefix = %q, want %q", item.AssignedPrefix, "2001:db8::1234/128")
	}
	if item.Address != "2001:db8::1234" || item.PrefixLen != 128 {
		t.Fatalf("legacy fields = address=%q prefix_len=%d, want address=%q prefix_len=128", item.Address, item.PrefixLen, "2001:db8::1234")
	}
}

func TestHandleAddIPv6AssignmentRejectsPrefixOutsideParent(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{
			{
				Name: "vmbr0",
				Addresses: []HostInterfaceAddress{
					{Family: ipFamilyIPv6, IP: "2001:db8:100::10", CIDR: "2001:db8:100::/48", PrefixLen: 48},
				},
			},
			{Name: "tap100i0"},
		}, nil
	}
	defer func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	}()

	req := newJSONRequest(t, http.MethodPost, "/api/ipv6-assignments", IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8:100::/48",
		AssignedPrefix:  "2001:db8:200:1::/64",
		Enabled:         true,
	})
	w := httptest.NewRecorder()

	handleAddIPv6Assignment(w, req, db, &ProcessManager{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "create", "assigned_prefix", "must be contained within parent_prefix")
}

func TestHandleAddIPv6AssignmentRejectsOverlappingPrefix(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{
			{
				Name: "vmbr0",
				Addresses: []HostInterfaceAddress{
					{Family: ipFamilyIPv6, IP: "2001:db8:100::10", CIDR: "2001:db8:100::/48", PrefixLen: 48},
				},
			},
			{Name: "tap100i0"},
			{Name: "tap101i0"},
		}, nil
	}
	defer func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	}()

	if _, err := dbAddIPv6Assignment(db, &IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8:100::/48",
		AssignedPrefix:  "2001:db8:100:1::/64",
		Enabled:         true,
	}); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	req := newJSONRequest(t, http.MethodPost, "/api/ipv6-assignments", IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap101i0",
		ParentPrefix:    "2001:db8:100::/48",
		AssignedPrefix:  "2001:db8:100:1::1/128",
		Enabled:         true,
	})
	w := httptest.NewRecorder()

	handleAddIPv6Assignment(w, req, db, &ProcessManager{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "create", "assigned_prefix", "overlaps with ipv6 assignment #1")
}

func TestHandleAddIPv6AssignmentIgnoresDisabledOverlap(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{
			{
				Name: "vmbr0",
				Addresses: []HostInterfaceAddress{
					{Family: ipFamilyIPv6, IP: "2001:db8:100::10", CIDR: "2001:db8:100::/48", PrefixLen: 48},
				},
			},
			{Name: "tap100i0"},
			{Name: "tap101i0"},
		}, nil
	}
	defer func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	}()

	if _, err := dbAddIPv6Assignment(db, &IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8:100::/48",
		AssignedPrefix:  "2001:db8:100:1::/64",
		Enabled:         false,
	}); err != nil {
		t.Fatalf("seed disabled assignment: %v", err)
	}

	req := newJSONRequest(t, http.MethodPost, "/api/ipv6-assignments", IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap101i0",
		ParentPrefix:    "2001:db8:100::/48",
		AssignedPrefix:  "2001:db8:100:1::1/128",
		Enabled:         true,
	})
	w := httptest.NewRecorder()

	handleAddIPv6Assignment(w, req, db, &ProcessManager{})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDBGetIPv6AssignmentSynthesizesAssignedPrefixFromLegacyColumns(t *testing.T) {
	db := openTestDB(t)

	if _, err := db.Exec(
		`INSERT INTO ipv6_assignments (parent_interface, target_interface, parent_prefix, address, prefix_len, remark, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"vmbr0",
		"tap100i0",
		"2001:db8::/64",
		"2001:db8::1234",
		128,
		"legacy",
		1,
	); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	item, err := dbGetIPv6Assignment(db, 1)
	if err != nil {
		t.Fatalf("dbGetIPv6Assignment() error = %v", err)
	}
	if item.AssignedPrefix != "2001:db8::1234/128" {
		t.Fatalf("assigned_prefix = %q, want %q", item.AssignedPrefix, "2001:db8::1234/128")
	}
	if item.Address != "2001:db8::1234" || item.PrefixLen != 128 {
		t.Fatalf("legacy fields = address=%q prefix_len=%d, want address=%q prefix_len=128", item.Address, item.PrefixLen, "2001:db8::1234")
	}
}

func TestHandleUpdateIPv6AssignmentNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)

	req := newJSONRequest(t, http.MethodPut, "/api/ipv6-assignments", IPv6Assignment{
		ID:              404,
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8::/64",
		AssignedPrefix:  "2001:db8::1/128",
		Enabled:         true,
	})
	w := httptest.NewRecorder()

	handleUpdateIPv6Assignment(w, req, db, &ProcessManager{})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "update", "id", "ipv6 assignment not found")
}

func TestHandleUpdateIPv6AssignmentEnableIgnoresDisabledOverlap(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{
			{
				Name: "vmbr0",
				Addresses: []HostInterfaceAddress{
					{Family: ipFamilyIPv6, IP: "2001:db8:100::10", CIDR: "2001:db8:100::/48", PrefixLen: 48},
				},
			},
			{Name: "tap100i0"},
			{Name: "tap101i0"},
		}, nil
	}
	defer func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	}()

	id, err := dbAddIPv6Assignment(db, &IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8:100::/48",
		AssignedPrefix:  "2001:db8:100:1::/64",
		Enabled:         false,
	})
	if err != nil {
		t.Fatalf("seed target assignment: %v", err)
	}
	if _, err := dbAddIPv6Assignment(db, &IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap101i0",
		ParentPrefix:    "2001:db8:100::/48",
		AssignedPrefix:  "2001:db8:100:1::1/128",
		Enabled:         false,
	}); err != nil {
		t.Fatalf("seed overlapping disabled assignment: %v", err)
	}

	req := newJSONRequest(t, http.MethodPut, "/api/ipv6-assignments", IPv6Assignment{
		ID:              id,
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8:100::/48",
		AssignedPrefix:  "2001:db8:100:1::/64",
		Enabled:         true,
	})
	w := httptest.NewRecorder()

	handleUpdateIPv6Assignment(w, req, db, &ProcessManager{})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestHandleUpdateIPv6AssignmentQueuesRedistribute(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{
			{
				Name: "vmbr0",
				Addresses: []HostInterfaceAddress{
					{Family: ipFamilyIPv6, IP: "2001:db8::10", CIDR: "2001:db8::/64", PrefixLen: 64},
				},
			},
			{Name: "tap100i0"},
		}, nil
	}
	defer func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	}()

	id, err := dbAddIPv6Assignment(db, &IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8::/64",
		AssignedPrefix:  "2001:db8::100/128",
		Remark:          "before",
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	req := newJSONRequest(t, http.MethodPut, "/api/ipv6-assignments", IPv6Assignment{
		ID:              id,
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8::/64",
		AssignedPrefix:  "2001:db8::100/128",
		Remark:          "after",
		Enabled:         true,
	})
	w := httptest.NewRecorder()
	pm := &ProcessManager{}

	handleUpdateIPv6Assignment(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if !pm.redistributePending {
		t.Fatal("redistributePending = false, want true after successful update")
	}
}

func TestHandleUpdateIPv6AssignmentRebasesStaleParentPrefixToCurrentHost(t *testing.T) {
	db := openTestDB(t)

	id, err := dbAddIPv6Assignment(db, &IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8:100::/64",
		AssignedPrefix:  "2001:db8:100::1234/128",
		Remark:          "before rotate",
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{
			{
				Name: "vmbr0",
				Addresses: []HostInterfaceAddress{
					{Family: ipFamilyIPv6, IP: "2001:db8:200::1", CIDR: "2001:db8:200::/64", PrefixLen: 64},
				},
			},
			{Name: "tap100i0"},
		}, nil
	}
	defer func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	}()

	req := newJSONRequest(t, http.MethodPut, "/api/ipv6-assignments", IPv6Assignment{
		ID:              id,
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8:100::/64",
		AssignedPrefix:  "2001:db8:100::1234/128",
		Remark:          "after rotate",
		Enabled:         false,
	})
	w := httptest.NewRecorder()
	pm := &ProcessManager{}

	handleUpdateIPv6Assignment(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if !pm.redistributePending {
		t.Fatal("redistributePending = false, want true after successful update")
	}

	var item IPv6Assignment
	if err := json.Unmarshal(w.Body.Bytes(), &item); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if item.ParentPrefix != "2001:db8:200::/64" {
		t.Fatalf("item.ParentPrefix = %q, want 2001:db8:200::/64", item.ParentPrefix)
	}
	if item.AssignedPrefix != "2001:db8:200::1234/128" {
		t.Fatalf("item.AssignedPrefix = %q, want 2001:db8:200::1234/128", item.AssignedPrefix)
	}
	if item.Address != "2001:db8:200::1234" {
		t.Fatalf("item.Address = %q, want 2001:db8:200::1234", item.Address)
	}
	if item.Remark != "after rotate" {
		t.Fatalf("item.Remark = %q, want after rotate", item.Remark)
	}
	if item.Enabled {
		t.Fatal("item.Enabled = true, want false")
	}

	stored, err := dbGetIPv6Assignment(db, id)
	if err != nil {
		t.Fatalf("dbGetIPv6Assignment() error = %v", err)
	}
	if stored.ParentPrefix != "2001:db8:200::/64" {
		t.Fatalf("stored.ParentPrefix = %q, want 2001:db8:200::/64", stored.ParentPrefix)
	}
	if stored.AssignedPrefix != "2001:db8:200::1234/128" {
		t.Fatalf("stored.AssignedPrefix = %q, want 2001:db8:200::1234/128", stored.AssignedPrefix)
	}
	if stored.Address != "2001:db8:200::1234" {
		t.Fatalf("stored.Address = %q, want 2001:db8:200::1234", stored.Address)
	}
}

func TestHandleDeleteIPv6AssignmentNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodDelete, "/api/ipv6-assignments?id=404", nil)
	w := httptest.NewRecorder()

	handleDeleteIPv6Assignment(w, req, db, &ProcessManager{})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "delete", "id", "ipv6 assignment not found")
}

func TestHandleDeleteIPv6AssignmentQueuesRedistribute(t *testing.T) {
	db := openTestDB(t)

	id, err := dbAddIPv6Assignment(db, &IPv6Assignment{
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2001:db8::/64",
		AssignedPrefix:  "2001:db8::100/128",
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	req := newJSONRequest(t, http.MethodDelete, "/api/ipv6-assignments?id="+strconv.FormatInt(id, 10), nil)
	w := httptest.NewRecorder()
	pm := &ProcessManager{}

	handleDeleteIPv6Assignment(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if !pm.redistributePending {
		t.Fatal("redistributePending = false, want true after successful delete")
	}
}
