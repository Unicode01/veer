package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

type managedNetworkReservationValidationScope struct {
	Network  ManagedNetwork
	ServerIP string
	Subnet   *net.IPNet
}

func normalizeManagedNetworkReservation(item ManagedNetworkReservation) ManagedNetworkReservation {
	item.MACAddress = strings.TrimSpace(item.MACAddress)
	item.IPv4Address = strings.TrimSpace(item.IPv4Address)
	item.Remark = strings.TrimSpace(item.Remark)
	return item
}

func normalizeManagedNetworkReservationMACAddress(value string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(hw) != 6 {
		return "", errors.New("must be a valid Ethernet MAC address")
	}
	return strings.ToLower(hw.String()), nil
}

func resolveManagedNetworkReservationValidationScope(db sqlRuleStore, managedNetworkID int64) (managedNetworkReservationValidationScope, []ruleValidationIssue, error) {
	if managedNetworkID <= 0 {
		return managedNetworkReservationValidationScope{}, singleValidationIssue("request", 0, "managed_network_id", "is required"), nil
	}
	network, err := dbGetManagedNetwork(db, managedNetworkID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return managedNetworkReservationValidationScope{}, singleValidationIssue("request", 0, "managed_network_id", "managed network not found"), nil
		}
		return managedNetworkReservationValidationScope{}, nil, err
	}
	if !network.IPv4Enabled {
		return managedNetworkReservationValidationScope{}, singleValidationIssue("request", 0, "managed_network_id", "managed network ipv4 is disabled"), nil
	}
	_, serverIP, subnet, err := normalizeManagedNetworkIPv4CIDR(network.IPv4CIDR)
	if err != nil {
		return managedNetworkReservationValidationScope{}, singleValidationIssue("request", 0, "managed_network_id", "managed network ipv4 configuration is invalid"), nil
	}
	if _, err := normalizeManagedNetworkIPv4Gateway(network.IPv4Gateway, serverIP); err != nil {
		return managedNetworkReservationValidationScope{}, singleValidationIssue("request", 0, "managed_network_id", "managed network ipv4 configuration is invalid"), nil
	}
	return managedNetworkReservationValidationScope{
		Network:  *network,
		ServerIP: serverIP,
		Subnet:   subnet,
	}, nil, nil
}

func validateManagedNetworkReservationFields(db sqlRuleStore, item ManagedNetworkReservation, scopeName string) (ManagedNetworkReservation, []ruleValidationIssue, error) {
	item = normalizeManagedNetworkReservation(item)

	scope, issues, err := resolveManagedNetworkReservationValidationScope(db, item.ManagedNetworkID)
	if err != nil || len(issues) > 0 {
		if len(issues) > 0 {
			for i := range issues {
				issues[i].Scope = scopeName
			}
		}
		return ManagedNetworkReservation{}, issues, err
	}

	macAddress, err := normalizeManagedNetworkReservationMACAddress(item.MACAddress)
	if err != nil {
		return ManagedNetworkReservation{}, singleValidationIssue(scopeName, item.ID, "mac_address", err.Error()), nil
	}
	item.MACAddress = macAddress

	ipv4Address, err := normalizeManagedNetworkIPv4Literal(item.IPv4Address)
	if err != nil {
		return ManagedNetworkReservation{}, singleValidationIssue(scopeName, item.ID, "ipv4_address", err.Error()), nil
	}
	if scope.Subnet == nil || !scope.Subnet.Contains(parseIPLiteral(ipv4Address)) {
		return ManagedNetworkReservation{}, singleValidationIssue(scopeName, item.ID, "ipv4_address", "must stay inside managed network ipv4_cidr"), nil
	}
	if ipv4Address == scope.ServerIP {
		return ManagedNetworkReservation{}, singleValidationIssue(scopeName, item.ID, "ipv4_address", "must not use the managed network gateway address"), nil
	}
	if isManagedNetworkIPv4ReservedHost(parseIPLiteral(ipv4Address).To4(), scope.Subnet.IP.To4(), scope.Subnet.Mask) {
		return ManagedNetworkReservation{}, singleValidationIssue(scopeName, item.ID, "ipv4_address", "must use a usable host address"), nil
	}
	item.IPv4Address = ipv4Address

	existing, err := dbGetManagedNetworkReservationsByManagedNetworkID(db, item.ManagedNetworkID)
	if err != nil {
		return ManagedNetworkReservation{}, nil, err
	}
	for _, current := range existing {
		if current.ID == item.ID {
			continue
		}
		switch {
		case strings.EqualFold(current.MACAddress, item.MACAddress):
			return ManagedNetworkReservation{}, singleValidationIssue(scopeName, item.ID, "mac_address", "conflicts with reservation #"+strconv.FormatInt(current.ID, 10)), nil
		case current.IPv4Address == item.IPv4Address:
			return ManagedNetworkReservation{}, singleValidationIssue(scopeName, item.ID, "ipv4_address", "conflicts with reservation #"+strconv.FormatInt(current.ID, 10)), nil
		}
	}

	return item, nil, nil
}

func prepareManagedNetworkReservationCreate(db sqlRuleStore, item ManagedNetworkReservation) (ManagedNetworkReservation, []ruleValidationIssue, error) {
	item = normalizeManagedNetworkReservation(item)
	if item.ID != 0 {
		return ManagedNetworkReservation{}, singleValidationIssue("create", 0, "id", "must be omitted when creating a managed network reservation"), nil
	}
	return validateManagedNetworkReservationFields(db, item, "create")
}

func prepareManagedNetworkReservationUpdate(db sqlRuleStore, item ManagedNetworkReservation) (ManagedNetworkReservation, []ruleValidationIssue, error) {
	item = normalizeManagedNetworkReservation(item)
	if item.ID <= 0 {
		return ManagedNetworkReservation{}, singleValidationIssue("update", item.ID, "id", "is required"), nil
	}
	if _, err := dbGetManagedNetworkReservation(db, item.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ManagedNetworkReservation{}, singleValidationIssue("update", item.ID, "id", "managed network reservation not found"), nil
		}
		return ManagedNetworkReservation{}, nil, err
	}
	return validateManagedNetworkReservationFields(db, item, "update")
}

func buildManagedNetworkReservationStatuses(db sqlRuleStore, items []ManagedNetworkReservation) ([]ManagedNetworkReservationStatus, error) {
	if len(items) == 0 {
		return []ManagedNetworkReservationStatus{}, nil
	}
	networks, err := dbGetManagedNetworks(db)
	if err != nil {
		return nil, err
	}
	networkByID := make(map[int64]ManagedNetwork, len(networks))
	for _, item := range networks {
		networkByID[item.ID] = item
	}

	statuses := make([]ManagedNetworkReservationStatus, 0, len(items))
	for _, item := range items {
		status := ManagedNetworkReservationStatus{ManagedNetworkReservation: item}
		if network, ok := networkByID[item.ManagedNetworkID]; ok {
			status.ManagedNetworkName = network.Name
			status.ManagedNetworkBridge = network.Bridge
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func handleListManagedNetworkReservations(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	items, err := dbGetManagedNetworkReservations(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	statuses, err := buildManagedNetworkReservationStatuses(db, items)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].ID < statuses[j].ID })
	if statuses == nil {
		statuses = []ManagedNetworkReservationStatus{}
	}
	writeJSON(w, http.StatusOK, statuses)
}

func handleListManagedNetworkReservationCandidates(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	items, err := loadManagedNetworkReservationCandidates(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func handleAddManagedNetworkReservation(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var item ManagedNetworkReservation
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	item, issues, err := prepareManagedNetworkReservationCreate(tx, item)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		status := http.StatusBadRequest
		if hasValidationMessage(issues, "managed network not found") {
			status = http.StatusNotFound
		}
		writeValidationIssueResponse(w, status, issues)
		return
	}

	id, err := dbAddManagedNetworkReservation(tx, &item)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	item.ID = id
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	maybeRedistributeManagedNetworkWorkers(pm)
	writeJSON(w, http.StatusOK, item)
}

func handleUpdateManagedNetworkReservation(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var item ManagedNetworkReservation
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	item, issues, err := prepareManagedNetworkReservationUpdate(tx, item)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		status := http.StatusBadRequest
		if hasValidationMessage(issues, "managed network reservation not found") || hasValidationMessage(issues, "managed network not found") {
			status = http.StatusNotFound
		}
		writeValidationIssueResponse(w, status, issues)
		return
	}

	if err := dbUpdateManagedNetworkReservation(tx, &item); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	maybeRedistributeManagedNetworkWorkers(pm)
	writeJSON(w, http.StatusOK, item)
}

func handleDeleteManagedNetworkReservation(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		writeValidationIssueResponse(w, http.StatusBadRequest, singleValidationIssue("delete", 0, "id", "invalid id"))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	if _, err := dbGetManagedNetworkReservation(tx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeValidationIssueResponse(w, http.StatusNotFound, singleValidationIssue("delete", id, "id", "managed network reservation not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if err := dbDeleteManagedNetworkReservation(tx, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	maybeRedistributeManagedNetworkWorkers(pm)
	writeJSON(w, http.StatusOK, map[string]int64{"id": id})
}
