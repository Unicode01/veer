package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	managedNetworkBridgeModeCreate            = "create"
	managedNetworkBridgeModeExisting          = "existing"
	managedNetworkIPv6AssignmentModeSingle128 = "single_128"
	managedNetworkIPv6AssignmentModePrefix64  = "prefix_64"
)

var loadInterfaceInfosForManagedNetworkPreviewTests func() ([]InterfaceInfo, error)
var loadHostNetworkInterfacesForManagedNetworkTests func() ([]HostNetworkInterface, error)

func normalizeManagedNetwork(item ManagedNetwork) ManagedNetwork {
	item.Name = strings.TrimSpace(item.Name)
	item.BridgeMode = normalizeManagedNetworkBridgeMode(item.BridgeMode)
	item.Bridge = strings.TrimSpace(item.Bridge)
	item.UplinkInterface = strings.TrimSpace(item.UplinkInterface)
	item.IPv4CIDR = strings.TrimSpace(item.IPv4CIDR)
	item.IPv4Gateway = strings.TrimSpace(item.IPv4Gateway)
	item.IPv4PoolStart = strings.TrimSpace(item.IPv4PoolStart)
	item.IPv4PoolEnd = strings.TrimSpace(item.IPv4PoolEnd)
	item.IPv4DNSServers = strings.TrimSpace(item.IPv4DNSServers)
	item.IPv6ParentInterface = strings.TrimSpace(item.IPv6ParentInterface)
	item.IPv6ParentPrefix = strings.TrimSpace(item.IPv6ParentPrefix)
	item.IPv6AssignmentMode = normalizeManagedNetworkIPv6AssignmentMode(item.IPv6AssignmentMode)
	item.Remark = strings.TrimSpace(item.Remark)
	if item.BridgeMode == managedNetworkBridgeModeExisting {
		item.BridgeMTU = 0
		item.BridgeVLANAware = false
	}
	return item
}

func normalizeManagedNetworkBridgeMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", managedNetworkBridgeModeCreate:
		return managedNetworkBridgeModeCreate
	case managedNetworkBridgeModeExisting:
		return managedNetworkBridgeModeExisting
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeManagedNetworkIPv6AssignmentMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "single", "single_ip", "single_128", "ip_128":
		return managedNetworkIPv6AssignmentModeSingle128
	case "prefix", "prefix64", "prefix_64":
		return managedNetworkIPv6AssignmentModePrefix64
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func isValidManagedNetworkBridgeMode(value string) bool {
	switch value {
	case managedNetworkBridgeModeCreate, managedNetworkBridgeModeExisting:
		return true
	default:
		return false
	}
}

func validateManagedNetworkBridgeConfig(item ManagedNetwork, scope string) []ruleValidationIssue {
	item = normalizeManagedNetwork(item)
	if item.BridgeMode != managedNetworkBridgeModeCreate {
		return nil
	}
	if item.BridgeMTU < 0 || item.BridgeMTU > 65535 {
		return singleValidationIssue(scope, item.ID, "bridge_mtu", "bridge_mtu must be between 0 and 65535")
	}
	return nil
}

func loadManagedNetworkHostInterfaces() ([]HostNetworkInterface, error) {
	load := loadCurrentHostNetworkInterfaces
	if loadHostNetworkInterfacesForManagedNetworkTests != nil {
		load = loadHostNetworkInterfacesForManagedNetworkTests
	}
	return load()
}

func validateManagedNetworkBridgeHostState(item ManagedNetwork) ([]ruleValidationIssue, error) {
	item = normalizeManagedNetwork(item)
	if item.Bridge == "" {
		return nil, nil
	}
	if item.BridgeMode == managedNetworkBridgeModeCreate {
		hostIfaces, err := loadManagedNetworkHostInterfaces()
		if err != nil {
			return nil, nil
		}
		if iface, ok := buildHostNetworkInterfaceMap(hostIfaces)[item.Bridge]; ok && !strings.EqualFold(strings.TrimSpace(iface.Kind), "bridge") {
			return singleValidationIssue("request", item.ID, "bridge", "bridge name is already used by a non-bridge interface"), nil
		}
		return nil, nil
	}
	if item.BridgeMode != managedNetworkBridgeModeExisting {
		return nil, nil
	}
	hostIfaces, err := loadManagedNetworkHostInterfaces()
	if err != nil {
		return nil, err
	}
	if _, ok := buildHostNetworkInterfaceMap(hostIfaces)[item.Bridge]; !ok {
		return singleValidationIssue("request", item.ID, "bridge", "bridge interface does not exist on this host"), nil
	}
	return nil, nil
}

func prepareManagedNetworkCreate(item ManagedNetwork) (ManagedNetwork, []ruleValidationIssue, error) {
	item = normalizeManagedNetwork(item)
	if item.ID != 0 {
		return ManagedNetwork{}, singleValidationIssue("create", 0, "id", "must be omitted when creating a managed network"), nil
	}
	if item.Name == "" {
		return ManagedNetwork{}, singleValidationIssue("create", 0, "name", "is required"), nil
	}
	if item.Bridge == "" {
		return ManagedNetwork{}, singleValidationIssue("create", 0, "bridge", "is required"), nil
	}
	if !isValidManagedNetworkBridgeMode(item.BridgeMode) {
		return ManagedNetwork{}, singleValidationIssue("create", 0, "bridge_mode", "must be one of create, existing"), nil
	}
	if !isValidManagedNetworkIPv6AssignmentMode(item.IPv6AssignmentMode) {
		return ManagedNetwork{}, singleValidationIssue("create", 0, "ipv6_assignment_mode", "must be one of single_128, prefix_64"), nil
	}
	if issues := validateManagedNetworkBridgeConfig(item, "create"); len(issues) > 0 {
		return ManagedNetwork{}, issues, nil
	}
	issues, err := validateManagedNetworkBridgeHostState(item)
	if err != nil {
		return ManagedNetwork{}, nil, err
	}
	if len(issues) > 0 {
		issues[0].Scope = "create"
		return ManagedNetwork{}, issues, nil
	}
	item.Enabled = true
	return item, nil, nil
}

func prepareManagedNetworkUpdate(db sqlRuleStore, item ManagedNetwork) (ManagedNetwork, []ruleValidationIssue, error) {
	item = normalizeManagedNetwork(item)
	if item.ID <= 0 {
		return ManagedNetwork{}, singleValidationIssue("update", item.ID, "id", "is required"), nil
	}
	existing, err := dbGetManagedNetwork(db, item.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ManagedNetwork{}, singleValidationIssue("update", item.ID, "id", "managed network not found"), nil
		}
		return ManagedNetwork{}, nil, err
	}
	if item.Name == "" {
		return ManagedNetwork{}, singleValidationIssue("update", item.ID, "name", "is required"), nil
	}
	if item.Bridge == "" {
		return ManagedNetwork{}, singleValidationIssue("update", item.ID, "bridge", "is required"), nil
	}
	if !isValidManagedNetworkBridgeMode(item.BridgeMode) {
		return ManagedNetwork{}, singleValidationIssue("update", item.ID, "bridge_mode", "must be one of create, existing"), nil
	}
	if !isValidManagedNetworkIPv6AssignmentMode(item.IPv6AssignmentMode) {
		return ManagedNetwork{}, singleValidationIssue("update", item.ID, "ipv6_assignment_mode", "must be one of single_128, prefix_64"), nil
	}
	if issues := validateManagedNetworkBridgeConfig(item, "update"); len(issues) > 0 {
		return ManagedNetwork{}, issues, nil
	}
	issues, err := validateManagedNetworkBridgeHostState(item)
	if err != nil {
		return ManagedNetwork{}, nil, err
	}
	if len(issues) > 0 {
		issues[0].Scope = "update"
		issues[0].ID = item.ID
		return ManagedNetwork{}, issues, nil
	}
	item.Enabled = existing.Enabled
	return item, nil, nil
}

func prepareManagedNetworkToggle(db sqlRuleStore, id int64) (ManagedNetwork, []ruleValidationIssue, error) {
	item, err := dbGetManagedNetwork(db, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ManagedNetwork{}, singleValidationIssue("toggle", id, "id", "managed network not found"), nil
		}
		return ManagedNetwork{}, nil, err
	}
	item.Enabled = !item.Enabled
	return *item, nil, nil
}

func isValidManagedNetworkIPv6AssignmentMode(value string) bool {
	switch value {
	case managedNetworkIPv6AssignmentModeSingle128, managedNetworkIPv6AssignmentModePrefix64:
		return true
	default:
		return false
	}
}

func loadManagedNetworkPreviewInterfaceInfos() ([]InterfaceInfo, error) {
	load := loadInterfaceInfos
	if loadInterfaceInfosForManagedNetworkPreviewTests != nil {
		load = loadInterfaceInfosForManagedNetworkPreviewTests
	}
	return load()
}

func buildManagedNetworkStatuses(db sqlRuleStore, items []ManagedNetwork, pm *ProcessManager) ([]ManagedNetworkStatus, error) {
	if len(items) == 0 {
		return []ManagedNetworkStatus{}, nil
	}

	statuses := make([]ManagedNetworkStatus, 0, len(items))
	infos, err := loadManagedNetworkPreviewInterfaceInfos()
	if err != nil {
		warning := fmt.Sprintf("interface inventory unavailable: %v", err)
		for _, item := range items {
			status := ManagedNetworkStatus{ManagedNetwork: item}
			if item.Enabled {
				status.PreviewWarnings = []string{warning}
			}
			statuses = append(statuses, status)
		}
		return statuses, nil
	}

	explicitIPv6, err := dbGetIPv6Assignments(db)
	if err != nil {
		return nil, err
	}
	reservationCounts, err := dbGetManagedNetworkReservationCounts(db)
	if err != nil {
		return nil, err
	}
	explicitEgressNATs, err := dbGetEgressNATs(db)
	if err != nil {
		return nil, err
	}

	inventory := buildManagedNetworkInterfaceInventory(infos, false)
	compiled := compileManagedNetworkRuntimeWithInventory(items, explicitIPv6, explicitEgressNATs, inventory)
	repairIssues := buildManagedNetworkRepairIssueMap(items, buildManagedNetworkRepairInterfaceParentMap(infos))
	var ipv6RuntimeStats map[int64]ipv6AssignmentRuntimeStats
	if len(compiled.IPv6Assignments) > 0 {
		ipv6RuntimeStats = pm.snapshotIPv6AssignmentRuntimeStats()
	}
	ipv4RuntimeStatuses := pm.snapshotManagedNetworkRuntimeStatus()
	for _, item := range items {
		preview := compiled.Previews[item.ID]
		status := ManagedNetworkStatus{
			ManagedNetwork:               item,
			ChildInterfaceCount:          len(preview.ChildInterfaces),
			ChildInterfaces:              append([]string(nil), preview.ChildInterfaces...),
			GeneratedIPv6AssignmentCount: preview.GeneratedIPv6AssignmentCount,
			GeneratedEgressNAT:           preview.GeneratedEgressNAT,
			ReservationCount:             reservationCounts[item.ID],
			PreviewWarnings:              append([]string(nil), preview.Warnings...),
			RepairRecommended:            len(repairIssues[item.ID]) > 0,
			RepairIssues:                 append([]string(nil), repairIssues[item.ID]...),
		}
		if runtime, ok := ipv4RuntimeStatuses[item.ID]; ok {
			status.IPv4RuntimeStatus = runtime.RuntimeStatus
			status.IPv4RuntimeDetail = runtime.RuntimeDetail
			status.IPv4DHCPv4ReplyCount = runtime.DHCPv4ReplyCount
		}
		if len(preview.GeneratedIPv6AssignmentIDs) > 0 {
			runtimeStatus, runtimeDetail, raCount, dhcpCount := aggregateManagedNetworkIPv6RuntimeStatus(preview.GeneratedIPv6AssignmentIDs, ipv6RuntimeStats)
			status.IPv6RuntimeStatus = runtimeStatus
			status.IPv6RuntimeDetail = runtimeDetail
			status.IPv6RAAdvertisementCount = raCount
			status.IPv6DHCPv6ReplyCount = dhcpCount
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func aggregateManagedNetworkIPv6RuntimeStatus(ids []int64, stats map[int64]ipv6AssignmentRuntimeStats) (string, string, uint64, uint64) {
	if len(ids) == 0 {
		return "", "", 0, 0
	}

	status := "running"
	var detailBuilder strings.Builder
	detailCount := 0
	var raCount uint64
	var dhcpCount uint64
	for _, id := range ids {
		stat, ok := stats[id]
		if !ok {
			if status != "error" {
				status = "draining"
			}
			appendManagedNetworkIPv6RuntimeDetail(&detailBuilder, &detailCount, id, "waiting for runtime apply")
			continue
		}
		raCount += stat.RAAdvertisementCount
		dhcpCount += stat.DHCPv6ReplyCount
		switch strings.TrimSpace(stat.RuntimeStatus) {
		case "error":
			status = "error"
		case "draining":
			if status != "error" {
				status = "draining"
			}
		case "":
			if status != "error" {
				status = "draining"
			}
		}
		if detail := strings.TrimSpace(stat.RuntimeDetail); detail != "" {
			appendManagedNetworkIPv6RuntimeDetail(&detailBuilder, &detailCount, id, detail)
		}
	}
	return status, detailBuilder.String(), raCount, dhcpCount
}

func appendManagedNetworkIPv6RuntimeDetail(builder *strings.Builder, count *int, id int64, detail string) {
	if builder == nil || count == nil {
		return
	}
	if *count > 0 {
		builder.WriteString("; ")
	}
	builder.WriteString("assignment #")
	var idBuf [20]byte
	builder.Write(strconv.AppendInt(idBuf[:0], id, 10))
	builder.WriteString(": ")
	builder.WriteString(detail)
	*count = *count + 1
}

func handleListManagedNetworks(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	items, err := dbGetManagedNetworks(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	statuses, err := buildManagedNetworkStatuses(db, items, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].ID < statuses[j].ID })
	if statuses == nil {
		statuses = []ManagedNetworkStatus{}
	}
	writeJSON(w, http.StatusOK, statuses)
}

func maybeRedistributeManagedNetworkWorkers(pm *ProcessManager) {
	if pm == nil || pm.db == nil || pm.cfg == nil {
		return
	}
	pm.redistributeWorkers()
}

func queueManagedNetworkRuntimeReload(pm *ProcessManager) ManagedNetworkRuntimeReloadResponse {
	if pm == nil {
		return ManagedNetworkRuntimeReloadResponse{}
	}
	if pm.db == nil || pm.cfg == nil {
		pm.mu.Lock()
		pm.managedRuntimeReloadLastRequestedAt = time.Now()
		pm.managedRuntimeReloadLastRequestSource = "manual"
		pm.managedRuntimeReloadLastRequestSummary = ""
		pm.mu.Unlock()
		pm.markManagedNetworkRuntimeReloadStarted()
		err := fmt.Errorf("managed network runtime reload requires database/config context")
		pm.markManagedNetworkRuntimeReloadCompleted("fallback", "", err)
		pm.requestRedistributeWorkers(0)
		return ManagedNetworkRuntimeReloadResponse{
			Status: "fallback",
			Error:  err.Error(),
		}
	}
	pm.mu.Lock()
	hasReloadLoop := pm.managedRuntimeReloadWake != nil
	pm.mu.Unlock()
	if hasReloadLoop {
		pm.requestManagedNetworkRuntimeReloadWithSource(0, "manual")
		return ManagedNetworkRuntimeReloadResponse{Status: "queued"}
	}
	pm.mu.Lock()
	pm.managedRuntimeReloadLastRequestedAt = time.Now()
	pm.managedRuntimeReloadLastRequestSource = "manual"
	pm.managedRuntimeReloadLastRequestSummary = ""
	pm.mu.Unlock()
	pm.markManagedNetworkRuntimeReloadStarted()
	if err := pm.reloadManagedNetworkRuntimeOnly(); err != nil {
		pm.markManagedNetworkRuntimeReloadCompleted("fallback", "", err)
		log.Printf("managed network runtime reload: targeted reload failed, falling back to full redistribute: %v", err)
		pm.requestRedistributeWorkers(0)
		return ManagedNetworkRuntimeReloadResponse{
			Status: "fallback",
			Error:  err.Error(),
		}
	}
	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	result := strings.TrimSpace(status.LastResult)
	if result == "" {
		result = "success"
	}
	return ManagedNetworkRuntimeReloadResponse{
		Status: result,
		Error:  strings.TrimSpace(status.LastError),
	}
}

func repairManagedNetworkHostStateForProcessManager(pm *ProcessManager) (managedNetworkRepairResult, error) {
	if pm == nil || pm.db == nil {
		return managedNetworkRepairResult{}, nil
	}
	managedNetworks, err := dbGetManagedNetworks(pm.db)
	if err != nil {
		return managedNetworkRepairResult{}, fmt.Errorf("load managed networks: %w", err)
	}
	return repairManagedNetworkHostStateWithHook(managedNetworks)
}

func hasManagedNetworkRepairChanges(result managedNetworkRepairResult) bool {
	return len(result.Bridges) > 0 || len(result.GuestLinks) > 0
}

func handleAddManagedNetwork(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var item ManagedNetwork
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	item, issues, err := prepareManagedNetworkCreate(item)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		writeValidationIssueResponse(w, http.StatusBadRequest, issues)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	id, err := dbAddManagedNetwork(tx, &item)
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

func handleUpdateManagedNetwork(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var item ManagedNetwork
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

	item, issues, err := prepareManagedNetworkUpdate(tx, item)
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

	if err := dbUpdateManagedNetwork(tx, &item); err != nil {
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

func handleToggleManagedNetwork(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		writeValidationIssueResponse(w, http.StatusBadRequest, singleValidationIssue("toggle", 0, "id", "invalid id"))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	item, issues, err := prepareManagedNetworkToggle(tx, id)
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
	if err := dbSetManagedNetworkEnabled(tx, id, item.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	maybeRedistributeManagedNetworkWorkers(pm)
	writeJSON(w, http.StatusOK, map[string]interface{}{"id": id, "enabled": item.Enabled})
}

func handleReloadManagedNetworkRuntime(w http.ResponseWriter, r *http.Request, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, queueManagedNetworkRuntimeReload(pm))
}

func handleRepairManagedNetworkRuntime(w http.ResponseWriter, r *http.Request, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result, err := repairManagedNetworkHostStateForProcessManager(pm)
	if err != nil {
		log.Printf("managed network repair: %v", err)
		if hasManagedNetworkRepairChanges(result) {
			queueManagedNetworkRuntimeReload(pm)
			writeJSON(w, http.StatusOK, ManagedNetworkRepairResponse{
				Status:     "partial",
				Bridges:    append([]string(nil), result.Bridges...),
				GuestLinks: append([]string(nil), result.GuestLinks...),
				Error:      err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	queueManagedNetworkRuntimeReload(pm)
	writeJSON(w, http.StatusOK, ManagedNetworkRepairResponse{
		Status:     "queued",
		Bridges:    append([]string(nil), result.Bridges...),
		GuestLinks: append([]string(nil), result.GuestLinks...),
	})
}

func handleManagedNetworkRuntimeReloadStatus(w http.ResponseWriter, r *http.Request, pm *ProcessManager) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if pm == nil {
		writeJSON(w, http.StatusOK, ManagedNetworkRuntimeReloadStatus{})
		return
	}
	writeJSON(w, http.StatusOK, pm.snapshotManagedNetworkRuntimeReloadStatus())
}

func handleDeleteManagedNetwork(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
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

	if _, err := dbGetManagedNetwork(tx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeValidationIssueResponse(w, http.StatusNotFound, singleValidationIssue("delete", id, "id", "managed network not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := dbDeleteManagedNetwork(tx, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	maybeRedistributeManagedNetworkWorkers(pm)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
