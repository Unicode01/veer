package app

import (
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strconv"
)

func handleHostNetwork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	items, err := loadCurrentHostNetworkInterfaces()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if items == nil {
		items = []HostNetworkInterface{}
	}
	writeJSON(w, http.StatusOK, HostNetworkResponse{Interfaces: items})
}

func handleListIPv6Assignments(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	items, err := dbGetIPv6Assignments(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	if stats := pm.snapshotIPv6AssignmentRuntimeStats(); len(stats) > 0 {
		for i := range items {
			if stat, ok := stats[items[i].ID]; ok {
				items[i].RAAdvertisementCount = stat.RAAdvertisementCount
				items[i].DHCPv6ReplyCount = stat.DHCPv6ReplyCount
				items[i].RuntimeStatus = stat.RuntimeStatus
				items[i].RuntimeDetail = stat.RuntimeDetail
			}
		}
	}
	if items == nil {
		items = []IPv6Assignment{}
	}
	writeJSON(w, http.StatusOK, items)
}

func queueIPv6AssignmentRedistribute(pm *ProcessManager) {
	if pm == nil {
		return
	}
	pm.requestRedistributeWorkers(0)
}

func prepareIPv6AssignmentCreate(db sqlRuleStore, item IPv6Assignment) (IPv6Assignment, []ruleValidationIssue, error) {
	hostIfaces, err := loadIPv6AssignmentHostNetworkInterfaces()
	if err != nil {
		return IPv6Assignment{}, nil, err
	}
	existing, err := dbGetEnabledIPv6Assignments(db)
	if err != nil {
		return IPv6Assignment{}, nil, err
	}
	item, issues := normalizeAndValidateIPv6Assignment(item, "create", false, buildHostNetworkInterfaceMap(hostIfaces), hostIfaces, existing)
	return item, issues, nil
}

func prepareIPv6AssignmentUpdate(db sqlRuleStore, item IPv6Assignment) (IPv6Assignment, []ruleValidationIssue, error) {
	if item.ID <= 0 {
		return IPv6Assignment{}, singleValidationIssue("update", item.ID, "id", "is required"), nil
	}
	if _, err := dbGetIPv6Assignment(db, item.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return IPv6Assignment{}, singleValidationIssue("update", item.ID, "id", "ipv6 assignment not found"), nil
		}
		return IPv6Assignment{}, nil, err
	}

	hostIfaces, err := loadIPv6AssignmentHostNetworkInterfaces()
	if err != nil {
		return IPv6Assignment{}, nil, err
	}
	existing, err := dbGetEnabledIPv6Assignments(db)
	if err != nil {
		return IPv6Assignment{}, nil, err
	}
	item, issues := normalizeAndValidateIPv6Assignment(item, "update", true, buildHostNetworkInterfaceMap(hostIfaces), hostIfaces, existing)
	return item, issues, nil
}

func handleAddIPv6Assignment(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var item IPv6Assignment
	if err := decodeJSONRequestBody(w, r, &item, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	item, issues, err := prepareIPv6AssignmentCreate(tx, item)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		writeValidationIssueResponse(w, http.StatusBadRequest, issues)
		return
	}

	id, err := dbAddIPv6Assignment(tx, &item)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	item.ID = id
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	queueIPv6AssignmentRedistribute(pm)
	writeJSON(w, http.StatusOK, item)
}

func handleUpdateIPv6Assignment(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var item IPv6Assignment
	if err := decodeJSONRequestBody(w, r, &item, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	item, issues, err := prepareIPv6AssignmentUpdate(tx, item)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		status := http.StatusBadRequest
		if hasValidationMessage(issues, "ipv6 assignment not found") {
			status = http.StatusNotFound
		}
		writeValidationIssueResponse(w, status, issues)
		return
	}

	if err := dbUpdateIPv6Assignment(tx, &item); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	queueIPv6AssignmentRedistribute(pm)
	writeJSON(w, http.StatusOK, item)
}

func handleDeleteIPv6Assignment(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
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

	if _, err := dbGetIPv6Assignment(tx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeValidationIssueResponse(w, http.StatusNotFound, singleValidationIssue("delete", id, "id", "ipv6 assignment not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := dbDeleteIPv6Assignment(tx, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	queueIPv6AssignmentRedistribute(pm)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
