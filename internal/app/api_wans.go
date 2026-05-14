package app

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
)

func handleListWANProfiles(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	items, err := dbGetWANProfiles(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, buildWANProfileStatuses(items))
}

func handleAddWANProfile(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	var item WANProfile
	if err := decodeJSONRequestBody(w, r, &item, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	item, issues := prepareWANProfileCreate(item)
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

	id, err := dbAddWANProfile(tx, &item)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	item.ID = id
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, maskWANProfilePassword(item))
}

func handleUpdateWANProfile(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	var item WANProfile
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

	item, issues, err := prepareWANProfileUpdate(tx, item)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		status := http.StatusBadRequest
		if hasValidationMessage(issues, "wan profile not found") {
			status = http.StatusNotFound
		}
		writeValidationIssueResponse(w, status, issues)
		return
	}

	if err := dbUpdateWANProfile(tx, &item); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, maskWANProfilePassword(item))
}

func handleDeleteWANProfile(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		writeValidationIssueResponse(w, http.StatusBadRequest, singleValidationIssue("delete", 0, "id", "invalid id"))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	if _, err := dbGetWANProfile(tx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeValidationIssueResponse(w, http.StatusNotFound, singleValidationIssue("delete", id, "id", "wan profile not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	refs, err := dbCountWANProfileReferences(tx, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if refs.EgressNATs > 0 || refs.ManagedNetworks > 0 {
		writeValidationIssueResponse(w, http.StatusBadRequest, []ruleValidationIssue{{
			Scope:   "delete",
			ID:      id,
			Field:   "id",
			Message: "wan profile is referenced",
		}})
		return
	}
	if err := dbDeleteWANProfile(tx, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func handleToggleWANProfile(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		writeValidationIssueResponse(w, http.StatusBadRequest, singleValidationIssue("toggle", 0, "id", "invalid id"))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	item, issues, err := prepareWANProfileToggle(tx, id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		status := http.StatusBadRequest
		if hasValidationMessage(issues, "wan profile not found") {
			status = http.StatusNotFound
		}
		writeValidationIssueResponse(w, status, issues)
		return
	}
	if err := dbSetWANProfileEnabled(tx, id, item.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"id": id, "enabled": item.Enabled})
}

func handleWANProfileStatus(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		writeValidationIssueResponse(w, http.StatusBadRequest, singleValidationIssue("status", 0, "id", "invalid id"))
		return
	}
	item, err := dbGetWANProfile(db, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeValidationIssueResponse(w, http.StatusNotFound, singleValidationIssue("status", id, "id", "wan profile not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	statuses := buildWANProfileStatuses([]WANProfile{*item})
	if len(statuses) == 0 {
		writeJSON(w, http.StatusOK, WANProfileStatus{WANProfile: maskWANProfilePassword(*item), Status: "unknown"})
		return
	}
	writeJSON(w, http.StatusOK, statuses[0])
}

func handleApplyWANProfile(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		writeValidationIssueResponse(w, http.StatusBadRequest, singleValidationIssue("apply", 0, "id", "invalid id"))
		return
	}
	item, err := dbGetWANProfile(db, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeValidationIssueResponse(w, http.StatusNotFound, singleValidationIssue("apply", id, "id", "wan profile not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	result, err := applyWANProfileConfig(*item)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wanCommandJSON(result))
		return
	}
	writeJSON(w, http.StatusOK, wanCommandJSON(result))
}

func handleReconnectWANProfile(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		writeValidationIssueResponse(w, http.StatusBadRequest, singleValidationIssue("reconnect", 0, "id", "invalid id"))
		return
	}
	item, err := dbGetWANProfile(db, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeValidationIssueResponse(w, http.StatusNotFound, singleValidationIssue("reconnect", id, "id", "wan profile not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	result, err := reconnectWANProfile(*item)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wanCommandJSON(result))
		return
	}
	writeJSON(w, http.StatusOK, wanCommandJSON(result))
}
