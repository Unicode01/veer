package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

//go:embed web
var webFS embed.FS

type ruleSetEnabledRequest struct {
	ID      int64 `json:"id"`
	Enabled bool  `json:"enabled"`
}

type ruleBatchRequest struct {
	Create     []Rule                  `json:"create"`
	Update     []Rule                  `json:"update"`
	DeleteIDs  []int64                 `json:"delete_ids"`
	SetEnabled []ruleSetEnabledRequest `json:"set_enabled"`
}

type ruleBatchResponse struct {
	Created    []Rule                  `json:"created,omitempty"`
	Updated    []Rule                  `json:"updated,omitempty"`
	DeletedIDs []int64                 `json:"deleted_ids,omitempty"`
	SetEnabled []ruleSetEnabledRequest `json:"set_enabled,omitempty"`
}

type ruleValidationIssue struct {
	Scope   string `json:"scope"`
	Index   int    `json:"index,omitempty"`
	ID      int64  `json:"id,omitempty"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

type ruleValidateResponse struct {
	Valid      bool                    `json:"valid"`
	Error      string                  `json:"error,omitempty"`
	Create     []Rule                  `json:"create,omitempty"`
	Update     []Rule                  `json:"update,omitempty"`
	DeleteIDs  []int64                 `json:"delete_ids,omitempty"`
	SetEnabled []ruleSetEnabledRequest `json:"set_enabled,omitempty"`
	Issues     []ruleValidationIssue   `json:"issues,omitempty"`
}

type ruleFilter struct {
	IDs          map[int64]struct{}
	Tags         map[string]struct{}
	Protocols    map[string]struct{}
	Statuses     map[string]struct{}
	Enabled      *bool
	Transparent  *bool
	InInterface  string
	OutInterface string
	InIP         string
	OutIP        string
	InPort       int
	OutPort      int
	Query        string
}

type preparedRuleBatch struct {
	Create     []Rule
	Update     []Rule
	DeleteIDs  []int64
	SetEnabled []ruleSetEnabledRequest
}

type projectedRuleState struct {
	Rule         Rule
	ContentScope string
	ContentIndex int
	EnableScope  string
	EnableIndex  int
}

func startAPI(cfg *Config, db *sql.DB, pm *ProcessManager) {
	mux := http.NewServeMux()

	webSub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(webSub)))

	mux.HandleFunc("/api/interfaces", authMiddleware(cfg, handleInterfaces))
	mux.HandleFunc("/api/tags", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tags := cfg.Tags
		if tags == nil {
			tags = []string{}
		}
		writeJSON(w, http.StatusOK, tags)
	}))
	mux.HandleFunc("/api/rules/validate", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleValidateRules(w, r, db)
	}))
	mux.HandleFunc("/api/rules/batch", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleBatchRules(w, r, db, pm)
	}))
	mux.HandleFunc("/api/rules", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleListRules(w, r, db, pm)
		case http.MethodPost:
			handleAddRule(w, r, db, pm)
		case http.MethodPut:
			handleUpdateRule(w, r, db, pm)
		case http.MethodDelete:
			handleDeleteRule(w, r, db, pm)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/sites", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleListSites(w, r, db, pm)
		case http.MethodPost:
			handleAddSite(w, r, db, pm)
		case http.MethodPut:
			handleUpdateSite(w, r, db, pm)
		case http.MethodDelete:
			handleDeleteSite(w, r, db, pm)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/ranges", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleListRanges(w, r, db, pm)
		case http.MethodPost:
			handleAddRange(w, r, db, pm)
		case http.MethodPut:
			handleUpdateRange(w, r, db, pm)
		case http.MethodDelete:
			handleDeleteRange(w, r, db, pm)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/rules/toggle", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		handleToggleRule(w, r, db, pm)
	}))
	mux.HandleFunc("/api/sites/toggle", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		handleToggleSite(w, r, db, pm)
	}))
	mux.HandleFunc("/api/ranges/toggle", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		handleToggleRange(w, r, db, pm)
	}))
	mux.HandleFunc("/api/workers", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleListWorkers(w, r, db, pm)
	}))
	mux.HandleFunc("/api/rules/stats", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleListRuleStats(w, r, pm)
	}))
	mux.HandleFunc("/api/ranges/stats", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleListRangeStats(w, r, pm)
	}))
	mux.HandleFunc("/api/sites/stats", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleListSiteStats(w, r, pm)
	}))

	addr := fmt.Sprintf(":%d", cfg.WebPort)
	log.Printf("web server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("http server: %v", err)
	}
}

func authMiddleware(cfg *Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")
		if token != cfg.WebToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		next(w, r)
	}
}

func handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		info := InterfaceInfo{Name: iface.Name}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				info.Addrs = append(info.Addrs, ipnet.IP.String())
			}
		}
		if len(info.Addrs) > 0 {
			sort.Strings(info.Addrs)
			result = append(result, info)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	writeJSON(w, http.StatusOK, result)
}

func handleListRules(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	filters, err := parseRuleFilter(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	rules, err := dbGetRules(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	runningRules, failedRules := collectRuleRuntimeStatus(pm)
	var statuses []RuleStatus
	for _, rule := range rules {
		item := pm.buildRuleStatus(rule, ruleRuntimeStatus(rule, runningRules, failedRules))
		if matchesRuleFilter(item, filters) {
			statuses = append(statuses, item)
		}
	}
	if statuses == nil {
		statuses = []RuleStatus{}
	}
	writeJSON(w, http.StatusOK, statuses)
}

func collectRuleRuntimeStatus(pm *ProcessManager) (map[int64]bool, map[int64]bool) {
	runningRules := make(map[int64]bool)
	failedRules := make(map[int64]bool)
	pm.mu.Lock()
	for id := range pm.kernelRules {
		runningRules[id] = true
	}
	for _, wi := range pm.ruleWorkers {
		if !wi.running {
			continue
		}
		for _, r := range wi.rules {
			if wi.failedRules != nil && wi.failedRules[r.ID] {
				failedRules[r.ID] = true
				continue
			}
			runningRules[r.ID] = true
		}
	}
	pm.mu.Unlock()
	return runningRules, failedRules
}

func ruleRuntimeStatus(rule Rule, runningRules, failedRules map[int64]bool) string {
	if failedRules[rule.ID] {
		return "error"
	}
	if runningRules[rule.ID] {
		return "running"
	}
	return "stopped"
}

func parseRuleFilter(r *http.Request) (ruleFilter, error) {
	query := r.URL.Query()
	filters := ruleFilter{
		InInterface:  strings.TrimSpace(query.Get("in_interface")),
		OutInterface: strings.TrimSpace(query.Get("out_interface")),
		InIP:         strings.TrimSpace(query.Get("in_ip")),
		OutIP:        strings.TrimSpace(query.Get("out_ip")),
		Query:        strings.ToLower(strings.TrimSpace(query.Get("q"))),
	}

	var err error
	filters.IDs, err = parseInt64SetQuery(query.Get("id"), query.Get("ids"))
	if err != nil {
		return filters, fmt.Errorf("invalid id filter: %w", err)
	}
	filters.Tags = mergeStringSets(parseCSVSet(query.Get("tag"), false), parseCSVSet(query.Get("tags"), false))
	filters.Protocols = mergeStringSets(parseCSVSet(query.Get("protocol"), true), parseCSVSet(query.Get("protocols"), true))
	if err := validateCSVValues(filters.Protocols, map[string]struct{}{"tcp": {}, "udp": {}, "tcp+udp": {}}, "protocol"); err != nil {
		return filters, err
	}
	filters.Statuses = mergeStringSets(parseCSVSet(query.Get("status"), true), parseCSVSet(query.Get("statuses"), true))
	if err := validateCSVValues(filters.Statuses, map[string]struct{}{"running": {}, "stopped": {}, "error": {}}, "status"); err != nil {
		return filters, err
	}
	filters.Enabled, err = parseOptionalBoolQuery(query.Get("enabled"))
	if err != nil {
		return filters, fmt.Errorf("invalid enabled filter: %w", err)
	}
	filters.Transparent, err = parseOptionalBoolQuery(query.Get("transparent"))
	if err != nil {
		return filters, fmt.Errorf("invalid transparent filter: %w", err)
	}
	if v := strings.TrimSpace(query.Get("in_port")); v != "" {
		filters.InPort, err = parsePortValue(v)
		if err != nil {
			return filters, fmt.Errorf("invalid in_port filter: %w", err)
		}
	}
	if v := strings.TrimSpace(query.Get("out_port")); v != "" {
		filters.OutPort, err = parsePortValue(v)
		if err != nil {
			return filters, fmt.Errorf("invalid out_port filter: %w", err)
		}
	}
	return filters, nil
}

func parseInt64SetQuery(values ...string) (map[int64]struct{}, error) {
	result := make(map[int64]struct{})
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			id, err := strconv.ParseInt(part, 10, 64)
			if err != nil || id <= 0 {
				return nil, fmt.Errorf("invalid value %q", part)
			}
			result[id] = struct{}{}
		}
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func parseCSVSet(value string, lower bool) map[string]struct{} {
	result := make(map[string]struct{})
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lower {
			part = strings.ToLower(part)
		}
		result[part] = struct{}{}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func mergeStringSets(a, b map[string]struct{}) map[string]struct{} {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	for item := range b {
		a[item] = struct{}{}
	}
	return a
}

func validateCSVValues(values map[string]struct{}, allowed map[string]struct{}, name string) error {
	for value := range values {
		if _, ok := allowed[value]; !ok {
			return fmt.Errorf("invalid %s value %q", name, value)
		}
	}
	return nil
}

func parseOptionalBoolQuery(value string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return nil, nil
	case "1", "true", "yes", "on":
		v := true
		return &v, nil
	case "0", "false", "no", "off":
		v := false
		return &v, nil
	default:
		return nil, fmt.Errorf("invalid value %q", value)
	}
}

func parsePortValue(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("must be between 1 and 65535")
	}
	return port, nil
}

func matchesRuleFilter(rule RuleStatus, filters ruleFilter) bool {
	if len(filters.IDs) > 0 {
		if _, ok := filters.IDs[rule.ID]; !ok {
			return false
		}
	}
	if len(filters.Tags) > 0 {
		if _, ok := filters.Tags[rule.Tag]; !ok {
			return false
		}
	}
	if len(filters.Protocols) > 0 {
		if _, ok := filters.Protocols[strings.ToLower(rule.Protocol)]; !ok {
			return false
		}
	}
	if len(filters.Statuses) > 0 {
		if _, ok := filters.Statuses[strings.ToLower(rule.Status)]; !ok {
			return false
		}
	}
	if filters.Enabled != nil && rule.Enabled != *filters.Enabled {
		return false
	}
	if filters.Transparent != nil && rule.Transparent != *filters.Transparent {
		return false
	}
	if filters.InInterface != "" && rule.InInterface != filters.InInterface {
		return false
	}
	if filters.OutInterface != "" && rule.OutInterface != filters.OutInterface {
		return false
	}
	if filters.InIP != "" && rule.InIP != filters.InIP {
		return false
	}
	if filters.OutIP != "" && rule.OutIP != filters.OutIP {
		return false
	}
	if filters.InPort > 0 && rule.InPort != filters.InPort {
		return false
	}
	if filters.OutPort > 0 && rule.OutPort != filters.OutPort {
		return false
	}
	if filters.Query != "" && !matchesRuleSearchQuery(rule, filters.Query) {
		return false
	}
	return true
}

func matchesRuleSearchQuery(rule RuleStatus, query string) bool {
	values := []string{
		strconv.FormatInt(rule.ID, 10),
		rule.Remark,
		rule.Tag,
		rule.InInterface,
		rule.InIP,
		strconv.Itoa(rule.InPort),
		rule.OutInterface,
		rule.OutIP,
		strconv.Itoa(rule.OutPort),
		rule.Protocol,
		rule.Status,
		rule.EnginePreference,
		rule.EffectiveEngine,
		rule.KernelReason,
		rule.FallbackReason,
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func handleValidateRules(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	var req ruleBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	prepared, issues, err := prepareRuleBatch(db, req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	resp := ruleValidateResponse{
		Valid:      len(issues) == 0,
		Error:      summarizeRuleIssues(issues),
		Create:     prepared.Create,
		Update:     prepared.Update,
		DeleteIDs:  prepared.DeleteIDs,
		SetEnabled: prepared.SetEnabled,
		Issues:     issues,
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleBatchRules(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var req ruleBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	prepared, issues, err := prepareRuleBatch(db, req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		writeJSON(w, http.StatusBadRequest, ruleValidateResponse{
			Valid:      false,
			Error:      summarizeRuleIssues(issues),
			Create:     prepared.Create,
			Update:     prepared.Update,
			DeleteIDs:  prepared.DeleteIDs,
			SetEnabled: prepared.SetEnabled,
			Issues:     issues,
		})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	var resp ruleBatchResponse
	for _, rule := range prepared.Create {
		item := rule
		id, err := dbAddRule(tx, &item)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		item.ID = id
		resp.Created = append(resp.Created, item)
	}
	for _, rule := range prepared.Update {
		item := rule
		if err := dbUpdateRule(tx, &item); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		resp.Updated = append(resp.Updated, item)
	}
	for _, id := range prepared.DeleteIDs {
		if err := dbDeleteRule(tx, id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		resp.DeletedIDs = append(resp.DeletedIDs, id)
	}
	for _, change := range prepared.SetEnabled {
		if err := dbSetRuleEnabled(tx, change.ID, change.Enabled); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		resp.SetEnabled = append(resp.SetEnabled, change)
	}

	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	pm.redistributeWorkers()
	writeJSON(w, http.StatusOK, resp)
}

func prepareRuleBatch(db sqlRuleStore, req ruleBatchRequest) (preparedRuleBatch, []ruleValidationIssue, error) {
	var prepared preparedRuleBatch
	if len(req.Create) == 0 && len(req.Update) == 0 && len(req.DeleteIDs) == 0 && len(req.SetEnabled) == 0 {
		return prepared, []ruleValidationIssue{{
			Scope:   "request",
			Message: "at least one batch operation is required",
		}}, nil
	}

	knownIfaces, err := loadInterfaceSet()
	if err != nil {
		return prepared, nil, err
	}
	existingRules, err := dbGetRules(db)
	if err != nil {
		return prepared, nil, err
	}

	existingByID := make(map[int64]Rule, len(existingRules))
	projected := make(map[int64]projectedRuleState, len(existingRules))
	for _, rule := range existingRules {
		existingByID[rule.ID] = rule
		projected[rule.ID] = projectedRuleState{
			Rule:         rule,
			ContentScope: "existing",
			ContentIndex: -1,
			EnableScope:  "existing",
			EnableIndex:  -1,
		}
	}

	var issues []ruleValidationIssue
	deleteSet := make(map[int64]struct{})
	for _, id := range req.DeleteIDs {
		if id <= 0 {
			issues = appendRuleIssue(issues, "delete_ids", 0, id, "id", "must be greater than 0")
			continue
		}
		if _, seen := deleteSet[id]; seen {
			continue
		}
		deleteSet[id] = struct{}{}
		if _, ok := projected[id]; ok {
			prepared.DeleteIDs = append(prepared.DeleteIDs, id)
			delete(projected, id)
		}
	}

	updateSeen := make(map[int64]struct{})
	for i, raw := range req.Update {
		index := i + 1
		rule, ruleIssues := normalizeAndValidateRule(raw, "update", index, true, knownIfaces)
		issues = append(issues, ruleIssues...)
		if len(ruleIssues) > 0 {
			continue
		}
		if _, seen := updateSeen[rule.ID]; seen {
			issues = appendRuleIssue(issues, "update", index, rule.ID, "id", "duplicate rule id in update list")
			continue
		}
		updateSeen[rule.ID] = struct{}{}
		if _, deleting := deleteSet[rule.ID]; deleting {
			issues = appendRuleIssue(issues, "update", index, rule.ID, "id", "cannot update a rule scheduled for deletion")
			continue
		}
		existing, ok := existingByID[rule.ID]
		if !ok {
			issues = appendRuleIssue(issues, "update", index, rule.ID, "id", "rule not found")
			continue
		}
		rule.Enabled = existing.Enabled
		prepared.Update = append(prepared.Update, rule)
		projected[rule.ID] = projectedRuleState{
			Rule:         rule,
			ContentScope: "update",
			ContentIndex: index,
			EnableScope:  "update",
			EnableIndex:  index,
		}
	}

	setEnabledSeen := make(map[int64]struct{})
	for i, change := range req.SetEnabled {
		index := i + 1
		if change.ID <= 0 {
			issues = appendRuleIssue(issues, "set_enabled", index, change.ID, "id", "must be greater than 0")
			continue
		}
		if _, seen := setEnabledSeen[change.ID]; seen {
			issues = appendRuleIssue(issues, "set_enabled", index, change.ID, "id", "duplicate rule id in set_enabled list")
			continue
		}
		setEnabledSeen[change.ID] = struct{}{}
		if _, deleting := deleteSet[change.ID]; deleting {
			issues = appendRuleIssue(issues, "set_enabled", index, change.ID, "id", "cannot change enabled state for a rule scheduled for deletion")
			continue
		}
		state, ok := projected[change.ID]
		if !ok {
			issues = appendRuleIssue(issues, "set_enabled", index, change.ID, "id", "rule not found")
			continue
		}
		state.Rule.Enabled = change.Enabled
		state.EnableScope = "set_enabled"
		state.EnableIndex = index
		projected[change.ID] = state
		prepared.SetEnabled = append(prepared.SetEnabled, change)
	}

	for i, raw := range req.Create {
		index := i + 1
		rule, ruleIssues := normalizeAndValidateRule(raw, "create", index, false, knownIfaces)
		issues = append(issues, ruleIssues...)
		if len(ruleIssues) > 0 {
			continue
		}
		rule.ID = 0
		rule.Enabled = true
		prepared.Create = append(prepared.Create, rule)
	}

	var conflictStates []projectedRuleState
	for _, state := range projected {
		if state.Rule.Enabled {
			conflictStates = append(conflictStates, state)
		}
	}
	for i, rule := range prepared.Create {
		if !rule.Enabled {
			continue
		}
		conflictStates = append(conflictStates, projectedRuleState{
			Rule:         rule,
			ContentScope: "create",
			ContentIndex: i + 1,
			EnableScope:  "create",
			EnableIndex:  i + 1,
		})
	}
	issues = append(issues, detectRuleConflicts(conflictStates)...)

	sort.Slice(prepared.DeleteIDs, func(i, j int) bool { return prepared.DeleteIDs[i] < prepared.DeleteIDs[j] })
	return prepared, issues, nil
}

func loadInterfaceSet() (map[string]struct{}, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make(map[string]struct{}, len(ifaces))
	for _, iface := range ifaces {
		result[iface.Name] = struct{}{}
	}
	return result, nil
}

func normalizeAndValidateRule(rule Rule, scope string, index int, requireID bool, knownIfaces map[string]struct{}) (Rule, []ruleValidationIssue) {
	rule.InInterface = strings.TrimSpace(rule.InInterface)
	rule.InIP = strings.TrimSpace(rule.InIP)
	rule.OutInterface = strings.TrimSpace(rule.OutInterface)
	rule.OutIP = strings.TrimSpace(rule.OutIP)
	rule.Protocol = strings.ToLower(strings.TrimSpace(rule.Protocol))
	rule.Remark = strings.TrimSpace(rule.Remark)
	rule.Tag = strings.TrimSpace(rule.Tag)
	rule.EnginePreference = ruleEngineAuto
	if rule.Protocol == "" {
		rule.Protocol = "tcp"
	}

	var issues []ruleValidationIssue
	if requireID {
		if rule.ID <= 0 {
			issues = appendRuleIssue(issues, scope, index, rule.ID, "id", "is required")
		}
	} else if rule.ID != 0 {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "id", "must be omitted when creating a rule")
	}

	if rule.InIP == "" {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "in_ip", "is required")
	} else if ip := net.ParseIP(rule.InIP); ip == nil || ip.To4() == nil {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "in_ip", "must be a valid IPv4 address")
	}
	if rule.OutIP == "" {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "out_ip", "is required")
	} else if ip := net.ParseIP(rule.OutIP); ip == nil || ip.To4() == nil {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "out_ip", "must be a valid IPv4 address")
	}
	if rule.InPort < 1 || rule.InPort > 65535 {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "in_port", "must be between 1 and 65535")
	}
	if rule.OutPort < 1 || rule.OutPort > 65535 {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "out_port", "must be between 1 and 65535")
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "tcp+udp" {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "protocol", "must be tcp, udp, or tcp+udp")
	}
	if rule.InInterface != "" {
		if _, ok := knownIfaces[rule.InInterface]; !ok {
			issues = appendRuleIssue(issues, scope, index, rule.ID, "in_interface", "interface does not exist on this host")
		}
	}
	if rule.OutInterface != "" {
		if _, ok := knownIfaces[rule.OutInterface]; !ok {
			issues = appendRuleIssue(issues, scope, index, rule.ID, "out_interface", "interface does not exist on this host")
		}
	}
	return rule, issues
}

func appendRuleIssue(issues []ruleValidationIssue, scope string, index int, id int64, field, message string) []ruleValidationIssue {
	return append(issues, ruleValidationIssue{
		Scope:   scope,
		Index:   index,
		ID:      id,
		Field:   field,
		Message: message,
	})
}

func detectRuleConflicts(states []projectedRuleState) []ruleValidationIssue {
	byPort := make(map[int][]projectedRuleState)
	for _, state := range states {
		byPort[state.Rule.InPort] = append(byPort[state.Rule.InPort], state)
	}

	var issues []ruleValidationIssue
	for _, group := range byPort {
		for i := 0; i < len(group); i++ {
			for j := i + 1; j < len(group); j++ {
				if !rulesConflict(group[i].Rule, group[j].Rule) {
					continue
				}
				issues = appendRuleConflictIssue(issues, group[i], group[j])
				issues = appendRuleConflictIssue(issues, group[j], group[i])
			}
		}
	}
	return issues
}

func rulesConflict(a, b Rule) bool {
	if !ruleProtocolsOverlap(a.Protocol, b.Protocol) {
		return false
	}
	if !ruleInterfacesOverlap(a.InInterface, b.InInterface) {
		return false
	}
	if !ruleIPsOverlap(a.InIP, b.InIP) {
		return false
	}
	return a.InPort == b.InPort
}

func ruleProtocolsOverlap(a, b string) bool {
	return ruleProtocolMask(a)&ruleProtocolMask(b) != 0
}

func ruleProtocolMask(protocol string) int {
	switch protocol {
	case "tcp":
		return 1
	case "udp":
		return 2
	case "tcp+udp":
		return 3
	default:
		return 0
	}
}

func ruleInterfacesOverlap(a, b string) bool {
	return a == "" || b == "" || a == b
}

func ruleIPsOverlap(a, b string) bool {
	return a == "0.0.0.0" || b == "0.0.0.0" || a == b
}

func appendRuleConflictIssue(issues []ruleValidationIssue, current, other projectedRuleState) []ruleValidationIssue {
	scope, index, id := ruleConflictIssueTarget(current)
	if scope == "" {
		return issues
	}
	return appendRuleIssue(issues, scope, index, id, "in_port", fmt.Sprintf("listener conflicts with %s", describeRuleConflict(other)))
}

func ruleConflictIssueTarget(state projectedRuleState) (string, int, int64) {
	switch state.ContentScope {
	case "create", "update":
		return state.ContentScope, state.ContentIndex, state.Rule.ID
	case "existing":
		if state.EnableScope == "set_enabled" {
			return "set_enabled", state.EnableIndex, state.Rule.ID
		}
	}
	return "", 0, 0
}

func describeRuleConflict(state projectedRuleState) string {
	iface := state.Rule.InInterface
	if iface == "" {
		iface = "*"
	}
	switch state.ContentScope {
	case "create":
		return fmt.Sprintf("create[%d] %s %s:%d [%s]", state.ContentIndex, iface, state.Rule.InIP, state.Rule.InPort, strings.ToUpper(state.Rule.Protocol))
	default:
		return fmt.Sprintf("rule #%d %s %s:%d [%s]", state.Rule.ID, iface, state.Rule.InIP, state.Rule.InPort, strings.ToUpper(state.Rule.Protocol))
	}
}

func summarizeRuleIssues(issues []ruleValidationIssue) string {
	if len(issues) == 0 {
		return ""
	}
	issue := issues[0]
	prefix := issue.Scope
	if issue.Index > 0 {
		prefix = fmt.Sprintf("%s[%d]", issue.Scope, issue.Index)
	} else if issue.ID > 0 {
		prefix = fmt.Sprintf("%s#%d", issue.Scope, issue.ID)
	}
	if issue.Field != "" {
		return fmt.Sprintf("%s %s: %s", prefix, issue.Field, issue.Message)
	}
	return fmt.Sprintf("%s: %s", prefix, issue.Message)
}

func hasRuleNotFoundIssue(issues []ruleValidationIssue) bool {
	for _, issue := range issues {
		if issue.Field == "id" && issue.Message == "rule not found" {
			return true
		}
	}
	return false
}

func handleAddRule(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var rule Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	prepared, issues, err := prepareRuleBatch(db, ruleBatchRequest{Create: []Rule{rule}})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 || len(prepared.Create) == 0 {
		writeJSON(w, http.StatusBadRequest, ruleValidateResponse{
			Valid:  false,
			Error:  summarizeRuleIssues(issues),
			Create: prepared.Create,
			Issues: issues,
		})
		return
	}

	rule = prepared.Create[0]
	id, err := dbAddRule(db, &rule)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rule.ID = id

	pm.redistributeWorkers()

	writeJSON(w, http.StatusOK, rule)
}

func handleUpdateRule(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var rule Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	prepared, issues, err := prepareRuleBatch(db, ruleBatchRequest{Update: []Rule{rule}})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 || len(prepared.Update) == 0 {
		status := http.StatusBadRequest
		if hasRuleNotFoundIssue(issues) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, ruleValidateResponse{
			Valid:  false,
			Error:  summarizeRuleIssues(issues),
			Update: prepared.Update,
			Issues: issues,
		})
		return
	}

	rule = prepared.Update[0]

	if err := dbUpdateRule(db, &rule); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	pm.redistributeWorkers()

	writeJSON(w, http.StatusOK, rule)
}

func handleToggleRule(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	rule, err := dbGetRule(db, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	newEnabled := !rule.Enabled
	if err := dbSetRuleEnabled(db, id, newEnabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pm.redistributeWorkers()
	writeJSON(w, http.StatusOK, map[string]interface{}{"id": id, "enabled": newEnabled})
}

func handleDeleteRule(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	if err := dbDeleteRule(db, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pm.redistributeWorkers()

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func handleListSites(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	sites, err := dbGetSites(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var statuses []SiteStatus
	pm.mu.Lock()
	proxyRunning := pm.sharedProxy != nil && pm.sharedProxy.running
	pm.mu.Unlock()
	for _, site := range sites {
		status := "stopped"
		if site.Enabled && proxyRunning {
			status = "running"
		}
		statuses = append(statuses, SiteStatus{Site: site, Status: status})
	}
	if statuses == nil {
		statuses = []SiteStatus{}
	}
	writeJSON(w, http.StatusOK, statuses)
}

func handleAddSite(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var site Site
	if err := json.NewDecoder(r.Body).Decode(&site); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if site.Domain == "" || site.BackendIP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain and backend_ip are required"})
		return
	}
	if site.BackendHTTP == 0 && site.BackendHTTPS == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one of backend_http_port or backend_https_port is required"})
		return
	}
	if site.ListenIP == "" {
		site.ListenIP = "0.0.0.0"
	}

	site.Enabled = true
	id, err := dbAddSite(db, &site)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	site.ID = id

	pm.redistributeWorkers()

	writeJSON(w, http.StatusOK, site)
}

func handleUpdateSite(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var site Site
	if err := json.NewDecoder(r.Body).Decode(&site); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if site.ID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}
	if site.Domain == "" || site.BackendIP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain and backend_ip are required"})
		return
	}
	if site.BackendHTTP == 0 && site.BackendHTTPS == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one of backend_http_port or backend_https_port is required"})
		return
	}
	if site.ListenIP == "" {
		site.ListenIP = "0.0.0.0"
	}

	existing, err := dbGetSite(db, site.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	site.Enabled = existing.Enabled

	if err := dbUpdateSite(db, &site); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pm.redistributeWorkers()
	writeJSON(w, http.StatusOK, site)
}

func handleToggleSite(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	sites, err := dbGetSites(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var found bool
	var curEnabled bool
	for _, s := range sites {
		if s.ID == id {
			found = true
			curEnabled = s.Enabled
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "site not found"})
		return
	}
	newEnabled := !curEnabled
	if err := dbSetSiteEnabled(db, id, newEnabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pm.redistributeWorkers()
	writeJSON(w, http.StatusOK, map[string]interface{}{"id": id, "enabled": newEnabled})
}

func handleDeleteSite(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	if err := dbDeleteSite(db, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	pm.redistributeWorkers()

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func handleListRanges(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	ranges, err := dbGetRanges(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var statuses []PortRangeStatus
	pm.mu.Lock()
	runningRanges := make(map[int64]bool)
	failedRanges := make(map[int64]bool)
	for id := range pm.kernelRanges {
		runningRanges[id] = true
	}
	for _, wi := range pm.rangeWorkers {
		if wi.running {
			for _, pr := range wi.ranges {
				if wi.failedRanges != nil && wi.failedRanges[pr.ID] {
					failedRanges[pr.ID] = true
					continue
				}
				runningRanges[pr.ID] = true
			}
		}
	}
	pm.mu.Unlock()
	for _, pr := range ranges {
		status := "stopped"
		if failedRanges[pr.ID] {
			status = "error"
		} else if runningRanges[pr.ID] {
			status = "running"
		}
		statuses = append(statuses, pm.buildRangeStatus(pr, status))
	}
	if statuses == nil {
		statuses = []PortRangeStatus{}
	}
	writeJSON(w, http.StatusOK, statuses)
}

func handleListWorkers(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	page := 1
	pageSize := 0
	if v := r.URL.Query().Get("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := r.URL.Query().Get("page_size"); v != "" {
		if s, err := strconv.Atoi(v); err == nil {
			pageSize = s
		}
	}
	if pageSize > 1000 {
		pageSize = 1000
	}

	allRules, err := dbGetRules(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	allRanges, err := dbGetRanges(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	enabledSites := 0
	if sites, err := dbGetSites(db); err == nil {
		for _, s := range sites {
			if s.Enabled {
				enabledSites++
			}
		}
	}

	type workerSnap struct {
		kind           string
		index          int
		running        bool
		errored        bool
		draining       bool
		activeRuleIDs  map[int64]bool
		activeRangeIDs map[int64]bool
		binaryHash     string
		rules          []Rule
		ranges         []PortRange
		failedRules    map[int64]bool
		failedRanges   map[int64]bool
	}

	var snaps []workerSnap
	kernelRuleIDs := make(map[int64]bool)
	kernelRangeIDs := make(map[int64]bool)
	kernelBinaryHash := ""
	pm.mu.Lock()
	for id := range pm.kernelRules {
		kernelRuleIDs[id] = true
	}
	for id := range pm.kernelRanges {
		kernelRangeIDs[id] = true
	}
	kernelBinaryHash = pm.binaryHash
	ruleOwner := make(map[int64]int)
	rangeOwner := make(map[int64]int)
	for idx, wi := range pm.ruleWorkers {
		for _, r := range wi.rules {
			ruleOwner[r.ID] = idx
		}
		if len(wi.rules) == 0 {
			continue
		}
		s := workerSnap{
			kind:        "rule",
			index:       idx,
			running:     wi.running,
			errored:     wi.errored,
			draining:    wi.draining,
			binaryHash:  wi.binaryHash,
			rules:       append([]Rule(nil), wi.rules...),
			failedRules: make(map[int64]bool),
		}
		for id := range wi.failedRules {
			s.failedRules[id] = true
		}
		if wi.draining && len(wi.activeRuleIDs) > 0 {
			s.activeRuleIDs = make(map[int64]bool, len(wi.activeRuleIDs))
			for _, id := range wi.activeRuleIDs {
				s.activeRuleIDs[id] = true
			}
		}
		snaps = append(snaps, s)
	}
	for idx, wi := range pm.rangeWorkers {
		for _, pr := range wi.ranges {
			rangeOwner[pr.ID] = idx
		}
		if len(wi.ranges) == 0 {
			continue
		}
		s := workerSnap{
			kind:         "range",
			index:        idx,
			running:      wi.running,
			errored:      wi.errored,
			draining:     wi.draining,
			binaryHash:   wi.binaryHash,
			ranges:       append([]PortRange(nil), wi.ranges...),
			failedRanges: make(map[int64]bool),
		}
		for id := range wi.failedRanges {
			s.failedRanges[id] = true
		}
		if wi.draining && len(wi.activeRangeIDs) > 0 {
			s.activeRangeIDs = make(map[int64]bool, len(wi.activeRangeIDs))
			for _, id := range wi.activeRangeIDs {
				s.activeRangeIDs[id] = true
			}
		}
		snaps = append(snaps, s)
	}
	if pm.sharedProxy != nil && enabledSites > 0 {
		snaps = append(snaps, workerSnap{
			kind:       "shared",
			index:      0,
			running:    pm.sharedProxy.running,
			errored:    pm.sharedProxy.errored,
			draining:   pm.sharedProxy.draining,
			binaryHash: pm.sharedProxy.binaryHash,
		})
	}
	for _, dw := range pm.drainingWorkers {
		if !dw.draining && !dw.running && !dw.errored {
			continue
		}
		mappedIndex := dw.workerIndex
		if dw.kind == "rule" {
			ruleSet := make(map[int64]struct{}, len(dw.rules))
			for _, r := range dw.rules {
				ruleSet[r.ID] = struct{}{}
			}
			ids := make([]int64, 0, len(dw.activeRuleIDs)+len(dw.rules))
			for _, id := range dw.activeRuleIDs {
				if _, ok := ruleSet[id]; ok {
					ids = append(ids, id)
				}
			}
			if len(ids) == 0 {
				for _, r := range dw.rules {
					ids = append(ids, r.ID)
				}
			}
			if len(ids) > 0 {
				candidate := -1
				consistent := true
				for _, id := range ids {
					idx, ok := ruleOwner[id]
					if !ok {
						continue
					}
					if candidate == -1 {
						candidate = idx
						continue
					}
					if candidate != idx {
						consistent = false
						break
					}
				}
				if consistent && candidate >= 0 {
					mappedIndex = candidate
				}
			}
		} else if dw.kind == "range" {
			rangeSet := make(map[int64]struct{}, len(dw.ranges))
			for _, pr := range dw.ranges {
				rangeSet[pr.ID] = struct{}{}
			}
			ids := make([]int64, 0, len(dw.activeRangeIDs)+len(dw.ranges))
			for _, id := range dw.activeRangeIDs {
				if _, ok := rangeSet[id]; ok {
					ids = append(ids, id)
				}
			}
			if len(ids) == 0 {
				for _, pr := range dw.ranges {
					ids = append(ids, pr.ID)
				}
			}
			if len(ids) > 0 {
				candidate := -1
				consistent := true
				for _, id := range ids {
					idx, ok := rangeOwner[id]
					if !ok {
						continue
					}
					if candidate == -1 {
						candidate = idx
						continue
					}
					if candidate != idx {
						consistent = false
						break
					}
				}
				if consistent && candidate >= 0 {
					mappedIndex = candidate
				}
			}
		}
		s := workerSnap{
			kind:       dw.kind,
			index:      mappedIndex,
			running:    dw.running,
			errored:    dw.errored,
			draining:   dw.draining,
			binaryHash: dw.binaryHash,
		}
		if dw.kind == "rule" {
			s.rules = append([]Rule(nil), dw.rules...)
			s.activeRuleIDs = make(map[int64]bool, len(dw.activeRuleIDs))
			for _, id := range dw.activeRuleIDs {
				s.activeRuleIDs[id] = true
			}
		} else if dw.kind == "range" {
			s.ranges = append([]PortRange(nil), dw.ranges...)
			s.activeRangeIDs = make(map[int64]bool, len(dw.activeRangeIDs))
			for _, id := range dw.activeRangeIDs {
				s.activeRangeIDs[id] = true
			}
		}
		snaps = append(snaps, s)
	}
	pm.mu.Unlock()

	if len(kernelRuleIDs) > 0 {
		kernelRules := make([]Rule, 0, len(kernelRuleIDs))
		for _, rule := range allRules {
			if !rule.Enabled || !kernelRuleIDs[rule.ID] {
				continue
			}
			kernelRules = append(kernelRules, rule)
		}
		if len(kernelRules) > 0 {
			sort.Slice(kernelRules, func(i, j int) bool { return kernelRules[i].ID < kernelRules[j].ID })
			snaps = append(snaps, workerSnap{
				kind:       "kernel",
				index:      0,
				running:    true,
				binaryHash: kernelBinaryHash,
				rules:      kernelRules,
			})
		}
	}
	if len(kernelRangeIDs) > 0 {
		kernelRanges := make([]PortRange, 0, len(kernelRangeIDs))
		for _, pr := range allRanges {
			if !pr.Enabled || !kernelRangeIDs[pr.ID] {
				continue
			}
			kernelRanges = append(kernelRanges, pr)
		}
		if len(kernelRanges) > 0 {
			sort.Slice(kernelRanges, func(i, j int) bool { return kernelRanges[i].ID < kernelRanges[j].ID })
			snaps = append(snaps, workerSnap{
				kind:       "kernel",
				index:      1,
				running:    true,
				binaryHash: kernelBinaryHash,
				ranges:     kernelRanges,
			})
		}
	}

	workers := make([]WorkerView, 0, len(snaps))
	for _, s := range snaps {
		view := WorkerView{
			Kind:       s.kind,
			Index:      s.index,
			Status:     "stopped",
			BinaryHash: s.binaryHash,
		}
		if s.errored {
			view.Status = "error"
		} else if s.draining {
			view.Status = "draining"
		} else if s.running {
			view.Status = "running"
		}

		switch s.kind {
		case "kernel":
			if len(s.rules) > 0 {
				view.RuleCount = len(s.rules)
				for _, r := range s.rules {
					view.Rules = append(view.Rules, pm.buildRuleStatus(r, "running"))
				}
			} else {
				view.RangeCount = len(s.ranges)
				for _, pr := range s.ranges {
					view.Ranges = append(view.Ranges, pm.buildRangeStatus(pr, "running"))
				}
			}
		case "rule":
			view.RuleCount = len(s.rules)
			for _, r := range s.rules {
				status := "stopped"
				if !r.Enabled {
					status = "disabled"
				} else if s.failedRules[r.ID] {
					status = "error"
				} else if s.running {
					status = "running"
				} else if s.draining && s.activeRuleIDs[r.ID] {
					status = "running"
				}
				view.Rules = append(view.Rules, pm.buildRuleStatus(r, status))
			}
			if view.Status == "stopped" && len(s.rules) > 0 && len(s.failedRules) == len(s.rules) {
				view.Status = "error"
			}
		case "range":
			view.RangeCount = len(s.ranges)
			for _, pr := range s.ranges {
				status := "stopped"
				if !pr.Enabled {
					status = "disabled"
				} else if s.failedRanges[pr.ID] {
					status = "error"
				} else if s.running {
					status = "running"
				} else if s.draining && s.activeRangeIDs[pr.ID] {
					status = "running"
				}
				view.Ranges = append(view.Ranges, pm.buildRangeStatus(pr, status))
			}
			if view.Status == "stopped" && len(s.ranges) > 0 && len(s.failedRanges) == len(s.ranges) {
				view.Status = "error"
			}
		case "shared":
			view.SiteCount = enabledSites
		}

		workers = append(workers, view)
	}

	kindOrder := map[string]int{"kernel": 0, "rule": 1, "range": 2, "shared": 3}
	sort.Slice(workers, func(i, j int) bool {
		ki := kindOrder[workers[i].Kind]
		kj := kindOrder[workers[j].Kind]
		if ki != kj {
			return ki < kj
		}
		return workers[i].Index < workers[j].Index
	})

	total := len(workers)
	out := workers
	if pageSize > 0 {
		totalPages := 1
		if total > 0 {
			totalPages = (total + pageSize - 1) / pageSize
		}
		if page > totalPages {
			page = totalPages
		}
		start := (page - 1) * pageSize
		if start < 0 {
			start = 0
		}
		if start > total {
			start = total
		}
		end := start + pageSize
		if end > total {
			end = total
		}
		out = workers[start:end]
	} else {
		page = 1
		pageSize = total
	}

	resp := WorkerListResponse{
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		BinaryHash: pm.binaryHash,
		Workers:    out,
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleAddRange(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var pr PortRange
	if err := json.NewDecoder(r.Body).Decode(&pr); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if pr.InIP == "" || pr.StartPort == 0 || pr.EndPort == 0 || pr.OutIP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "in_ip, start_port, end_port, out_ip are required"})
		return
	}
	if pr.StartPort > pr.EndPort {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "start_port must be <= end_port"})
		return
	}
	if pr.Protocol == "" {
		pr.Protocol = "tcp"
	}
	if pr.Protocol != "tcp" && pr.Protocol != "udp" && pr.Protocol != "tcp+udp" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "protocol must be tcp, udp, or tcp+udp"})
		return
	}
	if pr.OutStartPort == 0 {
		pr.OutStartPort = pr.StartPort
	}

	pr.Enabled = true
	id, err := dbAddRange(db, &pr)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pr.ID = id

	pm.redistributeWorkers()

	writeJSON(w, http.StatusOK, pr)
}

func handleUpdateRange(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var pr PortRange
	if err := json.NewDecoder(r.Body).Decode(&pr); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if pr.ID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}
	if pr.InIP == "" || pr.StartPort == 0 || pr.EndPort == 0 || pr.OutIP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "in_ip, start_port, end_port, out_ip are required"})
		return
	}
	if pr.StartPort > pr.EndPort {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "start_port must be <= end_port"})
		return
	}
	if pr.Protocol == "" {
		pr.Protocol = "tcp"
	}
	if pr.Protocol != "tcp" && pr.Protocol != "udp" && pr.Protocol != "tcp+udp" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "protocol must be tcp, udp, or tcp+udp"})
		return
	}
	if pr.OutStartPort == 0 {
		pr.OutStartPort = pr.StartPort
	}

	existing, err := dbGetRange(db, pr.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pr.Enabled = existing.Enabled

	if err := dbUpdateRange(db, &pr); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	pm.redistributeWorkers()

	writeJSON(w, http.StatusOK, pr)
}

func handleToggleRange(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	pr, err := dbGetRange(db, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	newEnabled := !pr.Enabled
	if err := dbSetRangeEnabled(db, id, newEnabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pm.redistributeWorkers()
	writeJSON(w, http.StatusOK, map[string]interface{}{"id": id, "enabled": newEnabled})
}

func handleDeleteRange(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	if err := dbDeleteRange(db, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pm.redistributeWorkers()

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func handleListRuleStats(w http.ResponseWriter, r *http.Request, pm *ProcessManager) {
	statsMap := pm.collectRuleStats()
	result := make([]RuleStatsReport, 0, len(statsMap))
	for _, s := range statsMap {
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RuleID < result[j].RuleID })
	writeJSON(w, http.StatusOK, result)
}

func handleListRangeStats(w http.ResponseWriter, r *http.Request, pm *ProcessManager) {
	statsMap := pm.collectRangeStats()
	result := make([]RangeStatsReport, 0, len(statsMap))
	for _, s := range statsMap {
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RangeID < result[j].RangeID })
	writeJSON(w, http.StatusOK, result)
}

func handleListSiteStats(w http.ResponseWriter, r *http.Request, pm *ProcessManager) {
	stats := pm.collectSiteStats()
	if stats == nil {
		stats = []SiteStatsReport{}
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].SiteID < stats[j].SiteID })
	writeJSON(w, http.StatusOK, stats)
}
