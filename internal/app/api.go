package app

import (
	"crypto/subtle"
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
	"time"
)

//go:embed web
var webFS embed.FS

const (
	apiServerReadHeaderTimeout = 10 * time.Second
	apiServerReadTimeout       = 30 * time.Second
	apiServerWriteTimeout      = 30 * time.Second
	apiServerIdleTimeout       = 120 * time.Second
	apiServerMaxHeaderBytes    = 1 << 20
)

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

type validationErrorResponse struct {
	Error  string                `json:"error,omitempty"`
	Issues []ruleValidationIssue `json:"issues,omitempty"`
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
	OutSourceIP  string
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

type statsListQuery struct {
	Page     int
	PageSize int
	SortKey  string
	SortAsc  bool
}

const maxStatsPageSize = 500

func startAPI(cfg *Config, db *sql.DB, pm *ProcessManager) (*http.Server, error) {
	addr := apiListenAddr(cfg)
	handler := buildAPIHandler(cfg, db, pm)
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: apiServerReadHeaderTimeout,
		ReadTimeout:       apiServerReadTimeout,
		WriteTimeout:      apiServerWriteTimeout,
		IdleTimeout:       apiServerIdleTimeout,
		MaxHeaderBytes:    apiServerMaxHeaderBytes,
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		log.Printf("web server listening on %s", addr)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server: %v", err)
		}
	}()
	return server, nil
}

func buildAPIHandler(cfg *Config, db *sql.DB, pm *ProcessManager) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		ready := pm.isReady()
		statusCode := http.StatusServiceUnavailable
		status := "starting"
		if ready {
			statusCode = http.StatusOK
			status = "ready"
		}
		writeJSON(w, statusCode, map[string]interface{}{
			"status": status,
			"ready":  ready,
		})
	})

	webUIEnabled := cfg.WebUIEnabled()
	webSub, _ := fs.Sub(webFS, "web")
	staticFileServer := http.FileServer(http.FS(webSub))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		if !webUIEnabled {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		staticFileServer.ServeHTTP(w, r)
	}))

	mux.HandleFunc("/api/host-network", authMiddleware(cfg, handleHostNetwork))
	mux.HandleFunc("/api/interfaces", authMiddleware(cfg, handleInterfaces))
	mux.HandleFunc("/api/managed-networks", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleListManagedNetworks(w, r, db, pm)
		case http.MethodPost:
			handleAddManagedNetwork(w, r, db, pm)
		case http.MethodPut:
			handleUpdateManagedNetwork(w, r, db, pm)
		case http.MethodDelete:
			handleDeleteManagedNetwork(w, r, db, pm)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/managed-networks/toggle", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		handleToggleManagedNetwork(w, r, db, pm)
	}))
	mux.HandleFunc("/api/managed-networks/persist-bridge", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		handlePersistManagedNetworkBridge(w, r, db, pm)
	}))
	mux.HandleFunc("/api/managed-networks/reload-runtime", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		handleReloadManagedNetworkRuntime(w, r, pm)
	}))
	mux.HandleFunc("/api/managed-networks/repair", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		handleRepairManagedNetworkRuntime(w, r, pm)
	}))
	mux.HandleFunc("/api/managed-networks/runtime-status", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		handleManagedNetworkRuntimeReloadStatus(w, r, pm)
	}))
	mux.HandleFunc("/api/managed-network-reservations", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleListManagedNetworkReservations(w, r, db)
		case http.MethodPost:
			handleAddManagedNetworkReservation(w, r, db, pm)
		case http.MethodPut:
			handleUpdateManagedNetworkReservation(w, r, db, pm)
		case http.MethodDelete:
			handleDeleteManagedNetworkReservation(w, r, db, pm)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/managed-network-reservation-candidates", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleListManagedNetworkReservationCandidates(w, r, db)
	}))
	mux.HandleFunc("/api/ipv6-assignments", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleListIPv6Assignments(w, r, db, pm)
		case http.MethodPost:
			handleAddIPv6Assignment(w, r, db, pm)
		case http.MethodPut:
			handleUpdateIPv6Assignment(w, r, db, pm)
		case http.MethodDelete:
			handleDeleteIPv6Assignment(w, r, db, pm)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
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
	mux.HandleFunc("/api/egress-nats", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleListEgressNATs(w, r, db, pm)
		case http.MethodPost:
			handleAddEgressNAT(w, r, db, pm)
		case http.MethodPut:
			handleUpdateEgressNAT(w, r, db, pm)
		case http.MethodDelete:
			handleDeleteEgressNAT(w, r, db, pm)
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
	mux.HandleFunc("/api/egress-nats/toggle", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		handleToggleEgressNAT(w, r, db, pm)
	}))
	mux.HandleFunc("/api/workers", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleListWorkers(w, r, db, pm)
	}))
	mux.HandleFunc("/api/kernel/runtime", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleKernelRuntime(w, r, pm)
	}))
	mux.HandleFunc("/api/kernel/runtime/dismiss-note", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleDismissKernelRuntimeNote(w, r, pm)
	}))
	mux.HandleFunc("/api/rules/stats", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleListRuleStats(w, r, db, pm)
	}))
	mux.HandleFunc("/api/ranges/stats", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleListRangeStats(w, r, db, pm)
	}))
	mux.HandleFunc("/api/egress-nats/stats", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleListEgressNATStats(w, r, db, pm)
	}))
	mux.HandleFunc("/api/sites/stats", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleListSiteStats(w, r, pm)
	}))
	mux.HandleFunc("/api/stats/current-conns", authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleListCurrentConns(w, r, db, pm)
	}))
	return securityHeadersMiddleware(mux)
}

func apiListenAddr(cfg *Config) string {
	bind := normalizeWebBind("")
	port := 8080
	if cfg != nil {
		bind = normalizeWebBind(cfg.WebBind)
		if cfg.WebPort > 0 {
			port = cfg.WebPort
		}
	}
	return net.JoinHostPort(bind, strconv.Itoa(port))
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func authMiddleware(cfg *Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := strings.TrimSpace(cfg.WebToken)
		fields := strings.Fields(strings.TrimSpace(r.Header.Get("Authorization")))
		token := ""
		if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
			token = fields[1]
		}
		if expected == "" || token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		next(w, r)
	}
}

func handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ifaces, err := loadInterfaceInfos()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ifaces)
}

func handleListRules(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	filters, err := parseRuleFilter(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	rules, err := dbGetRulesFiltered(db, filters)
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
		OutSourceIP:  strings.TrimSpace(query.Get("out_source_ip")),
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
	if filters.OutSourceIP != "" && rule.OutSourceIP != filters.OutSourceIP {
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
		rule.OutSourceIP,
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
	if err := decodeJSONRequestBody(w, r, &req, apiJSONBatchBodyMaxBytes); err != nil {
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
	if err := decodeJSONRequestBody(w, r, &req, apiJSONBatchBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	prepared, issues, err := prepareRuleBatch(tx, req)
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

	knownIfaces, hostAddrs, err := loadHostValidationData()
	if err != nil {
		return prepared, nil, err
	}
	existingRules, err := dbGetEnabledRules(db)
	if err != nil {
		return prepared, nil, err
	}
	referencedRules, err := dbGetRulesByIDs(db, collectReferencedRuleBatchIDs(req))
	if err != nil {
		return prepared, nil, err
	}
	existingSites, err := dbGetEnabledSites(db)
	if err != nil {
		return prepared, nil, err
	}
	existingRanges, err := dbGetEnabledRanges(db)
	if err != nil {
		return prepared, nil, err
	}

	existingByID := make(map[int64]Rule, len(existingRules)+len(referencedRules))
	projected := make(map[int64]projectedRuleState, len(existingRules)+len(referencedRules))
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
	for _, rule := range referencedRules {
		existingByID[rule.ID] = rule
		if _, ok := projected[rule.ID]; ok {
			continue
		}
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
		rule, ruleIssues := normalizeAndValidateRule(raw, "update", index, true, knownIfaces, hostAddrs)
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
		rule, ruleIssues := normalizeAndValidateRule(raw, "create", index, false, knownIfaces, hostAddrs)
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
	issues = append(issues, detectProjectedConflicts(conflictStates, projectExistingSiteStates(existingSites), projectExistingRangeStates(existingRanges))...)

	sort.Slice(prepared.DeleteIDs, func(i, j int) bool { return prepared.DeleteIDs[i] < prepared.DeleteIDs[j] })
	return prepared, issues, nil
}

func collectReferencedRuleBatchIDs(req ruleBatchRequest) []int64 {
	ids := make([]int64, 0, len(req.DeleteIDs)+len(req.Update)+len(req.SetEnabled))
	ids = append(ids, req.DeleteIDs...)
	for _, rule := range req.Update {
		ids = append(ids, rule.ID)
	}
	for _, change := range req.SetEnabled {
		ids = append(ids, change.ID)
	}
	return ids
}

func loadHostValidationData() (map[string]struct{}, hostInterfaceAddrs, error) {
	hostAddrs, err := loadHostInterfaceAddrs()
	if err != nil {
		return nil, nil, err
	}
	knownIfaces := make(map[string]struct{}, len(hostAddrs))
	for name := range hostAddrs {
		knownIfaces[name] = struct{}{}
	}
	return knownIfaces, hostAddrs, nil
}

func normalizeOptionalSpecificIP(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	ip := parseIPLiteral(value)
	if ip == nil {
		return "", fmt.Errorf("must be a valid IP address")
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return "", fmt.Errorf("must be a specific non-loopback IP address")
	}
	return canonicalIPLiteral(ip), nil
}

func hostHasIP(hostAddrs hostInterfaceAddrs, ifaceName, ip string) bool {
	if ip == "" {
		return false
	}
	if ifaceName != "" {
		ifaceAddrs, ok := hostAddrs[ifaceName]
		if !ok {
			return false
		}
		_, ok = ifaceAddrs[ip]
		return ok
	}
	for _, ifaceAddrs := range hostAddrs {
		if _, ok := ifaceAddrs[ip]; ok {
			return true
		}
	}
	return false
}

func validateLocalSourceIP(sourceIP, outInterface string, hostAddrs hostInterfaceAddrs) string {
	if sourceIP == "" {
		return ""
	}
	if outInterface != "" {
		if hostHasIP(hostAddrs, outInterface, sourceIP) {
			return ""
		}
		return "must be assigned to the selected outbound interface"
	}
	if hostHasIP(hostAddrs, "", sourceIP) {
		return ""
	}
	return "must be assigned to a local interface"
}

func normalizeAndValidateRule(rule Rule, scope string, index int, requireID bool, knownIfaces map[string]struct{}, hostAddrs hostInterfaceAddrs) (Rule, []ruleValidationIssue) {
	rule.InInterface = strings.TrimSpace(rule.InInterface)
	rule.InIP = strings.TrimSpace(rule.InIP)
	rule.OutInterface = strings.TrimSpace(rule.OutInterface)
	rule.OutIP = strings.TrimSpace(rule.OutIP)
	rule.OutSourceIP = strings.TrimSpace(rule.OutSourceIP)
	rule.Protocol = strings.ToLower(strings.TrimSpace(rule.Protocol))
	rule.Remark = strings.TrimSpace(rule.Remark)
	rule.Tag = strings.TrimSpace(rule.Tag)
	rule.EnginePreference = normalizeRuleEnginePreference(rule.EnginePreference)
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

	inFamily := ""
	if rule.InIP == "" {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "in_ip", "is required")
	} else if normalized, err := normalizeIPLiteral(rule.InIP); err != nil {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "in_ip", err.Error())
	} else {
		rule.InIP = normalized
		inFamily = ipLiteralFamily(rule.InIP)
	}
	outFamily := ""
	if rule.OutIP == "" {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "out_ip", "is required")
	} else if normalized, err := normalizeIPLiteral(rule.OutIP); err != nil {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "out_ip", err.Error())
	} else {
		rule.OutIP = normalized
		outFamily = ipLiteralFamily(rule.OutIP)
	}
	if normalized, err := normalizeOptionalSpecificIP(rule.OutSourceIP); err != nil {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "out_source_ip", err.Error())
	} else {
		rule.OutSourceIP = normalized
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
	if !isValidRuleEnginePreference(rule.EnginePreference) {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "engine_preference", "must be auto, userspace, or kernel")
	}
	if rule.InInterface != "" {
		if _, ok := knownIfaces[rule.InInterface]; !ok {
			issues = appendRuleIssue(issues, scope, index, rule.ID, "in_interface", "interface does not exist on this host")
		}
	}
	outIfaceValid := true
	if rule.OutInterface != "" {
		if _, ok := knownIfaces[rule.OutInterface]; !ok {
			issues = appendRuleIssue(issues, scope, index, rule.ID, "out_interface", "interface does not exist on this host")
			outIfaceValid = false
		}
	}
	pureIPv4 := ipLiteralPairIsPureIPv4(rule.InIP, rule.OutIP)
	if inFamily != "" && outFamily != "" {
		if rule.Transparent && !pureIPv4 {
			issues = appendRuleIssue(issues, scope, index, rule.ID, "transparent", "transparent mode currently supports only IPv4 rules")
		}
	}
	if rule.Transparent && rule.OutSourceIP != "" {
		issues = appendRuleIssue(issues, scope, index, rule.ID, "out_source_ip", "must be omitted when transparent mode is enabled")
	} else if rule.OutSourceIP != "" {
		if outFamily != "" && ipLiteralFamily(rule.OutSourceIP) != outFamily {
			issues = appendRuleIssue(issues, scope, index, rule.ID, "out_source_ip", "must match outbound IP address family")
		} else if outIfaceValid {
			if msg := validateLocalSourceIP(rule.OutSourceIP, rule.OutInterface, hostAddrs); msg != "" {
				issues = appendRuleIssue(issues, scope, index, rule.ID, "out_source_ip", msg)
			}
		}
	}
	return rule, issues
}

func normalizeAndValidateSite(site Site, requireID bool, knownIfaces map[string]struct{}, hostAddrs hostInterfaceAddrs) (Site, string) {
	site.Domain = strings.TrimSpace(site.Domain)
	site.ListenIP = strings.TrimSpace(site.ListenIP)
	site.ListenIface = strings.TrimSpace(site.ListenIface)
	site.BackendIP = strings.TrimSpace(site.BackendIP)
	site.BackendSourceIP = strings.TrimSpace(site.BackendSourceIP)
	site.Tag = strings.TrimSpace(site.Tag)
	if site.ListenIP == "" {
		site.ListenIP = "0.0.0.0"
	}

	if requireID && site.ID == 0 {
		return site, "id is required"
	}
	if site.Domain == "" || site.BackendIP == "" {
		return site, "domain and backend_ip are required"
	}
	if site.BackendHTTP == 0 && site.BackendHTTPS == 0 {
		return site, "at least one of backend_http_port or backend_https_port is required"
	}
	if site.ListenIface != "" {
		if _, ok := knownIfaces[site.ListenIface]; !ok {
			return site, "listen_interface does not exist on this host"
		}
	}
	if normalized, err := normalizeIPLiteral(site.ListenIP); err != nil {
		return site, "listen_ip " + err.Error()
	} else {
		site.ListenIP = normalized
	}
	if normalized, err := normalizeIPLiteral(site.BackendIP); err != nil {
		return site, "backend_ip " + err.Error()
	} else {
		site.BackendIP = normalized
	}
	normalizedSourceIP, err := normalizeOptionalSpecificIP(site.BackendSourceIP)
	if err != nil {
		return site, "backend_source_ip " + err.Error()
	}
	site.BackendSourceIP = normalizedSourceIP
	pureIPv4 := ipLiteralPairIsPureIPv4(site.ListenIP, site.BackendIP)
	backendFamily := ipLiteralFamily(site.BackendIP)
	if site.Transparent && !pureIPv4 {
		return site, "transparent mode currently supports only IPv4 rules"
	}
	if site.Transparent && site.BackendSourceIP != "" {
		return site, "backend_source_ip must be omitted when transparent mode is enabled"
	}
	if site.BackendSourceIP != "" {
		if backendFamily != "" && ipLiteralFamily(site.BackendSourceIP) != backendFamily {
			return site, "backend_source_ip must match backend_ip address family"
		}
		if msg := validateLocalSourceIP(site.BackendSourceIP, "", hostAddrs); msg != "" {
			return site, "backend_source_ip " + msg
		}
	}
	return site, ""
}

func normalizeAndValidateRange(pr PortRange, requireID bool, knownIfaces map[string]struct{}, hostAddrs hostInterfaceAddrs) (PortRange, string) {
	pr.InInterface = strings.TrimSpace(pr.InInterface)
	pr.InIP = strings.TrimSpace(pr.InIP)
	pr.OutInterface = strings.TrimSpace(pr.OutInterface)
	pr.OutIP = strings.TrimSpace(pr.OutIP)
	pr.OutSourceIP = strings.TrimSpace(pr.OutSourceIP)
	pr.Protocol = strings.ToLower(strings.TrimSpace(pr.Protocol))
	pr.Remark = strings.TrimSpace(pr.Remark)
	pr.Tag = strings.TrimSpace(pr.Tag)
	if pr.Protocol == "" {
		pr.Protocol = "tcp"
	}
	if pr.OutStartPort == 0 {
		pr.OutStartPort = pr.StartPort
	}

	if requireID && pr.ID == 0 {
		return pr, "id is required"
	}
	if pr.InIP == "" || pr.StartPort == 0 || pr.EndPort == 0 || pr.OutIP == "" {
		return pr, "in_ip, start_port, end_port, out_ip are required"
	}
	if pr.StartPort > pr.EndPort {
		return pr, "start_port must be <= end_port"
	}
	if pr.Protocol != "tcp" && pr.Protocol != "udp" && pr.Protocol != "tcp+udp" {
		return pr, "protocol must be tcp, udp, or tcp+udp"
	}
	if normalized, err := normalizeIPLiteral(pr.InIP); err != nil {
		return pr, "in_ip " + err.Error()
	} else {
		pr.InIP = normalized
	}
	if normalized, err := normalizeIPLiteral(pr.OutIP); err != nil {
		return pr, "out_ip " + err.Error()
	} else {
		pr.OutIP = normalized
	}
	if pr.StartPort < 1 || pr.StartPort > 65535 || pr.EndPort < 1 || pr.EndPort > 65535 || pr.OutStartPort < 1 || pr.OutStartPort > 65535 {
		return pr, "ports must be between 1 and 65535"
	}
	if pr.InInterface != "" {
		if _, ok := knownIfaces[pr.InInterface]; !ok {
			return pr, "in_interface does not exist on this host"
		}
	}
	outIfaceValid := true
	if pr.OutInterface != "" {
		if _, ok := knownIfaces[pr.OutInterface]; !ok {
			outIfaceValid = false
			return pr, "out_interface does not exist on this host"
		}
	}
	normalizedSourceIP, err := normalizeOptionalSpecificIP(pr.OutSourceIP)
	if err != nil {
		return pr, "out_source_ip " + err.Error()
	}
	pr.OutSourceIP = normalizedSourceIP
	pureIPv4 := ipLiteralPairIsPureIPv4(pr.InIP, pr.OutIP)
	outFamily := ipLiteralFamily(pr.OutIP)
	if pr.Transparent && !pureIPv4 {
		return pr, "transparent mode currently supports only IPv4 rules"
	}
	if pr.Transparent && pr.OutSourceIP != "" {
		return pr, "out_source_ip must be omitted when transparent mode is enabled"
	}
	if pr.OutSourceIP != "" {
		if outFamily != "" && ipLiteralFamily(pr.OutSourceIP) != outFamily {
			return pr, "out_source_ip must match out_ip address family"
		}
		if outIfaceValid {
			if msg := validateLocalSourceIP(pr.OutSourceIP, pr.OutInterface, hostAddrs); msg != "" {
				return pr, "out_source_ip " + msg
			}
		}
	}
	return pr, ""
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
	return protocolMaskFromString(protocol)
}

func ruleInterfacesOverlap(a, b string) bool {
	return a == "" || b == "" || a == b
}

func ruleIPsOverlap(a, b string) bool {
	aFamily := ipLiteralFamily(a)
	bFamily := ipLiteralFamily(b)
	if aFamily == "" || bFamily == "" || aFamily != bFamily {
		return false
	}
	return ipLiteralIsWildcard(a) || ipLiteralIsWildcard(b) || a == b
}

func appendRuleConflictIssue(issues []ruleValidationIssue, current, other projectedRuleState) []ruleValidationIssue {
	scope, index, id, field := ruleConflictIssueTarget(current)
	if scope == "" {
		return issues
	}
	return appendRuleIssue(issues, scope, index, id, field, fmt.Sprintf("listener conflicts with %s", describeRuleConflict(other)))
}

func ruleConflictIssueTarget(state projectedRuleState) (string, int, int64, string) {
	switch state.ContentScope {
	case "create", "update":
		return state.ContentScope, state.ContentIndex, state.Rule.ID, "in_port"
	case "existing":
		if state.EnableScope == "set_enabled" {
			return "set_enabled", state.EnableIndex, state.Rule.ID, "in_port"
		}
	}
	return "", 0, 0, ""
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

func writeValidationIssueResponse(w http.ResponseWriter, status int, issues []ruleValidationIssue) {
	writeJSON(w, status, validationErrorResponse{
		Error:  summarizeRuleIssues(issues),
		Issues: issues,
	})
}

func singleValidationIssue(scope string, id int64, field, message string) []ruleValidationIssue {
	return []ruleValidationIssue{{
		Scope:   scope,
		ID:      id,
		Field:   field,
		Message: message,
	}}
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
	if err := decodeJSONRequestBody(w, r, &rule, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	prepared, issues, err := prepareRuleBatch(tx, ruleBatchRequest{Create: []Rule{rule}})
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
	id, err := dbAddRule(tx, &rule)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rule.ID = id
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	pm.redistributeWorkers()

	writeJSON(w, http.StatusOK, rule)
}

func handleUpdateRule(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var rule Rule
	if err := decodeJSONRequestBody(w, r, &rule, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	prepared, issues, err := prepareRuleBatch(tx, ruleBatchRequest{Update: []Rule{rule}})
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

	if err := dbUpdateRule(tx, &rule); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
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
		writeValidationIssueResponse(w, http.StatusBadRequest, singleValidationIssue("toggle", 0, "id", "invalid id"))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	rule, err := dbGetRule(tx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeValidationIssueResponse(w, http.StatusNotFound, singleValidationIssue("toggle", id, "id", "rule not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	newEnabled := !rule.Enabled
	prepared, issues, err := prepareRuleBatch(tx, ruleBatchRequest{
		SetEnabled: []ruleSetEnabledRequest{{ID: id, Enabled: newEnabled}},
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 || len(prepared.SetEnabled) == 0 {
		status := http.StatusBadRequest
		if hasRuleNotFoundIssue(issues) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, ruleValidateResponse{
			Valid:      false,
			Error:      summarizeRuleIssues(issues),
			SetEnabled: prepared.SetEnabled,
			Issues:     issues,
		})
		return
	}
	if err := dbSetRuleEnabled(tx, id, newEnabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
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
		writeValidationIssueResponse(w, http.StatusBadRequest, singleValidationIssue("delete", 0, "id", "invalid id"))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	if _, err := dbGetRule(tx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeValidationIssueResponse(w, http.StatusNotFound, singleValidationIssue("delete", id, "id", "rule not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := dbDeleteRule(tx, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
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
	proxyErrored := pm.sharedProxy != nil && pm.sharedProxy.errored
	failedSiteIDs := make(map[int64]bool)
	if pm.sharedProxy != nil {
		for id := range pm.sharedProxy.failedSites {
			failedSiteIDs[id] = true
		}
	}
	pm.mu.Unlock()
	for _, site := range sites {
		status := "stopped"
		if site.Enabled && failedSiteIDs[site.ID] {
			status = "error"
		} else if site.Enabled && proxyRunning {
			status = "running"
		} else if site.Enabled && proxyErrored && len(failedSiteIDs) == 0 {
			status = "error"
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
	if err := decodeJSONRequestBody(w, r, &site, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	site, issues, err := prepareSiteCreate(tx, site)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		writeValidationIssueResponse(w, http.StatusBadRequest, issues)
		return
	}

	id, err := dbAddSite(tx, &site)
	if err != nil {
		if issues := siteConstraintIssuesFromDBError(tx, site, err, "create"); len(issues) > 0 {
			writeValidationIssueResponse(w, http.StatusBadRequest, issues)
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	site.ID = id
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	pm.redistributeWorkers()

	writeJSON(w, http.StatusOK, site)
}

func handleUpdateSite(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var site Site
	if err := decodeJSONRequestBody(w, r, &site, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	site, issues, err := prepareSiteUpdate(tx, site)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		status := http.StatusBadRequest
		if hasValidationMessage(issues, "site not found") {
			status = http.StatusNotFound
		}
		writeValidationIssueResponse(w, status, issues)
		return
	}

	if err := dbUpdateSite(tx, &site); err != nil {
		if issues := siteConstraintIssuesFromDBError(tx, site, err, "update"); len(issues) > 0 {
			writeValidationIssueResponse(w, http.StatusBadRequest, issues)
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
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
		writeValidationIssueResponse(w, http.StatusBadRequest, singleValidationIssue("toggle", 0, "id", "invalid id"))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	site, issues, err := prepareSiteToggle(tx, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		status := http.StatusBadRequest
		if hasValidationMessage(issues, "site not found") {
			status = http.StatusNotFound
		}
		writeValidationIssueResponse(w, status, issues)
		return
	}
	if err := dbSetSiteEnabled(tx, id, site.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pm.redistributeWorkers()
	writeJSON(w, http.StatusOK, map[string]interface{}{"id": id, "enabled": site.Enabled})
}

func handleDeleteSite(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
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

	if _, err := dbGetSite(tx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeValidationIssueResponse(w, http.StatusNotFound, singleValidationIssue("delete", id, "id", "site not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := dbDeleteSite(tx, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
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

func handleListEgressNATs(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	items, err := dbGetEgressNATs(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	items = normalizeEgressNATItemsWithCurrentInterfaces(items)

	statuses := make([]EgressNATStatus, 0, len(items))
	for _, item := range items {
		status := "stopped"
		if pm != nil {
			status = pm.egressNATRuntimeStatus(item.ID, item.Enabled)
		}
		if pm != nil {
			statuses = append(statuses, pm.buildEgressNATStatus(item, status))
			continue
		}
		statuses = append(statuses, EgressNATStatus{
			EgressNAT:       item,
			Status:          status,
			EffectiveEngine: ruleEngineKernel,
		})
	}
	if statuses == nil {
		statuses = []EgressNATStatus{}
	}
	writeJSON(w, http.StatusOK, statuses)
}

func loadEffectiveEgressNATMetaByIDs(db sqlRuleStore, ids []int64) (map[int64]EgressNAT, error) {
	result := make(map[int64]EgressNAT, len(ids))
	if len(ids) == 0 {
		return result, nil
	}

	snapshot := loadEgressNATInterfaceSnapshot()

	items, err := dbGetEgressNATsByIDs(db, ids)
	if err != nil {
		return nil, err
	}
	items = normalizeEgressNATItemsWithSnapshot(items, snapshot)
	for _, item := range items {
		result[item.ID] = item
	}

	hasSynthetic := false
	requested := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		requested[id] = struct{}{}
		if id < 0 {
			hasSynthetic = true
		}
	}
	if !hasSynthetic {
		return result, nil
	}

	managedNetworks, err := dbGetEnabledManagedNetworks(db)
	if err != nil {
		return nil, err
	}
	if len(managedNetworks) == 0 {
		return result, nil
	}

	ipv6Assignments, err := dbGetEnabledIPv6Assignments(db)
	if err != nil {
		return nil, err
	}

	allItems, err := dbGetEgressNATs(db)
	if err != nil {
		return nil, err
	}
	allItems = normalizeEgressNATItemsWithSnapshot(allItems, snapshot)

	compiled := compileManagedNetworkRuntime(managedNetworks, ipv6Assignments, allItems, snapshot.Infos)
	for _, item := range compiled.EgressNATs {
		if _, ok := requested[item.ID]; ok {
			result[item.ID] = item
		}
	}
	return result, nil
}

func loadEffectiveEgressNATProtocolByIDs(db sqlRuleStore, ids []int64) (map[int64]string, error) {
	result := make(map[int64]string, len(ids))
	if len(ids) == 0 {
		return result, nil
	}

	protocols, err := dbGetEgressNATProtocolMapByIDs(db, ids)
	if err != nil {
		return nil, err
	}
	for id, protocol := range protocols {
		result[id] = protocol
	}

	hasSynthetic := false
	requested := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		requested[id] = struct{}{}
		if id < 0 {
			hasSynthetic = true
		}
	}
	if !hasSynthetic {
		return result, nil
	}

	managedNetworks, err := dbGetEnabledManagedNetworks(db)
	if err != nil {
		return nil, err
	}
	if len(managedNetworks) == 0 {
		return result, nil
	}

	ipv6Assignments, err := dbGetEnabledIPv6Assignments(db)
	if err != nil {
		return nil, err
	}

	snapshot := loadEgressNATInterfaceSnapshot()
	explicitItems, err := dbGetEgressNATs(db)
	if err != nil {
		return nil, err
	}
	explicitItems = normalizeEgressNATItemsWithSnapshot(explicitItems, snapshot)

	compiled := compileManagedNetworkRuntime(managedNetworks, ipv6Assignments, explicitItems, snapshot.Infos)
	for _, item := range compiled.EgressNATs {
		if _, ok := requested[item.ID]; ok {
			result[item.ID] = item.Protocol
		}
	}
	return result, nil
}

func loadEffectiveEnabledEgressNATItems(db sqlRuleStore) ([]EgressNAT, error) {
	items, err := dbGetEnabledEgressNATs(db)
	if err != nil {
		return nil, err
	}

	snapshot := loadEgressNATInterfaceSnapshot()
	items = normalizeEgressNATItemsWithSnapshot(items, snapshot)

	managedNetworks, err := dbGetEnabledManagedNetworks(db)
	if err != nil {
		return nil, err
	}
	if len(managedNetworks) == 0 {
		return items, nil
	}

	ipv6Assignments, err := dbGetEnabledIPv6Assignments(db)
	if err != nil {
		return nil, err
	}
	compiled := compileManagedNetworkRuntime(managedNetworks, ipv6Assignments, items, snapshot.Infos)
	if len(compiled.EgressNATs) == 0 {
		return items, nil
	}

	items = append(items, compiled.EgressNATs...)
	return items, nil
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
	needsSharedSiteCount := false
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
	if pm.sharedProxy != nil {
		needsSharedSiteCount = true
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

	enabledSites := 0
	if needsSharedSiteCount {
		count, err := dbCountEnabledSites(db)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		enabledSites = count
		if enabledSites == 0 {
			filtered := snaps[:0]
			for _, snap := range snaps {
				if snap.kind == workerKindShared {
					continue
				}
				filtered = append(filtered, snap)
			}
			snaps = filtered
		}
	}

	var kernelRules []Rule
	if len(kernelRuleIDs) > 0 {
		var err error
		kernelRules, err = dbGetEnabledRulesByIDs(db, trueInt64Keys(kernelRuleIDs))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}

	var kernelRanges []PortRange
	if len(kernelRangeIDs) > 0 {
		var err error
		kernelRanges, err = dbGetEnabledRangesByIDs(db, trueInt64Keys(kernelRangeIDs))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}

	if len(kernelRuleIDs) > 0 {
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

	allEgressNATs, err := loadEffectiveEnabledEgressNATItems(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	enabledEgressNATs := make([]EgressNATStatus, 0, len(allEgressNATs))
	for _, item := range allEgressNATs {
		enabledEgressNATs = append(enabledEgressNATs, pm.buildEgressNATStatus(item, pm.egressNATRuntimeStatus(item.ID, item.Enabled)))
	}
	if len(enabledEgressNATs) > 0 {
		sort.Slice(enabledEgressNATs, func(i, j int) bool { return enabledEgressNATs[i].ID < enabledEgressNATs[j].ID })

		status := "stopped"
		hasError := false
		for _, item := range enabledEgressNATs {
			if item.Status == "running" {
				status = "running"
				hasError = false
				break
			}
			if item.Status == "error" {
				hasError = true
			}
		}
		if status != "running" && hasError {
			status = "error"
		}

		workers = append(workers, WorkerView{
			Kind:           workerKindEgressNAT,
			Index:          0,
			Status:         status,
			BinaryHash:     kernelBinaryHash,
			EgressNATCount: len(enabledEgressNATs),
			EgressNATs:     enabledEgressNATs,
		})
	}

	kindOrder := map[string]int{"kernel": 0, "rule": 1, "range": 2, workerKindEgressNAT: 3, "shared": 4}
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
		BinaryHash: kernelBinaryHash,
		Workers:    out,
	}
	writeJSON(w, http.StatusOK, resp)
}

func trueInt64Keys(values map[int64]bool) []int64 {
	keys := make([]int64, 0, len(values))
	for id, ok := range values {
		if ok {
			keys = append(keys, id)
		}
	}
	return keys
}

func siteConstraintIssuesFromDBError(db sqlRuleStore, site Site, err error, scope string) []ruleValidationIssue {
	indexName := sqliteUniqueConstraintIndexName(err)
	switch indexName {
	case dbConstraintIndexSitesHTTPDomainEnabled:
		return loadSiteDomainConstraintIssue(db, site, scope, "http")
	case dbConstraintIndexSitesHTTPSDomainEnabled:
		return loadSiteDomainConstraintIssue(db, site, scope, "https")
	default:
		return nil
	}
}

func loadSiteDomainConstraintIssue(db sqlRuleStore, site Site, scope, kind string) []ruleValidationIssue {
	conflictID, err := dbFindConflictingEnabledSiteDomainID(db, site, kind)
	if err != nil {
		return []ruleValidationIssue{singleSiteConstraintIssue(scope, site.ID, "domain", strings.ToUpper(kind)+" route conflicts with an existing enabled site domain")}
	}

	domain := strings.ToLower(strings.TrimSpace(site.Domain))
	message := strings.ToUpper(kind) + " route conflicts with an existing enabled site domain"
	if conflictID > 0 {
		message = fmt.Sprintf("%s route conflicts with site #%d domain=%s [%s]", strings.ToUpper(kind), conflictID, domain, strings.ToUpper(kind))
	}
	return []ruleValidationIssue{singleSiteConstraintIssue(scope, site.ID, "domain", message)}
}

func singleSiteConstraintIssue(scope string, id int64, field, message string) ruleValidationIssue {
	issue := ruleValidationIssue{
		Scope:   scope,
		ID:      id,
		Field:   field,
		Message: message,
	}
	if scope == "create" || scope == "update" {
		issue.Index = 1
	}
	return issue
}

func dbFindConflictingEnabledSiteDomainID(db sqlRuleStore, site Site, kind string) (int64, error) {
	var query string
	switch kind {
	case "http":
		query = `SELECT id FROM sites WHERE id <> ? AND enabled = 1 AND backend_http > 0 AND lower(trim(domain)) = lower(trim(?)) ORDER BY id LIMIT 1`
	case "https":
		query = `SELECT id FROM sites WHERE id <> ? AND enabled = 1 AND backend_https > 0 AND lower(trim(domain)) = lower(trim(?)) ORDER BY id LIMIT 1`
	default:
		return 0, nil
	}

	var id int64
	err := db.QueryRow(query, site.ID, site.Domain).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return id, nil
}

func handleKernelRuntime(w http.ResponseWriter, r *http.Request, pm *ProcessManager) {
	forceFresh := false
	if r != nil {
		cacheControl := strings.ToLower(r.Header.Get("Cache-Control"))
		forceFresh = strings.Contains(cacheControl, "no-cache") || strings.EqualFold(r.URL.Query().Get("refresh"), "1")
	}
	writeJSON(w, http.StatusOK, pm.snapshotKernelRuntimeShared(time.Time{}, forceFresh))
}

func handleDismissKernelRuntimeNote(w http.ResponseWriter, r *http.Request, pm *ProcessManager) {
	var req struct {
		Key string `json:"key"`
	}
	if err := decodeJSONRequestBody(w, r, &req, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	key := normalizeKernelRuntimeNoteKey(req.Key)
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key is required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dismissed_note_keys": pm.dismissKernelRuntimeNote(key),
	})
}

func handleAddRange(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var pr PortRange
	if err := decodeJSONRequestBody(w, r, &pr, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	pr, issues, err := prepareRangeCreate(tx, pr)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		writeValidationIssueResponse(w, http.StatusBadRequest, issues)
		return
	}

	id, err := dbAddRange(tx, &pr)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pr.ID = id
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	pm.redistributeWorkers()

	writeJSON(w, http.StatusOK, pr)
}

func handleUpdateRange(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var pr PortRange
	if err := decodeJSONRequestBody(w, r, &pr, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	pr, issues, err := prepareRangeUpdate(tx, pr)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		status := http.StatusBadRequest
		if hasValidationMessage(issues, "range not found") {
			status = http.StatusNotFound
		}
		writeValidationIssueResponse(w, status, issues)
		return
	}

	if err := dbUpdateRange(tx, &pr); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
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
		writeValidationIssueResponse(w, http.StatusBadRequest, singleValidationIssue("toggle", 0, "id", "invalid id"))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	pr, issues, err := prepareRangeToggle(tx, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		status := http.StatusBadRequest
		if hasValidationMessage(issues, "range not found") {
			status = http.StatusNotFound
		}
		writeValidationIssueResponse(w, status, issues)
		return
	}
	if err := dbSetRangeEnabled(tx, id, pr.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pm.redistributeWorkers()
	writeJSON(w, http.StatusOK, map[string]interface{}{"id": id, "enabled": pr.Enabled})
}

func handleDeleteRange(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
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

	if _, err := dbGetRange(tx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeValidationIssueResponse(w, http.StatusNotFound, singleValidationIssue("delete", id, "id", "range not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := dbDeleteRange(tx, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pm.redistributeWorkers()

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func handleAddEgressNAT(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var item EgressNAT
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

	item, issues, err := prepareEgressNATCreate(tx, item)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		writeValidationIssueResponse(w, http.StatusBadRequest, issues)
		return
	}

	id, err := dbAddEgressNAT(tx, &item)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	item.ID = id
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	pm.redistributeWorkers()
	writeJSON(w, http.StatusOK, item)
}

func handleUpdateEgressNAT(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var item EgressNAT
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

	item, issues, err := prepareEgressNATUpdate(tx, item)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		status := http.StatusBadRequest
		if hasValidationMessage(issues, "egress nat not found") {
			status = http.StatusNotFound
		}
		writeValidationIssueResponse(w, status, issues)
		return
	}

	if err := dbUpdateEgressNAT(tx, &item); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	pm.redistributeWorkers()
	writeJSON(w, http.StatusOK, item)
}

func handleToggleEgressNAT(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
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

	item, issues, err := prepareEgressNATToggle(tx, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(issues) > 0 {
		status := http.StatusBadRequest
		if hasValidationMessage(issues, "egress nat not found") {
			status = http.StatusNotFound
		}
		writeValidationIssueResponse(w, status, issues)
		return
	}
	if err := dbSetEgressNATEnabled(tx, id, item.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	pm.redistributeWorkers()
	writeJSON(w, http.StatusOK, map[string]interface{}{"id": id, "enabled": item.Enabled})
}

func handleDeleteEgressNAT(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
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

	if _, err := dbGetEgressNAT(tx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeValidationIssueResponse(w, http.StatusNotFound, singleValidationIssue("delete", id, "id", "egress nat not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := dbDeleteEgressNAT(tx, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	pm.redistributeWorkers()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func parseStatsListQuery(r *http.Request, allowedSortKeys map[string]struct{}) (statsListQuery, error) {
	query := statsListQuery{
		Page:     1,
		PageSize: 20,
		SortAsc:  true,
	}

	values := r.URL.Query()
	if v := strings.TrimSpace(values.Get("page")); v != "" {
		page, err := strconv.Atoi(v)
		if err != nil || page <= 0 {
			return query, fmt.Errorf("invalid page")
		}
		query.Page = page
	}
	if v := strings.TrimSpace(values.Get("page_size")); v != "" {
		pageSize, err := strconv.Atoi(v)
		if err != nil || pageSize <= 0 {
			return query, fmt.Errorf("invalid page_size")
		}
		if pageSize > maxStatsPageSize {
			pageSize = maxStatsPageSize
		}
		query.PageSize = pageSize
	}
	query.SortKey = strings.TrimSpace(values.Get("sort_key"))
	if query.SortKey != "" {
		if _, ok := allowedSortKeys[query.SortKey]; !ok {
			return query, fmt.Errorf("invalid sort_key")
		}
	}
	if v := strings.TrimSpace(values.Get("sort_asc")); v != "" {
		sortAsc, err := parseOptionalBoolQuery(v)
		if err != nil {
			return query, fmt.Errorf("invalid sort_asc")
		}
		if sortAsc != nil {
			query.SortAsc = *sortAsc
		}
	}
	return query, nil
}

func paginateRuleStatsItems(items []RuleStatsListItem, query statsListQuery) RuleStatsListResponse {
	total := len(items)
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}
	totalPages := 1
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	page := query.Page
	if page > totalPages {
		page = totalPages
	}
	if page < 1 {
		page = 1
	}
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}

	resp := RuleStatsListResponse{
		Page:     page,
		PageSize: pageSize,
		Total:    total,
		SortKey:  query.SortKey,
		SortAsc:  query.SortAsc,
		Items:    make([]RuleStatsListItem, 0, end-start),
	}
	if start < end {
		resp.Items = append(resp.Items, items[start:end]...)
	}
	return resp
}

func paginateRangeStatsItems(items []RangeStatsListItem, query statsListQuery) RangeStatsListResponse {
	total := len(items)
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}
	totalPages := 1
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	page := query.Page
	if page > totalPages {
		page = totalPages
	}
	if page < 1 {
		page = 1
	}
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}

	resp := RangeStatsListResponse{
		Page:     page,
		PageSize: pageSize,
		Total:    total,
		SortKey:  query.SortKey,
		SortAsc:  query.SortAsc,
		Items:    make([]RangeStatsListItem, 0, end-start),
	}
	if start < end {
		resp.Items = append(resp.Items, items[start:end]...)
	}
	return resp
}

func paginateEgressNATStatsItems(items []EgressNATStatsListItem, query statsListQuery) EgressNATStatsListResponse {
	total := len(items)
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}
	totalPages := 1
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	page := query.Page
	if page > totalPages {
		page = totalPages
	}
	if page < 1 {
		page = 1
	}
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}

	resp := EgressNATStatsListResponse{
		Page:     page,
		PageSize: pageSize,
		Total:    total,
		SortKey:  query.SortKey,
		SortAsc:  query.SortAsc,
		Items:    make([]EgressNATStatsListItem, 0, end-start),
	}
	if start < end {
		resp.Items = append(resp.Items, items[start:end]...)
	}
	return resp
}

func ruleStatsPageIDs(items []RuleStatsListItem) []int64 {
	ids := make([]int64, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.RuleID)
	}
	return ids
}

func rangeStatsPageIDs(items []RangeStatsListItem) []int64 {
	ids := make([]int64, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.RangeID)
	}
	return ids
}

func egressNATStatsPageIDs(items []EgressNATStatsListItem) []int64 {
	ids := make([]int64, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.EgressNATID)
	}
	return ids
}

func ruleStatsMapIDs(items map[int64]RuleStatsReport) []int64 {
	ids := make([]int64, 0, len(items))
	for id := range items {
		ids = append(ids, id)
	}
	return ids
}

func rangeStatsMapIDs(items map[int64]RangeStatsReport) []int64 {
	ids := make([]int64, 0, len(items))
	for id := range items {
		ids = append(ids, id)
	}
	return ids
}

func egressNATStatsMapIDs(items map[int64]EgressNATStatsReport) []int64 {
	ids := make([]int64, 0, len(items))
	for id := range items {
		ids = append(ids, id)
	}
	return ids
}

func currentConnStatsMapIDs(items map[int64]currentConnProtocolStats) []int64 {
	ids := make([]int64, 0, len(items))
	for id := range items {
		ids = append(ids, id)
	}
	return ids
}

func egressNATStatsSortNeedsAllMeta(sortKey string) bool {
	switch sortKey {
	case "parent_interface", "child_interface", "out_interface", "out_source_ip", "protocol", "nat_type":
		return true
	default:
		return false
	}
}

func populateEgressNATStatsItemsMeta(items []EgressNATStatsListItem, metaByID map[int64]EgressNAT) {
	for i := range items {
		meta := metaByID[items[i].EgressNATID]
		items[i].ParentInterface = meta.ParentInterface
		items[i].ChildInterface = meta.ChildInterface
		items[i].OutInterface = meta.OutInterface
		items[i].OutSourceIP = meta.OutSourceIP
		items[i].Protocol = meta.Protocol
		items[i].NATType = meta.NATType
	}
}

func ruleStatsLess(a, b RuleStatsListItem, sortKey string, sortAsc bool) bool {
	compare := 0
	switch sortKey {
	case "remark":
		compare = strings.Compare(strings.ToLower(a.Remark), strings.ToLower(b.Remark))
	case "current_conns":
		compare = compareInt64(a.CurrentConns, b.CurrentConns)
	case "total_conns":
		compare = compareInt64(a.TotalConns, b.TotalConns)
	case "rejected_conns":
		compare = compareInt64(a.RejectedConns, b.RejectedConns)
	case "speed_in":
		compare = compareInt64(a.SpeedIn, b.SpeedIn)
	case "speed_out":
		compare = compareInt64(a.SpeedOut, b.SpeedOut)
	case "bytes_in":
		compare = compareInt64(a.BytesIn, b.BytesIn)
	case "bytes_out":
		compare = compareInt64(a.BytesOut, b.BytesOut)
	default:
		compare = compareInt64(a.RuleID, b.RuleID)
	}
	if compare == 0 {
		compare = compareInt64(a.RuleID, b.RuleID)
	}
	if sortAsc {
		return compare < 0
	}
	return compare > 0
}

func rangeStatsLess(a, b RangeStatsListItem, sortKey string, sortAsc bool) bool {
	compare := 0
	switch sortKey {
	case "remark":
		compare = strings.Compare(strings.ToLower(a.Remark), strings.ToLower(b.Remark))
	case "current_conns":
		compare = compareInt64(a.CurrentConns, b.CurrentConns)
	case "total_conns":
		compare = compareInt64(a.TotalConns, b.TotalConns)
	case "rejected_conns":
		compare = compareInt64(a.RejectedConns, b.RejectedConns)
	case "speed_in":
		compare = compareInt64(a.SpeedIn, b.SpeedIn)
	case "speed_out":
		compare = compareInt64(a.SpeedOut, b.SpeedOut)
	case "bytes_in":
		compare = compareInt64(a.BytesIn, b.BytesIn)
	case "bytes_out":
		compare = compareInt64(a.BytesOut, b.BytesOut)
	default:
		compare = compareInt64(a.RangeID, b.RangeID)
	}
	if compare == 0 {
		compare = compareInt64(a.RangeID, b.RangeID)
	}
	if sortAsc {
		return compare < 0
	}
	return compare > 0
}

func egressNATStatsLess(a, b EgressNATStatsListItem, sortKey string, sortAsc bool) bool {
	compare := 0
	switch sortKey {
	case "parent_interface":
		compare = strings.Compare(strings.ToLower(a.ParentInterface), strings.ToLower(b.ParentInterface))
	case "child_interface":
		compare = strings.Compare(strings.ToLower(a.ChildInterface), strings.ToLower(b.ChildInterface))
	case "out_interface":
		compare = strings.Compare(strings.ToLower(a.OutInterface), strings.ToLower(b.OutInterface))
	case "out_source_ip":
		compare = strings.Compare(strings.ToLower(a.OutSourceIP), strings.ToLower(b.OutSourceIP))
	case "protocol":
		compare = strings.Compare(strings.ToLower(a.Protocol), strings.ToLower(b.Protocol))
	case "nat_type":
		compare = strings.Compare(strings.ToLower(a.NATType), strings.ToLower(b.NATType))
	case "current_conns":
		compare = compareInt64(a.CurrentConns, b.CurrentConns)
	case "total_conns":
		compare = compareInt64(a.TotalConns, b.TotalConns)
	case "speed_in":
		compare = compareInt64(a.SpeedIn, b.SpeedIn)
	case "speed_out":
		compare = compareInt64(a.SpeedOut, b.SpeedOut)
	case "bytes_in":
		compare = compareInt64(a.BytesIn, b.BytesIn)
	case "bytes_out":
		compare = compareInt64(a.BytesOut, b.BytesOut)
	default:
		compare = compareInt64(a.EgressNATID, b.EgressNATID)
	}
	if compare == 0 {
		compare = compareInt64(a.EgressNATID, b.EgressNATID)
	}
	if sortAsc {
		return compare < 0
	}
	return compare > 0
}

func compareInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func handleListRuleStats(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	query, err := parseStatsListQuery(r, map[string]struct{}{
		"rule_id":        {},
		"remark":         {},
		"current_conns":  {},
		"total_conns":    {},
		"rejected_conns": {},
		"speed_in":       {},
		"speed_out":      {},
		"bytes_in":       {},
		"bytes_out":      {},
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	pm.markKernelStatsDemand()
	pm.refreshKernelStatsCacheIfNeeded()
	statsMap := pm.collectRuleStats()
	if len(statsMap) == 0 {
		writeJSON(w, http.StatusOK, paginateRuleStatsItems(nil, query))
		return
	}

	result := make([]RuleStatsListItem, 0, len(statsMap))
	for _, s := range statsMap {
		result = append(result, RuleStatsListItem{RuleStatsReport: s})
	}

	statsIDs := ruleStatsMapIDs(statsMap)
	needsAllMeta := query.SortKey == "remark"
	if needsAllMeta {
		ruleMeta, err := dbGetRuleMetaByIDs(db, statsIDs)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		for i := range result {
			meta := ruleMeta[result[i].RuleID]
			result[i].Remark = meta.Remark
		}
	} else if query.SortKey == "current_conns" {
		ruleProtocols, err := dbGetRuleProtocolMapByIDs(db, statsIDs)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		for i := range result {
			protocol := ruleProtocols[result[i].RuleID]
			result[i].CurrentConns = currentConnCountForProtocolWithICMP(protocol, result[i].ActiveConns, int64(result[i].NatTableSize), int64(result[i].ICMPNatSize))
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return ruleStatsLess(result[i], result[j], query.SortKey, query.SortAsc)
	})

	resp := paginateRuleStatsItems(result, query)
	if !needsAllMeta && len(resp.Items) > 0 {
		ruleMeta, err := dbGetRuleMetaByIDs(db, ruleStatsPageIDs(resp.Items))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		for i := range resp.Items {
			meta := ruleMeta[resp.Items[i].RuleID]
			resp.Items[i].Remark = meta.Remark
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleListRangeStats(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	query, err := parseStatsListQuery(r, map[string]struct{}{
		"range_id":       {},
		"remark":         {},
		"current_conns":  {},
		"total_conns":    {},
		"rejected_conns": {},
		"speed_in":       {},
		"speed_out":      {},
		"bytes_in":       {},
		"bytes_out":      {},
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	pm.markKernelStatsDemand()
	pm.refreshKernelStatsCacheIfNeeded()
	statsMap := pm.collectRangeStats()
	if len(statsMap) == 0 {
		writeJSON(w, http.StatusOK, paginateRangeStatsItems(nil, query))
		return
	}

	result := make([]RangeStatsListItem, 0, len(statsMap))
	for _, s := range statsMap {
		result = append(result, RangeStatsListItem{RangeStatsReport: s})
	}

	statsIDs := rangeStatsMapIDs(statsMap)
	needsAllMeta := query.SortKey == "remark"
	if needsAllMeta {
		rangeMeta, err := dbGetRangeMetaByIDs(db, statsIDs)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		for i := range result {
			meta := rangeMeta[result[i].RangeID]
			result[i].Remark = meta.Remark
		}
	} else if query.SortKey == "current_conns" {
		rangeProtocols, err := dbGetRangeProtocolMapByIDs(db, statsIDs)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		for i := range result {
			protocol := rangeProtocols[result[i].RangeID]
			result[i].CurrentConns = currentConnCountForProtocolWithICMP(protocol, result[i].ActiveConns, int64(result[i].NatTableSize), int64(result[i].ICMPNatSize))
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return rangeStatsLess(result[i], result[j], query.SortKey, query.SortAsc)
	})

	resp := paginateRangeStatsItems(result, query)
	if !needsAllMeta && len(resp.Items) > 0 {
		rangeMeta, err := dbGetRangeMetaByIDs(db, rangeStatsPageIDs(resp.Items))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		for i := range resp.Items {
			meta := rangeMeta[resp.Items[i].RangeID]
			resp.Items[i].Remark = meta.Remark
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleListEgressNATStats(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	query, err := parseStatsListQuery(r, map[string]struct{}{
		"egress_nat_id":    {},
		"parent_interface": {},
		"child_interface":  {},
		"out_interface":    {},
		"out_source_ip":    {},
		"protocol":         {},
		"nat_type":         {},
		"current_conns":    {},
		"total_conns":      {},
		"speed_in":         {},
		"speed_out":        {},
		"bytes_in":         {},
		"bytes_out":        {},
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	pm.markKernelStatsDemand()
	pm.refreshKernelStatsCacheIfNeeded()
	statsMap := pm.collectEgressNATStats()
	if len(statsMap) == 0 {
		writeJSON(w, http.StatusOK, paginateEgressNATStatsItems(nil, query))
		return
	}

	result := make([]EgressNATStatsListItem, 0, len(statsMap))
	for _, s := range statsMap {
		result = append(result, EgressNATStatsListItem{EgressNATStatsReport: s})
	}

	statsIDs := egressNATStatsMapIDs(statsMap)
	needsAllMeta := egressNATStatsSortNeedsAllMeta(query.SortKey)
	if needsAllMeta {
		metaByID, err := loadEffectiveEgressNATMetaByIDs(db, statsIDs)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		populateEgressNATStatsItemsMeta(result, metaByID)
	} else if query.SortKey == "current_conns" {
		protocols, err := loadEffectiveEgressNATProtocolByIDs(db, statsIDs)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		for i := range result {
			result[i].CurrentConns = currentConnCountForProtocolWithICMP(protocols[result[i].EgressNATID], result[i].ActiveConns, int64(result[i].NatTableSize), int64(result[i].ICMPNatSize))
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return egressNATStatsLess(result[i], result[j], query.SortKey, query.SortAsc)
	})

	resp := paginateEgressNATStatsItems(result, query)
	if !needsAllMeta && len(resp.Items) > 0 {
		metaByID, err := loadEffectiveEgressNATMetaByIDs(db, egressNATStatsPageIDs(resp.Items))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		populateEgressNATStatsItemsMeta(resp.Items, metaByID)
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleListSiteStats(w http.ResponseWriter, r *http.Request, pm *ProcessManager) {
	stats := pm.collectSiteStats()
	if stats == nil {
		stats = []SiteStatsReport{}
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].SiteID < stats[j].SiteID })
	writeJSON(w, http.StatusOK, stats)
}

func handleListCurrentConns(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	pm.markKernelStatsDemand()
	ruleStats, rangeStats, siteCounts, egressNATStats, err := pm.collectCurrentConnStats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	ruleProtocols, err := dbGetRuleProtocolMapByIDs(db, currentConnStatsMapIDs(ruleStats))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rangeProtocols, err := dbGetRangeProtocolMapByIDs(db, currentConnStatsMapIDs(rangeStats))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	egressNATProtocols, err := loadEffectiveEgressNATProtocolByIDs(db, currentConnStatsMapIDs(egressNATStats))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	ruleCounts := make(map[int64]int64, len(ruleStats))
	for id, stats := range ruleStats {
		ruleCounts[id] = currentConnCountForProtocolDatagrams(ruleProtocols[id], stats.ActiveConns, stats.UDPNatEntries, stats.ICMPNatEntries)
	}
	rangeCounts := make(map[int64]int64, len(rangeStats))
	for id, stats := range rangeStats {
		rangeCounts[id] = currentConnCountForProtocolDatagrams(rangeProtocols[id], stats.ActiveConns, stats.UDPNatEntries, stats.ICMPNatEntries)
	}
	egressNATCounts := make(map[int64]int64, len(egressNATStats))
	for id, stats := range egressNATStats {
		egressNATCounts[id] = currentConnCountForProtocolDatagrams(egressNATProtocols[id], stats.ActiveConns, stats.UDPNatEntries, stats.ICMPNatEntries)
	}

	resp := CurrentConnsResponse{
		Rules:      make([]RuleCurrentConnsReport, 0, len(ruleCounts)),
		Ranges:     make([]RangeCurrentConnsReport, 0, len(rangeCounts)),
		Sites:      make([]SiteCurrentConnsReport, 0, len(siteCounts)),
		EgressNATs: make([]EgressNATCurrentConnsReport, 0, len(egressNATCounts)),
	}
	for id, current := range ruleCounts {
		resp.Rules = append(resp.Rules, RuleCurrentConnsReport{RuleID: id, CurrentConns: current})
	}
	for id, current := range rangeCounts {
		resp.Ranges = append(resp.Ranges, RangeCurrentConnsReport{RangeID: id, CurrentConns: current})
	}
	for id, current := range siteCounts {
		resp.Sites = append(resp.Sites, SiteCurrentConnsReport{SiteID: id, CurrentConns: current})
	}
	for id, current := range egressNATCounts {
		resp.EgressNATs = append(resp.EgressNATs, EgressNATCurrentConnsReport{EgressNATID: id, CurrentConns: current})
	}

	sort.Slice(resp.Rules, func(i, j int) bool { return resp.Rules[i].RuleID < resp.Rules[j].RuleID })
	sort.Slice(resp.Ranges, func(i, j int) bool { return resp.Ranges[i].RangeID < resp.Ranges[j].RangeID })
	sort.Slice(resp.Sites, func(i, j int) bool { return resp.Sites[i].SiteID < resp.Sites[j].SiteID })
	sort.Slice(resp.EgressNATs, func(i, j int) bool { return resp.EgressNATs[i].EgressNATID < resp.EgressNATs[j].EgressNATID })
	writeJSON(w, http.StatusOK, resp)
}
