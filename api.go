package main

import (
	"database/sql"
	"embed"
	"encoding/json"
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
	rules, err := dbGetRules(db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var statuses []RuleStatus
	pm.mu.Lock()
	runningRules := make(map[int64]bool)
	failedRules := make(map[int64]bool)
	for _, wi := range pm.ruleWorkers {
		if wi.running {
			for _, r := range wi.rules {
				if wi.failedRules != nil && wi.failedRules[r.ID] {
					failedRules[r.ID] = true
					continue
				}
				runningRules[r.ID] = true
			}
		}
	}
	pm.mu.Unlock()
	for _, rule := range rules {
		status := "stopped"
		if failedRules[rule.ID] {
			status = "error"
		} else if runningRules[rule.ID] {
			status = "running"
		}
		statuses = append(statuses, RuleStatus{Rule: rule, Status: status})
	}
	if statuses == nil {
		statuses = []RuleStatus{}
	}
	writeJSON(w, http.StatusOK, statuses)
}

func handleAddRule(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	var rule Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if rule.InIP == "" || rule.InPort == 0 || rule.OutIP == "" || rule.OutPort == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "in_ip, in_port, out_ip, out_port are required"})
		return
	}
	if rule.Protocol == "" {
		rule.Protocol = "tcp"
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "tcp+udp" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "protocol must be tcp, udp, or tcp+udp"})
		return
	}

	rule.Enabled = true
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

	if rule.ID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}
	if rule.InIP == "" || rule.InPort == 0 || rule.OutIP == "" || rule.OutPort == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "in_ip, in_port, out_ip, out_port are required"})
		return
	}
	if rule.Protocol == "" {
		rule.Protocol = "tcp"
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "tcp+udp" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "protocol must be tcp, udp, or tcp+udp"})
		return
	}

	existing, err := dbGetRule(db, rule.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rule.Enabled = existing.Enabled

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
		statuses = append(statuses, PortRangeStatus{PortRange: pr, Status: status})
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
	pm.mu.Lock()
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
				view.Rules = append(view.Rules, RuleStatus{Rule: r, Status: status})
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
				view.Ranges = append(view.Ranges, PortRangeStatus{PortRange: pr, Status: status})
			}
			if view.Status == "stopped" && len(s.ranges) > 0 && len(s.failedRanges) == len(s.ranges) {
				view.Status = "error"
			}
		case "shared":
			view.SiteCount = enabledSites
		}

		workers = append(workers, view)
	}

	kindOrder := map[string]int{"rule": 0, "range": 1, "shared": 2}
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
