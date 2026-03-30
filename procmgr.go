package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

type WorkerInfo struct {
	workerIndex    int
	kind           string
	rules          []Rule
	ranges         []PortRange
	failedRules    map[int64]bool
	failedRanges   map[int64]bool
	ruleStats      map[int64]RuleStatsReport
	rangeStats     map[int64]RangeStatsReport
	siteStatsMap   []SiteStatsReport
	process        *os.Process
	conn           net.Conn
	running        bool
	errored        bool
	draining       bool
	activeRuleIDs  []int64
	activeRangeIDs []int64
	ruleRetryCount int
	ruleNextRetry  time.Time
	binaryHash     string
	lastStart      time.Time
	writeMu        sync.Mutex
	waitCh         chan struct{} // closed when process exits
}

const (
	workerKindRule   = "rule"
	workerKindRange  = "range"
	workerKindShared = "shared"

	ruleRetryBaseDelay = 1 * time.Second
	ruleRetryMaxDelay  = 1 * time.Minute
)

func nextRuleRetryDelay(retryCount int) time.Duration {
	if retryCount <= 1 {
		return ruleRetryBaseDelay
	}
	delay := ruleRetryBaseDelay
	for i := 1; i < retryCount; i++ {
		if delay >= ruleRetryMaxDelay {
			return ruleRetryMaxDelay
		}
		delay *= 2
	}
	if delay > ruleRetryMaxDelay {
		return ruleRetryMaxDelay
	}
	return delay
}

type ProcessManager struct {
	ruleWorkers     map[int]*WorkerInfo
	rangeWorkers    map[int]*WorkerInfo
	sharedProxy     *WorkerInfo
	drainingWorkers []*WorkerInfo
	mu              sync.Mutex
	redistributeMu  sync.Mutex // serializes redistributeWorkers calls
	db              *sql.DB
	cfg             *Config
	sockPath        string
	listener        net.Listener
	binaryHash      string
	ready           bool
	rulePlans       map[int64]ruleDataplanePlan
	rangePlans      map[int64]rangeDataplanePlan
	kernelRuntime   kernelRuleRuntime
	kernelRules     map[int64]bool
	kernelRanges    map[int64]bool
}

func newProcessManager(db *sql.DB, cfg *Config, binaryHash string) (*ProcessManager, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("get executable path: %w", err)
	}
	exeDir := filepath.Dir(exe)
	sockPath := filepath.Join(exeDir, "forward-ctl.sock")
	os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("listen unix socket: %w", err)
	}

	pm := &ProcessManager{
		ruleWorkers:   make(map[int]*WorkerInfo),
		rangeWorkers:  make(map[int]*WorkerInfo),
		db:            db,
		cfg:           cfg,
		sockPath:      sockPath,
		listener:      ln,
		binaryHash:    binaryHash,
		rulePlans:     make(map[int64]ruleDataplanePlan),
		rangePlans:    make(map[int64]rangeDataplanePlan),
		kernelRuntime: newKernelRuleRuntime(),
		kernelRules:   make(map[int64]bool),
		kernelRanges:  make(map[int64]bool),
	}

	if pm.kernelRuntime != nil {
		available, reason := pm.kernelRuntime.Available()
		if available {
			log.Printf("kernel dataplane ready (default_engine=%s): %s", cfg.DefaultEngine, reason)
		} else {
			log.Printf("kernel dataplane unavailable (default_engine=%s): %s", cfg.DefaultEngine, reason)
		}
	}

	go pm.monitorLoop()

	return pm, nil
}

func (pm *ProcessManager) startAccepting() {
	go pm.acceptLoop()
}

func (pm *ProcessManager) acceptLoop() {
	for {
		conn, err := pm.listener.Accept()
		if err != nil {
			return
		}
		go pm.handleWorkerConn(conn)
	}
}

func (pm *ProcessManager) handleWorkerConn(conn net.Conn) {
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	if !scanner.Scan() {
		conn.Close()
		return
	}

	var msg IPCMessage
	if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
		conn.Close()
		return
	}

	switch msg.Type {
	case "register":
		pm.handleRuleWorkerConn(conn, scanner, msg.WorkerIndex, msg.BinaryHash)
	case "register_range":
		pm.handleRangeWorkerConn(conn, scanner, msg.WorkerIndex, msg.BinaryHash)
	case "register_proxy":
		pm.handleSharedProxyConn(conn, scanner, msg.BinaryHash)
	default:
		conn.Close()
	}
}

func (pm *ProcessManager) handleRuleWorkerConn(conn net.Conn, scanner *bufio.Scanner, workerIndex int, workerHash string) {
	pm.mu.Lock()
	wi, ok := pm.ruleWorkers[workerIndex]
	if !ok {
		pm.mu.Unlock()
		sendStop(conn)
		conn.Close()
		return
	}
	wi.conn = conn
	wi.running = false
	wi.errored = false
	wi.ruleRetryCount = 0
	wi.ruleNextRetry = time.Time{}
	wi.binaryHash = workerHash
	rules := append([]Rule(nil), wi.rules...)
	binHash := pm.binaryHash
	pm.mu.Unlock()

	wi.writeMu.Lock()
	writeIPC(conn, IPCMessage{Type: "config", Rules: rules, BinaryHash: binHash})
	wi.writeMu.Unlock()

	// target tracks where stats/status go; starts as wi, may switch to draining entry
	target := wi

	for scanner.Scan() {
		var status IPCMessage
		if err := json.Unmarshal(scanner.Bytes(), &status); err != nil {
			continue
		}
		if status.Type == "status" {
			startNewWorker := false
			pm.mu.Lock()
			if status.Status == "draining" && target == wi {
				// Move to draining list, free up the worker slot
				// Deep-copy ruleStats so draining and new worker have independent maps
				copiedStats := make(map[int64]RuleStatsReport, len(wi.ruleStats))
				for id, s := range wi.ruleStats {
					copiedStats[id] = s
				}
				dw := &WorkerInfo{
					workerIndex:   workerIndex,
					kind:          workerKindRule,
					conn:          conn,
					draining:      true,
					binaryHash:    workerHash,
					activeRuleIDs: status.ActiveRuleIDs,
					rules:         rules,
					ruleStats:     copiedStats,
					process:       wi.process,
					waitCh:        wi.waitCh,
					lastStart:     time.Now(),
				}
				pm.drainingWorkers = append(pm.drainingWorkers, dw)
				wi.conn = nil
				wi.running = false
				wi.process = nil
				wi.waitCh = nil
				wi.ruleStats = make(map[int64]RuleStatsReport)
				wi.lastStart = time.Now()
				target = dw
				startNewWorker = len(wi.rules) > 0
				log.Printf("worker[%d]: moved to draining list", workerIndex)
			} else {
				target.running = status.Status == "running"
				target.draining = status.Status == "draining"
				target.activeRuleIDs = append([]int64(nil), status.ActiveRuleIDs...)
				if status.Status == "error" {
					target.errored = true
					if target == wi {
						target.ruleRetryCount++
						target.ruleNextRetry = time.Now().Add(nextRuleRetryDelay(target.ruleRetryCount))
					}
				} else {
					target.errored = false
					if target == wi {
						target.ruleNextRetry = time.Time{}
						if status.Status == "running" || status.Status == "idle" {
							target.ruleRetryCount = 0
						}
					}
				}
				target.failedRules = make(map[int64]bool)
				for _, id := range status.FailedRuleIDs {
					target.failedRules[id] = true
				}
			}
			pm.mu.Unlock()
			if startNewWorker {
				log.Printf("worker[%d]: starting replacement worker", workerIndex)
				if err := pm.startRuleWorker(workerIndex); err != nil {
					log.Printf("start replacement rule worker[%d]: %v", workerIndex, err)
				}
			}
			if status.Status == "error" {
				log.Printf("worker[%d] error: %s", workerIndex, status.Error)
			}
		} else if status.Type == "stats" {
			pm.mu.Lock()
			if target.ruleStats == nil {
				target.ruleStats = make(map[int64]RuleStatsReport)
			}
			for _, s := range status.Stats {
				target.ruleStats[s.RuleID] = s
			}
			pm.mu.Unlock()
		}
	}

	pm.mu.Lock()
	if target == wi {
		if wi2, ok2 := pm.ruleWorkers[workerIndex]; ok2 && wi2 == wi {
			wi2.conn = nil
			wi2.running = false
		}
	} else {
		// Remove from draining list
		for i, dw := range pm.drainingWorkers {
			if dw == target {
				pm.drainingWorkers = append(pm.drainingWorkers[:i], pm.drainingWorkers[i+1:]...)
				break
			}
		}
	}
	pm.mu.Unlock()
}

func (pm *ProcessManager) handleSharedProxyConn(conn net.Conn, scanner *bufio.Scanner, workerHash string) {
	sites, err := dbGetSites(pm.db)
	if err != nil {
		conn.Close()
		return
	}

	var enabledSites []Site
	for _, s := range sites {
		if s.Enabled {
			enabledSites = append(enabledSites, s)
		}
	}

	pm.mu.Lock()
	proxy := pm.sharedProxy
	if proxy != nil {
		proxy.conn = conn
		proxy.running = false
		proxy.errored = false
		proxy.binaryHash = workerHash
	}
	pm.mu.Unlock()
	if proxy == nil {
		sendStop(conn)
		conn.Close()
		return
	}

	pm.sendSitesConfig(proxy, enabledSites)

	target := proxy

	for scanner.Scan() {
		var status IPCMessage
		if err := json.Unmarshal(scanner.Bytes(), &status); err != nil {
			continue
		}
		if status.Type == "status" {
			startNewProxy := false
			pm.mu.Lock()
			if status.Status == "draining" && target == proxy {
				// Copy siteStatsMap so draining and new proxy have independent slices
				copiedStats := make([]SiteStatsReport, len(proxy.siteStatsMap))
				copy(copiedStats, proxy.siteStatsMap)
				dw := &WorkerInfo{
					kind:         workerKindShared,
					conn:         conn,
					draining:     true,
					binaryHash:   workerHash,
					siteStatsMap: copiedStats,
					process:      proxy.process,
					waitCh:       proxy.waitCh,
					lastStart:    time.Now(),
				}
				pm.drainingWorkers = append(pm.drainingWorkers, dw)
				proxy.conn = nil
				proxy.running = false
				proxy.process = nil
				proxy.waitCh = nil
				proxy.siteStatsMap = nil
				proxy.lastStart = time.Now()
				target = dw
				startNewProxy = true
				log.Println("shared proxy: moved to draining list")
			} else {
				target.running = status.Status == "running"
				target.draining = status.Status == "draining"
				if status.Status == "error" {
					target.errored = true
				}
			}
			pm.mu.Unlock()
			if startNewProxy {
				log.Println("shared proxy: starting replacement proxy")
				pm.startSharedProxy()
			}
			if status.Status == "error" {
				log.Printf("shared proxy error: %s", status.Error)
			}
		} else if status.Type == "site_stats" {
			pm.mu.Lock()
			target.siteStatsMap = status.SiteStats
			pm.mu.Unlock()
		}
	}

	pm.mu.Lock()
	if target == proxy {
		if pm.sharedProxy != nil {
			pm.sharedProxy.conn = nil
			pm.sharedProxy.running = false
		}
	} else {
		for i, dw := range pm.drainingWorkers {
			if dw == target {
				pm.drainingWorkers = append(pm.drainingWorkers[:i], pm.drainingWorkers[i+1:]...)
				break
			}
		}
	}
	pm.mu.Unlock()
}

func (pm *ProcessManager) redistributeWorkers() {
	pm.redistributeMu.Lock()
	defer pm.redistributeMu.Unlock()

	rules, err := dbGetRules(pm.db)
	if err != nil {
		log.Printf("load rules: %v", err)
		return
	}
	ranges, err := dbGetRanges(pm.db)
	if err != nil {
		log.Printf("load ranges: %v", err)
		return
	}

	planner := newRuleDataplanePlanner(pm.kernelRuntime, pm.cfg.DefaultEngine)
	candidates, rulePlans, rangePlans := buildKernelCandidateRules(rules, ranges, planner)
	applyKernelOwnerConstraints(candidates, rulePlans, rangePlans)

	activeKernelCandidates := filterActiveKernelCandidates(candidates, rulePlans, rangePlans)
	if pm.kernelRuntime != nil {
		for {
			results, err := pm.kernelRuntime.Reconcile(kernelCandidateRules(activeKernelCandidates))
			if len(activeKernelCandidates) == 0 {
				break
			}

			ownerFailures := collectKernelOwnerFailures(activeKernelCandidates, results, err)
			if len(ownerFailures) == 0 {
				break
			}
			for owner, reason := range ownerFailures {
				applyKernelOwnerFallback(owner, reason, rulePlans, rangePlans)
			}
			activeKernelCandidates = filterActiveKernelCandidates(candidates, rulePlans, rangePlans)
		}
	}

	logRuleDataplanePlans(rules, rulePlans, pm.cfg.DefaultEngine)
	logRangeDataplanePlans(ranges, rangePlans, pm.cfg.DefaultEngine)
	log.Printf(
		"kernel dataplane planner summary: default_engine=%s enabled_rules=%d enabled_ranges=%d kernel_target_rules=%d kernel_target_ranges=%d kernel_target_entries=%d",
		pm.cfg.DefaultEngine,
		countEnabledRules(rules),
		countEnabledRanges(ranges),
		countKernelRulePlans(rules, rulePlans),
		countKernelRangePlans(ranges, rangePlans),
		len(filterActiveKernelCandidates(candidates, rulePlans, rangePlans)),
	)

	kernelAppliedRules := make(map[int64]bool)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if plan, ok := rulePlans[rule.ID]; ok && plan.EffectiveEngine == ruleEngineKernel {
			kernelAppliedRules[rule.ID] = true
		}
	}
	kernelAppliedRanges := make(map[int64]bool)
	for _, pr := range ranges {
		if !pr.Enabled {
			continue
		}
		if plan, ok := rangePlans[pr.ID]; ok && plan.EffectiveEngine == ruleEngineKernel {
			kernelAppliedRanges[pr.ID] = true
		}
	}

	pm.mu.Lock()
	pm.rulePlans = rulePlans
	pm.rangePlans = rangePlans
	pm.kernelRules = kernelAppliedRules
	pm.kernelRanges = kernelAppliedRanges
	pm.mu.Unlock()

	var enabledRules []Rule
	for _, r := range rules {
		if r.Enabled {
			if plan, ok := rulePlans[r.ID]; ok && plan.EffectiveEngine == ruleEngineKernel {
				continue
			}
			enabledRules = append(enabledRules, r)
		}
	}
	sort.Slice(enabledRules, func(i, j int) bool { return enabledRules[i].ID < enabledRules[j].ID })
	var enabledRanges []PortRange
	for _, r := range ranges {
		if r.Enabled {
			if plan, ok := rangePlans[r.ID]; ok && plan.EffectiveEngine == ruleEngineKernel {
				continue
			}
			enabledRanges = append(enabledRanges, r)
		}
	}
	sort.Slice(enabledRanges, func(i, j int) bool { return enabledRanges[i].ID < enabledRanges[j].ID })
	// Auto-configure transparent proxy routing BEFORE dispatching config to workers,
	// so iptables rules are in place before any worker starts using IP_TRANSPARENT sockets.
	pm.updateTransparentRouting(enabledRules, enabledRanges)

	pm.updateSharedProxy()

	totalWorkers := pm.cfg.MaxWorkers
	if totalWorkers <= 0 {
		totalWorkers = runtime.NumCPU()
	}
	if totalWorkers < 3 {
		totalWorkers = 3
	}
	ruleCount, rangeCount := computeWorkerCounts(totalWorkers)
	if len(enabledRules) == 0 {
		ruleCount = 0
	}
	if len(enabledRanges) == 0 {
		rangeCount = 0
	}
	ruleAssignments := make([][]Rule, ruleCount)
	if ruleCount > 0 {
		for i, r := range enabledRules {
			idx := i % ruleCount
			ruleAssignments[idx] = append(ruleAssignments[idx], r)
		}
	}

	rangeAssignments := make([][]PortRange, rangeCount)
	if rangeCount > 0 {
		for i, pr := range enabledRanges {
			idx := i % rangeCount
			rangeAssignments[idx] = append(rangeAssignments[idx], pr)
		}
	}

	pm.applyRuleAssignments(ruleAssignments)
	pm.applyRangeAssignments(rangeAssignments)
}

func countEnabledRules(rules []Rule) int {
	count := 0
	for _, rule := range rules {
		if rule.Enabled {
			count++
		}
	}
	return count
}

func countEnabledRanges(ranges []PortRange) int {
	count := 0
	for _, pr := range ranges {
		if pr.Enabled {
			count++
		}
	}
	return count
}

type kernelCandidateOwner struct {
	kind string
	id   int64
}

type kernelCandidateRule struct {
	owner kernelCandidateOwner
	rule  Rule
}

func kernelProtocolVariants(protocol string) []string {
	switch protocol {
	case "tcp":
		return []string{"tcp"}
	case "udp":
		return []string{"udp"}
	case "tcp+udp":
		return []string{"tcp", "udp"}
	default:
		return nil
	}
}

func allocateSyntheticKernelRuleID(nextID *int64, used map[int64]struct{}) (int64, error) {
	limit := int64(^uint32(0))
	for {
		if *nextID <= 0 {
			*nextID = 1
		}
		if *nextID > limit {
			return 0, fmt.Errorf("kernel dataplane synthetic rule ids exhausted uint32 range")
		}
		id := *nextID
		*nextID++
		if _, exists := used[id]; exists {
			continue
		}
		used[id] = struct{}{}
		return id, nil
	}
}

func aggregateKernelOwnerPlan(preferred string, entryPlans []ruleDataplanePlan) ruleDataplanePlan {
	plan := ruleDataplanePlan{
		PreferredEngine: preferred,
		EffectiveEngine: ruleEngineUserspace,
	}
	if len(entryPlans) == 0 {
		return plan
	}

	allKernel := true
	allEligible := true
	for _, item := range entryPlans {
		if !item.KernelEligible {
			allEligible = false
			if plan.KernelReason == "" {
				plan.KernelReason = item.KernelReason
			}
		}
		if item.EffectiveEngine != ruleEngineKernel {
			allKernel = false
			if plan.FallbackReason == "" && item.FallbackReason != "" {
				plan.FallbackReason = item.FallbackReason
			}
		}
	}
	plan.KernelEligible = allEligible
	if allKernel {
		plan.EffectiveEngine = ruleEngineKernel
	}
	return plan
}

func kernelRulesCapacityReason(currentEntries int, neededEntries int) string {
	if neededEntries > kernelRulesMapLimit {
		return fmt.Sprintf("kernel rules map capacity %d is lower than requested entries %d", kernelRulesMapLimit, neededEntries)
	}
	if currentEntries >= kernelRulesMapLimit {
		return fmt.Sprintf("kernel rules map capacity %d is already exhausted", kernelRulesMapLimit)
	}
	return fmt.Sprintf(
		"kernel rules map capacity %d would be exceeded by reserving %d more entries (currently reserved %d)",
		kernelRulesMapLimit,
		neededEntries,
		currentEntries,
	)
}

func sampleKernelRangePlan(pr PortRange, variants []string, planner *ruleDataplanePlanner, preferred string) rangeDataplanePlan {
	entryPlans := make([]ruleDataplanePlan, 0, len(variants))
	for _, proto := range variants {
		entryPlans = append(entryPlans, planner.Plan(Rule{
			ID:               1,
			InInterface:      pr.InInterface,
			InIP:             pr.InIP,
			InPort:           pr.StartPort,
			OutInterface:     pr.OutInterface,
			OutIP:            pr.OutIP,
			OutPort:          pr.OutStartPort,
			Protocol:         proto,
			Remark:           pr.Remark,
			Tag:              pr.Tag,
			Enabled:          pr.Enabled,
			Transparent:      pr.Transparent,
			EnginePreference: ruleEngineAuto,
		}))
	}
	return aggregateKernelOwnerPlan(preferred, entryPlans)
}

func applyKernelOwnerFallback(owner kernelCandidateOwner, reason string, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan) {
	if owner.kind == workerKindRule {
		plan := rulePlans[owner.id]
		plan.EffectiveEngine = ruleEngineUserspace
		if plan.FallbackReason == "" {
			plan.FallbackReason = reason
		}
		rulePlans[owner.id] = plan
		return
	}

	plan := rangePlans[owner.id]
	plan.EffectiveEngine = ruleEngineUserspace
	if plan.FallbackReason == "" {
		plan.FallbackReason = reason
	}
	rangePlans[owner.id] = plan
}

func kernelOwnerEffectiveEngine(owner kernelCandidateOwner, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan) string {
	if owner.kind == workerKindRule {
		return rulePlans[owner.id].EffectiveEngine
	}
	return rangePlans[owner.id].EffectiveEngine
}

func buildKernelCandidateRules(rules []Rule, ranges []PortRange, planner *ruleDataplanePlanner) ([]kernelCandidateRule, map[int64]ruleDataplanePlan, map[int64]rangeDataplanePlan) {
	rulePlans := make(map[int64]ruleDataplanePlan, len(rules))
	rangePlans := make(map[int64]rangeDataplanePlan, len(ranges))

	maxRuleID := int64(0)
	usedIDs := make(map[int64]struct{}, len(rules))
	for _, rule := range rules {
		if rule.ID > maxRuleID {
			maxRuleID = rule.ID
		}
		if rule.ID > 0 {
			usedIDs[rule.ID] = struct{}{}
		}
	}
	nextSyntheticID := maxRuleID + 1

	candidates := make([]kernelCandidateRule, 0)
	reservedKernelEntries := 0

	for _, rule := range rules {
		owner := kernelCandidateOwner{kind: workerKindRule, id: rule.ID}
		variants := kernelProtocolVariants(rule.Protocol)
		if len(variants) == 0 {
			plan := planner.Plan(rule)
			rulePlans[rule.ID] = plan
			continue
		}

		entryPlans := make([]ruleDataplanePlan, 0, len(variants))
		entryCandidates := make([]kernelCandidateRule, 0, len(variants))
		for idx, proto := range variants {
			item := rule
			item.Protocol = proto
			if idx > 0 {
				id, err := allocateSyntheticKernelRuleID(&nextSyntheticID, usedIDs)
				if err != nil {
					entryPlans = append(entryPlans, ruleDataplanePlan{
						PreferredEngine: planner.resolvePreferredEngine(rule.EnginePreference),
						EffectiveEngine: ruleEngineUserspace,
						FallbackReason:  err.Error(),
					})
					continue
				}
				item.ID = id
			}
			entryPlans = append(entryPlans, planner.Plan(item))
			entryCandidates = append(entryCandidates, kernelCandidateRule{owner: owner, rule: item})
		}

		plan := aggregateKernelOwnerPlan(planner.resolvePreferredEngine(rule.EnginePreference), entryPlans)
		if rule.Enabled && plan.EffectiveEngine == ruleEngineKernel {
			neededEntries := len(entryCandidates)
			if reservedKernelEntries+neededEntries > kernelRulesMapLimit {
				plan.EffectiveEngine = ruleEngineUserspace
				if plan.FallbackReason == "" {
					plan.FallbackReason = kernelRulesCapacityReason(reservedKernelEntries, neededEntries)
				}
			} else {
				candidates = append(candidates, entryCandidates...)
				reservedKernelEntries += neededEntries
			}
		}
		rulePlans[rule.ID] = plan
	}

	rangePreferred := planner.resolvePreferredEngine("")
	for _, pr := range ranges {
		owner := kernelCandidateOwner{kind: workerKindRange, id: pr.ID}
		variants := kernelProtocolVariants(pr.Protocol)
		if len(variants) == 0 {
			rangePlans[pr.ID] = rangeDataplanePlan{
				PreferredEngine: rangePreferred,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  "kernel dataplane currently supports only transparent single-protocol TCP/UDP rules",
			}
			continue
		}

		totalEntries := (pr.EndPort - pr.StartPort + 1) * len(variants)
		if pr.Enabled && reservedKernelEntries+totalEntries > kernelRulesMapLimit {
			plan := sampleKernelRangePlan(pr, variants, planner, rangePreferred)
			if plan.EffectiveEngine == ruleEngineKernel {
				plan.EffectiveEngine = ruleEngineUserspace
				if plan.FallbackReason == "" {
					plan.FallbackReason = kernelRulesCapacityReason(reservedKernelEntries, totalEntries)
				}
			}
			rangePlans[pr.ID] = plan
			continue
		}
		entryPlans := make([]ruleDataplanePlan, 0, totalEntries)
		entryCandidates := make([]kernelCandidateRule, 0, totalEntries)
		allExpanded := true
		for port := pr.StartPort; port <= pr.EndPort; port++ {
			outPort := pr.OutStartPort + (port - pr.StartPort)
			for _, proto := range variants {
				id, err := allocateSyntheticKernelRuleID(&nextSyntheticID, usedIDs)
				if err != nil {
					entryPlans = append(entryPlans, ruleDataplanePlan{
						PreferredEngine: rangePreferred,
						EffectiveEngine: ruleEngineUserspace,
						FallbackReason:  err.Error(),
					})
					allExpanded = false
					continue
				}

				item := Rule{
					ID:               id,
					InInterface:      pr.InInterface,
					InIP:             pr.InIP,
					InPort:           port,
					OutInterface:     pr.OutInterface,
					OutIP:            pr.OutIP,
					OutPort:          outPort,
					Protocol:         proto,
					Remark:           pr.Remark,
					Tag:              pr.Tag,
					Enabled:          pr.Enabled,
					Transparent:      pr.Transparent,
					EnginePreference: ruleEngineAuto,
				}
				entryPlans = append(entryPlans, planner.Plan(item))
				entryCandidates = append(entryCandidates, kernelCandidateRule{owner: owner, rule: item})
			}
		}

		plan := aggregateKernelOwnerPlan(rangePreferred, entryPlans)
		if !allExpanded && plan.FallbackReason == "" {
			plan.FallbackReason = "kernel dataplane synthetic rule expansion failed"
		}
		rangePlans[pr.ID] = plan
		if pr.Enabled && plan.EffectiveEngine == ruleEngineKernel {
			candidates = append(candidates, entryCandidates...)
			reservedKernelEntries += len(entryCandidates)
		}
	}

	return candidates, rulePlans, rangePlans
}

func applyKernelOwnerConstraints(candidates []kernelCandidateRule, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan) {
	type backendKey struct {
		OutIP    string
		OutPort  int
		Protocol string
	}

	grouped := make(map[backendKey]map[kernelCandidateOwner]struct{})
	for _, candidate := range candidates {
		if kernelOwnerEffectiveEngine(candidate.owner, rulePlans, rangePlans) != ruleEngineKernel {
			continue
		}
		key := backendKey{
			OutIP:    candidate.rule.OutIP,
			OutPort:  candidate.rule.OutPort,
			Protocol: candidate.rule.Protocol,
		}
		if grouped[key] == nil {
			grouped[key] = make(map[kernelCandidateOwner]struct{})
		}
		grouped[key][candidate.owner] = struct{}{}
	}

	for _, owners := range grouped {
		if len(owners) < 2 {
			continue
		}
		for owner := range owners {
			applyKernelOwnerFallback(owner, "kernel dataplane requires a unique backend endpoint per active protocol binding", rulePlans, rangePlans)
		}
	}
}

func filterActiveKernelCandidates(candidates []kernelCandidateRule, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan) []kernelCandidateRule {
	out := make([]kernelCandidateRule, 0, len(candidates))
	for _, candidate := range candidates {
		if kernelOwnerEffectiveEngine(candidate.owner, rulePlans, rangePlans) == ruleEngineKernel {
			out = append(out, candidate)
		}
	}
	return out
}

func kernelCandidateRules(candidates []kernelCandidateRule) []Rule {
	out := make([]Rule, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.rule)
	}
	return out
}

func collectKernelOwnerFailures(candidates []kernelCandidateRule, results map[int64]kernelRuleApplyResult, err error) map[kernelCandidateOwner]string {
	failures := make(map[kernelCandidateOwner]string)
	if err != nil {
		for _, candidate := range candidates {
			if _, exists := failures[candidate.owner]; !exists {
				failures[candidate.owner] = err.Error()
			}
		}
		return failures
	}

	for _, candidate := range candidates {
		result, ok := results[candidate.rule.ID]
		if ok && result.Running {
			continue
		}

		reason := "kernel dataplane did not report a running state"
		if ok && result.Error != "" {
			reason = result.Error
		}
		if _, exists := failures[candidate.owner]; !exists {
			failures[candidate.owner] = reason
		}
	}
	return failures
}

func countKernelRulePlans(rules []Rule, plans map[int64]ruleDataplanePlan) int {
	count := 0
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if plan, ok := plans[rule.ID]; ok && plan.EffectiveEngine == ruleEngineKernel {
			count++
		}
	}
	return count
}

func countKernelRangePlans(ranges []PortRange, plans map[int64]rangeDataplanePlan) int {
	count := 0
	for _, pr := range ranges {
		if !pr.Enabled {
			continue
		}
		if plan, ok := plans[pr.ID]; ok && plan.EffectiveEngine == ruleEngineKernel {
			count++
		}
	}
	return count
}

func logRangeDataplanePlans(ranges []PortRange, plans map[int64]rangeDataplanePlan, defaultEngine string) {
	if len(ranges) == 0 || len(plans) == 0 {
		return
	}

	ordered := make([]PortRange, 0, len(ranges))
	for _, pr := range ranges {
		if pr.Enabled {
			ordered = append(ordered, pr)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	for _, pr := range ordered {
		plan, ok := plans[pr.ID]
		if !ok {
			continue
		}
		shouldLog := plan.EffectiveEngine == ruleEngineKernel || plan.KernelEligible || plan.KernelReason != "" || plan.FallbackReason != ""
		if !shouldLog {
			continue
		}

		if plan.EffectiveEngine == ruleEngineKernel {
			log.Printf("kernel dataplane range plan: range=%d preferred=%s effective=%s eligible=%t reason=%q in=%s:%d-%d out=%s:%d transparent=%t",
				pr.ID, plan.PreferredEngine, plan.EffectiveEngine, plan.KernelEligible, plan.KernelReason,
				pr.InIP, pr.StartPort, pr.EndPort, pr.OutIP, pr.OutStartPort, pr.Transparent)
			continue
		}

		log.Printf("kernel dataplane range fallback: range=%d default_engine=%s preferred=%s effective=%s eligible=%t kernel_reason=%q fallback=%q in=%s:%d-%d out=%s:%d transparent=%t",
			pr.ID, defaultEngine, plan.PreferredEngine, plan.EffectiveEngine, plan.KernelEligible, plan.KernelReason, plan.FallbackReason,
			pr.InIP, pr.StartPort, pr.EndPort, pr.OutIP, pr.OutStartPort, pr.Transparent)
	}
}

func logRuleDataplanePlans(rules []Rule, plans map[int64]ruleDataplanePlan, defaultEngine string) {
	if len(rules) == 0 || len(plans) == 0 {
		return
	}

	ordered := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if rule.Enabled {
			ordered = append(ordered, rule)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	for _, rule := range ordered {
		plan, ok := plans[rule.ID]
		if !ok {
			continue
		}
		shouldLog := plan.EffectiveEngine == ruleEngineKernel || plan.KernelEligible || plan.KernelReason != "" || plan.FallbackReason != ""
		if !shouldLog {
			continue
		}

		if plan.EffectiveEngine == ruleEngineKernel {
			log.Printf("kernel dataplane plan: rule=%d preferred=%s effective=%s eligible=%t reason=%q in=%s:%d out=%s:%d transparent=%t",
				rule.ID, plan.PreferredEngine, plan.EffectiveEngine, plan.KernelEligible, plan.KernelReason,
				rule.InIP, rule.InPort, rule.OutIP, rule.OutPort, rule.Transparent)
			continue
		}

		log.Printf("kernel dataplane fallback: rule=%d default_engine=%s preferred=%s effective=%s eligible=%t kernel_reason=%q fallback=%q in=%s:%d out=%s:%d transparent=%t",
			rule.ID, defaultEngine, plan.PreferredEngine, plan.EffectiveEngine, plan.KernelEligible, plan.KernelReason, plan.FallbackReason,
			rule.InIP, rule.InPort, rule.OutIP, rule.OutPort, rule.Transparent)
	}
}

func computeWorkerCounts(total int) (int, int) {
	if total < 3 {
		total = 3
	}
	// Reserve one slot each: rule worker, range worker, shared proxy.
	ruleCount := 1
	rangeCount := 1

	remaining := total - 3
	if remaining < 0 {
		remaining = 0
	}

	// Extra workers alternate: rule > range > rule ...
	ruleCount += (remaining + 1) / 2
	rangeCount += remaining / 2
	return ruleCount, rangeCount
}

func (pm *ProcessManager) applyRuleAssignments(assignments [][]Rule) {
	desired := len(assignments)
	toStart := make(map[int]struct{})
	var toStop []*WorkerInfo
	var toUpdate []*WorkerInfo

	pm.mu.Lock()
	for idx, wi := range pm.ruleWorkers {
		if idx >= desired {
			delete(pm.ruleWorkers, idx)
			toStop = append(toStop, wi)
		}
	}
	for idx := 0; idx < desired; idx++ {
		rules := assignments[idx]
		wi, ok := pm.ruleWorkers[idx]
		if len(rules) == 0 {
			// No rules for this slot — stop existing worker if any
			if ok {
				delete(pm.ruleWorkers, idx)
				toStop = append(toStop, wi)
			}
			continue
		}
		if !ok {
			wi = &WorkerInfo{
				workerIndex: idx,
				kind:        workerKindRule,
				rules:       rules,
				failedRules: make(map[int64]bool),
				ruleStats:   make(map[int64]RuleStatsReport),
				lastStart:   time.Now(),
			}
			pm.ruleWorkers[idx] = wi
			if pm.ready {
				toStart[idx] = struct{}{}
			}
			continue
		}
		if !rulesEqual(wi.rules, rules) {
			wi.rules = rules
			wi.failedRules = make(map[int64]bool)
			wi.ruleStats = make(map[int64]RuleStatsReport)
			wi.errored = false
			wi.ruleRetryCount = 0
			wi.ruleNextRetry = time.Time{}
			toUpdate = append(toUpdate, wi)
		}
		if wi.process == nil && wi.conn == nil {
			toStart[idx] = struct{}{}
		}
	}
	pm.mu.Unlock()

	for _, wi := range toStop {
		killWorkerInfo(wi)
	}
	for idx := range toStart {
		if err := pm.startRuleWorker(idx); err != nil {
			log.Printf("start rule worker[%d]: %v", idx, err)
		}
	}
	for _, wi := range toUpdate {
		pm.sendRuleConfig(wi)
	}
}

func (pm *ProcessManager) applyRangeAssignments(assignments [][]PortRange) {
	desired := len(assignments)
	toStart := make(map[int]struct{})
	var toStop []*WorkerInfo
	var toUpdate []*WorkerInfo

	pm.mu.Lock()
	for idx, wi := range pm.rangeWorkers {
		if idx >= desired {
			delete(pm.rangeWorkers, idx)
			toStop = append(toStop, wi)
		}
	}
	for idx := 0; idx < desired; idx++ {
		ranges := assignments[idx]
		wi, ok := pm.rangeWorkers[idx]
		if len(ranges) == 0 {
			if ok {
				delete(pm.rangeWorkers, idx)
				toStop = append(toStop, wi)
			}
			continue
		}
		if !ok {
			wi = &WorkerInfo{workerIndex: idx, kind: workerKindRange, ranges: ranges, failedRanges: make(map[int64]bool), lastStart: time.Now()}
			pm.rangeWorkers[idx] = wi
			if pm.ready {
				toStart[idx] = struct{}{}
			}
			continue
		}
		if !rangesEqual(wi.ranges, ranges) {
			wi.ranges = ranges
			wi.failedRanges = make(map[int64]bool)
			wi.errored = false
			toUpdate = append(toUpdate, wi)
		}
		if wi.process == nil && wi.conn == nil {
			toStart[idx] = struct{}{}
		}
	}
	pm.mu.Unlock()

	for _, wi := range toStop {
		killWorkerInfo(wi)
	}
	for idx := range toStart {
		if err := pm.startRangeWorker(idx); err != nil {
			log.Printf("start range worker[%d]: %v", idx, err)
		}
	}
	for _, wi := range toUpdate {
		pm.sendRangeConfig(wi)
	}
}

func rulesEqual(a, b []Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func rangesEqual(a, b []PortRange) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (pm *ProcessManager) buildRuleStatus(rule Rule, status string) RuleStatus {
	item := RuleStatus{
		Rule:            rule,
		Status:          status,
		EffectiveEngine: ruleEngineUserspace,
	}
	item.Rule.EnginePreference = normalizeRuleEnginePreference(item.Rule.EnginePreference)

	pm.mu.Lock()
	plan, ok := pm.rulePlans[rule.ID]
	pm.mu.Unlock()
	if !ok {
		return item
	}

	item.EffectiveEngine = plan.EffectiveEngine
	item.KernelEligible = plan.KernelEligible
	item.KernelReason = plan.KernelReason
	item.FallbackReason = plan.FallbackReason
	return item
}

func (pm *ProcessManager) buildRangeStatus(pr PortRange, status string) PortRangeStatus {
	item := PortRangeStatus{
		PortRange:       pr,
		Status:          status,
		EffectiveEngine: ruleEngineUserspace,
	}

	pm.mu.Lock()
	plan, ok := pm.rangePlans[pr.ID]
	pm.mu.Unlock()
	if !ok {
		return item
	}

	item.EffectiveEngine = plan.EffectiveEngine
	item.KernelEligible = plan.KernelEligible
	item.KernelReason = plan.KernelReason
	item.FallbackReason = plan.FallbackReason
	return item
}

func (pm *ProcessManager) startRuleWorker(workerIndex int) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	cmd := exec.Command(exe,
		"--worker",
		"--id", fmt.Sprintf("%d", workerIndex),
		"--sock", pm.sockPath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	setSysProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start worker process: %w", err)
	}

	pm.mu.Lock()
	wi, ok := pm.ruleWorkers[workerIndex]
	if !ok {
		wi = &WorkerInfo{
			workerIndex: workerIndex,
			kind:        workerKindRule,
			failedRules: make(map[int64]bool),
			ruleStats:   make(map[int64]RuleStatsReport),
		}
		pm.ruleWorkers[workerIndex] = wi
	}
	waitCh := make(chan struct{})
	wi.process = cmd.Process
	wi.waitCh = waitCh
	wi.running = false
	wi.errored = false
	wi.ruleRetryCount = 0
	wi.ruleNextRetry = time.Time{}
	wi.lastStart = time.Now()
	pm.mu.Unlock()

	go func() {
		cmd.Wait()
		close(waitCh)
		pm.mu.Lock()
		if wi2, ok2 := pm.ruleWorkers[workerIndex]; ok2 && wi2.process == cmd.Process {
			wi2.process = nil
			wi2.running = false
			wi2.conn = nil
		}
		pm.mu.Unlock()
	}()

	return nil
}

func (pm *ProcessManager) stopRuleWorker(workerIndex int) {
	pm.mu.Lock()
	wi, ok := pm.ruleWorkers[workerIndex]
	if !ok {
		pm.mu.Unlock()
		return
	}
	delete(pm.ruleWorkers, workerIndex)
	pm.mu.Unlock()

	killWorkerInfo(wi)
}

func (pm *ProcessManager) handleRangeWorkerConn(conn net.Conn, scanner *bufio.Scanner, workerIndex int, workerHash string) {
	pm.mu.Lock()
	wi, ok := pm.rangeWorkers[workerIndex]
	if !ok {
		pm.mu.Unlock()
		sendStop(conn)
		conn.Close()
		return
	}
	wi.conn = conn
	wi.running = false
	wi.errored = false
	wi.binaryHash = workerHash
	ranges := append([]PortRange(nil), wi.ranges...)
	binHash := pm.binaryHash
	pm.mu.Unlock()

	wi.writeMu.Lock()
	writeIPC(conn, IPCMessage{Type: "range_config", PortRanges: ranges, BinaryHash: binHash})
	wi.writeMu.Unlock()

	target := wi

	for scanner.Scan() {
		var status IPCMessage
		if err := json.Unmarshal(scanner.Bytes(), &status); err != nil {
			continue
		}
		if status.Type == "status" {
			startNewWorker := false
			pm.mu.Lock()
			if status.Status == "draining" && target == wi {
				// Deep-copy rangeStats so draining and new worker have independent maps
				copiedStats := make(map[int64]RangeStatsReport, len(wi.rangeStats))
				for id, s := range wi.rangeStats {
					copiedStats[id] = s
				}
				dw := &WorkerInfo{
					workerIndex:    workerIndex,
					kind:           workerKindRange,
					conn:           conn,
					draining:       true,
					binaryHash:     workerHash,
					activeRangeIDs: status.ActiveRangeIDs,
					ranges:         ranges,
					rangeStats:     copiedStats,
					process:        wi.process,
					waitCh:         wi.waitCh,
					lastStart:      time.Now(),
				}
				pm.drainingWorkers = append(pm.drainingWorkers, dw)
				wi.conn = nil
				wi.running = false
				wi.process = nil
				wi.waitCh = nil
				wi.rangeStats = make(map[int64]RangeStatsReport)
				wi.lastStart = time.Now()
				target = dw
				startNewWorker = len(wi.ranges) > 0
				log.Printf("range worker[%d]: moved to draining list", workerIndex)
			} else {
				target.running = status.Status == "running"
				target.draining = status.Status == "draining"
				target.activeRangeIDs = append([]int64(nil), status.ActiveRangeIDs...)
				if status.Status == "error" {
					target.errored = true
				}
				target.failedRanges = make(map[int64]bool)
				for _, id := range status.FailedRangeIDs {
					target.failedRanges[id] = true
				}
			}
			pm.mu.Unlock()
			if startNewWorker {
				log.Printf("range worker[%d]: starting replacement worker", workerIndex)
				if err := pm.startRangeWorker(workerIndex); err != nil {
					log.Printf("start replacement range worker[%d]: %v", workerIndex, err)
				}
			}
			if status.Status == "error" {
				log.Printf("range worker[%d] error: %s", workerIndex, status.Error)
			}
		} else if status.Type == "range_stats" {
			pm.mu.Lock()
			if target.rangeStats == nil {
				target.rangeStats = make(map[int64]RangeStatsReport)
			}
			for _, s := range status.RangeStats {
				target.rangeStats[s.RangeID] = s
			}
			pm.mu.Unlock()
		}
	}

	pm.mu.Lock()
	if target == wi {
		if wi2, ok2 := pm.rangeWorkers[workerIndex]; ok2 && wi2 == wi {
			wi2.conn = nil
			wi2.running = false
		}
	} else {
		for i, dw := range pm.drainingWorkers {
			if dw == target {
				pm.drainingWorkers = append(pm.drainingWorkers[:i], pm.drainingWorkers[i+1:]...)
				break
			}
		}
	}
	pm.mu.Unlock()
}

func (pm *ProcessManager) startRangeWorker(workerIndex int) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	cmd := exec.Command(exe,
		"--range-worker",
		"--id", fmt.Sprintf("%d", workerIndex),
		"--sock", pm.sockPath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	setSysProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start range worker process: %w", err)
	}

	pm.mu.Lock()
	wi, ok := pm.rangeWorkers[workerIndex]
	if !ok {
		wi = &WorkerInfo{workerIndex: workerIndex, kind: workerKindRange, failedRanges: make(map[int64]bool)}
		pm.rangeWorkers[workerIndex] = wi
	}
	waitCh := make(chan struct{})
	wi.process = cmd.Process
	wi.waitCh = waitCh
	wi.running = false
	wi.errored = false
	wi.lastStart = time.Now()
	pm.mu.Unlock()

	go func() {
		cmd.Wait()
		close(waitCh)
		pm.mu.Lock()
		if wi2, ok2 := pm.rangeWorkers[workerIndex]; ok2 && wi2.process == cmd.Process {
			wi2.process = nil
			wi2.running = false
			wi2.conn = nil
		}
		pm.mu.Unlock()
	}()

	return nil
}

func (pm *ProcessManager) stopRangeWorker(workerIndex int) {
	pm.mu.Lock()
	wi, ok := pm.rangeWorkers[workerIndex]
	if !ok {
		pm.mu.Unlock()
		return
	}
	delete(pm.rangeWorkers, workerIndex)
	pm.mu.Unlock()

	killWorkerInfo(wi)
}

func (pm *ProcessManager) sendRuleConfig(wi *WorkerInfo) {
	if wi == nil {
		return
	}
	pm.mu.Lock()
	rules := append([]Rule(nil), wi.rules...)
	conn := wi.conn
	binHash := pm.binaryHash
	pm.mu.Unlock()
	if conn == nil {
		return
	}
	wi.writeMu.Lock()
	writeIPC(conn, IPCMessage{Type: "config", Rules: rules, BinaryHash: binHash})
	wi.writeMu.Unlock()
}

func (pm *ProcessManager) sendRangeConfig(wi *WorkerInfo) {
	if wi == nil {
		return
	}
	pm.mu.Lock()
	ranges := append([]PortRange(nil), wi.ranges...)
	conn := wi.conn
	binHash := pm.binaryHash
	pm.mu.Unlock()
	if conn == nil {
		return
	}
	wi.writeMu.Lock()
	writeIPC(conn, IPCMessage{Type: "range_config", PortRanges: ranges, BinaryHash: binHash})
	wi.writeMu.Unlock()
}

func (pm *ProcessManager) sendSitesConfig(wi *WorkerInfo, sites []Site) {
	if wi == nil {
		return
	}
	pm.mu.Lock()
	conn := wi.conn
	binHash := pm.binaryHash
	pm.mu.Unlock()
	if conn == nil {
		return
	}
	wi.writeMu.Lock()
	writeIPC(conn, IPCMessage{Type: "sites_config", Sites: sites, BinaryHash: binHash})
	wi.writeMu.Unlock()
}

func (pm *ProcessManager) startSharedProxyIfNeeded() {
	sites, err := dbGetSites(pm.db)
	if err != nil || len(sites) == 0 {
		return
	}
	hasEnabled := false
	for _, s := range sites {
		if s.Enabled {
			hasEnabled = true
			break
		}
	}
	if !hasEnabled {
		return
	}
	pm.startSharedProxy()
}

func (pm *ProcessManager) startSharedProxy() {
	pm.mu.Lock()
	if pm.sharedProxy != nil && (pm.sharedProxy.running || pm.sharedProxy.process != nil || pm.sharedProxy.conn != nil) {
		pm.mu.Unlock()
		return
	}
	pm.mu.Unlock()

	exe, err := os.Executable()
	if err != nil {
		log.Printf("start shared proxy: %v", err)
		return
	}

	cmd := exec.Command(exe,
		"--shared-proxy",
		"--sock", pm.sockPath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	setSysProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		log.Printf("start shared proxy process: %v", err)
		return
	}

	waitCh := make(chan struct{})
	pm.mu.Lock()
	pm.sharedProxy = &WorkerInfo{
		kind:      workerKindShared,
		process:   cmd.Process,
		waitCh:    waitCh,
		running:   false,
		errored:   false,
		lastStart: time.Now(),
	}
	pm.mu.Unlock()

	go func() {
		cmd.Wait()
		close(waitCh)
		pm.mu.Lock()
		if pm.sharedProxy != nil && pm.sharedProxy.process == cmd.Process {
			pm.sharedProxy.process = nil
			pm.sharedProxy.running = false
			pm.sharedProxy.conn = nil
		}
		pm.mu.Unlock()
	}()
}

func (pm *ProcessManager) stopSharedProxy() {
	pm.mu.Lock()
	wi := pm.sharedProxy
	pm.sharedProxy = nil
	pm.mu.Unlock()

	if wi != nil {
		killWorkerInfo(wi)
	}
}

func (pm *ProcessManager) updateSharedProxy() {
	sites, err := dbGetSites(pm.db)
	if err != nil {
		log.Printf("load sites for update: %v", err)
		return
	}

	var enabledSites []Site
	for _, s := range sites {
		if s.Enabled {
			enabledSites = append(enabledSites, s)
		}
	}

	if len(enabledSites) == 0 {
		pm.stopSharedProxy()
		return
	}

	pm.mu.Lock()
	proxy := pm.sharedProxy
	pm.mu.Unlock()

	if proxy == nil {
		// Create slot; monitorLoop will start process if no worker reconnects
		pm.mu.Lock()
		pm.sharedProxy = &WorkerInfo{kind: workerKindShared, lastStart: time.Now()}
		pm.mu.Unlock()
		return
	}
	if !proxy.running && proxy.conn == nil && proxy.process == nil {
		return // monitorLoop will handle starting
	}

	// Send updated sites to running proxy
	pm.sendSitesConfig(proxy, enabledSites)
}

func writeIPC(conn net.Conn, msg IPCMessage) {
	data, _ := json.Marshal(msg)
	data = append(data, '\n')
	conn.Write(data)
}

func sendStop(conn net.Conn) {
	writeIPC(conn, IPCMessage{Type: "stop"})
}

func killWorkerInfo(wi *WorkerInfo) {
	if wi.conn != nil {
		wi.writeMu.Lock()
		sendStop(wi.conn)
		wi.conn.Close()
		wi.writeMu.Unlock()
	}

	if wi.process != nil && wi.waitCh != nil {
		select {
		case <-wi.waitCh:
			// Process already exited
		case <-time.After(3 * time.Second):
			wi.process.Kill()
			<-wi.waitCh
		}
	}
}

func (pm *ProcessManager) collectRuleStats() map[int64]RuleStatsReport {
	result := make(map[int64]RuleStatsReport)
	pm.mu.Lock()
	for _, wi := range pm.ruleWorkers {
		for id, s := range wi.ruleStats {
			result[id] = s
		}
	}
	for _, dw := range pm.drainingWorkers {
		for id, s := range dw.ruleStats {
			if existing, ok := result[id]; ok {
				existing.ActiveConns += s.ActiveConns
				existing.TotalConns += s.TotalConns
				existing.RejectedConns += s.RejectedConns
				existing.BytesIn += s.BytesIn
				existing.BytesOut += s.BytesOut
				existing.SpeedIn += s.SpeedIn
				existing.SpeedOut += s.SpeedOut
				existing.NatTableSize += s.NatTableSize
				result[id] = existing
			} else {
				result[id] = s
			}
		}
	}
	pm.mu.Unlock()
	return result
}

func (pm *ProcessManager) collectRangeStats() map[int64]RangeStatsReport {
	result := make(map[int64]RangeStatsReport)
	pm.mu.Lock()
	for _, wi := range pm.rangeWorkers {
		for id, s := range wi.rangeStats {
			result[id] = s
		}
	}
	for _, dw := range pm.drainingWorkers {
		for id, s := range dw.rangeStats {
			if existing, ok := result[id]; ok {
				existing.ActiveConns += s.ActiveConns
				existing.TotalConns += s.TotalConns
				existing.RejectedConns += s.RejectedConns
				existing.BytesIn += s.BytesIn
				existing.BytesOut += s.BytesOut
				existing.SpeedIn += s.SpeedIn
				existing.SpeedOut += s.SpeedOut
				existing.NatTableSize += s.NatTableSize
				result[id] = existing
			} else {
				result[id] = s
			}
		}
	}
	pm.mu.Unlock()
	return result
}

func (pm *ProcessManager) collectSiteStats() []SiteStatsReport {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	var result []SiteStatsReport
	if pm.sharedProxy != nil {
		result = append(result, pm.sharedProxy.siteStatsMap...)
	}
	for _, dw := range pm.drainingWorkers {
		if dw.kind == workerKindShared {
			result = append(result, dw.siteStatsMap...)
		}
	}
	return result
}

func (pm *ProcessManager) updateTransparentRouting(enabledRules []Rule, enabledRanges []PortRange) {
	needTransparent := false
	for _, r := range enabledRules {
		if r.Transparent {
			needTransparent = true
			break
		}
	}
	if !needTransparent {
		for _, r := range enabledRanges {
			if r.Transparent {
				needTransparent = true
				break
			}
		}
	}
	if !needTransparent {
		sites, err := dbGetSites(pm.db)
		if err != nil {
			log.Printf("load sites for transparent check: %v", err)
			return // don't change routing on DB error
		}
		for _, s := range sites {
			if s.Enabled && s.Transparent {
				needTransparent = true
				break
			}
		}
	}
	if needTransparent {
		ensureTransparentRouting()
	} else {
		cleanupTransparentRouting()
	}
}

func (pm *ProcessManager) stopAll() {
	if pm.kernelRuntime != nil {
		if err := pm.kernelRuntime.Close(); err != nil {
			log.Printf("stop kernel runtime: %v", err)
		}
	}

	pm.listener.Close()

	// Close IPC connections without sending stop - workers will reconnect
	pm.mu.Lock()
	for _, wi := range pm.ruleWorkers {
		if wi.conn != nil {
			wi.conn.Close()
			wi.conn = nil
		}
	}
	for _, wi := range pm.rangeWorkers {
		if wi.conn != nil {
			wi.conn.Close()
			wi.conn = nil
		}
	}
	if pm.sharedProxy != nil && pm.sharedProxy.conn != nil {
		pm.sharedProxy.conn.Close()
		pm.sharedProxy.conn = nil
	}
	pm.mu.Unlock()
}

func (pm *ProcessManager) monitorLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		type ruleRetryTask struct {
			index        int
			failureCount int
		}
		var restartRuleIdx []int
		var retryRuleConfig []ruleRetryTask
		var restartRangeIdx []int
		var stopDraining []*WorkerInfo
		proxyDead := false
		now := time.Now()

		pm.mu.Lock()
		for idx, wi := range pm.ruleWorkers {
			if len(wi.rules) == 0 {
				continue
			}
			if wi.errored {
				if wi.ruleNextRetry.IsZero() {
					wi.ruleNextRetry = now.Add(nextRuleRetryDelay(wi.ruleRetryCount + 1))
				}
				if !now.Before(wi.ruleNextRetry) {
					wi.ruleNextRetry = now.Add(nextRuleRetryDelay(wi.ruleRetryCount + 1))
					if wi.conn != nil {
						retryRuleConfig = append(retryRuleConfig, ruleRetryTask{
							index:        idx,
							failureCount: wi.ruleRetryCount,
						})
					} else if wi.process == nil {
						restartRuleIdx = append(restartRuleIdx, idx)
					}
				}
				continue
			}
			if wi.process == nil && wi.conn == nil {
				if now.Sub(wi.lastStart) > 3*time.Second {
					restartRuleIdx = append(restartRuleIdx, idx)
				}
			}
		}
		for idx, wi := range pm.rangeWorkers {
			if wi.process == nil && wi.conn == nil && !wi.errored && len(wi.ranges) > 0 {
				if now.Sub(wi.lastStart) > 3*time.Second {
					restartRangeIdx = append(restartRangeIdx, idx)
				}
			}
		}
		if pm.sharedProxy != nil && pm.sharedProxy.process == nil && pm.sharedProxy.conn == nil && !pm.sharedProxy.errored {
			if now.Sub(pm.sharedProxy.lastStart) > 3*time.Second {
				proxyDead = true
			}
		}
		if len(pm.drainingWorkers) > 0 {
			kept := pm.drainingWorkers[:0]
			for _, dw := range pm.drainingWorkers {
				stopNow := false
				switch dw.kind {
				case workerKindRule:
					hasOwnActive := false
					if len(dw.activeRuleIDs) > 0 && len(dw.rules) > 0 {
						own := make(map[int64]struct{}, len(dw.rules))
						for _, r := range dw.rules {
							own[r.ID] = struct{}{}
						}
						for _, id := range dw.activeRuleIDs {
							if _, ok := own[id]; ok {
								hasOwnActive = true
								break
							}
						}
					}
					if dw.draining && !dw.running && !hasOwnActive {
						stopNow = true
					}
				case workerKindRange:
					hasOwnActive := false
					if len(dw.activeRangeIDs) > 0 && len(dw.ranges) > 0 {
						own := make(map[int64]struct{}, len(dw.ranges))
						for _, pr := range dw.ranges {
							own[pr.ID] = struct{}{}
						}
						for _, id := range dw.activeRangeIDs {
							if _, ok := own[id]; ok {
								hasOwnActive = true
								break
							}
						}
					}
					if dw.draining && !dw.running && !hasOwnActive {
						stopNow = true
					}
				case workerKindShared:
					if dw.draining && !dw.running {
						stopNow = true
					}
				}
				if !stopNow && !dw.draining && !dw.running {
					stopNow = true
				}
				drainTimeout := time.Duration(pm.cfg.DrainTimeoutHours) * time.Hour
				if drainTimeout > 0 && !stopNow && !dw.lastStart.IsZero() && now.Sub(dw.lastStart) > drainTimeout {
					log.Printf("draining %s worker[%d]: timeout after %v, force stopping", dw.kind, dw.workerIndex, drainTimeout)
					stopNow = true
				}
				if stopNow {
					dw.draining = false
					dw.running = false
					stopDraining = append(stopDraining, dw)
					continue
				}
				kept = append(kept, dw)
			}
			pm.drainingWorkers = kept
		}
		pm.mu.Unlock()

		for _, idx := range restartRuleIdx {
			log.Printf("restarting rule worker[%d]", idx)
			if err := pm.startRuleWorker(idx); err != nil {
				log.Printf("restart rule worker[%d]: %v", idx, err)
			}
		}
		for _, idx := range restartRangeIdx {
			log.Printf("restarting range worker[%d]", idx)
			if err := pm.startRangeWorker(idx); err != nil {
				log.Printf("restart range worker[%d]: %v", idx, err)
			}
		}
		for _, task := range retryRuleConfig {
			pm.mu.Lock()
			wi := pm.ruleWorkers[task.index]
			pm.mu.Unlock()
			if wi == nil || wi.conn == nil || len(wi.rules) == 0 {
				continue
			}
			log.Printf("retrying rule worker[%d] config (failure_count=%d)", task.index, task.failureCount)
			pm.sendRuleConfig(wi)
		}
		for _, dw := range stopDraining {
			log.Printf("stopping stale draining %s worker[%d]", dw.kind, dw.workerIndex)
			killWorkerInfo(dw)
		}

		if proxyDead {
			sites, err := dbGetSites(pm.db)
			if err == nil {
				hasEnabled := false
				for _, s := range sites {
					if s.Enabled {
						hasEnabled = true
						break
					}
				}
				if hasEnabled {
					log.Println("restarting shared proxy")
					pm.startSharedProxy()
				}
			}
		}
	}
}
