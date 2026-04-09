package app

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
	"strconv"
	"strings"
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
	failedSites    map[int64]bool
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
	retryCount     int
	nextRetry      time.Time
	binaryHash     string
	lastStart      time.Time
	lastMessageAt  time.Time
	lastIssueAt    time.Time
	lastIssueText  string
	staleRecoverAt time.Time
	writeMu        sync.Mutex
	waitCh         chan struct{} // closed when process exits
}

const (
	workerKindRule   = "rule"
	workerKindRange  = "range"
	workerKindShared = "shared"

	workerRetryBaseDelay               = 1 * time.Second
	workerRetryMaxDelay                = 1 * time.Minute
	workerIssueLogEvery                = 10 * time.Minute
	workerControlStaleTimeout          = 30 * time.Second
	workerControlStaleRecoverEvery     = 30 * time.Second
	kernelDegradedRebuildCooldown      = 30 * time.Second
	redistributeRetryDelay             = 250 * time.Millisecond
	kernelStatsRefreshInterval         = 5 * time.Second
	kernelStatsDemandWindow            = 15 * time.Second
	kernelStatsSnapshotShareTTL        = 1 * time.Second
	kernelMaintenanceInterval          = 10 * time.Second
	kernelFallbackRetryInterval        = 30 * time.Second
	kernelFallbackRetryLogEvery        = 10 * time.Minute
	kernelAttachmentCheckEvery         = 15 * time.Second
	kernelAttachmentHealBackoff        = 30 * time.Second
	kernelNetlinkRetryDebounce         = 3 * time.Second
	kernelNetlinkOwnerRetryCooldown    = 6 * time.Second
	kernelNetlinkOwnerRetryCooldownMax = 30 * time.Second
	kernelUserspaceWarmupTimeout       = 5 * time.Second
	kernelUserspaceWarmupPoll          = 100 * time.Millisecond
	managedNetworkReloadDebounce       = 1 * time.Second
	managedNetworkSelfEventSuppressFor = 2 * time.Second
)

const forwardKernelMaintenanceIntervalEnv = "FORWARD_KERNEL_MAINTENANCE_INTERVAL_MS"

func nextWorkerRetryDelay(retryCount int) time.Duration {
	if retryCount <= 1 {
		return workerRetryBaseDelay
	}
	delay := workerRetryBaseDelay
	for i := 1; i < retryCount; i++ {
		if delay >= workerRetryMaxDelay {
			return workerRetryMaxDelay
		}
		delay *= 2
	}
	if delay > workerRetryMaxDelay {
		return workerRetryMaxDelay
	}
	return delay
}

func resetWorkerRetryState(wi *WorkerInfo) {
	if wi == nil {
		return
	}
	wi.errored = false
	wi.retryCount = 0
	wi.nextRetry = time.Time{}
	wi.lastIssueAt = time.Time{}
	wi.lastIssueText = ""
}

func noteWorkerMessage(wi *WorkerInfo, now time.Time) {
	if wi == nil {
		return
	}
	wi.lastMessageAt = now
	wi.staleRecoverAt = time.Time{}
}

func scheduleWorkerRetry(wi *WorkerInfo, now time.Time) {
	if wi == nil {
		return
	}
	wi.errored = true
	wi.retryCount++
	wi.nextRetry = now.Add(nextWorkerRetryDelay(wi.retryCount))
}

func shouldLogWorkerIssue(wi *WorkerInfo, issue string, now time.Time) bool {
	if wi == nil {
		return false
	}
	issue = strings.TrimSpace(issue)
	if issue == "" {
		issue = "unknown issue"
	}
	if wi.lastIssueText != issue || wi.lastIssueAt.IsZero() || now.Sub(wi.lastIssueAt) >= workerIssueLogEvery {
		wi.lastIssueText = issue
		wi.lastIssueAt = now
		return true
	}
	return false
}

func shouldRecoverStaleWorkerControl(wi *WorkerInfo, now time.Time) bool {
	if wi == nil || wi.conn == nil || wi.draining || wi.lastMessageAt.IsZero() {
		return false
	}
	if now.Sub(wi.lastMessageAt) < workerControlStaleTimeout {
		return false
	}
	if !wi.staleRecoverAt.IsZero() && now.Sub(wi.staleRecoverAt) < workerControlStaleRecoverEvery {
		return false
	}
	wi.staleRecoverAt = now
	return true
}

func configuredKernelMaintenanceInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv(forwardKernelMaintenanceIntervalEnv))
	if raw == "" {
		return kernelMaintenanceInterval
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return kernelMaintenanceInterval
	}
	return time.Duration(ms) * time.Millisecond
}

type ProcessManager struct {
	ruleWorkers                                    map[int]*WorkerInfo
	rangeWorkers                                   map[int]*WorkerInfo
	sharedProxy                                    *WorkerInfo
	drainingWorkers                                []*WorkerInfo
	mu                                             sync.Mutex
	redistributeMu                                 sync.Mutex // serializes redistributeWorkers calls
	db                                             *sql.DB
	cfg                                            *Config
	sockPath                                       string
	listener                                       net.Listener
	binaryHash                                     string
	ready                                          bool
	rulePlans                                      map[int64]ruleDataplanePlan
	rangePlans                                     map[int64]rangeDataplanePlan
	egressNATPlans                                 map[int64]ruleDataplanePlan
	dynamicEgressNATParents                        map[string]struct{}
	managedNetworkRuntime                          managedNetworkRuntime
	managedNetworkInterfaces                       map[string]struct{}
	ipv6Runtime                                    ipv6AssignmentRuntime
	ipv6AssignmentsConfigured                      bool
	ipv6AssignmentInterfaces                       map[string]struct{}
	kernelRuntime                                  kernelRuleRuntime
	kernelRules                                    map[int64]bool
	kernelRanges                                   map[int64]bool
	kernelEgressNATs                               map[int64]bool
	kernelRuleEngines                              map[int64]string
	kernelRangeEngines                             map[int64]string
	kernelEgressNATEngines                         map[int64]string
	kernelFlowOwners                               map[uint32]kernelCandidateOwner
	kernelRuleStats                                map[int64]RuleStatsReport
	kernelRangeStats                               map[int64]RangeStatsReport
	kernelEgressNATStats                           map[int64]EgressNATStatsReport
	kernelStatsSnapshot                            kernelRuleStatsSnapshot
	kernelStatsAt                                  time.Time
	kernelStatsSnapshotAt                          time.Time
	kernelStatsLastDuration                        time.Duration
	kernelStatsLastError                           string
	kernelStatsDemandAt                            time.Time
	kernelMaintenanceAt                            time.Time
	kernelMaintenanceEvery                         time.Duration
	kernelAttachmentCheckAt                        time.Time
	kernelAttachmentHealAt                         time.Time
	kernelDegradedHealAt                           time.Time
	kernelNetlinkRetryAt                           time.Time
	kernelRetryAt                                  time.Time
	kernelRetryLogAt                               time.Time
	kernelRetryCount                               int
	lastKernelRetryAt                              time.Time
	lastKernelRetryReason                          string
	kernelIncrementalRetryCount                    int
	kernelIncrementalRetryFallbackCount            int
	lastKernelIncrementalRetryAt                   time.Time
	lastKernelIncrementalRetryResult               string
	lastKernelIncrementalRetryMatchedRuleOwners    int
	lastKernelIncrementalRetryMatchedRangeOwners   int
	lastKernelIncrementalRetryAttemptedRuleOwners  int
	lastKernelIncrementalRetryAttemptedRangeOwners int
	lastKernelIncrementalRetryRetainedRuleOwners   int
	lastKernelIncrementalRetryRetainedRangeOwners  int
	lastKernelIncrementalRetryRecoveredRuleOwners  int
	lastKernelIncrementalRetryRecoveredRangeOwners int
	lastKernelIncrementalRetryCooldownRuleOwners   int
	lastKernelIncrementalRetryCooldownRangeOwners  int
	lastKernelIncrementalRetryCooldownSummary      string
	lastKernelIncrementalRetryCooldownScope        string
	lastKernelIncrementalRetryBackoffRuleOwners    int
	lastKernelIncrementalRetryBackoffRangeOwners   int
	lastKernelIncrementalRetryBackoffSummary       string
	lastKernelIncrementalRetryBackoffScope         string
	lastKernelIncrementalRetryBackoffMaxFailures   int
	lastKernelIncrementalRetryBackoffMaxDelay      time.Duration
	lastKernelAttachmentIssue                      string
	lastKernelAttachmentHealSummary                string
	lastKernelAttachmentHealError                  string
	kernelNetlinkStop                              chan struct{}
	kernelNetlinkRecoverWake                       chan struct{}
	kernelNetlinkRecoverPending                    bool
	kernelNetlinkRecoverSource                     string
	kernelNetlinkRecoverSummary                    string
	kernelNetlinkRecoverTrigger                    kernelNetlinkRecoveryTrigger
	kernelNetlinkRecoverRequestedAt                time.Time
	kernelNetlinkLinkStates                        map[int]kernelNetlinkLinkSnapshot
	kernelNetlinkOwnerRetryCooldownUntil           map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState
	kernelNetlinkOwnerRetryFailures                map[kernelCandidateOwner]int
	kernelPressureSnapshot                         kernelRuntimePressureSnapshot
	managedRuntimeReloadWake                       chan struct{}
	managedRuntimeReloadPending                    bool
	managedRuntimeReloadDueAt                      time.Time
	managedRuntimeReloadInterfaces                 map[string]struct{}
	managedRuntimeReloadSuppressUntil              map[string]time.Time
	managedRuntimeReloadLastRequestedAt            time.Time
	managedRuntimeReloadLastRequestSource          string
	managedRuntimeReloadLastRequestSummary         string
	managedRuntimeReloadLastStartedAt              time.Time
	managedRuntimeReloadLastCompletedAt            time.Time
	managedRuntimeReloadLastResult                 string
	managedRuntimeReloadLastAppliedSummary         string
	managedRuntimeReloadLastError                  string
	redistributeWake                               chan struct{}
	redistributePending                            bool
	redistributeDueAt                              time.Time
	shuttingDown                                   bool
	shutdownCh                                     chan struct{}
	monitorDone                                    chan struct{}
	managedRuntimeReloadDone                       chan struct{}
	redistributeDone                               chan struct{}
	lastRulePlanLog                                map[int64]string
	lastRangePlanLog                               map[int64]string
	lastPlannerSummary                             string
	lastKernelRetryLog                             string
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
		ruleWorkers:                          make(map[int]*WorkerInfo),
		rangeWorkers:                         make(map[int]*WorkerInfo),
		db:                                   db,
		cfg:                                  cfg,
		sockPath:                             sockPath,
		listener:                             ln,
		binaryHash:                           binaryHash,
		rulePlans:                            make(map[int64]ruleDataplanePlan),
		rangePlans:                           make(map[int64]rangeDataplanePlan),
		egressNATPlans:                       make(map[int64]ruleDataplanePlan),
		dynamicEgressNATParents:              make(map[string]struct{}),
		managedNetworkRuntime:                newManagedNetworkRuntime(),
		managedNetworkInterfaces:             make(map[string]struct{}),
		ipv6Runtime:                          newIPv6AssignmentRuntime(),
		ipv6AssignmentInterfaces:             make(map[string]struct{}),
		kernelRuntime:                        newKernelRuleRuntime(cfg),
		kernelRules:                          make(map[int64]bool),
		kernelRanges:                         make(map[int64]bool),
		kernelEgressNATs:                     make(map[int64]bool),
		kernelRuleEngines:                    make(map[int64]string),
		kernelRangeEngines:                   make(map[int64]string),
		kernelEgressNATEngines:               make(map[int64]string),
		kernelFlowOwners:                     make(map[uint32]kernelCandidateOwner),
		kernelRuleStats:                      make(map[int64]RuleStatsReport),
		kernelRangeStats:                     make(map[int64]RangeStatsReport),
		kernelEgressNATStats:                 make(map[int64]EgressNATStatsReport),
		kernelNetlinkOwnerRetryCooldownUntil: make(map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState),
		kernelNetlinkOwnerRetryFailures:      make(map[kernelCandidateOwner]int),
		kernelStatsSnapshot:                  emptyKernelRuleStatsSnapshot(),
		managedRuntimeReloadWake:             make(chan struct{}, 1),
		managedRuntimeReloadSuppressUntil:    make(map[string]time.Time),
		redistributeWake:                     make(chan struct{}, 1),
		shutdownCh:                           make(chan struct{}),
		monitorDone:                          make(chan struct{}),
		managedRuntimeReloadDone:             make(chan struct{}),
		redistributeDone:                     make(chan struct{}),
		lastRulePlanLog:                      make(map[int64]string),
		lastRangePlanLog:                     make(map[int64]string),
		kernelMaintenanceEvery:               configuredKernelMaintenanceInterval(),
	}

	if pm.kernelRuntime != nil {
		available, reason := pm.kernelRuntime.Available()
		profileFields := kernelAdaptiveMapProfileLogFields(currentKernelAdaptiveMapProfile())
		if available {
			log.Printf("kernel dataplane ready (default_engine=%s): %s | %s", cfg.DefaultEngine, reason, profileFields)
		} else {
			log.Printf("kernel dataplane unavailable (default_engine=%s): %s | %s", cfg.DefaultEngine, reason, profileFields)
		}
	}

	go pm.monitorLoop()
	go pm.managedRuntimeReloadLoop()
	go pm.redistributeLoop()
	pm.startKernelNetlinkMonitor()

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
	resetWorkerRetryState(wi)
	noteWorkerMessage(wi, time.Now())
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
			logIssue := false
			pm.mu.Lock()
			now := time.Now()
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
					lastStart:     now,
					lastMessageAt: now,
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
				noteWorkerMessage(target, now)
				if status.Status == "error" {
					logIssue = shouldLogWorkerIssue(target, status.Error, now)
					if target == wi {
						scheduleWorkerRetry(target, now)
					} else {
						target.errored = true
					}
				} else {
					resetWorkerRetryState(target)
					if target == wi {
						target.errored = false
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
			if status.Status == "error" && logIssue {
				log.Printf("worker[%d] error: %s", workerIndex, status.Error)
			}
		} else if status.Type == "stats" {
			pm.mu.Lock()
			if target.ruleStats == nil {
				target.ruleStats = make(map[int64]RuleStatsReport)
			}
			noteWorkerMessage(target, time.Now())
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
		proxy.failedSites = make(map[int64]bool)
		resetWorkerRetryState(proxy)
		noteWorkerMessage(proxy, time.Now())
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
			logIssue := false
			issueText := ""
			pm.mu.Lock()
			now := time.Now()
			if status.Status == "draining" && target == proxy {
				// Copy siteStatsMap so draining and new proxy have independent slices
				copiedStats := make([]SiteStatsReport, len(proxy.siteStatsMap))
				copy(copiedStats, proxy.siteStatsMap)
				dw := &WorkerInfo{
					kind:          workerKindShared,
					conn:          conn,
					draining:      true,
					binaryHash:    workerHash,
					siteStatsMap:  copiedStats,
					process:       proxy.process,
					waitCh:        proxy.waitCh,
					lastStart:     now,
					lastMessageAt: now,
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
				target.failedSites = make(map[int64]bool)
				for _, id := range status.FailedSiteIDs {
					target.failedSites[id] = true
				}
				noteWorkerMessage(target, now)
				issueText = strings.TrimSpace(status.Error)
				issueActive := status.Status == "error" || len(status.FailedSiteIDs) > 0
				if issueActive {
					if issueText == "" {
						issueText = fmt.Sprintf("%d site listener(s) unavailable", len(target.failedSites))
					}
					logIssue = shouldLogWorkerIssue(target, issueText, now)
					if target == proxy {
						scheduleWorkerRetry(target, now)
					} else {
						target.errored = true
					}
				} else {
					resetWorkerRetryState(target)
				}
			}
			pm.mu.Unlock()
			if startNewProxy {
				log.Println("shared proxy: starting replacement proxy")
				pm.startSharedProxy()
			}
			if logIssue {
				log.Printf("shared proxy issue: %s", issueText)
			}
		} else if status.Type == "site_stats" {
			pm.mu.Lock()
			target.siteStatsMap = status.SiteStats
			noteWorkerMessage(target, time.Now())
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
	managedNetworks, err := dbGetManagedNetworks(pm.db)
	if err != nil {
		log.Printf("load managed networks: %v", err)
		return
	}
	managedNetworkReservations, err := dbGetManagedNetworkReservations(pm.db)
	if err != nil {
		log.Printf("load managed network reservations: %v", err)
		return
	}
	if pm.managedNetworkRuntime != nil {
		if err := pm.managedNetworkRuntime.Reconcile(managedNetworks, managedNetworkReservations); err != nil {
			log.Printf("managed network runtime reconcile: %v", err)
		}
	}
	egressNATs, err := dbGetEgressNATs(pm.db)
	if err != nil {
		log.Printf("load egress nats: %v", err)
		return
	}
	ipv6Assignments, ipv6AssignmentLoadErr := dbGetIPv6Assignments(pm.db)
	if ipv6AssignmentLoadErr != nil {
		log.Printf("load ipv6 assignments: %v", ipv6AssignmentLoadErr)
	}
	egressNATSnapshot := egressNATInterfaceSnapshot{}
	dynamicEgressNATParents := map[string]struct{}{}
	needsManagedNetworkCompilation := len(managedNetworks) > 0
	if len(egressNATs) > 0 || needsManagedNetworkCompilation {
		egressNATSnapshot = loadEgressNATInterfaceSnapshot()
	}
	if needsManagedNetworkCompilation && egressNATSnapshot.Err != nil {
		log.Printf("managed network runtime: interface inventory unavailable: %v", egressNATSnapshot.Err)
	}
	egressNATs = normalizeEgressNATItemsWithSnapshot(egressNATs, egressNATSnapshot)
	managedNetworkCompiled := compileManagedNetworkRuntime(managedNetworks, ipv6Assignments, egressNATs, egressNATSnapshot.Infos)
	if len(managedNetworkCompiled.Warnings) > 0 {
		for _, warning := range managedNetworkCompiled.Warnings {
			log.Printf("managed network runtime: %s", warning)
		}
	}
	if len(managedNetworkCompiled.IPv6Assignments) > 0 {
		ipv6Assignments = append(ipv6Assignments, managedNetworkCompiled.IPv6Assignments...)
	}
	if len(managedNetworkCompiled.EgressNATs) > 0 {
		egressNATs = append(egressNATs, managedNetworkCompiled.EgressNATs...)
	}
	dynamicEgressNATParents = collectDynamicEgressNATParentsWithSnapshot(egressNATs, egressNATSnapshot)
	if ipv6AssignmentLoadErr == nil {
		if pm.ipv6Runtime != nil {
			if err := pm.ipv6Runtime.Reconcile(ipv6Assignments); err != nil {
				log.Printf("ipv6 assignment runtime reconcile: %v", err)
			}
		}
		ipv6Interfaces, ipv6ConfiguredCount := collectIPv6AssignmentInterfaceNames(ipv6Assignments)
		for name := range managedNetworkCompiled.RedistributeIfaces {
			if ipv6Interfaces == nil {
				ipv6Interfaces = make(map[string]struct{})
			}
			ipv6Interfaces[name] = struct{}{}
		}
		pm.mu.Lock()
		pm.ipv6AssignmentsConfigured = ipv6ConfiguredCount > 0 || len(managedNetworkCompiled.RedistributeIfaces) > 0
		pm.ipv6AssignmentInterfaces = ipv6Interfaces
		pm.mu.Unlock()
	}
	planner := newRuleDataplanePlanner(pm.kernelRuntime, pm.cfg.DefaultEngine)
	configuredKernelRulesMapLimit := 0
	if pm.cfg != nil {
		configuredKernelRulesMapLimit = pm.cfg.KernelRulesMapLimit
	}
	kernelPressure := snapshotKernelRuntimePressure(pm.kernelRuntime)
	previousKernelRules := make(map[int64]bool)
	previousKernelRanges := make(map[int64]bool)
	pm.mu.Lock()
	for id, ok := range pm.kernelRules {
		previousKernelRules[id] = ok
	}
	for id, ok := range pm.kernelRanges {
		previousKernelRanges[id] = ok
	}
	pm.mu.Unlock()
	candidates, rulePlans, rangePlans := buildKernelCandidateRules(rules, ranges, planner, configuredKernelRulesMapLimit)
	applyKernelOwnerConstraints(candidates, rulePlans, rangePlans)
	applyKernelPressurePolicy(kernelPressure, candidates, previousKernelRules, previousKernelRanges, rulePlans, rangePlans)
	candidates = pm.prewarmKernelToUserspaceHandoffs(rules, ranges, candidates, rulePlans, rangePlans)

	activeRuleRangeKernelCandidateCount := countActiveKernelCandidates(candidates, rulePlans, rangePlans, nil)
	maxCandidateRuleID := int64(0)
	for _, rule := range rules {
		if rule.ID > maxCandidateRuleID {
			maxCandidateRuleID = rule.ID
		}
	}
	for _, candidate := range candidates {
		if candidate.rule.ID > maxCandidateRuleID {
			maxCandidateRuleID = candidate.rule.ID
		}
	}
	nextSyntheticID := maxCandidateRuleID + 1
	egressNATCandidates, egressNATPlans := buildEgressNATKernelCandidatesWithSnapshot(egressNATs, planner, configuredKernelRulesMapLimit, activeRuleRangeKernelCandidateCount, &nextSyntheticID, egressNATSnapshot)
	allKernelCandidates := make([]kernelCandidateRule, 0, len(candidates)+len(egressNATCandidates))
	allKernelCandidates = append(allKernelCandidates, candidates...)
	allKernelCandidates = append(allKernelCandidates, egressNATCandidates...)
	activeKernelCandidateBuf := make([]kernelCandidateRule, 0, len(allKernelCandidates))
	activeKernelCandidates := filterActiveKernelCandidatesInto(activeKernelCandidateBuf, allKernelCandidates, rulePlans, rangePlans, egressNATPlans)
	activeKernelCandidateBuf = activeKernelCandidates[:0]
	activeKernelRuleBuf := make([]Rule, 0, len(activeKernelCandidates))
	if pm.kernelRuntime != nil {
		for {
			activeKernelRules := kernelCandidateRulesInto(activeKernelRuleBuf, activeKernelCandidates)
			activeKernelRuleBuf = activeKernelRules[:0]
			results, err := pm.kernelRuntime.Reconcile(activeKernelRules)
			if len(activeKernelCandidates) == 0 {
				break
			}

			ownerFailures := collectKernelOwnerFailures(activeKernelCandidates, results, err)
			if len(ownerFailures) == 0 {
				break
			}
			ownerMetadata := collectKernelOwnerFallbackMetadata(activeKernelCandidates, ownerFailures)
			for owner, reason := range ownerFailures {
				applyKernelOwnerFallbackWithMetadata(owner, reason, ownerMetadata[owner], rulePlans, rangePlans, egressNATPlans)
			}
			activeKernelCandidates = filterActiveKernelCandidatesInto(activeKernelCandidateBuf, allKernelCandidates, rulePlans, rangePlans, egressNATPlans)
			activeKernelCandidateBuf = activeKernelCandidates[:0]
		}
	}

	pm.logRuleDataplanePlans(rules, rulePlans, pm.cfg.DefaultEngine)
	pm.logRangeDataplanePlans(ranges, rangePlans, pm.cfg.DefaultEngine)
	pm.logPlannerSummary(
		"kernel dataplane planner summary: default_engine=%s enabled_rules=%d enabled_ranges=%d enabled_egress_nats=%d kernel_target_rules=%d kernel_target_ranges=%d kernel_target_egress_nats=%d kernel_target_entries=%d kernel_rules_map_capacity=%d capacity_mode=%s %s",
		pm.cfg.DefaultEngine,
		countEnabledRules(rules),
		countEnabledRanges(ranges),
		countEnabledEgressNATs(egressNATs),
		countKernelRulePlans(rules, rulePlans),
		countKernelRangePlans(ranges, rangePlans),
		countKernelEgressNATPlans(egressNATs, egressNATPlans),
		len(activeKernelCandidates),
		effectiveKernelRulesMapLimit(configuredKernelRulesMapLimit, len(activeKernelCandidates)),
		kernelRulesMapCapacityMode(configuredKernelRulesMapLimit),
		kernelAdaptiveMapProfileLogFields(currentKernelAdaptiveMapProfile()),
	)

	kernelAssignments := map[int64]string{}
	if pm.kernelRuntime != nil {
		kernelAssignments = pm.kernelRuntime.SnapshotAssignments()
	}

	kernelAppliedRuleEngines := make(map[int64]string)
	kernelAppliedRangeEngines := make(map[int64]string)
	kernelAppliedEgressNATEngines := make(map[int64]string)
	kernelAppliedRules := make(map[int64]bool)
	kernelAppliedRanges := make(map[int64]bool)
	kernelAppliedEgressNATs := make(map[int64]bool)
	kernelFlowOwners := make(map[uint32]kernelCandidateOwner, len(activeKernelCandidates))
	for _, candidate := range activeKernelCandidates {
		if candidate.rule.ID <= 0 || candidate.rule.ID > int64(^uint32(0)) {
			continue
		}
		engine := strings.TrimSpace(kernelAssignments[candidate.rule.ID])
		if engine == "" {
			continue
		}
		if candidate.owner.kind == workerKindRule {
			kernelFlowOwners[uint32(candidate.rule.ID)] = candidate.owner
			kernelAppliedRules[candidate.owner.id] = true
			kernelAppliedRuleEngines[candidate.owner.id] = mergeKernelEngineName(kernelAppliedRuleEngines[candidate.owner.id], engine)
			continue
		}
		if candidate.owner.kind == workerKindEgressNAT {
			kernelFlowOwners[uint32(candidate.rule.ID)] = candidate.owner
			kernelAppliedEgressNATs[candidate.owner.id] = true
			kernelAppliedEgressNATEngines[candidate.owner.id] = mergeKernelEngineName(kernelAppliedEgressNATEngines[candidate.owner.id], engine)
			continue
		}
		kernelFlowOwners[uint32(candidate.rule.ID)] = candidate.owner
		kernelAppliedRanges[candidate.owner.id] = true
		kernelAppliedRangeEngines[candidate.owner.id] = mergeKernelEngineName(kernelAppliedRangeEngines[candidate.owner.id], engine)
	}

	pm.mu.Lock()
	pm.rulePlans = rulePlans
	pm.rangePlans = rangePlans
	pm.egressNATPlans = egressNATPlans
	pm.managedNetworkInterfaces = cloneManagedNetworkInterfaceSet(managedNetworkCompiled.RedistributeIfaces)
	pm.dynamicEgressNATParents = dynamicEgressNATParents
	pm.kernelRules = kernelAppliedRules
	pm.kernelRanges = kernelAppliedRanges
	pm.kernelEgressNATs = kernelAppliedEgressNATs
	pm.kernelRuleEngines = kernelAppliedRuleEngines
	pm.kernelRangeEngines = kernelAppliedRangeEngines
	pm.kernelEgressNATEngines = kernelAppliedEgressNATEngines
	pm.kernelFlowOwners = kernelFlowOwners
	pm.kernelRuleStats, pm.kernelRangeStats, pm.kernelEgressNATStats = pm.buildEmptyKernelStatsLocked()
	pm.kernelStatsSnapshot = emptyKernelRuleStatsSnapshot()
	pm.kernelStatsAt = time.Time{}
	pm.kernelStatsSnapshotAt = time.Time{}
	pm.kernelStatsLastDuration = 0
	pm.kernelStatsLastError = ""
	pm.kernelMaintenanceAt = time.Now()
	pm.kernelNetlinkOwnerRetryCooldownUntil = syncKernelNetlinkOwnerRetryCooldowns(pm.kernelNetlinkOwnerRetryCooldownUntil, time.Now(), rulePlans, rangePlans, egressNATPlans)
	pm.kernelNetlinkOwnerRetryFailures = syncKernelNetlinkOwnerRetryFailures(pm.kernelNetlinkOwnerRetryFailures, rulePlans, rangePlans, egressNATPlans)
	pm.mu.Unlock()

	enabledRules, enabledRanges, ruleAssignments, rangeAssignments := buildUserspaceAssignments(rules, ranges, rulePlans, rangePlans, pm.cfg.MaxWorkers)
	// Auto-configure transparent proxy routing BEFORE dispatching config to workers,
	// so iptables rules are in place before any worker starts using IP_TRANSPARENT sockets.
	pm.updateTransparentRouting(enabledRules, enabledRanges)

	pm.updateSharedProxy()

	pm.applyRuleAssignments(ruleAssignments)
	pm.applyRangeAssignments(rangeAssignments)
	if pm.kernelRuntime != nil {
		pm.refreshKernelStatsCacheIfNeeded()
	}
}

func (pm *ProcessManager) requestRedistributeWorkers(delay time.Duration) {
	if pm == nil {
		return
	}
	if delay < 0 {
		delay = 0
	}
	dueAt := time.Now().Add(delay)

	pm.mu.Lock()
	if pm.shuttingDown {
		pm.mu.Unlock()
		return
	}
	if !pm.redistributePending || dueAt.Before(pm.redistributeDueAt) {
		pm.redistributeDueAt = dueAt
	}
	pm.redistributePending = true
	wake := pm.redistributeWake
	pm.mu.Unlock()

	if wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (pm *ProcessManager) redistributeLoop() {
	defer close(pm.redistributeDone)

	var timer *time.Timer
	for {
		pm.mu.Lock()
		pending := pm.redistributePending
		dueAt := pm.redistributeDueAt
		wake := pm.redistributeWake
		shutdownCh := pm.shutdownCh
		shuttingDown := pm.shuttingDown
		pm.mu.Unlock()

		if shuttingDown {
			if timer != nil {
				stopTimer(timer)
			}
			return
		}

		if !pending {
			if timer != nil {
				stopTimer(timer)
				timer = nil
			}
			if wake == nil {
				return
			}
			select {
			case <-shutdownCh:
				return
			case _, ok := <-wake:
				if !ok {
					return
				}
			}
			continue
		}

		if wait := time.Until(dueAt); wait > 0 {
			if timer == nil {
				timer = time.NewTimer(wait)
			} else {
				resetTimer(timer, wait)
			}
			select {
			case <-shutdownCh:
				stopTimer(timer)
				return
			case _, ok := <-wake:
				if !ok {
					stopTimer(timer)
					return
				}
				continue
			case <-timer.C:
			}
		}

		pm.mu.Lock()
		if pm.shuttingDown {
			pm.mu.Unlock()
			if timer != nil {
				stopTimer(timer)
			}
			return
		}
		if !pm.redistributePending {
			pm.mu.Unlock()
			continue
		}
		if !pm.redistributeDueAt.IsZero() && time.Now().Before(pm.redistributeDueAt) {
			pm.mu.Unlock()
			continue
		}
		pm.redistributePending = false
		pm.redistributeDueAt = time.Time{}
		pm.mu.Unlock()

		if pm.isShuttingDown() {
			return
		}
		pm.redistributeWorkers()
	}
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

func (pm *ProcessManager) isShuttingDown() bool {
	if pm == nil {
		return true
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.shuttingDown
}

func (pm *ProcessManager) beginShutdown() {
	if pm == nil {
		return
	}
	pm.mu.Lock()
	if pm.shuttingDown {
		pm.mu.Unlock()
		return
	}
	pm.shuttingDown = true
	shutdownCh := pm.shutdownCh
	pm.mu.Unlock()

	if shutdownCh != nil {
		close(shutdownCh)
	}
}

func countEnabledEgressNATs(items []EgressNAT) int {
	count := 0
	for _, item := range items {
		if item.Enabled {
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

type kernelRuleFamilyFallbackCacheKey struct {
	inIP        string
	outIP       string
	transparent bool
}

type kernelRuleFamilyFallbackCache struct {
	firstKey   kernelRuleFamilyFallbackCacheKey
	firstValue string
	firstSet   bool
	byKey      map[kernelRuleFamilyFallbackCacheKey]string
}

func (c *kernelRuleFamilyFallbackCache) Reason(inIP string, outIP string, transparent bool) string {
	if c == nil {
		return kernelRuleFamilyFallbackReasonFromIPs(inIP, outIP, transparent)
	}
	key := kernelRuleFamilyFallbackCacheKey{
		inIP:        inIP,
		outIP:       outIP,
		transparent: transparent,
	}
	if c.firstSet {
		if key == c.firstKey {
			return c.firstValue
		}
		if reason, ok := c.byKey[key]; ok {
			return reason
		}
	}
	reason := kernelRuleFamilyFallbackReasonFromIPs(inIP, outIP, transparent)
	if !c.firstSet {
		c.firstKey = key
		c.firstValue = reason
		c.firstSet = true
		return reason
	}
	if c.byKey == nil {
		c.byKey = make(map[kernelRuleFamilyFallbackCacheKey]string, 8)
	}
	c.byKey[key] = reason
	return reason
}

var (
	kernelProtocolVariantTCP    = []string{"tcp"}
	kernelProtocolVariantUDP    = []string{"udp"}
	kernelProtocolVariantTCPUDP = []string{"tcp", "udp"}
)

func kernelProtocolVariants(protocol string) []string {
	switch protocol {
	case "tcp":
		return kernelProtocolVariantTCP
	case "udp":
		return kernelProtocolVariantUDP
	case "tcp+udp":
		return kernelProtocolVariantTCPUDP
	default:
		return nil
	}
}

func allocateSyntheticKernelRuleID(nextID *int64) (int64, error) {
	limit := int64(^uint32(0))
	if *nextID <= 0 {
		*nextID = 1
	}
	if *nextID > limit {
		return 0, fmt.Errorf("kernel dataplane synthetic rule ids exhausted uint32 range")
	}
	id := *nextID
	*nextID++
	return id, nil
}

func annotateKernelCandidateRule(item *Rule, owner kernelCandidateOwner) {
	if item == nil {
		return
	}
	item.kernelLogKind = owner.kind
	item.kernelLogOwnerID = owner.id
}

type kernelOwnerPlanAccumulator struct {
	plan        ruleDataplanePlan
	initialized bool
	allKernel   bool
	allEligible bool
}

func newKernelOwnerPlanAccumulator(preferred string) kernelOwnerPlanAccumulator {
	return kernelOwnerPlanAccumulator{
		plan: ruleDataplanePlan{
			PreferredEngine: preferred,
			EffectiveEngine: ruleEngineUserspace,
		},
		allKernel:   true,
		allEligible: true,
	}
}

func (a *kernelOwnerPlanAccumulator) Add(item ruleDataplanePlan) {
	if a == nil {
		return
	}
	a.initialized = true
	if !item.KernelEligible {
		a.allEligible = false
		if a.plan.KernelReason == "" {
			a.plan.KernelReason = item.KernelReason
		}
	}
	if item.EffectiveEngine != ruleEngineKernel {
		a.allKernel = false
		if a.plan.FallbackReason == "" && item.FallbackReason != "" {
			a.plan.FallbackReason = item.FallbackReason
			a.plan.TransientFallback = item.TransientFallback
		}
	}
}

func (a kernelOwnerPlanAccumulator) Result() ruleDataplanePlan {
	if !a.initialized {
		return a.plan
	}
	a.plan.KernelEligible = a.allEligible
	if a.allKernel {
		a.plan.EffectiveEngine = ruleEngineKernel
	}
	return a.plan
}

func aggregateKernelOwnerPlan(preferred string, entryPlans []ruleDataplanePlan) ruleDataplanePlan {
	acc := newKernelOwnerPlanAccumulator(preferred)
	for _, item := range entryPlans {
		acc.Add(item)
	}
	return acc.Result()
}

func sampleKernelRangePlan(pr PortRange, variants []string, planner *ruleDataplanePlanner, preferred string, kernelReason string) rangeDataplanePlan {
	acc := newKernelOwnerPlanAccumulator(preferred)
	baseRule := Rule{
		ID:               1,
		InInterface:      pr.InInterface,
		InIP:             pr.InIP,
		InPort:           pr.StartPort,
		OutInterface:     pr.OutInterface,
		OutIP:            pr.OutIP,
		OutSourceIP:      pr.OutSourceIP,
		OutPort:          pr.OutStartPort,
		Remark:           pr.Remark,
		Tag:              pr.Tag,
		Enabled:          pr.Enabled,
		Transparent:      pr.Transparent,
		EnginePreference: ruleEngineAuto,
	}
	for _, proto := range variants {
		item := baseRule
		item.Protocol = proto
		acc.Add(planner.planWithPreferredAndKernelReason(item, preferred, kernelReason))
	}
	return acc.Result()
}

func applyKernelOwnerFallback(owner kernelCandidateOwner, reason string, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan, egressNATPlans map[int64]ruleDataplanePlan) {
	applyKernelOwnerFallbackWithMetadata(owner, reason, kernelTransientFallbackMetadata{}, rulePlans, rangePlans, egressNATPlans)
}

func applyKernelOwnerFallbackWithMetadata(owner kernelCandidateOwner, reason string, metadata kernelTransientFallbackMetadata, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan, egressNATPlans map[int64]ruleDataplanePlan) {
	if owner.kind == workerKindRule {
		plan := rulePlans[owner.id]
		plan.EffectiveEngine = ruleEngineUserspace
		if plan.FallbackReason == "" {
			plan.FallbackReason = reason
			plan.TransientFallback = metadata
		}
		rulePlans[owner.id] = plan
		return
	}
	if owner.kind == workerKindEgressNAT {
		plan := egressNATPlans[owner.id]
		plan.EffectiveEngine = ruleEngineUserspace
		if plan.FallbackReason == "" {
			plan.FallbackReason = reason
			plan.TransientFallback = metadata
		}
		egressNATPlans[owner.id] = plan
		return
	}

	plan := rangePlans[owner.id]
	plan.EffectiveEngine = ruleEngineUserspace
	if plan.FallbackReason == "" {
		plan.FallbackReason = reason
		plan.TransientFallback = metadata
	}
	rangePlans[owner.id] = plan
}

type kernelPressureOwnerInfo struct {
	owner    kernelCandidateOwner
	previous bool
	entries  int
}

func applyKernelPressurePolicy(snapshot kernelRuntimePressureSnapshot, candidates []kernelCandidateRule, previousKernelRules map[int64]bool, previousKernelRanges map[int64]bool, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan) {
	level := snapshot.level()
	if !level.active() {
		return
	}

	owners := collectKernelPressureOwners(candidates, previousKernelRules, previousKernelRanges, rulePlans, rangePlans)
	if len(owners) == 0 {
		return
	}

	reason := strings.TrimSpace(snapshot.Reason)
	if reason == "" {
		reason = "kernel dataplane pressure"
	}

	switch level {
	case kernelRuntimePressureLevelHold:
		for _, item := range owners {
			if item.previous {
				continue
			}
			applyKernelOwnerFallback(item.owner, reason, rulePlans, rangePlans, nil)
		}
	case kernelRuntimePressureLevelShed:
		targetFallbackEntries := kernelPressureShedTargetEntries(owners)
		fallbackEntries := 0
		previousOwners := make([]kernelPressureOwnerInfo, 0, len(owners))
		for _, item := range owners {
			if item.previous {
				previousOwners = append(previousOwners, item)
				continue
			}
			applyKernelOwnerFallback(item.owner, reason, rulePlans, rangePlans, nil)
			fallbackEntries += item.entries
		}
		remainingPrevious := len(previousOwners)
		mustKeepPrevious := 0
		if remainingPrevious > 0 {
			mustKeepPrevious = 1
		}
		for idx := len(previousOwners) - 1; idx >= 0 && fallbackEntries < targetFallbackEntries; idx-- {
			if remainingPrevious <= mustKeepPrevious {
				break
			}
			item := previousOwners[idx]
			applyKernelOwnerFallback(item.owner, reason, rulePlans, rangePlans, nil)
			fallbackEntries += item.entries
			remainingPrevious--
		}
	case kernelRuntimePressureLevelFull:
		for _, item := range owners {
			applyKernelOwnerFallback(item.owner, reason, rulePlans, rangePlans, nil)
		}
	}
}

func collectKernelPressureOwners(candidates []kernelCandidateRule, previousKernelRules map[int64]bool, previousKernelRanges map[int64]bool, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan) []kernelPressureOwnerInfo {
	byOwner := make(map[kernelCandidateOwner]*kernelPressureOwnerInfo, len(candidates))
	for _, candidate := range candidates {
		if kernelOwnerEffectiveEngine(candidate.owner, rulePlans, rangePlans, nil) != ruleEngineKernel {
			continue
		}
		item := byOwner[candidate.owner]
		if item == nil {
			item = &kernelPressureOwnerInfo{
				owner:    candidate.owner,
				previous: isPreviousKernelOwner(candidate.owner, previousKernelRules, previousKernelRanges),
			}
			byOwner[candidate.owner] = item
		}
		item.entries++
	}
	owners := make([]kernelPressureOwnerInfo, 0, len(byOwner))
	for _, item := range byOwner {
		owners = append(owners, *item)
	}
	sort.Slice(owners, func(i, j int) bool {
		if owners[i].owner.kind != owners[j].owner.kind {
			return owners[i].owner.kind < owners[j].owner.kind
		}
		return owners[i].owner.id < owners[j].owner.id
	})
	return owners
}

func isPreviousKernelOwner(owner kernelCandidateOwner, previousKernelRules map[int64]bool, previousKernelRanges map[int64]bool) bool {
	if owner.kind == workerKindRule {
		return previousKernelRules[owner.id]
	}
	return previousKernelRanges[owner.id]
}

func kernelPressureShedTargetEntries(owners []kernelPressureOwnerInfo) int {
	totalEntries := 0
	for _, item := range owners {
		totalEntries += item.entries
	}
	if totalEntries <= 1 {
		return totalEntries
	}
	fallbackEntries := totalEntries / kernelRuntimePressureShedFallbackDivisor
	if fallbackEntries < 1 {
		return 1
	}
	if fallbackEntries >= totalEntries {
		return totalEntries - 1
	}
	return fallbackEntries
}

func kernelOwnerEffectiveEngine(owner kernelCandidateOwner, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan, egressNATPlans map[int64]ruleDataplanePlan) string {
	if owner.kind == workerKindRule {
		return rulePlans[owner.id].EffectiveEngine
	}
	if owner.kind == workerKindEgressNAT {
		return egressNATPlans[owner.id].EffectiveEngine
	}
	return rangePlans[owner.id].EffectiveEngine
}

func buildKernelCandidateRules(rules []Rule, ranges []PortRange, planner *ruleDataplanePlanner, configuredKernelRulesMapLimit int) ([]kernelCandidateRule, map[int64]ruleDataplanePlan, map[int64]rangeDataplanePlan) {
	rulePlans := make(map[int64]ruleDataplanePlan, len(rules))
	rangePlans := make(map[int64]rangeDataplanePlan, len(ranges))
	familyFallbackCache := kernelRuleFamilyFallbackCache{}

	maxRuleID := int64(0)
	ruleCandidateCapacity := 0
	for _, rule := range rules {
		if rule.ID > maxRuleID {
			maxRuleID = rule.ID
		}
		if !rule.Enabled {
			continue
		}
		ruleCandidateCapacity += len(kernelProtocolVariants(rule.Protocol))
	}
	nextSyntheticID := maxRuleID + 1

	candidates := make([]kernelCandidateRule, 0, ruleCandidateCapacity)
	reservedKernelEntries := 0

	for _, rule := range rules {
		owner := kernelCandidateOwner{kind: workerKindRule, id: rule.ID}
		preferred := planner.resolvePreferredEngine(rule.EnginePreference)
		kernelReason := familyFallbackCache.Reason(rule.InIP, rule.OutIP, rule.Transparent)
		variants := kernelProtocolVariants(rule.Protocol)
		if len(variants) == 0 {
			plan := planner.planWithPreferredAndKernelReason(rule, preferred, kernelReason)
			rulePlans[rule.ID] = plan
			continue
		}

		var entryCandidates [2]kernelCandidateRule
		entryCount := 0
		acc := newKernelOwnerPlanAccumulator(preferred)
		for idx, proto := range variants {
			item := rule
			item.Protocol = proto
			if idx > 0 {
				id, err := allocateSyntheticKernelRuleID(&nextSyntheticID)
				if err != nil {
					acc.Add(ruleDataplanePlan{
						PreferredEngine: preferred,
						EffectiveEngine: ruleEngineUserspace,
						FallbackReason:  err.Error(),
					})
					continue
				}
				item.ID = id
			}
			annotateKernelCandidateRule(&item, owner)
			acc.Add(planner.planWithPreferredAndKernelReason(item, preferred, kernelReason))
			entryCandidates[entryCount] = kernelCandidateRule{owner: owner, rule: item}
			entryCount++
		}

		plan := acc.Result()
		if rule.Enabled && plan.EffectiveEngine == ruleEngineKernel {
			neededEntries := entryCount
			requestedEntries := reservedKernelEntries + neededEntries
			if requestedEntries > effectiveKernelRulesMapLimit(configuredKernelRulesMapLimit, requestedEntries) {
				plan.EffectiveEngine = ruleEngineUserspace
				if plan.FallbackReason == "" {
					plan.FallbackReason = kernelRulesCapacityReason(configuredKernelRulesMapLimit, requestedEntries)
				}
			} else {
				candidates = append(candidates, entryCandidates[:entryCount]...)
				reservedKernelEntries += neededEntries
			}
		}
		rulePlans[rule.ID] = plan
	}

	rangePreferred := planner.resolvePreferredEngine("")
	for _, pr := range ranges {
		owner := kernelCandidateOwner{kind: workerKindRange, id: pr.ID}
		kernelReason := familyFallbackCache.Reason(pr.InIP, pr.OutIP, pr.Transparent)
		variants := kernelProtocolVariants(pr.Protocol)
		if len(variants) == 0 {
			rangePlans[pr.ID] = rangeDataplanePlan{
				PreferredEngine: rangePreferred,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  "kernel dataplane currently supports only single-protocol TCP/UDP rules",
			}
			continue
		}

		totalEntries := (pr.EndPort - pr.StartPort + 1) * len(variants)
		requestedEntries := reservedKernelEntries + totalEntries
		if pr.Enabled && requestedEntries > effectiveKernelRulesMapLimit(configuredKernelRulesMapLimit, requestedEntries) {
			plan := sampleKernelRangePlan(pr, variants, planner, rangePreferred, kernelReason)
			if plan.EffectiveEngine == ruleEngineKernel {
				plan.EffectiveEngine = ruleEngineUserspace
				if plan.FallbackReason == "" {
					plan.FallbackReason = kernelRulesCapacityReason(configuredKernelRulesMapLimit, requestedEntries)
				}
			}
			rangePlans[pr.ID] = plan
			continue
		}
		if pr.Enabled {
			candidates = growKernelCandidateBuffer(candidates, totalEntries)
		}
		acc := newKernelOwnerPlanAccumulator(rangePreferred)
		candidateStart := len(candidates)
		allExpanded := true
		baseRule := Rule{
			InInterface:      pr.InInterface,
			InIP:             pr.InIP,
			OutInterface:     pr.OutInterface,
			OutIP:            pr.OutIP,
			OutSourceIP:      pr.OutSourceIP,
			Remark:           pr.Remark,
			Tag:              pr.Tag,
			Enabled:          pr.Enabled,
			Transparent:      pr.Transparent,
			EnginePreference: ruleEngineAuto,
			kernelLogKind:    owner.kind,
			kernelLogOwnerID: owner.id,
		}
		for port := pr.StartPort; port <= pr.EndPort; port++ {
			outPort := pr.OutStartPort + (port - pr.StartPort)
			for _, proto := range variants {
				id, err := allocateSyntheticKernelRuleID(&nextSyntheticID)
				if err != nil {
					acc.Add(ruleDataplanePlan{
						PreferredEngine: rangePreferred,
						EffectiveEngine: ruleEngineUserspace,
						FallbackReason:  err.Error(),
					})
					allExpanded = false
					continue
				}

				item := baseRule
				item.ID = id
				item.InPort = port
				item.OutPort = outPort
				item.Protocol = proto
				acc.Add(planner.planWithPreferredAndKernelReason(item, rangePreferred, kernelReason))
				if pr.Enabled {
					candidates = append(candidates, kernelCandidateRule{owner: owner, rule: item})
				}
			}
		}

		plan := acc.Result()
		if !allExpanded && plan.FallbackReason == "" {
			plan.FallbackReason = "kernel dataplane synthetic rule expansion failed"
		}
		rangePlans[pr.ID] = plan
		if pr.Enabled && plan.EffectiveEngine == ruleEngineKernel {
			reservedKernelEntries += len(candidates) - candidateStart
			continue
		}
		candidates = candidates[:candidateStart]
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
		if kernelOwnerEffectiveEngine(candidate.owner, rulePlans, rangePlans, nil) != ruleEngineKernel {
			continue
		}
		if !candidate.rule.Transparent {
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
			applyKernelOwnerFallback(owner, "transparent kernel dataplane requires a unique backend endpoint per active protocol binding", rulePlans, rangePlans, nil)
		}
	}
}

func countActiveKernelCandidates(candidates []kernelCandidateRule, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan, egressNATPlans map[int64]ruleDataplanePlan) int {
	count := 0
	for _, candidate := range candidates {
		if kernelOwnerEffectiveEngine(candidate.owner, rulePlans, rangePlans, egressNATPlans) == ruleEngineKernel {
			count++
		}
	}
	return count
}

func growKernelCandidateBuffer(candidates []kernelCandidateRule, additional int) []kernelCandidateRule {
	if additional <= 0 {
		return candidates
	}
	required := len(candidates) + additional
	if required <= cap(candidates) {
		return candidates
	}
	newCap := cap(candidates) * 2
	if newCap < required {
		newCap = required
	}
	if newCap <= 0 {
		newCap = additional
	}
	grown := make([]kernelCandidateRule, len(candidates), newCap)
	copy(grown, candidates)
	return grown
}

func filterActiveKernelCandidatesInto(dst []kernelCandidateRule, candidates []kernelCandidateRule, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan, egressNATPlans map[int64]ruleDataplanePlan) []kernelCandidateRule {
	var out []kernelCandidateRule
	if cap(dst) >= len(candidates) {
		out = dst[:0]
	} else {
		out = make([]kernelCandidateRule, 0, len(candidates))
	}
	for _, candidate := range candidates {
		if kernelOwnerEffectiveEngine(candidate.owner, rulePlans, rangePlans, egressNATPlans) == ruleEngineKernel {
			out = append(out, candidate)
		}
	}
	return out
}

func filterActiveKernelCandidates(candidates []kernelCandidateRule, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan, egressNATPlans map[int64]ruleDataplanePlan) []kernelCandidateRule {
	return filterActiveKernelCandidatesInto(nil, candidates, rulePlans, rangePlans, egressNATPlans)
}

func kernelCandidateRulesInto(dst []Rule, candidates []kernelCandidateRule) []Rule {
	var out []Rule
	if cap(dst) >= len(candidates) {
		out = dst[:0]
	} else {
		out = make([]Rule, 0, len(candidates))
	}
	for _, candidate := range candidates {
		out = append(out, candidate.rule)
	}
	return out
}

func kernelCandidateRules(candidates []kernelCandidateRule) []Rule {
	return kernelCandidateRulesInto(nil, candidates)
}

func splitKernelFailureReason(reason string) []string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil
	}
	parts := strings.Split(reason, "; ")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return []string{reason}
	}
	return out
}

func appendKernelFailureReasons(dst []string, reason string) []string {
	for _, part := range splitKernelFailureReason(reason) {
		exists := false
		for _, current := range dst {
			if current == part {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		dst = append(dst, part)
	}
	return dst
}

func collectKernelOwnerFailures(candidates []kernelCandidateRule, results map[int64]kernelRuleApplyResult, err error) map[kernelCandidateOwner]string {
	reasonsByOwner := make(map[kernelCandidateOwner][]string)
	if err != nil {
		for _, candidate := range candidates {
			reasonsByOwner[candidate.owner] = appendKernelFailureReasons(reasonsByOwner[candidate.owner], err.Error())
		}
	} else {
		for _, candidate := range candidates {
			result, ok := results[candidate.rule.ID]
			if ok && result.Running {
				continue
			}

			reason := "kernel dataplane did not report a running state"
			if ok && result.Error != "" {
				reason = result.Error
			}
			reasonsByOwner[candidate.owner] = appendKernelFailureReasons(reasonsByOwner[candidate.owner], reason)
		}
	}

	failures := make(map[kernelCandidateOwner]string, len(reasonsByOwner))
	for owner, reasons := range reasonsByOwner {
		if len(reasons) == 0 {
			continue
		}
		failures[owner] = strings.Join(reasons, "; ")
	}
	return failures
}

func collectKernelOwnerFallbackMetadata(candidates []kernelCandidateRule, reasons map[kernelCandidateOwner]string) map[kernelCandidateOwner]kernelTransientFallbackMetadata {
	if len(candidates) == 0 || len(reasons) == 0 {
		return nil
	}
	ownerRules := make(map[kernelCandidateOwner]Rule, len(reasons))
	for _, candidate := range candidates {
		if _, ok := reasons[candidate.owner]; !ok {
			continue
		}
		if _, exists := ownerRules[candidate.owner]; exists {
			continue
		}
		ownerRules[candidate.owner] = candidate.rule
	}
	if len(ownerRules) == 0 {
		return nil
	}

	out := make(map[kernelCandidateOwner]kernelTransientFallbackMetadata, len(ownerRules))
	for owner, reason := range reasons {
		rule, ok := ownerRules[owner]
		if !ok {
			continue
		}
		metadata := kernelTransientFallbackMetadataForRule(rule, reason)
		if metadata.ReasonClass == "" {
			continue
		}
		out[owner] = metadata
	}
	return out
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

func countKernelEgressNATPlans(items []EgressNAT, plans map[int64]ruleDataplanePlan) int {
	count := 0
	for _, item := range items {
		if !item.Enabled {
			continue
		}
		if plan, ok := plans[item.ID]; ok && plan.EffectiveEngine == ruleEngineKernel {
			count++
		}
	}
	return count
}

func (pm *ProcessManager) logRangeDataplanePlans(ranges []PortRange, plans map[int64]rangeDataplanePlan, defaultEngine string) {
	if len(ranges) == 0 || len(plans) == 0 {
		pm.lastRangePlanLog = make(map[int64]string)
		return
	}

	ordered := make([]PortRange, 0, len(ranges))
	for _, pr := range ranges {
		if pr.Enabled {
			ordered = append(ordered, pr)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	next := make(map[int64]string, len(ordered))
	for _, pr := range ordered {
		plan, ok := plans[pr.ID]
		if !ok {
			continue
		}
		line := formatRangeDataplanePlanLog(pr, plan, defaultEngine)
		if line == "" {
			continue
		}
		next[pr.ID] = line
		if pm.lastRangePlanLog[pr.ID] != line {
			log.Print(line)
		}
	}
	pm.lastRangePlanLog = next
}

func (pm *ProcessManager) logRuleDataplanePlans(rules []Rule, plans map[int64]ruleDataplanePlan, defaultEngine string) {
	if len(rules) == 0 || len(plans) == 0 {
		pm.lastRulePlanLog = make(map[int64]string)
		return
	}

	ordered := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if rule.Enabled {
			ordered = append(ordered, rule)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	next := make(map[int64]string, len(ordered))
	for _, rule := range ordered {
		plan, ok := plans[rule.ID]
		if !ok {
			continue
		}
		line := formatRuleDataplanePlanLog(rule, plan, defaultEngine)
		if line == "" {
			continue
		}
		next[rule.ID] = line
		if pm.lastRulePlanLog[rule.ID] != line {
			log.Print(line)
		}
	}
	pm.lastRulePlanLog = next
}

func (pm *ProcessManager) logPlannerSummary(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	if line == pm.lastPlannerSummary {
		return
	}
	pm.lastPlannerSummary = line
	log.Print(line)
}

func formatRangeDataplanePlanLog(pr PortRange, plan rangeDataplanePlan, defaultEngine string) string {
	shouldLog := plan.EffectiveEngine == ruleEngineKernel || plan.KernelEligible || plan.KernelReason != "" || plan.FallbackReason != ""
	if !shouldLog {
		return ""
	}
	if plan.EffectiveEngine == ruleEngineKernel {
		return fmt.Sprintf("kernel dataplane range plan: range=%d preferred=%s effective=%s eligible=%t reason=%q in=%s:%d-%d out=%s:%d transparent=%t",
			pr.ID, plan.PreferredEngine, plan.EffectiveEngine, plan.KernelEligible, plan.KernelReason,
			pr.InIP, pr.StartPort, pr.EndPort, pr.OutIP, pr.OutStartPort, pr.Transparent)
	}
	return fmt.Sprintf("kernel dataplane range fallback: range=%d default_engine=%s preferred=%s effective=%s eligible=%t kernel_reason=%q fallback=%q in=%s:%d-%d out=%s:%d transparent=%t",
		pr.ID, defaultEngine, plan.PreferredEngine, plan.EffectiveEngine, plan.KernelEligible, plan.KernelReason, plan.FallbackReason,
		pr.InIP, pr.StartPort, pr.EndPort, pr.OutIP, pr.OutStartPort, pr.Transparent)
}

func formatRuleDataplanePlanLog(rule Rule, plan ruleDataplanePlan, defaultEngine string) string {
	shouldLog := plan.EffectiveEngine == ruleEngineKernel || plan.KernelEligible || plan.KernelReason != "" || plan.FallbackReason != ""
	if !shouldLog {
		return ""
	}
	if plan.EffectiveEngine == ruleEngineKernel {
		return fmt.Sprintf("kernel dataplane plan: rule=%d preferred=%s effective=%s eligible=%t reason=%q in=%s:%d out=%s:%d transparent=%t",
			rule.ID, plan.PreferredEngine, plan.EffectiveEngine, plan.KernelEligible, plan.KernelReason,
			rule.InIP, rule.InPort, rule.OutIP, rule.OutPort, rule.Transparent)
	}
	return fmt.Sprintf("kernel dataplane fallback: rule=%d default_engine=%s preferred=%s effective=%s eligible=%t kernel_reason=%q fallback=%q in=%s:%d out=%s:%d transparent=%t",
		rule.ID, defaultEngine, plan.PreferredEngine, plan.EffectiveEngine, plan.KernelEligible, plan.KernelReason, plan.FallbackReason,
		rule.InIP, rule.InPort, rule.OutIP, rule.OutPort, rule.Transparent)
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

func retainRuleStatsReports(current map[int64]RuleStatsReport, rules []Rule) map[int64]RuleStatsReport {
	next := make(map[int64]RuleStatsReport, len(rules))
	for _, rule := range rules {
		if current == nil {
			continue
		}
		if stats, ok := current[rule.ID]; ok {
			next[rule.ID] = stats
		}
	}
	return next
}

func retainRangeStatsReports(current map[int64]RangeStatsReport, ranges []PortRange) map[int64]RangeStatsReport {
	next := make(map[int64]RangeStatsReport, len(ranges))
	for _, pr := range ranges {
		if current == nil {
			continue
		}
		if stats, ok := current[pr.ID]; ok {
			next[pr.ID] = stats
		}
	}
	return next
}

func snapshotRuleWorkerStats(workers map[int]*WorkerInfo) map[int64]RuleStatsReport {
	snap := make(map[int64]RuleStatsReport)
	for _, wi := range workers {
		for id, stats := range wi.ruleStats {
			snap[id] = stats
		}
	}
	return snap
}

func snapshotRangeWorkerStats(workers map[int]*WorkerInfo) map[int64]RangeStatsReport {
	snap := make(map[int64]RangeStatsReport)
	for _, wi := range workers {
		for id, stats := range wi.rangeStats {
			snap[id] = stats
		}
	}
	return snap
}

func buildUserspaceAssignments(rules []Rule, ranges []PortRange, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan, totalWorkers int) ([]Rule, []PortRange, [][]Rule, [][]PortRange) {
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
		for _, r := range enabledRules {
			idx := stableWorkerSlotForID(r.ID, ruleCount)
			ruleAssignments[idx] = append(ruleAssignments[idx], r)
		}
		for idx := range ruleAssignments {
			sort.Slice(ruleAssignments[idx], func(i, j int) bool {
				return ruleAssignments[idx][i].ID < ruleAssignments[idx][j].ID
			})
		}
	}

	rangeAssignments := make([][]PortRange, rangeCount)
	if rangeCount > 0 {
		for _, pr := range enabledRanges {
			idx := stableWorkerSlotForID(pr.ID, rangeCount)
			rangeAssignments[idx] = append(rangeAssignments[idx], pr)
		}
		for idx := range rangeAssignments {
			sort.Slice(rangeAssignments[idx], func(i, j int) bool {
				return rangeAssignments[idx][i].ID < rangeAssignments[idx][j].ID
			})
		}
	}

	return enabledRules, enabledRanges, ruleAssignments, rangeAssignments
}

func stableWorkerSlotForID(id int64, slots int) int {
	if slots <= 1 {
		return 0
	}
	u := uint64(id)
	u ^= u >> 33
	u *= 0xff51afd7ed558ccd
	u ^= u >> 33
	u *= 0xc4ceb9fe1a85ec53
	u ^= u >> 33
	return int(u % uint64(slots))
}

func collectKernelToUserspaceRuleIDs(rules []Rule, previous map[int64]bool, plans map[int64]ruleDataplanePlan) map[int64]struct{} {
	out := make(map[int64]struct{})
	for _, rule := range rules {
		if !rule.Enabled || !previous[rule.ID] {
			continue
		}
		if plan, ok := plans[rule.ID]; ok && plan.EffectiveEngine != ruleEngineKernel {
			out[rule.ID] = struct{}{}
		}
	}
	return out
}

func collectKernelToUserspaceRangeIDs(ranges []PortRange, previous map[int64]bool, plans map[int64]rangeDataplanePlan) map[int64]struct{} {
	out := make(map[int64]struct{})
	for _, pr := range ranges {
		if !pr.Enabled || !previous[pr.ID] {
			continue
		}
		if plan, ok := plans[pr.ID]; ok && plan.EffectiveEngine != ruleEngineKernel {
			out[pr.ID] = struct{}{}
		}
	}
	return out
}

func collectRuleWorkerIndexesForIDs(assignments [][]Rule, ids map[int64]struct{}) []int {
	if len(ids) == 0 {
		return nil
	}
	var out []int
	for idx, rules := range assignments {
		for _, rule := range rules {
			if _, ok := ids[rule.ID]; !ok {
				continue
			}
			out = append(out, idx)
			break
		}
	}
	return out
}

func collectRangeWorkerIndexesForIDs(assignments [][]PortRange, ids map[int64]struct{}) []int {
	if len(ids) == 0 {
		return nil
	}
	var out []int
	for idx, ranges := range assignments {
		for _, pr := range ranges {
			if _, ok := ids[pr.ID]; !ok {
				continue
			}
			out = append(out, idx)
			break
		}
	}
	return out
}

func (pm *ProcessManager) waitForUserspaceWorkers(ruleIndexes []int, rangeIndexes []int, timeout time.Duration) bool {
	if len(ruleIndexes) == 0 && len(rangeIndexes) == 0 {
		return true
	}
	deadline := time.Now().Add(timeout)
	for {
		ready := true

		pm.mu.Lock()
		for _, idx := range ruleIndexes {
			wi := pm.ruleWorkers[idx]
			if wi == nil || len(wi.rules) == 0 {
				continue
			}
			if !wi.running {
				ready = false
				break
			}
		}
		if ready {
			for _, idx := range rangeIndexes {
				wi := pm.rangeWorkers[idx]
				if wi == nil || len(wi.ranges) == 0 {
					continue
				}
				if !wi.running {
					ready = false
					break
				}
			}
		}
		pm.mu.Unlock()

		if ready {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(kernelUserspaceWarmupPoll)
	}
}

func (pm *ProcessManager) prewarmKernelToUserspaceHandoffs(rules []Rule, ranges []PortRange, candidates []kernelCandidateRule, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan) []kernelCandidateRule {
	if pm.kernelRuntime == nil || pm.cfg == nil {
		return candidates
	}

	pm.mu.Lock()
	previousKernelRules := make(map[int64]bool, len(pm.kernelRules))
	for id, ok := range pm.kernelRules {
		previousKernelRules[id] = ok
	}
	previousKernelRanges := make(map[int64]bool, len(pm.kernelRanges))
	for id, ok := range pm.kernelRanges {
		previousKernelRanges[id] = ok
	}
	pm.mu.Unlock()

	transitionRuleIDs := collectKernelToUserspaceRuleIDs(rules, previousKernelRules, rulePlans)
	transitionRangeIDs := collectKernelToUserspaceRangeIDs(ranges, previousKernelRanges, rangePlans)
	if len(transitionRuleIDs) == 0 && len(transitionRangeIDs) == 0 {
		return candidates
	}

	enabledRules, enabledRanges, ruleAssignments, rangeAssignments := buildUserspaceAssignments(rules, ranges, rulePlans, rangePlans, pm.cfg.MaxWorkers)
	ruleWorkerIndexes := collectRuleWorkerIndexesForIDs(ruleAssignments, transitionRuleIDs)
	rangeWorkerIndexes := collectRangeWorkerIndexesForIDs(rangeAssignments, transitionRangeIDs)
	if len(ruleWorkerIndexes) == 0 && len(rangeWorkerIndexes) == 0 {
		return candidates
	}

	pm.updateTransparentRouting(enabledRules, enabledRanges)
	pm.applyRuleAssignments(ruleAssignments)
	pm.applyRangeAssignments(rangeAssignments)
	if pm.waitForUserspaceWorkers(ruleWorkerIndexes, rangeWorkerIndexes, kernelUserspaceWarmupTimeout) {
		log.Printf("kernel to userspace handoff warmup complete: rule_workers=%d range_workers=%d", len(ruleWorkerIndexes), len(rangeWorkerIndexes))
		return candidates
	}
	candidates, preservedRules, preservedRanges, remainingRules, remainingRanges := preserveKernelOwnersOnWarmupTimeout(pm.kernelRuntime, rules, ranges, candidates, transitionRuleIDs, transitionRangeIDs, rulePlans, rangePlans)
	log.Printf(
		"kernel to userspace handoff warmup timed out: rule_workers=%d range_workers=%d preserved_rules=%d preserved_ranges=%d remaining_userspace_rules=%d remaining_userspace_ranges=%d",
		len(ruleWorkerIndexes),
		len(rangeWorkerIndexes),
		preservedRules,
		preservedRanges,
		remainingRules,
		remainingRanges,
	)
	return candidates
}

func preserveKernelOwnersOnWarmupTimeout(runtime kernelRuleRuntime, rules []Rule, ranges []PortRange, candidates []kernelCandidateRule, transitionRuleIDs map[int64]struct{}, transitionRangeIDs map[int64]struct{}, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan) ([]kernelCandidateRule, int, int, int, int) {
	retainer, ok := runtime.(kernelHandoffRetentionRuntime)
	if !ok || retainer == nil {
		return candidates, 0, 0, len(transitionRuleIDs), len(transitionRangeIDs)
	}

	ruleByID := make(map[int64]Rule, len(rules))
	for _, rule := range rules {
		ruleByID[rule.ID] = rule
	}
	rangeByID := make(map[int64]PortRange, len(ranges))
	for _, pr := range ranges {
		rangeByID[pr.ID] = pr
	}

	existingCandidateRuleIDs := make(map[int64]struct{}, len(candidates))
	for _, candidate := range candidates {
		existingCandidateRuleIDs[candidate.rule.ID] = struct{}{}
	}

	preservedRules := 0
	remainingRules := 0
	for id := range transitionRuleIDs {
		plan, ok := rulePlans[id]
		if !ok || plan.EffectiveEngine == ruleEngineKernel {
			continue
		}
		rule, exists := ruleByID[id]
		if !exists {
			remainingRules++
			continue
		}
		retainedCandidates, retainable := retainer.retainedKernelRuleCandidates(rule)
		if !retainable || !canAppendRetainedKernelCandidates(existingCandidateRuleIDs, retainedCandidates) {
			remainingRules++
			continue
		}
		plan.EffectiveEngine = ruleEngineKernel
		plan.FallbackReason = ""
		rulePlans[id] = plan
		candidates = appendRetainedKernelCandidates(candidates, existingCandidateRuleIDs, kernelCandidateOwner{kind: workerKindRule, id: id}, retainedCandidates)
		preservedRules++
	}

	preservedRanges := 0
	remainingRanges := 0
	for id := range transitionRangeIDs {
		plan, ok := rangePlans[id]
		if !ok || plan.EffectiveEngine == ruleEngineKernel {
			continue
		}
		pr, exists := rangeByID[id]
		if !exists {
			remainingRanges++
			continue
		}
		retainedCandidates, retainable := retainer.retainedKernelRangeCandidates(pr)
		if !retainable || !canAppendRetainedKernelCandidates(existingCandidateRuleIDs, retainedCandidates) {
			remainingRanges++
			continue
		}
		plan.EffectiveEngine = ruleEngineKernel
		plan.FallbackReason = ""
		rangePlans[id] = plan
		candidates = appendRetainedKernelCandidates(candidates, existingCandidateRuleIDs, kernelCandidateOwner{kind: workerKindRange, id: id}, retainedCandidates)
		preservedRanges++
	}

	return candidates, preservedRules, preservedRanges, remainingRules, remainingRanges
}

func appendRetainedKernelCandidates(candidates []kernelCandidateRule, existing map[int64]struct{}, owner kernelCandidateOwner, retained []Rule) []kernelCandidateRule {
	for _, rule := range retained {
		existing[rule.ID] = struct{}{}
		candidates = append(candidates, kernelCandidateRule{
			owner: owner,
			rule:  rule,
		})
	}
	return candidates
}

func canAppendRetainedKernelCandidates(existing map[int64]struct{}, retained []Rule) bool {
	if len(retained) == 0 {
		return false
	}
	for _, rule := range retained {
		if _, ok := existing[rule.ID]; ok {
			return false
		}
	}
	return true
}

func (pm *ProcessManager) applyRuleAssignments(assignments [][]Rule) {
	desired := len(assignments)
	toStart := make(map[int]struct{})
	var toStop []*WorkerInfo
	var toUpdate []*WorkerInfo

	pm.mu.Lock()
	existingStats := snapshotRuleWorkerStats(pm.ruleWorkers)
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
				ruleStats:   retainRuleStatsReports(existingStats, rules),
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
			wi.ruleStats = retainRuleStatsReports(existingStats, rules)
			wi.running = false
			resetWorkerRetryState(wi)
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
	existingStats := snapshotRangeWorkerStats(pm.rangeWorkers)
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
			wi = &WorkerInfo{
				workerIndex:  idx,
				kind:         workerKindRange,
				ranges:       ranges,
				failedRanges: make(map[int64]bool),
				rangeStats:   retainRangeStatsReports(existingStats, ranges),
				lastStart:    time.Now(),
			}
			pm.rangeWorkers[idx] = wi
			if pm.ready {
				toStart[idx] = struct{}{}
			}
			continue
		}
		if !rangesEqual(wi.ranges, ranges) {
			wi.ranges = ranges
			wi.failedRanges = make(map[int64]bool)
			wi.rangeStats = retainRangeStatsReports(existingStats, ranges)
			wi.running = false
			resetWorkerRetryState(wi)
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
		if !sameUserspaceRuleConfig(a[i], b[i]) {
			return false
		}
	}
	return true
}

func ruleAssignmentSlicesEqual(a, b [][]Rule) bool {
	a = trimTrailingEmptyRuleAssignments(a)
	b = trimTrailingEmptyRuleAssignments(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !rulesEqual(a[i], b[i]) {
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
		if !sameUserspaceRangeConfig(a[i], b[i]) {
			return false
		}
	}
	return true
}

func rangeAssignmentSlicesEqual(a, b [][]PortRange) bool {
	a = trimTrailingEmptyRangeAssignments(a)
	b = trimTrailingEmptyRangeAssignments(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !rangesEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func trimTrailingEmptyRuleAssignments(assignments [][]Rule) [][]Rule {
	end := len(assignments)
	for end > 0 && len(assignments[end-1]) == 0 {
		end--
	}
	return assignments[:end]
}

func trimTrailingEmptyRangeAssignments(assignments [][]PortRange) [][]PortRange {
	end := len(assignments)
	for end > 0 && len(assignments[end-1]) == 0 {
		end--
	}
	return assignments[:end]
}

func sameUserspaceRuleConfig(a, b Rule) bool {
	return a.ID == b.ID &&
		a.InInterface == b.InInterface &&
		a.InIP == b.InIP &&
		a.InPort == b.InPort &&
		a.OutInterface == b.OutInterface &&
		a.OutIP == b.OutIP &&
		a.OutSourceIP == b.OutSourceIP &&
		a.OutPort == b.OutPort &&
		a.Protocol == b.Protocol &&
		a.Transparent == b.Transparent
}

func sameUserspaceRangeConfig(a, b PortRange) bool {
	return a.ID == b.ID &&
		a.InInterface == b.InInterface &&
		a.InIP == b.InIP &&
		a.StartPort == b.StartPort &&
		a.EndPort == b.EndPort &&
		a.OutInterface == b.OutInterface &&
		a.OutIP == b.OutIP &&
		a.OutSourceIP == b.OutSourceIP &&
		a.OutStartPort == b.OutStartPort &&
		a.Protocol == b.Protocol &&
		a.Transparent == b.Transparent
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
	kernelEngine := pm.kernelRuleEngines[rule.ID]
	pm.mu.Unlock()
	if !ok {
		return item
	}

	item.EffectiveEngine = plan.EffectiveEngine
	item.EffectiveKernelEngine = kernelEngine
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
	kernelEngine := pm.kernelRangeEngines[pr.ID]
	pm.mu.Unlock()
	if !ok {
		return item
	}

	item.EffectiveEngine = plan.EffectiveEngine
	item.EffectiveKernelEngine = kernelEngine
	item.KernelEligible = plan.KernelEligible
	item.KernelReason = plan.KernelReason
	item.FallbackReason = plan.FallbackReason
	return item
}

func (pm *ProcessManager) egressNATRuntimeStatus(id int64, enabled bool) string {
	if !enabled {
		return "stopped"
	}
	pm.mu.Lock()
	running := pm.kernelEgressNATs[id]
	plan, ok := pm.egressNATPlans[id]
	pm.mu.Unlock()
	if running {
		return "running"
	}
	if ok && egressNATPlanIsUnavailable(plan) {
		return "error"
	}
	return "stopped"
}

func egressNATPlanIsUnavailable(plan ruleDataplanePlan) bool {
	return strings.TrimSpace(plan.FallbackReason) != "" || (!plan.KernelEligible && strings.TrimSpace(plan.KernelReason) != "")
}

func (pm *ProcessManager) buildEgressNATStatus(item EgressNAT, status string) EgressNATStatus {
	out := EgressNATStatus{
		EgressNAT:       item,
		Status:          status,
		EffectiveEngine: ruleEngineKernel,
	}
	if pm == nil {
		return out
	}

	pm.mu.Lock()
	plan, ok := pm.egressNATPlans[item.ID]
	kernelEngine := pm.kernelEgressNATEngines[item.ID]
	pm.mu.Unlock()
	if !ok {
		return out
	}

	out.EffectiveEngine = ruleEngineKernel
	out.EffectiveKernelEngine = kernelEngine
	out.KernelEligible = plan.KernelEligible
	out.KernelReason = plan.KernelReason
	out.FallbackReason = plan.FallbackReason
	return out
}

func mergeKernelEngineName(current string, next string) string {
	current = strings.TrimSpace(current)
	next = strings.TrimSpace(next)
	if current == "" {
		return next
	}
	if next == "" || current == next {
		return current
	}
	return "mixed"
}

func (pm *ProcessManager) startRuleWorker(workerIndex int) error {
	if pm.isShuttingDown() {
		return nil
	}

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
	if pm.shuttingDown {
		pm.mu.Unlock()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil
	}
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
	resetWorkerRetryState(wi)
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
	resetWorkerRetryState(wi)
	noteWorkerMessage(wi, time.Now())
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
			logIssue := false
			pm.mu.Lock()
			now := time.Now()
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
					lastStart:      now,
					lastMessageAt:  now,
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
				noteWorkerMessage(target, now)
				if status.Status == "error" {
					logIssue = shouldLogWorkerIssue(target, status.Error, now)
					if target == wi {
						scheduleWorkerRetry(target, now)
					} else {
						target.errored = true
					}
				} else {
					resetWorkerRetryState(target)
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
			if status.Status == "error" && logIssue {
				log.Printf("range worker[%d] error: %s", workerIndex, status.Error)
			}
		} else if status.Type == "range_stats" {
			pm.mu.Lock()
			if target.rangeStats == nil {
				target.rangeStats = make(map[int64]RangeStatsReport)
			}
			noteWorkerMessage(target, time.Now())
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
	if pm.isShuttingDown() {
		return nil
	}

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
	if pm.shuttingDown {
		pm.mu.Unlock()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil
	}
	wi, ok := pm.rangeWorkers[workerIndex]
	if !ok {
		wi = &WorkerInfo{workerIndex: workerIndex, kind: workerKindRange, failedRanges: make(map[int64]bool)}
		pm.rangeWorkers[workerIndex] = wi
	}
	waitCh := make(chan struct{})
	wi.process = cmd.Process
	wi.waitCh = waitCh
	wi.running = false
	resetWorkerRetryState(wi)
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
	if pm.isShuttingDown() {
		return
	}

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
	if pm.shuttingDown {
		pm.mu.Unlock()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return
	}
	pm.sharedProxy = &WorkerInfo{
		kind:        workerKindShared,
		process:     cmd.Process,
		waitCh:      waitCh,
		running:     false,
		failedSites: make(map[int64]bool),
		lastStart:   time.Now(),
	}
	resetWorkerRetryState(pm.sharedProxy)
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
		pm.sharedProxy = &WorkerInfo{
			kind:        workerKindShared,
			failedSites: make(map[int64]bool),
			lastStart:   time.Now(),
		}
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
	kernelRuleStats := cloneRuleStatsReports(pm.kernelRuleStats)
	pm.mu.Unlock()

	for id, s := range kernelRuleStats {
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
	kernelRangeStats := cloneRangeStatsReports(pm.kernelRangeStats)
	pm.mu.Unlock()

	for id, s := range kernelRangeStats {
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
	return result
}

func (pm *ProcessManager) collectEgressNATStats() map[int64]EgressNATStatsReport {
	pm.mu.Lock()
	result := cloneEgressNATStatsReports(pm.kernelEgressNATStats)
	pm.mu.Unlock()
	return result
}

func currentConnCountForProtocol(protocol string, activeConns int64, natTableSize int64) int64 {
	return currentConnCountForProtocolDatagrams(protocol, activeConns, natTableSize, 0)
}

func currentConnCountForProtocolDatagrams(protocol string, activeConns int64, udpNatTableSize int64, icmpNatTableSize int64) int64 {
	mask := protocolMaskFromString(protocol)
	hasTCP := mask&protocolMaskTCP != 0
	hasUDP := mask&protocolMaskUDP != 0
	hasICMP := mask&protocolMaskICMP != 0
	datagramConns := int64(0)

	if hasUDP {
		datagramConns += udpNatTableSize
	}
	if hasICMP {
		datagramConns += icmpNatTableSize
	}

	switch {
	case hasTCP && (hasUDP || hasICMP):
		return activeConns + datagramConns
	case hasUDP || hasICMP:
		return datagramConns
	case hasTCP:
		return activeConns
	default:
		return activeConns + udpNatTableSize + icmpNatTableSize
	}
}

func addRuleCurrentConnCount(result map[int64]int64, protocols map[int64]string, ruleID int64, activeConns int64, udpNatTableSize int64, icmpNatTableSize int64) {
	result[ruleID] += currentConnCountForProtocolDatagrams(protocols[ruleID], activeConns, udpNatTableSize, icmpNatTableSize)
}

func addRangeCurrentConnCount(result map[int64]int64, protocols map[int64]string, rangeID int64, activeConns int64, udpNatTableSize int64, icmpNatTableSize int64) {
	result[rangeID] += currentConnCountForProtocolDatagrams(protocols[rangeID], activeConns, udpNatTableSize, icmpNatTableSize)
}

func addEgressNATCurrentConnCount(result map[int64]int64, protocols map[int64]string, egressNATID int64, activeConns int64, udpNatTableSize int64, icmpNatTableSize int64) {
	result[egressNATID] += currentConnCountForProtocolDatagrams(protocols[egressNATID], activeConns, udpNatTableSize, icmpNatTableSize)
}

func (pm *ProcessManager) collectCurrentConns(ruleProtocols map[int64]string, rangeProtocols map[int64]string, egressNATProtocols map[int64]string) (map[int64]int64, map[int64]int64, map[int64]int64, map[int64]int64, error) {
	ruleResult := make(map[int64]int64)
	rangeResult := make(map[int64]int64)
	siteResult := make(map[int64]int64)
	egressNATResult := make(map[int64]int64)

	pm.mu.Lock()
	for _, wi := range pm.ruleWorkers {
		for id, stats := range wi.ruleStats {
			addRuleCurrentConnCount(ruleResult, ruleProtocols, id, stats.ActiveConns, int64(stats.NatTableSize), 0)
		}
	}
	for _, wi := range pm.rangeWorkers {
		for id, stats := range wi.rangeStats {
			addRangeCurrentConnCount(rangeResult, rangeProtocols, id, stats.ActiveConns, int64(stats.NatTableSize), 0)
		}
	}
	for _, dw := range pm.drainingWorkers {
		for id, stats := range dw.ruleStats {
			addRuleCurrentConnCount(ruleResult, ruleProtocols, id, stats.ActiveConns, int64(stats.NatTableSize), 0)
		}
		for id, stats := range dw.rangeStats {
			addRangeCurrentConnCount(rangeResult, rangeProtocols, id, stats.ActiveConns, int64(stats.NatTableSize), 0)
		}
		if dw.kind == workerKindShared {
			for _, stats := range dw.siteStatsMap {
				siteResult[stats.SiteID] += stats.ActiveConns
			}
		}
	}
	if pm.sharedProxy != nil {
		for _, stats := range pm.sharedProxy.siteStatsMap {
			siteResult[stats.SiteID] += stats.ActiveConns
		}
	}
	ownerIndex := make(map[uint32]kernelCandidateOwner, len(pm.kernelFlowOwners))
	for id, owner := range pm.kernelFlowOwners {
		ownerIndex[id] = owner
	}
	runtime := pm.kernelRuntime
	pm.mu.Unlock()

	if runtime == nil {
		return ruleResult, rangeResult, siteResult, egressNATResult, nil
	}

	_ = runtime
	snapshot, _, err := pm.snapshotKernelStatsShared(time.Time{})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	for kernelRuleID, counts := range snapshot.ByRuleID {
		owner, ok := ownerIndex[kernelRuleID]
		if !ok {
			continue
		}
		if owner.kind == workerKindRule {
			addRuleCurrentConnCount(ruleResult, ruleProtocols, owner.id, counts.TCPActiveConns, counts.UDPNatEntries, counts.ICMPNatEntries)
			continue
		}
		if owner.kind == workerKindRange {
			addRangeCurrentConnCount(rangeResult, rangeProtocols, owner.id, counts.TCPActiveConns, counts.UDPNatEntries, counts.ICMPNatEntries)
			continue
		}
		if owner.kind == workerKindEgressNAT {
			addEgressNATCurrentConnCount(egressNATResult, egressNATProtocols, owner.id, counts.TCPActiveConns, counts.UDPNatEntries, counts.ICMPNatEntries)
		}
	}

	return ruleResult, rangeResult, siteResult, egressNATResult, nil
}

func cloneRuleStatsReports(src map[int64]RuleStatsReport) map[int64]RuleStatsReport {
	if len(src) == 0 {
		return map[int64]RuleStatsReport{}
	}
	dst := make(map[int64]RuleStatsReport, len(src))
	for id, stats := range src {
		dst[id] = stats
	}
	return dst
}

func cloneRangeStatsReports(src map[int64]RangeStatsReport) map[int64]RangeStatsReport {
	if len(src) == 0 {
		return map[int64]RangeStatsReport{}
	}
	dst := make(map[int64]RangeStatsReport, len(src))
	for id, stats := range src {
		dst[id] = stats
	}
	return dst
}

func cloneEgressNATStatsReports(src map[int64]EgressNATStatsReport) map[int64]EgressNATStatsReport {
	if len(src) == 0 {
		return map[int64]EgressNATStatsReport{}
	}
	dst := make(map[int64]EgressNATStatsReport, len(src))
	for id, stats := range src {
		dst[id] = stats
	}
	return dst
}

func isTransientKernelFallbackReason(reason string) bool {
	text := strings.ToLower(strings.TrimSpace(reason))
	if text == "" {
		return false
	}
	return strings.Contains(text, "no learned ipv4 neighbor entry was found") ||
		strings.Contains(text, "requires a learned ipv4 neighbor entry") ||
		strings.Contains(text, "no forwarding database entry matched the backend mac")
}

func isPressureTriggeredKernelFallbackReason(reason string) bool {
	text := strings.ToLower(strings.TrimSpace(reason))
	if text == "" {
		return false
	}
	return strings.Contains(text, "kernel dataplane pressure")
}

func normalizeTransientKernelFallbackReason(reason string) string {
	text := strings.ToLower(strings.TrimSpace(reason))
	switch {
	case strings.Contains(text, "no learned ipv4 neighbor entry was found"):
		return "neighbor_missing"
	case strings.Contains(text, "requires a learned ipv4 neighbor entry"):
		return "neighbor_missing"
	case strings.Contains(text, "no forwarding database entry matched the backend mac"):
		return "fdb_missing"
	case strings.Contains(text, "kernel dataplane pressure"):
		return "table_pressure"
	default:
		if text == "" {
			return "unknown"
		}
		return text
	}
}

func (pm *ProcessManager) hasTransientKernelFallbacksLocked() bool {
	for _, plan := range pm.rulePlans {
		if plan.EffectiveEngine == ruleEngineKernel || !plan.KernelEligible {
			continue
		}
		if isTransientKernelFallbackReason(plan.FallbackReason) {
			return true
		}
	}
	for _, plan := range pm.rangePlans {
		if plan.EffectiveEngine == ruleEngineKernel || !plan.KernelEligible {
			continue
		}
		if isTransientKernelFallbackReason(plan.FallbackReason) {
			return true
		}
	}
	return false
}

func (pm *ProcessManager) hasPressureTriggeredKernelFallbacksLocked() bool {
	for _, plan := range pm.rulePlans {
		if plan.EffectiveEngine == ruleEngineKernel || !plan.KernelEligible {
			continue
		}
		if isPressureTriggeredKernelFallbackReason(plan.FallbackReason) {
			return true
		}
	}
	for _, plan := range pm.rangePlans {
		if plan.EffectiveEngine == ruleEngineKernel || !plan.KernelEligible {
			continue
		}
		if isPressureTriggeredKernelFallbackReason(plan.FallbackReason) {
			return true
		}
	}
	return false
}

func (pm *ProcessManager) summarizeTransientKernelFallbacksLocked() string {
	ruleCount := 0
	rangeCount := 0
	reasonCounts := make(map[string]int)

	for _, plan := range pm.rulePlans {
		if plan.EffectiveEngine == ruleEngineKernel || !plan.KernelEligible {
			continue
		}
		if !isTransientKernelFallbackReason(plan.FallbackReason) {
			continue
		}
		ruleCount++
		reasonCounts[normalizeTransientKernelFallbackReason(plan.FallbackReason)]++
	}
	for _, plan := range pm.rangePlans {
		if plan.EffectiveEngine == ruleEngineKernel || !plan.KernelEligible {
			continue
		}
		if !isTransientKernelFallbackReason(plan.FallbackReason) {
			continue
		}
		rangeCount++
		reasonCounts[normalizeTransientKernelFallbackReason(plan.FallbackReason)]++
	}
	if ruleCount == 0 && rangeCount == 0 {
		return ""
	}

	reasons := make([]string, 0, len(reasonCounts))
	for reason, count := range reasonCounts {
		reasons = append(reasons, fmt.Sprintf("%s=%d", reason, count))
	}
	sort.Strings(reasons)
	return fmt.Sprintf("rules=%d ranges=%d reasons=%s", ruleCount, rangeCount, strings.Join(reasons, ","))
}

func (pm *ProcessManager) takeKernelRetryLogLineLocked(summary string, now time.Time) string {
	summary = strings.TrimSpace(summary)
	if summary == "" {
		pm.lastKernelRetryLog = ""
		pm.kernelRetryLogAt = time.Time{}
		return ""
	}
	if summary == pm.lastKernelRetryLog && !pm.kernelRetryLogAt.IsZero() && now.Sub(pm.kernelRetryLogAt) < kernelFallbackRetryLogEvery {
		return ""
	}
	pm.lastKernelRetryLog = summary
	pm.kernelRetryLogAt = now
	return fmt.Sprintf("kernel dataplane retry: re-evaluating transient kernel path fallbacks (%s)", summary)
}

func (pm *ProcessManager) buildEmptyKernelStatsLocked() (map[int64]RuleStatsReport, map[int64]RangeStatsReport, map[int64]EgressNATStatsReport) {
	ruleStats := make(map[int64]RuleStatsReport)
	rangeStats := make(map[int64]RangeStatsReport)
	egressNATStats := make(map[int64]EgressNATStatsReport)
	for id := range pm.kernelRules {
		ruleStats[id] = RuleStatsReport{RuleID: id}
	}
	for id := range pm.kernelRanges {
		rangeStats[id] = RangeStatsReport{RangeID: id}
	}
	for id := range pm.kernelEgressNATs {
		egressNATStats[id] = EgressNATStatsReport{EgressNATID: id}
	}
	return ruleStats, rangeStats, egressNATStats
}

func (pm *ProcessManager) markKernelStatsDemand() {
	pm.mu.Lock()
	pm.kernelStatsDemandAt = time.Now()
	pm.mu.Unlock()
}

func (pm *ProcessManager) shouldRefreshKernelStatsLocked(now time.Time) bool {
	if pm.kernelRuntime == nil {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	if len(pm.kernelRules) == 0 && len(pm.kernelRanges) == 0 && len(pm.kernelEgressNATs) == 0 {
		return false
	}
	if pm.kernelStatsDemandAt.IsZero() || now.Sub(pm.kernelStatsDemandAt) > kernelStatsDemandWindow {
		return false
	}
	return pm.kernelStatsAt.IsZero() || now.Sub(pm.kernelStatsAt) >= kernelStatsRefreshInterval
}

func (pm *ProcessManager) refreshKernelStatsCacheIfNeeded() {
	pm.mu.Lock()
	shouldRefresh := pm.shouldRefreshKernelStatsLocked(time.Now())
	pm.mu.Unlock()
	if shouldRefresh {
		pm.refreshKernelStatsCache()
	}
}

func (pm *ProcessManager) snapshotKernelStatsShared(now time.Time) (kernelRuleStatsSnapshot, time.Time, error) {
	if pm == nil {
		if now.IsZero() {
			now = time.Now()
		}
		return emptyKernelRuleStatsSnapshot(), now, nil
	}
	if now.IsZero() {
		now = time.Now()
	}

	pm.mu.Lock()
	if pm.kernelRuntime == nil {
		pm.mu.Unlock()
		return emptyKernelRuleStatsSnapshot(), now, nil
	}
	if !pm.kernelStatsSnapshotAt.IsZero() && now.Sub(pm.kernelStatsSnapshotAt) < kernelStatsSnapshotShareTTL {
		snapshot := pm.kernelStatsSnapshot
		sampledAt := pm.kernelStatsSnapshotAt
		pm.mu.Unlock()
		return snapshot, sampledAt, nil
	}
	runtime := pm.kernelRuntime
	pm.mu.Unlock()

	startedAt := time.Now()
	snapshot, err := runtime.SnapshotStats()
	duration := time.Since(startedAt)
	if err != nil {
		pm.mu.Lock()
		pm.kernelStatsLastDuration = duration
		pm.kernelStatsLastError = err.Error()
		pm.mu.Unlock()
		return emptyKernelRuleStatsSnapshot(), now, err
	}

	pm.mu.Lock()
	pm.kernelStatsSnapshot = snapshot
	pm.kernelStatsSnapshotAt = now
	pm.kernelStatsLastDuration = duration
	pm.kernelStatsLastError = ""
	pm.mu.Unlock()
	return snapshot, now, nil
}

func kernelTrafficSpeed(nextBytes int64, prevBytes int64, elapsed time.Duration) int64 {
	if elapsed <= 0 || nextBytes <= prevBytes {
		return 0
	}
	return int64((float64(nextBytes-prevBytes) * float64(time.Second)) / float64(elapsed))
}

func applyKernelRuleTrafficSpeeds(dst map[int64]RuleStatsReport, prev map[int64]RuleStatsReport, elapsed time.Duration) {
	if elapsed <= 0 {
		return
	}
	for id, current := range dst {
		previous := prev[id]
		current.SpeedIn = kernelTrafficSpeed(current.BytesIn, previous.BytesIn, elapsed)
		current.SpeedOut = kernelTrafficSpeed(current.BytesOut, previous.BytesOut, elapsed)
		dst[id] = current
	}
}

func applyKernelRangeTrafficSpeeds(dst map[int64]RangeStatsReport, prev map[int64]RangeStatsReport, elapsed time.Duration) {
	if elapsed <= 0 {
		return
	}
	for id, current := range dst {
		previous := prev[id]
		current.SpeedIn = kernelTrafficSpeed(current.BytesIn, previous.BytesIn, elapsed)
		current.SpeedOut = kernelTrafficSpeed(current.BytesOut, previous.BytesOut, elapsed)
		dst[id] = current
	}
}

func applyKernelEgressNATTrafficSpeeds(dst map[int64]EgressNATStatsReport, prev map[int64]EgressNATStatsReport, elapsed time.Duration) {
	if elapsed <= 0 {
		return
	}
	for id, current := range dst {
		previous := prev[id]
		current.SpeedIn = kernelTrafficSpeed(current.BytesIn, previous.BytesIn, elapsed)
		current.SpeedOut = kernelTrafficSpeed(current.BytesOut, previous.BytesOut, elapsed)
		dst[id] = current
	}
}

func (pm *ProcessManager) refreshKernelStatsCache() {
	if pm.kernelRuntime == nil {
		pm.mu.Lock()
		pm.kernelRuleStats = make(map[int64]RuleStatsReport)
		pm.kernelRangeStats = make(map[int64]RangeStatsReport)
		pm.kernelEgressNATStats = make(map[int64]EgressNATStatsReport)
		pm.kernelStatsSnapshot = emptyKernelRuleStatsSnapshot()
		pm.kernelStatsAt = time.Now()
		pm.kernelStatsSnapshotAt = time.Time{}
		pm.kernelStatsLastDuration = 0
		pm.kernelStatsLastError = ""
		pm.mu.Unlock()
		return
	}

	pm.mu.Lock()
	ownerIndex := make(map[uint32]kernelCandidateOwner, len(pm.kernelFlowOwners))
	for id, owner := range pm.kernelFlowOwners {
		ownerIndex[id] = owner
	}
	prevRuleStats := cloneRuleStatsReports(pm.kernelRuleStats)
	prevRangeStats := cloneRangeStatsReports(pm.kernelRangeStats)
	prevEgressNATStats := cloneEgressNATStatsReports(pm.kernelEgressNATStats)
	prevStatsAt := pm.kernelStatsAt
	trafficStatsEnabled := pm.cfg != nil && pm.cfg.ExperimentalFeatureEnabled(experimentalFeatureKernelTraffic)
	ruleStats, rangeStats, egressNATStats := pm.buildEmptyKernelStatsLocked()
	pm.mu.Unlock()

	snapshot, sampledAt, err := pm.snapshotKernelStatsShared(time.Time{})
	if err != nil {
		pm.mu.Lock()
		pm.kernelStatsLastError = err.Error()
		pm.mu.Unlock()
		log.Printf("kernel dataplane stats snapshot failed: %v", err)
		return
	}

	for kernelRuleID, counts := range snapshot.ByRuleID {
		owner, ok := ownerIndex[kernelRuleID]
		if !ok {
			continue
		}
		if owner.kind == workerKindRule {
			item := ruleStats[owner.id]
			item.RuleID = owner.id
			item.ActiveConns += counts.TCPActiveConns
			item.TotalConns += counts.TotalConns
			item.NatTableSize += int(counts.UDPNatEntries + counts.ICMPNatEntries)
			if trafficStatsEnabled {
				item.BytesIn += counts.BytesIn
				item.BytesOut += counts.BytesOut
			}
			ruleStats[owner.id] = item
			continue
		}
		if owner.kind == workerKindRange {
			item := rangeStats[owner.id]
			item.RangeID = owner.id
			item.ActiveConns += counts.TCPActiveConns
			item.TotalConns += counts.TotalConns
			item.NatTableSize += int(counts.UDPNatEntries + counts.ICMPNatEntries)
			if trafficStatsEnabled {
				item.BytesIn += counts.BytesIn
				item.BytesOut += counts.BytesOut
			}
			rangeStats[owner.id] = item
			continue
		}
		if owner.kind == workerKindEgressNAT {
			item := egressNATStats[owner.id]
			item.EgressNATID = owner.id
			item.ActiveConns += counts.TCPActiveConns
			item.TotalConns += counts.TotalConns
			item.NatTableSize += int(counts.UDPNatEntries + counts.ICMPNatEntries)
			if trafficStatsEnabled {
				item.BytesIn += counts.BytesIn
				item.BytesOut += counts.BytesOut
			}
			egressNATStats[owner.id] = item
		}
	}

	now := sampledAt
	if trafficStatsEnabled && !prevStatsAt.IsZero() {
		elapsed := now.Sub(prevStatsAt)
		applyKernelRuleTrafficSpeeds(ruleStats, prevRuleStats, elapsed)
		applyKernelRangeTrafficSpeeds(rangeStats, prevRangeStats, elapsed)
		applyKernelEgressNATTrafficSpeeds(egressNATStats, prevEgressNATStats, elapsed)
	}

	pm.mu.Lock()
	pm.kernelRuleStats = ruleStats
	pm.kernelRangeStats = rangeStats
	pm.kernelEgressNATStats = egressNATStats
	pm.kernelStatsAt = now
	pm.mu.Unlock()
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
	pm.beginShutdown()
	pm.stopKernelNetlinkMonitor()
	if pm.ipv6Runtime != nil {
		if err := pm.ipv6Runtime.Close(); err != nil {
			log.Printf("stop ipv6 assignment runtime: %v", err)
		}
	}
	if pm.managedNetworkRuntime != nil {
		if err := pm.managedNetworkRuntime.Close(); err != nil {
			log.Printf("stop managed network runtime: %v", err)
		}
	}
	if pm.kernelRuntime != nil {
		if err := pm.kernelRuntime.Close(); err != nil {
			log.Printf("stop kernel runtime: %v", err)
		}
	}

	if pm.listener != nil {
		pm.listener.Close()
	}
	if pm.sockPath != "" {
		_ = os.Remove(pm.sockPath)
	}

	pm.mu.Lock()
	workers := make([]*WorkerInfo, 0, len(pm.ruleWorkers)+len(pm.rangeWorkers)+len(pm.drainingWorkers)+1)
	for _, wi := range pm.ruleWorkers {
		workers = append(workers, wi)
	}
	for _, wi := range pm.rangeWorkers {
		workers = append(workers, wi)
	}
	for _, wi := range pm.drainingWorkers {
		workers = append(workers, wi)
	}
	if pm.sharedProxy != nil {
		workers = append(workers, pm.sharedProxy)
	}
	pm.ruleWorkers = map[int]*WorkerInfo{}
	pm.rangeWorkers = map[int]*WorkerInfo{}
	pm.drainingWorkers = nil
	pm.sharedProxy = nil
	pm.mu.Unlock()

	for _, wi := range uniqueWorkerInfosByProcess(workers) {
		killWorkerInfo(wi)
	}
	pm.waitForBackgroundLoops(2 * time.Second)
}

func uniqueWorkerInfosByProcess(items []*WorkerInfo) []*WorkerInfo {
	if len(items) == 0 {
		return nil
	}
	out := make([]*WorkerInfo, 0, len(items))
	seenProcess := make(map[int]struct{}, len(items))
	seenNoProcess := make(map[*WorkerInfo]struct{}, len(items))
	for _, wi := range items {
		if wi == nil {
			continue
		}
		if wi.process != nil && wi.process.Pid > 0 {
			if _, ok := seenProcess[wi.process.Pid]; ok {
				continue
			}
			seenProcess[wi.process.Pid] = struct{}{}
			out = append(out, wi)
			continue
		}
		if _, ok := seenNoProcess[wi]; ok {
			continue
		}
		seenNoProcess[wi] = struct{}{}
		out = append(out, wi)
	}
	return out
}

func waitForStopChannel(ch <-chan struct{}, timeout time.Duration) bool {
	if ch == nil {
		return true
	}
	if timeout <= 0 {
		<-ch
		return true
	}
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (pm *ProcessManager) waitForBackgroundLoops(timeout time.Duration) {
	if pm == nil {
		return
	}
	pm.mu.Lock()
	monitorDone := pm.monitorDone
	managedRuntimeReloadDone := pm.managedRuntimeReloadDone
	redistributeDone := pm.redistributeDone
	pm.mu.Unlock()

	_ = waitForStopChannel(monitorDone, timeout)
	_ = waitForStopChannel(managedRuntimeReloadDone, timeout)
	_ = waitForStopChannel(redistributeDone, timeout)
}

func (pm *ProcessManager) monitorLoop() {
	defer close(pm.monitorDone)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-pm.shutdownCh:
			return
		case <-ticker.C:
		}

		type workerRetryTask struct {
			index        int
			failureCount int
		}
		type staleControlTask struct {
			kind          string
			index         int
			conn          net.Conn
			lastMessageAt time.Time
			logIssue      bool
		}
		var restartRuleIdx []int
		var retryRuleConfig []workerRetryTask
		var restartRangeIdx []int
		var retryRangeConfig []workerRetryTask
		var retrySharedProxy bool
		sharedProxyFailureCount := 0
		var staleControls []staleControlTask
		var stopDraining []*WorkerInfo
		proxyDead := false
		refreshKernelStats := false
		runKernelMaintenance := false
		checkKernelAttachments := false
		checkKernelDegradedIdleRebuild := false
		retryKernelFallbacks := false
		retryKernelLogLine := ""
		recoverPressureFallbacks := false
		pressureRecoveryLogLine := ""
		kernelAttachmentIssue := ""
		kernelAttachmentRecovered := ""
		attemptKernelAttachmentHeal := false
		kernelAttachmentHealSummary := ""
		kernelAttachmentHealError := ""
		kernelDegradedIdleRebuildReason := ""
		var kernelPressurePrev kernelRuntimePressureSnapshot
		hasPressureFallbacks := false
		now := time.Now()

		if pm.isShuttingDown() {
			return
		}

		pm.mu.Lock()
		runtime := pm.kernelRuntime
		if pm.shuttingDown {
			pm.mu.Unlock()
			return
		}
		if pm.shouldRefreshKernelStatsLocked(now) {
			refreshKernelStats = true
		}
		if pm.kernelRuntime != nil && (pm.kernelMaintenanceAt.IsZero() || now.Sub(pm.kernelMaintenanceAt) >= pm.kernelMaintenanceEvery) {
			runKernelMaintenance = true
			pm.kernelMaintenanceAt = now
		}
		if pm.kernelRuntime != nil && (pm.kernelAttachmentCheckAt.IsZero() || now.Sub(pm.kernelAttachmentCheckAt) >= kernelAttachmentCheckEvery) {
			checkKernelAttachments = true
			pm.kernelAttachmentCheckAt = now
		}
		if pm.kernelRuntime != nil && (pm.kernelDegradedHealAt.IsZero() || now.Sub(pm.kernelDegradedHealAt) >= kernelDegradedRebuildCooldown) {
			checkKernelDegradedIdleRebuild = true
		}
		if pm.kernelRuntime != nil {
			transientSummary := pm.summarizeTransientKernelFallbacksLocked()
			hasPressureFallbacks = pm.hasPressureTriggeredKernelFallbacksLocked()
			kernelPressurePrev = pm.kernelPressureSnapshot
			if transientSummary == "" {
				pm.takeKernelRetryLogLineLocked("", now)
			} else if pm.kernelRetryAt.IsZero() || now.Sub(pm.kernelRetryAt) >= kernelFallbackRetryInterval {
				retryKernelFallbacks = true
				pm.kernelRetryAt = now
				pm.kernelRetryCount++
				pm.lastKernelRetryAt = now
				pm.lastKernelRetryReason = transientSummary
				retryKernelLogLine = pm.takeKernelRetryLogLineLocked(transientSummary, now)
			}
		}
		for idx, wi := range pm.ruleWorkers {
			if len(wi.rules) == 0 {
				continue
			}
			if shouldRecoverStaleWorkerControl(wi, now) {
				staleControls = append(staleControls, staleControlTask{
					kind:          workerKindRule,
					index:         idx,
					conn:          wi.conn,
					lastMessageAt: wi.lastMessageAt,
					logIssue:      shouldLogWorkerIssue(wi, "stale control connection", now),
				})
				wi.conn = nil
				wi.running = false
				continue
			}
			if wi.errored {
				if wi.nextRetry.IsZero() {
					wi.nextRetry = now.Add(nextWorkerRetryDelay(wi.retryCount + 1))
				}
				if !now.Before(wi.nextRetry) {
					wi.nextRetry = now.Add(nextWorkerRetryDelay(wi.retryCount + 1))
					if wi.conn != nil {
						retryRuleConfig = append(retryRuleConfig, workerRetryTask{
							index:        idx,
							failureCount: wi.retryCount,
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
			if len(wi.ranges) == 0 {
				continue
			}
			if shouldRecoverStaleWorkerControl(wi, now) {
				staleControls = append(staleControls, staleControlTask{
					kind:          workerKindRange,
					index:         idx,
					conn:          wi.conn,
					lastMessageAt: wi.lastMessageAt,
					logIssue:      shouldLogWorkerIssue(wi, "stale control connection", now),
				})
				wi.conn = nil
				wi.running = false
				continue
			}
			if wi.errored {
				if wi.nextRetry.IsZero() {
					wi.nextRetry = now.Add(nextWorkerRetryDelay(wi.retryCount + 1))
				}
				if !now.Before(wi.nextRetry) {
					wi.nextRetry = now.Add(nextWorkerRetryDelay(wi.retryCount + 1))
					if wi.conn != nil {
						retryRangeConfig = append(retryRangeConfig, workerRetryTask{
							index:        idx,
							failureCount: wi.retryCount,
						})
					} else if wi.process == nil {
						restartRangeIdx = append(restartRangeIdx, idx)
					}
				}
				continue
			}
			if wi.process == nil && wi.conn == nil {
				if now.Sub(wi.lastStart) > 3*time.Second {
					restartRangeIdx = append(restartRangeIdx, idx)
				}
			}
		}
		if pm.sharedProxy != nil {
			if shouldRecoverStaleWorkerControl(pm.sharedProxy, now) {
				staleControls = append(staleControls, staleControlTask{
					kind:          workerKindShared,
					index:         0,
					conn:          pm.sharedProxy.conn,
					lastMessageAt: pm.sharedProxy.lastMessageAt,
					logIssue:      shouldLogWorkerIssue(pm.sharedProxy, "stale control connection", now),
				})
				pm.sharedProxy.conn = nil
				pm.sharedProxy.running = false
			} else if pm.sharedProxy.errored {
				if pm.sharedProxy.nextRetry.IsZero() {
					pm.sharedProxy.nextRetry = now.Add(nextWorkerRetryDelay(pm.sharedProxy.retryCount + 1))
				}
				if !now.Before(pm.sharedProxy.nextRetry) {
					pm.sharedProxy.nextRetry = now.Add(nextWorkerRetryDelay(pm.sharedProxy.retryCount + 1))
					if pm.sharedProxy.conn != nil {
						retrySharedProxy = true
						sharedProxyFailureCount = pm.sharedProxy.retryCount
					} else if pm.sharedProxy.process == nil {
						proxyDead = true
					}
				}
			} else if pm.sharedProxy.process == nil && pm.sharedProxy.conn == nil {
				if now.Sub(pm.sharedProxy.lastStart) > 3*time.Second {
					proxyDead = true
				}
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

		if runKernelMaintenance && pm.kernelRuntime != nil {
			if err := pm.kernelRuntime.Maintain(); err != nil {
				log.Printf("kernel dataplane maintenance failed: %v", err)
			}
		}
		if checkKernelAttachments && runtime != nil {
			kernelAttachmentIssue = summarizeUnhealthyKernelAttachments(snapshotKernelAttachmentHealth(runtime))
			pm.mu.Lock()
			pm.lastKernelAttachmentIssue, kernelAttachmentRecovered, attemptKernelAttachmentHeal, pm.kernelAttachmentHealAt =
				nextKernelAttachmentHealState(pm.lastKernelAttachmentIssue, pm.kernelAttachmentHealAt, now, kernelAttachmentIssue)
			pm.mu.Unlock()
		}
		if attemptKernelAttachmentHeal && runtime != nil {
			healResults, healErr := healKernelAttachments(runtime)
			if healErr != nil {
				kernelAttachmentHealError = healErr.Error()
				pm.mu.Lock()
				pm.lastKernelAttachmentHealSummary = ""
				pm.lastKernelAttachmentHealError = kernelAttachmentHealError
				pm.mu.Unlock()
				log.Printf("kernel dataplane self-heal: targeted attachment repair failed (%s): %v", kernelAttachmentIssue, healErr)
				pm.requestRedistributeWorkers(0)
			} else {
				rawKernelAttachmentHealSummary := summarizeKernelAttachmentHealResults(healResults)
				postHealIssue := summarizeUnhealthyKernelAttachments(snapshotKernelAttachmentHealth(runtime))
				kernelAttachmentHealSummary = kernelAttachmentHealOutcomeSummary(rawKernelAttachmentHealSummary, postHealIssue)
				pm.mu.Lock()
				pm.lastKernelAttachmentIssue = postHealIssue
				pm.lastKernelAttachmentHealSummary = kernelAttachmentHealSummary
				pm.lastKernelAttachmentHealError = ""
				pm.mu.Unlock()
				if strings.TrimSpace(postHealIssue) == "" {
					if strings.TrimSpace(rawKernelAttachmentHealSummary) != "" {
						log.Printf("kernel dataplane self-heal: repaired attachments: %s", rawKernelAttachmentHealSummary)
					} else {
						log.Printf("kernel dataplane self-heal: attachment issue cleared without a full redistribute")
					}
				} else {
					if strings.TrimSpace(rawKernelAttachmentHealSummary) != "" {
						log.Printf("kernel dataplane self-heal: partial repair applied (%s), remaining issue: %s", rawKernelAttachmentHealSummary, postHealIssue)
					} else {
						log.Printf("kernel dataplane self-heal: targeted repair could not clear attachment issue (%s), re-evaluating kernel assignments", postHealIssue)
					}
					pm.requestRedistributeWorkers(0)
				}
			}
		}
		if checkKernelDegradedIdleRebuild && runtime != nil {
			for _, engine := range snapshotKernelRuntimeEngines(runtime) {
				if reason := kernelRuntimeIdleDegradedRebuildReason(engine); reason != "" {
					kernelDegradedIdleRebuildReason = reason
					pm.mu.Lock()
					pm.kernelDegradedHealAt = now
					pm.mu.Unlock()
					break
				}
			}
		}
		kernelPressureCurrent := snapshotKernelRuntimePressure(runtime)
		pm.mu.Lock()
		pm.kernelPressureSnapshot = kernelPressureCurrent
		pm.mu.Unlock()
		if needsRedistribute, _ := kernelRuntimeNeedsRedistributeSnapshot(kernelPressureCurrent); needsRedistribute {
			pm.requestRedistributeWorkers(0)
		}
		if hasPressureFallbacks && kernelRuntimePressureCleared(kernelPressurePrev, kernelPressureCurrent) {
			engine := strings.TrimSpace(kernelPressurePrev.Engine)
			if engine == "" {
				engine = "kernel"
			}
			recoverPressureFallbacks = true
			pressureRecoveryLogLine = fmt.Sprintf("kernel dataplane retry: %s pressure cleared, re-evaluating table pressure fallbacks", engine)
		}
		if refreshKernelStats {
			pm.refreshKernelStatsCache()
		}
		if retryKernelLogLine != "" {
			log.Print(retryKernelLogLine)
		}
		if pressureRecoveryLogLine != "" {
			log.Print(pressureRecoveryLogLine)
		}
		if kernelAttachmentRecovered != "" {
			log.Printf("kernel dataplane attachments recovered: %s", kernelAttachmentRecovered)
		}
		if retryKernelFallbacks {
			pm.requestRedistributeWorkers(redistributeRetryDelay)
		}
		if recoverPressureFallbacks {
			pm.requestRedistributeWorkers(0)
		}
		if kernelDegradedIdleRebuildReason != "" {
			log.Printf("kernel dataplane self-heal: %s; rebuilding kernel dataplane now", kernelDegradedIdleRebuildReason)
			pm.requestRedistributeWorkers(0)
		}

		for _, task := range staleControls {
			if task.conn != nil {
				if task.logIssue {
					age := time.Since(task.lastMessageAt).Round(time.Second)
					switch task.kind {
					case workerKindRule:
						log.Printf("worker[%d]: stale control connection after %v, forcing reconnect", task.index, age)
					case workerKindRange:
						log.Printf("range worker[%d]: stale control connection after %v, forcing reconnect", task.index, age)
					case workerKindShared:
						log.Printf("shared proxy: stale control connection after %v, forcing reconnect", age)
					}
				}
				task.conn.Close()
			}
		}
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
		for _, task := range retryRangeConfig {
			pm.mu.Lock()
			wi := pm.rangeWorkers[task.index]
			pm.mu.Unlock()
			if wi == nil || wi.conn == nil || len(wi.ranges) == 0 {
				continue
			}
			log.Printf("retrying range worker[%d] config (failure_count=%d)", task.index, task.failureCount)
			pm.sendRangeConfig(wi)
		}
		for _, dw := range stopDraining {
			log.Printf("stopping stale draining %s worker[%d]", dw.kind, dw.workerIndex)
			killWorkerInfo(dw)
		}

		if retrySharedProxy || proxyDead {
			sites, err := dbGetSites(pm.db)
			if err == nil {
				hasEnabled := false
				var enabledSites []Site
				for _, s := range sites {
					if s.Enabled {
						hasEnabled = true
						enabledSites = append(enabledSites, s)
					}
				}
				if retrySharedProxy {
					pm.mu.Lock()
					proxy := pm.sharedProxy
					pm.mu.Unlock()
					if proxy != nil && proxy.conn != nil && len(enabledSites) > 0 {
						log.Printf("retrying shared proxy config (failure_count=%d)", sharedProxyFailureCount)
						pm.sendSitesConfig(proxy, enabledSites)
					}
				}
				if proxyDead && hasEnabled {
					log.Println("restarting shared proxy")
					pm.startSharedProxy()
				}
			}
		}
	}
}
