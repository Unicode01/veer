//go:build linux

package app

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	kernelForwardProgramName  = "forward_ingress"
	kernelReplyProgramName    = "reply_ingress"
	kernelRulesMapName        = "rules_v4"
	kernelFlowsMapName        = "flows_v4"
	kernelNatPortsMapName     = "nat_ports_v4"
	kernelStatsMapName        = "stats_v4"
	kernelReplyFilterPrio     = 10
	kernelForwardFilterPrio   = 20
	kernelForwardFilterHandle = 10
	kernelReplyFilterHandle   = 20
	kernelVerifierLogSize     = 4 * 1024 * 1024
	kernelTCPClosingGraceNS   = 15 * 1000000000
	kernelTCPUnrepliedTimeout = 30 * 1000000000
	kernelTCPFlowIdleTimeout  = 10 * 60 * 1000000000
	kernelUDPFlowIdleTimeout  = 300 * 1000000000
	kernelNATPortMin          = 20000
	kernelNATPortMax          = 60999
)

const (
	kernelFlowFlagFrontClosing = 0x1
	kernelFlowFlagReplySeen    = 0x2
	kernelFlowFlagFullNAT      = 0x4
	kernelFlowFlagFrontEntry   = 0x8
	kernelFlowFlagCounted      = 0x20
)

const (
	kernelRuleFlagFullNAT      = 0x1
	kernelRuleFlagBridgeL2     = 0x2
	kernelRuleFlagTrafficStats = 0x4
)

//go:embed ebpf/forward-tc-bpf.o
var embeddedForwardTCObject []byte

//go:embed ebpf/forward-tc-bpf-stats.o
var embeddedForwardTCStatsObject []byte

type tcRuleKeyV4 struct {
	IfIndex uint32
	DstAddr uint32
	DstPort uint16
	Proto   uint8
	Pad     uint8
}

type tcRuleValueV4 struct {
	RuleID      uint32
	BackendAddr uint32
	BackendPort uint16
	Flags       uint16
	OutIfIndex  uint32
	NATAddr     uint32
	SrcMAC      [6]byte
	DstMAC      [6]byte
}

type tcFlowKeyV4 struct {
	IfIndex uint32
	SrcAddr uint32
	DstAddr uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Pad     [3]uint8
}

type tcFlowValueV4 struct {
	RuleID           uint32
	FrontAddr        uint32
	ClientAddr       uint32
	NATAddr          uint32
	InIfIndex        uint32
	FrontPort        uint16
	ClientPort       uint16
	NATPort          uint16
	Flags            uint16
	Pad              uint32
	LastSeenNS       uint64
	FrontCloseSeenNS uint64
}

type tcNATPortKeyV4 struct {
	IfIndex uint32
	NATAddr uint32
	NATPort uint16
	Proto   uint8
	Pad     uint8
}

type kernelAttachment struct {
	filter *netlink.BpfFilter
}

type kernelAttachmentKey struct {
	linkIndex int
	parent    uint32
	priority  uint16
	handle    uint32
}

type kernelRuleMapEntry struct {
	key   tcRuleKeyV4
	value tcRuleValueV4
}

type kernelRuleMapDiff struct {
	upserts []kernelRuleMapEntry
	deletes []tcRuleKeyV4
}

type kernelRuleMapSnapshot struct {
	key    tcRuleKeyV4
	value  tcRuleValueV4
	exists bool
}

type kernelAttachmentPlan struct {
	key         kernelAttachmentKey
	ifindex     int
	priority    uint16
	handleMinor uint16
	name        string
	prog        *ebpf.Program
}

type preparedKernelRule struct {
	rule       Rule
	inIfIndex  int
	outIfIndex int
	key        tcRuleKeyV4
	value      tcRuleValueV4
}

type preparedKernelPath struct {
	outIfIndex int
	flags      uint16
	srcMAC     [6]byte
	dstMAC     [6]byte
}

type cachedKernelLink struct {
	link netlink.Link
	err  error
}

type cachedKernelSNAT struct {
	addr uint32
	err  error
}

type cachedKernelPath struct {
	path preparedKernelPath
	err  error
}

type kernelPrepareContext struct {
	enableTrafficStats bool
	links              map[string]cachedKernelLink
	snatAddrs          map[string]cachedKernelSNAT
	outPaths           map[string]cachedKernelPath
}

func newKernelPrepareContext(enableTrafficStats bool) *kernelPrepareContext {
	return &kernelPrepareContext{
		enableTrafficStats: enableTrafficStats,
		links:              make(map[string]cachedKernelLink),
		snatAddrs:          make(map[string]cachedKernelSNAT),
		outPaths:           make(map[string]cachedKernelPath),
	}
}

func (ctx *kernelPrepareContext) linkByName(name string) (netlink.Link, error) {
	if ctx == nil {
		return netlink.LinkByName(name)
	}
	if item, ok := ctx.links[name]; ok {
		return item.link, item.err
	}
	link, err := netlink.LinkByName(name)
	ctx.links[name] = cachedKernelLink{link: link, err: err}
	return link, err
}

func (ctx *kernelPrepareContext) resolveSNATIPv4(link netlink.Link, backendIP string, preferredIP string) (uint32, error) {
	if link == nil || link.Attrs() == nil {
		return 0, fmt.Errorf("invalid outbound interface")
	}
	key := fmt.Sprintf("%d|%s|%s", link.Attrs().Index, strings.TrimSpace(backendIP), strings.TrimSpace(preferredIP))
	if ctx != nil {
		if item, ok := ctx.snatAddrs[key]; ok {
			return item.addr, item.err
		}
	}
	addr, err := resolveKernelSNATIPv4(link, backendIP, preferredIP)
	if ctx != nil {
		ctx.snatAddrs[key] = cachedKernelSNAT{addr: addr, err: err}
	}
	return addr, err
}

func (ctx *kernelPrepareContext) resolveOutboundPath(outLink netlink.Link, rule Rule) (preparedKernelPath, error) {
	if outLink == nil || outLink.Attrs() == nil {
		return preparedKernelPath{}, fmt.Errorf("invalid outbound interface")
	}
	key := fmt.Sprintf("%d|%s", outLink.Attrs().Index, strings.TrimSpace(rule.OutIP))
	if ctx != nil {
		if item, ok := ctx.outPaths[key]; ok {
			return item.path, item.err
		}
	}

	path := preparedKernelPath{
		outIfIndex: outLink.Attrs().Index,
	}
	var err error
	if isXDPBridgeLink(outLink) {
		path, err = resolveTCOutboundPath(outLink, rule)
	}
	if ctx != nil {
		ctx.outPaths[key] = cachedKernelPath{path: path, err: err}
	}
	return path, err
}

type linuxKernelRuleRuntime struct {
	mu                 sync.Mutex
	availableOnce      sync.Once
	available          bool
	availableReason    string
	rulesMapLimit      int
	flowsMapLimit      int
	natMapLimit        int
	rulesMapCapacity   int
	flowsMapCapacity   int
	natMapCapacity     int
	memlockOnce        sync.Once
	memlockErr         error
	coll               *ebpf.Collection
	attachments        []kernelAttachment
	preparedRules      []preparedKernelRule
	lastSkipLog        map[string]struct{}
	lastReconcileMode  string
	stateLog           kernelStateLogger
	pressureState      kernelRuntimePressureState
	statsCorrection    map[uint32]kernelRuleStats
	flowPruneState     kernelFlowPruneState
	runtimeMapCounts   kernelRuntimeMapCountSnapshot
	enableTrafficStats bool
}

func newTCKernelRuleRuntime(cfg *Config) *linuxKernelRuleRuntime {
	rulesLimit := 0
	flowsLimit := 0
	natLimit := 0
	enableTrafficStats := false
	if cfg != nil {
		rulesLimit = cfg.KernelRulesMapLimit
		flowsLimit = cfg.KernelFlowsMapLimit
		natLimit = cfg.KernelNATMapLimit
		enableTrafficStats = cfg.ExperimentalFeatureEnabled(experimentalFeatureKernelTraffic)
	}
	return &linuxKernelRuleRuntime{
		rulesMapLimit:      rulesLimit,
		flowsMapLimit:      flowsLimit,
		natMapLimit:        natLimit,
		statsCorrection:    make(map[uint32]kernelRuleStats),
		enableTrafficStats: enableTrafficStats,
	}
}

func newKernelRuleRuntime(cfg *Config) kernelRuleRuntime {
	if cfg == nil {
		return newOrderedKernelRuleRuntime(nil, nil)
	}
	return newOrderedKernelRuleRuntime(cfg.KernelEngineOrder, cfg)
}

func (rt *linuxKernelRuleRuntime) Available() (bool, string) {
	rt.availableOnce.Do(func() {
		spec, err := loadEmbeddedKernelCollectionSpec(rt.enableTrafficStats)
		if err != nil {
			rt.available = false
			rt.availableReason = err.Error()
			log.Printf("kernel dataplane unavailable: %s", rt.availableReason)
			return
		}
		if err := validateKernelCollectionSpec(spec); err != nil {
			rt.available = false
			rt.availableReason = err.Error()
			log.Printf("kernel dataplane unavailable: %s", rt.availableReason)
			return
		}
		if err := rt.ensureMemlock(); err != nil {
			rt.available = true
			rt.availableReason = fmt.Sprintf("embedded tc eBPF object available; memlock auto-raise unavailable: %v (%s)", err, kernelMemlockStatus())
			log.Printf("kernel dataplane warning: %s", rt.availableReason)
			return
		}
		rt.available = true
		rt.availableReason = "embedded tc eBPF object available"
		if rt.enableTrafficStats {
			rt.availableReason += "; kernel_traffic_stats experimental path enabled"
		}
	})
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.currentAvailabilityLocked(time.Now())
}

func (rt *linuxKernelRuleRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	results := make(map[int64]kernelRuleApplyResult, len(rules))
	if rt.coll == nil && !kernelHotRestartStateExists(kernelEngineTC) {
		if err := cleanupOrphanTCKernelRuntimeState(); err != nil {
			log.Printf("kernel dataplane startup cleanup: tc orphan cleanup failed: %v", err)
		}
	}
	if len(rules) == 0 {
		if err := rt.clearActiveRulesLockedPreserveFlows(); err != nil {
			rt.cleanupLocked()
			return results, err
		}
		return results, nil
	}

	prepared, forwardIfRules, replyIfRules, prepareResults, skipLines := prepareKernelRules(rules, rt.preparedRules, rt.coll != nil, rt.enableTrafficStats)
	rt.lastSkipLog = logKernelLineSetOnce(rt.lastSkipLog, skipLines)
	for id, result := range prepareResults {
		results[id] = result
	}
	if len(prepared) == 0 {
		rt.stateLog.Logf("kernel dataplane reconcile: no entries passed kernel preparation")
		if err := rt.clearActiveRulesLockedPreserveFlows(); err != nil {
			rt.cleanupLocked()
			for _, rule := range rules {
				results[rule.ID] = kernelRuleApplyResult{Error: err.Error()}
			}
		}
		return results, nil
	}
	if rt.samePreparedRulesLocked(prepared, forwardIfRules, replyIfRules) {
		rt.lastReconcileMode = "steady"
		rt.stateLog.Logf("kernel dataplane reconcile: entry set unchanged, keeping %d active kernel entry(s)", len(prepared))
		for _, rule := range rules {
			if current, ok := results[rule.ID]; ok && current.Error != "" {
				continue
			}
			results[rule.ID] = kernelRuleApplyResult{Running: true, Engine: kernelEngineTC}
		}
		return results, nil
	}

	desiredCapacities := desiredKernelMapCapacities(rt.rulesMapLimit, rt.flowsMapLimit, rt.natMapLimit, len(prepared), true)
	if rt.canReconcileInPlaceLocked(desiredCapacities) {
		if err := rt.reconcileInPlaceLocked(prepared, forwardIfRules, replyIfRules, results); err == nil {
			return results, nil
		} else {
			log.Printf("kernel dataplane reconcile: in-place update unavailable, falling back to collection rebuild: %v", err)
		}
	}

	spec, err := loadEmbeddedKernelCollectionSpec(rt.enableTrafficStats)
	if err != nil {
		msg := err.Error()
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane reconcile: load embedded object failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if err := validateKernelCollectionSpec(spec); err != nil {
		msg := err.Error()
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane reconcile: object validation failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	desiredCapacities, err = applyKernelMapCapacities(spec, rt.rulesMapLimit, rt.flowsMapLimit, rt.natMapLimit, len(prepared), true)
	if err != nil {
		msg := err.Error()
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane reconcile: map capacity setup failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	memlockErr := rt.ensureMemlock()
	if memlockErr != nil {
		log.Printf("kernel dataplane reconcile: memlock auto-raise unavailable: %v (%s); continuing with current limit", memlockErr, kernelMemlockStatus())
	}
	if rt.rulesMapCapacity != desiredCapacities.Rules || rt.flowsMapCapacity != desiredCapacities.Flows || rt.natMapCapacity != desiredCapacities.NATPorts {
		log.Printf(
			"kernel dataplane reconcile: rules/stats=%d(%s) flows=%d(%s) nat=%d(%s) requested_entries=%d",
			desiredCapacities.Rules,
			kernelRulesMapCapacityMode(rt.rulesMapLimit),
			desiredCapacities.Flows,
			kernelFlowsMapCapacityMode(rt.flowsMapLimit),
			desiredCapacities.NATPorts,
			kernelNATMapCapacityMode(rt.natMapLimit),
			len(prepared),
		)
	}

	var coll *ebpf.Collection
	mapReplacements := map[string]*ebpf.Map(nil)
	actualCapacities := desiredCapacities
	var oldStatsMap *ebpf.Map
	var hotRestartState *kernelHotRestartMapState
	if rt.coll != nil && rt.coll.Maps != nil {
		if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
			if mapReplacements == nil {
				mapReplacements = make(map[string]*ebpf.Map, 3)
			}
			mapReplacements[kernelFlowsMapName] = flowsMap
			actualCapacities.Flows = int(flowsMap.MaxEntries())
			if actualCapacities.Flows < desiredCapacities.Flows {
				log.Printf(
					"kernel dataplane reconcile: keeping existing %s map capacity=%d below desired=%d until restart to preserve active sessions",
					kernelFlowsMapName,
					actualCapacities.Flows,
					desiredCapacities.Flows,
				)
			}
		}
		if natPortsMap := rt.coll.Maps[kernelNatPortsMapName]; natPortsMap != nil {
			if mapReplacements == nil {
				mapReplacements = make(map[string]*ebpf.Map, 3)
			}
			mapReplacements[kernelNatPortsMapName] = natPortsMap
			actualCapacities.NATPorts = int(natPortsMap.MaxEntries())
			if actualCapacities.NATPorts < desiredCapacities.NATPorts {
				log.Printf(
					"kernel dataplane reconcile: keeping existing %s map capacity=%d below desired=%d until restart to preserve active sessions",
					kernelNatPortsMapName,
					actualCapacities.NATPorts,
					desiredCapacities.NATPorts,
				)
			}
		}
		if statsMap := rt.coll.Maps[kernelStatsMapName]; statsMap != nil {
			if kernelMapReusableWithCapacity(statsMap, desiredCapacities.Rules) {
				if mapReplacements == nil {
					mapReplacements = make(map[string]*ebpf.Map, 3)
				}
				mapReplacements[kernelStatsMapName] = statsMap
			} else {
				oldStatsMap = statsMap
				log.Printf(
					"kernel dataplane reconcile: recreating %s map with capacity=%d (existing=%d too small)",
					kernelStatsMapName,
					desiredCapacities.Rules,
					statsMap.MaxEntries(),
				)
			}
		}
	} else if state, err := loadTCKernelHotRestartState(desiredCapacities); err != nil {
		log.Printf("kernel dataplane hot restart: load tc state failed, cleaning stale hot restart state: %v", err)
		if cleanupErr := cleanupStaleTCKernelHotRestartState(); cleanupErr != nil {
			log.Printf("kernel dataplane hot restart: cleanup stale tc state failed, discarding pinned state only: %v", cleanupErr)
			clearKernelHotRestartState(kernelEngineTC)
		}
	} else if state != nil {
		hotRestartState = state
		if len(state.replacements) > 0 {
			mapReplacements = state.replacements
		}
		oldStatsMap = state.oldStatsMap
		actualCapacities = state.actualCapacities
		if actualCapacities.Flows < desiredCapacities.Flows {
			log.Printf(
				"kernel dataplane hot restart: keeping pinned %s map capacity=%d below desired=%d until restart to preserve active sessions",
				kernelFlowsMapName,
				actualCapacities.Flows,
				desiredCapacities.Flows,
			)
		}
		if actualCapacities.NATPorts < desiredCapacities.NATPorts {
			log.Printf(
				"kernel dataplane hot restart: keeping pinned %s map capacity=%d below desired=%d until restart to preserve active sessions",
				kernelNatPortsMapName,
				actualCapacities.NATPorts,
				desiredCapacities.NATPorts,
			)
		}
		if oldStatsMap != nil {
			log.Printf(
				"kernel dataplane hot restart: recreating %s map with capacity=%d (pinned=%d too small)",
				kernelStatsMapName,
				desiredCapacities.Rules,
				oldStatsMap.MaxEntries(),
			)
		}
		log.Printf(
			"kernel dataplane hot restart: adopting pinned tc maps=%s from %s",
			strings.Join(state.replacementMapNames(), ","),
			kernelHotRestartEngineDir(kernelEngineTC),
		)
	}
	if len(mapReplacements) > 0 {
		coll, err = ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(mapReplacements))
	} else {
		coll, err = ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(nil))
	}
	if err != nil && hotRestartState != nil {
		log.Printf("kernel dataplane hot restart: adopt tc state failed, retrying with fresh maps: %v", err)
		hotRestartState.close()
		hotRestartState = nil
		mapReplacements = nil
		oldStatsMap = nil
		actualCapacities = desiredCapacities
		if cleanupErr := cleanupStaleTCKernelHotRestartState(); cleanupErr != nil {
			log.Printf("kernel dataplane hot restart: cleanup stale tc state failed, discarding pinned state only: %v", cleanupErr)
			clearKernelHotRestartState(kernelEngineTC)
		}
		coll, err = ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(nil))
	}
	if err != nil {
		logKernelVerifierDetails(err)
		msg := kernelCollectionLoadError(err, memlockErr)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		rt.disableLocked(kernelRuntimeUnavailableReason(err))
		rt.cleanupLocked()
		log.Printf("kernel dataplane reconcile: collection load failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}

	forwardProg, replyProg, rulesMap, err := lookupKernelCollectionPieces(coll)
	if err != nil {
		coll.Close()
		msg := err.Error()
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane reconcile: object lookup failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if oldStatsMap != nil {
		if err := copyKernelStatsMap(coll.Maps[kernelStatsMapName], oldStatsMap); err != nil {
			log.Printf("kernel dataplane reconcile: copy %s contents failed: %v", kernelStatsMapName, err)
			rt.statsCorrection = make(map[uint32]kernelRuleStats)
		}
		if hotRestartState != nil {
			_ = oldStatsMap.Close()
			hotRestartState.oldStatsMap = nil
		}
	}

	keys := make([]tcRuleKeyV4, 0, len(prepared))
	values := make([]tcRuleValueV4, 0, len(prepared))
	for _, item := range prepared {
		keys = append(keys, item.key)
		values = append(values, item.value)
	}
	if err := updateKernelMapEntries(rulesMap, keys, values); err != nil {
		coll.Close()
		msg := fmt.Sprintf("update kernel rule map: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane rule map bulk update failed: %v", err)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}

	oldAttachments := append([]kernelAttachment(nil), rt.attachments...)
	forwardReady := make(map[int]bool)
	replyReady := make(map[int]bool)
	newAttachments := make([]kernelAttachment, 0, len(forwardIfRules)+len(replyIfRules))
	attachFailure := ""

	for ifindex, ruleIDs := range forwardIfRules {
		if err := rt.attachProgramLocked(&newAttachments, ifindex, kernelForwardFilterPrio, kernelForwardFilterHandle, kernelForwardProgramName, forwardProg); err != nil {
			log.Printf("kernel dataplane attach failed: program=%s ifindex=%d rules=%v err=%v", kernelForwardProgramName, ifindex, ruleIDs, err)
			for _, id := range ruleIDs {
				results[id] = kernelRuleApplyResult{Error: fmt.Sprintf("attach forward program on ifindex %d: %v", ifindex, err)}
			}
			if attachFailure == "" {
				attachFailure = fmt.Sprintf("attach forward program on ifindex %d: %v", ifindex, err)
			}
			break
		}
		forwardReady[ifindex] = true
	}

	if attachFailure == "" {
		for ifindex, ruleIDs := range replyIfRules {
			if err := rt.attachProgramLocked(&newAttachments, ifindex, kernelReplyFilterPrio, kernelReplyFilterHandle, kernelReplyProgramName, replyProg); err != nil {
				log.Printf("kernel dataplane attach failed: program=%s ifindex=%d rules=%v err=%v", kernelReplyProgramName, ifindex, ruleIDs, err)
				for _, id := range ruleIDs {
					results[id] = kernelRuleApplyResult{Error: fmt.Sprintf("attach reply program on ifindex %d: %v", ifindex, err)}
				}
				if attachFailure == "" {
					attachFailure = fmt.Sprintf("attach reply program on ifindex %d: %v", ifindex, err)
				}
				break
			}
			replyReady[ifindex] = true
		}
	}

	if attachFailure != "" {
		rt.discardAttachmentsLocked(newAttachments)
		coll.Close()
		if rt.applyRetainedRulesOnFailureLocked(results, rules, attachFailure) {
			return results, nil
		}
		for _, rule := range rules {
			if current, ok := results[rule.ID]; ok && current.Error != "" {
				continue
			}
			results[rule.ID] = kernelRuleApplyResult{Error: attachFailure}
		}
		return results, nil
	}

	runningAny := false
	for _, item := range prepared {
		if current, ok := results[item.rule.ID]; ok && current.Error != "" {
			continue
		}
		if !forwardReady[item.inIfIndex] {
			results[item.rule.ID] = kernelRuleApplyResult{Error: "kernel forward hook is not attached"}
			continue
		}
		if !replyReady[item.outIfIndex] {
			results[item.rule.ID] = kernelRuleApplyResult{Error: "kernel reply hook is not attached"}
			continue
		}
		results[item.rule.ID] = kernelRuleApplyResult{Running: true, Engine: kernelEngineTC}
		runningAny = true
	}

	if !runningAny {
		rt.stateLog.Logf("kernel dataplane reconcile: no rules reached running state")
		coll.Close()
		rt.cleanupLocked()
		return results, nil
	}

	rt.stateLog.Logf("kernel dataplane reconcile: applied %d/%d kernel entry(s)", len(prepared), len(rules))
	rt.deleteStaleAttachmentsLocked(oldAttachments, newAttachments)
	if rt.coll != nil {
		rt.coll.Close()
	}
	rt.coll = coll
	rt.attachments = newAttachments
	rt.preparedRules = clonePreparedKernelRules(prepared)
	rt.rulesMapCapacity = actualCapacities.Rules
	rt.flowsMapCapacity = actualCapacities.Flows
	rt.natMapCapacity = actualCapacities.NATPorts
	rt.flowPruneState.reset()
	rt.lastReconcileMode = "rebuild"
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	if err := writeKernelRuntimeMetadata(kernelEngineTC, kernelHotRestartTCMetadata(rt.attachments)); err != nil {
		log.Printf("kernel dataplane runtime metadata: write tc runtime metadata failed: %v", err)
	}
	if hotRestartState != nil {
		clearKernelHotRestartState(kernelEngineTC)
	}
	return results, nil
}

func (rt *linuxKernelRuleRuntime) ensureMemlock() error {
	rt.memlockOnce.Do(func() {
		rt.memlockErr = rlimit.RemoveMemlock()
	})
	return rt.memlockErr
}

func (rt *linuxKernelRuleRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	return snapshotKernelStatsFromCollection(rt.coll, cloneKernelStatsCorrections(rt.statsCorrection))
}

func (rt *linuxKernelRuleRuntime) Maintain() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	corrections, err := pruneStaleKernelFlowsInCollection(rt.coll, &rt.flowPruneState, rt.flowMaintenanceBudgetLocked())
	if err != nil {
		return err
	}
	mergeKernelStatsCorrections(rt.statsCorrection, corrections)
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	return nil
}

func (rt *linuxKernelRuleRuntime) SnapshotAssignments() map[int64]string {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	assignments := make(map[int64]string, len(rt.preparedRules))
	for _, item := range rt.preparedRules {
		assignments[item.rule.ID] = kernelEngineTC
	}
	return assignments
}

func kernelCollectionLoadError(err error, memlockErr error) string {
	msg := fmt.Sprintf("create kernel collection: %v", err)
	errText := strings.ToLower(err.Error())
	if strings.Contains(errText, "operation not permitted") {
		msg += fmt.Sprintf("; check service capabilities CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON and memlock limit (%s)", kernelMemlockStatus())
		if memlockErr != nil {
			msg += fmt.Sprintf("; memlock auto-raise unavailable: %v", memlockErr)
		}
	}
	if strings.Contains(errText, "prohibited for !root") {
		msg += "; kernel treated the loader as unprivileged, CAP_PERFMON or CAP_SYS_ADMIN may be missing"
	}
	if strings.Contains(errText, "hit verifier bug") {
		msg += fmt.Sprintf("; kernel verifier bug detected on %s, upgrade to a kernel with the verifier fix", kernelRelease())
	}
	return msg
}

func kernelCollectionOptions(mapReplacements map[string]*ebpf.Map) ebpf.CollectionOptions {
	return ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSizeStart: kernelVerifierLogSize,
		},
		MapReplacements: mapReplacements,
	}
}

func logKernelVerifierDetails(err error) {
	var verr *ebpf.VerifierError
	if !errors.As(err, &verr) || len(verr.Log) == 0 {
		return
	}
	log.Printf("kernel dataplane verifier log: begin")
	for _, line := range verr.Log {
		log.Printf("kernel dataplane verifier: %s", line)
	}
	log.Printf("kernel dataplane verifier log: end")
}

func kernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "unknown-kernel"
	}

	var buf []byte
	for _, c := range uts.Release {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	if len(buf) == 0 {
		return "unknown-kernel"
	}
	return string(buf)
}

func kernelVerifierBugDetected(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "hit verifier bug")
}

func kernelRuntimeUnavailableReason(err error) string {
	if kernelVerifierBugDetected(err) {
		return fmt.Sprintf("kernel verifier bug on %s blocked tc eBPF program load", kernelRelease())
	}
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		return fmt.Sprintf("kernel verifier rejected the tc eBPF program on %s", kernelRelease())
	}
	errText := strings.ToLower(err.Error())
	if strings.Contains(errText, "prohibited for !root") || strings.Contains(errText, "operation not permitted") || strings.Contains(errText, "permission denied") {
		return fmt.Sprintf("kernel tc eBPF load is unavailable in the current service context on %s", kernelRelease())
	}
	return ""
}

func (rt *linuxKernelRuleRuntime) disableLocked(reason string) {
	if strings.TrimSpace(reason) == "" {
		return
	}
	rt.available = false
	rt.availableReason = reason
}

func kernelMemlockStatus() string {
	var lim unix.Rlimit
	if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, nil, &lim); err != nil {
		return fmt.Sprintf("memlock=unknown err=%v", err)
	}
	return fmt.Sprintf("memlock_cur=%s memlock_max=%s", formatKernelRlimit(lim.Cur), formatKernelRlimit(lim.Max))
}

func formatKernelRlimit(v uint64) string {
	if v == unix.RLIM_INFINITY {
		return "infinity"
	}
	return fmt.Sprintf("%d", v)
}

func (rt *linuxKernelRuleRuntime) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.prepareHotRestartLocked() {
		return nil
	}
	rt.cleanupLocked()
	return nil
}

func (rt *linuxKernelRuleRuntime) prepareHotRestartLocked() bool {
	if !kernelHotRestartRequested() {
		return false
	}
	if rt.coll == nil || rt.coll.Maps == nil || len(rt.attachments) == 0 {
		return false
	}
	if err := pinKernelHotRestartMaps(kernelEngineTC, map[string]*ebpf.Map{
		kernelFlowsMapName:    rt.coll.Maps[kernelFlowsMapName],
		kernelNatPortsMapName: rt.coll.Maps[kernelNatPortsMapName],
		kernelStatsMapName:    rt.coll.Maps[kernelStatsMapName],
	}); err != nil {
		log.Printf("kernel dataplane hot restart: preserve tc maps failed, falling back to full cleanup: %v", err)
		rt.cleanupLocked()
		return true
	}
	if err := writeKernelHotRestartMetadata(kernelEngineTC, kernelHotRestartTCMetadata(rt.attachments)); err != nil {
		clearKernelHotRestartState(kernelEngineTC)
		log.Printf("kernel dataplane hot restart: write tc metadata failed, falling back to full cleanup: %v", err)
		rt.cleanupLocked()
		return true
	}
	log.Printf(
		"kernel dataplane hot restart: preserved tc session state at %s, leaving %d attachment(s) active for successor",
		kernelHotRestartEngineDir(kernelEngineTC),
		len(rt.attachments),
	)
	rt.attachments = nil
	rt.preparedRules = nil
	rt.rulesMapCapacity = 0
	rt.flowsMapCapacity = 0
	rt.natMapCapacity = 0
	rt.lastReconcileMode = ""
	rt.statsCorrection = make(map[uint32]kernelRuleStats)
	rt.flowPruneState = kernelFlowPruneState{}
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	if rt.coll != nil {
		rt.coll.Close()
		rt.coll = nil
	}
	return true
}

func (rt *linuxKernelRuleRuntime) cleanupLocked() {
	for i := len(rt.attachments) - 1; i >= 0; i-- {
		if rt.attachments[i].filter != nil {
			_ = netlink.FilterDel(rt.attachments[i].filter)
		}
	}
	clearKernelRuntimeMetadata(kernelEngineTC)
	rt.attachments = nil
	rt.preparedRules = nil
	rt.rulesMapCapacity = 0
	rt.flowsMapCapacity = 0
	rt.natMapCapacity = 0
	rt.lastReconcileMode = ""
	rt.statsCorrection = make(map[uint32]kernelRuleStats)
	rt.flowPruneState = kernelFlowPruneState{}
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	if rt.coll != nil {
		rt.coll.Close()
		rt.coll = nil
	}
}

func (rt *linuxKernelRuleRuntime) applyRetainedRulesOnFailureLocked(results map[int64]kernelRuleApplyResult, rules []Rule, reason string) bool {
	retained, err := rt.retainMatchingRulesLocked(rules)
	if err != nil {
		log.Printf("kernel dataplane reconcile: failed to retain active kernel rules after rebuild failure: %v", err)
		rt.cleanupLocked()
		return false
	}
	if len(retained) == 0 {
		return false
	}
	log.Printf("kernel dataplane reconcile: rebuild failed, preserving %d active tc rule(s): %s", len(retained), reason)
	for _, rule := range rules {
		if _, ok := retained[rule.ID]; ok {
			results[rule.ID] = kernelRuleApplyResult{Running: true, Engine: kernelEngineTC}
			continue
		}
		if current, ok := results[rule.ID]; ok && current.Running {
			continue
		}
		results[rule.ID] = kernelRuleApplyResult{Error: reason}
	}
	return true
}

func (rt *linuxKernelRuleRuntime) retainMatchingRulesLocked(rules []Rule) (map[int64]struct{}, error) {
	retained := make(map[int64]struct{})
	if rt.coll == nil || rt.coll.Maps == nil || len(rt.preparedRules) == 0 {
		return retained, nil
	}
	rulesMap := rt.coll.Maps[kernelRulesMapName]
	if rulesMap == nil {
		return retained, nil
	}

	desiredByKey := indexKernelRulesByMatchKey(rules)

	kept := make([]preparedKernelRule, 0, len(rt.preparedRules))
	for _, item := range rt.preparedRules {
		desired, ok := matchDesiredKernelRule(desiredByKey, item.rule)
		if ok {
			kept = append(kept, item)
			retained[desired.ID] = struct{}{}
			continue
		}
		if err := deleteKernelMapEntry(rulesMap, item.key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("delete stale preserved kernel rule %d: %w", item.rule.ID, err)
		}
	}
	rt.preparedRules = kept
	capacities := rt.currentMapCapacitiesLocked()
	rt.rulesMapCapacity = capacities.Rules
	rt.flowsMapCapacity = capacities.Flows
	rt.natMapCapacity = capacities.NATPorts
	rt.flowPruneState.reset()
	rt.invalidatePressureStateLocked()
	return retained, nil
}

func (rt *linuxKernelRuleRuntime) flowMaintenanceBudgetLocked() int {
	if rt.coll != nil && rt.coll.Maps != nil {
		if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
			return kernelFlowMaintenanceBudgetForCapacity(int(flowsMap.MaxEntries()))
		}
	}
	return kernelFlowMaintenanceBudgetForCapacity(rt.flowsMapCapacity)
}

func kernelAttachmentKeyForFilter(filter *netlink.BpfFilter) kernelAttachmentKey {
	return kernelAttachmentKey{
		linkIndex: filter.LinkIndex,
		parent:    filter.Parent,
		priority:  filter.Priority,
		handle:    filter.Handle,
	}
}

func desiredKernelAttachmentPlans(forwardIfRules map[int][]int64, replyIfRules map[int][]int64, forwardProg *ebpf.Program, replyProg *ebpf.Program) []kernelAttachmentPlan {
	plans := make([]kernelAttachmentPlan, 0, len(forwardIfRules)+len(replyIfRules))
	for ifindex := range forwardIfRules {
		plans = append(plans, kernelAttachmentPlan{
			key: kernelAttachmentKey{
				linkIndex: ifindex,
				parent:    netlink.HANDLE_MIN_INGRESS,
				priority:  kernelForwardFilterPrio,
				handle:    netlink.MakeHandle(0, kernelForwardFilterHandle),
			},
			ifindex:     ifindex,
			priority:    kernelForwardFilterPrio,
			handleMinor: kernelForwardFilterHandle,
			name:        kernelForwardProgramName,
			prog:        forwardProg,
		})
	}
	for ifindex := range replyIfRules {
		plans = append(plans, kernelAttachmentPlan{
			key: kernelAttachmentKey{
				linkIndex: ifindex,
				parent:    netlink.HANDLE_MIN_INGRESS,
				priority:  kernelReplyFilterPrio,
				handle:    netlink.MakeHandle(0, kernelReplyFilterHandle),
			},
			ifindex:     ifindex,
			priority:    kernelReplyFilterPrio,
			handleMinor: kernelReplyFilterHandle,
			name:        kernelReplyProgramName,
			prog:        replyProg,
		})
	}
	sort.Slice(plans, func(i, j int) bool {
		if plans[i].ifindex != plans[j].ifindex {
			return plans[i].ifindex < plans[j].ifindex
		}
		if plans[i].priority != plans[j].priority {
			return plans[i].priority < plans[j].priority
		}
		return plans[i].key.handle < plans[j].key.handle
	})
	return plans
}

func diffPreparedKernelRules(oldItems []preparedKernelRule, nextItems []preparedKernelRule) kernelRuleMapDiff {
	if len(oldItems) == 0 && len(nextItems) == 0 {
		return kernelRuleMapDiff{}
	}

	oldByKey := make(map[tcRuleKeyV4]tcRuleValueV4, len(oldItems))
	nextByKey := make(map[tcRuleKeyV4]tcRuleValueV4, len(nextItems))
	for _, item := range oldItems {
		oldByKey[item.key] = item.value
	}
	for _, item := range nextItems {
		nextByKey[item.key] = item.value
	}

	diff := kernelRuleMapDiff{
		upserts: make([]kernelRuleMapEntry, 0),
		deletes: make([]tcRuleKeyV4, 0),
	}
	for _, item := range nextItems {
		oldValue, ok := oldByKey[item.key]
		if ok && oldValue == item.value {
			continue
		}
		diff.upserts = append(diff.upserts, kernelRuleMapEntry{key: item.key, value: item.value})
		delete(oldByKey, item.key)
	}
	for _, item := range oldItems {
		if _, ok := nextByKey[item.key]; ok {
			continue
		}
		diff.deletes = append(diff.deletes, item.key)
	}
	return diff
}

func (rt *linuxKernelRuleRuntime) currentMapCapacitiesLocked() kernelMapCapacities {
	capacities := kernelMapCapacities{
		Rules:    rt.rulesMapCapacity,
		Flows:    rt.flowsMapCapacity,
		NATPorts: rt.natMapCapacity,
	}
	if rt.coll == nil || rt.coll.Maps == nil {
		return capacities
	}
	if rulesMap := rt.coll.Maps[kernelRulesMapName]; rulesMap != nil {
		capacities.Rules = int(rulesMap.MaxEntries())
	}
	if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
		capacities.Flows = int(flowsMap.MaxEntries())
	}
	if natPortsMap := rt.coll.Maps[kernelNatPortsMapName]; natPortsMap != nil {
		capacities.NATPorts = int(natPortsMap.MaxEntries())
	}
	return capacities
}

func mergeKernelAttachments(oldAttachments, newAttachments []kernelAttachment) []kernelAttachment {
	if len(oldAttachments) == 0 {
		return append([]kernelAttachment(nil), newAttachments...)
	}
	out := make([]kernelAttachment, 0, len(oldAttachments)+len(newAttachments))
	seen := make(map[kernelAttachmentKey]struct{}, len(oldAttachments)+len(newAttachments))
	for _, att := range newAttachments {
		if att.filter == nil {
			continue
		}
		key := kernelAttachmentKeyForFilter(att.filter)
		seen[key] = struct{}{}
		out = append(out, att)
	}
	for _, att := range oldAttachments {
		if att.filter == nil {
			continue
		}
		key := kernelAttachmentKeyForFilter(att.filter)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, att)
	}
	return out
}

func (rt *linuxKernelRuleRuntime) canReconcileInPlaceLocked(desired kernelMapCapacities) bool {
	if rt.coll == nil || rt.coll.Maps == nil {
		return false
	}
	if rt.coll.Programs[kernelForwardProgramName] == nil || rt.coll.Programs[kernelReplyProgramName] == nil {
		return false
	}
	rulesMap := rt.coll.Maps[kernelRulesMapName]
	flowsMap := rt.coll.Maps[kernelFlowsMapName]
	natPortsMap := rt.coll.Maps[kernelNatPortsMapName]
	statsMap := rt.coll.Maps[kernelStatsMapName]
	if rulesMap == nil || flowsMap == nil || natPortsMap == nil || statsMap == nil {
		return false
	}
	if !kernelMapReusableWithCapacity(rulesMap, desired.Rules) {
		return false
	}
	if !kernelMapReusableWithCapacity(statsMap, desired.Rules) {
		return false
	}
	return true
}

func (rt *linuxKernelRuleRuntime) clearActiveRulesLockedPreserveFlows() error {
	if rt.coll == nil || rt.coll.Maps == nil {
		if !kernelHotRestartStateExists(kernelEngineTC) {
			if err := cleanupOrphanTCKernelRuntimeState(); err != nil {
				return fmt.Errorf("cleanup tc orphan runtime state: %w", err)
			}
		}
		if err := cleanupStaleTCKernelHotRestartState(); err != nil {
			return fmt.Errorf("cleanup stale tc hot restart state: %w", err)
		}
		rt.cleanupLocked()
		return nil
	}
	rulesMap := rt.coll.Maps[kernelRulesMapName]
	if rulesMap == nil {
		rt.cleanupLocked()
		return nil
	}
	for _, item := range rt.preparedRules {
		if err := deleteKernelMapEntry(rulesMap, item.key); err != nil {
			return fmt.Errorf("clear kernel rule key during drain: %w", err)
		}
	}
	capacities := rt.currentMapCapacitiesLocked()
	rt.preparedRules = nil
	rt.rulesMapCapacity = capacities.Rules
	rt.flowsMapCapacity = capacities.Flows
	rt.natMapCapacity = capacities.NATPorts
	rt.lastReconcileMode = "cleared"
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	if len(rt.attachments) > 0 {
		if err := writeKernelRuntimeMetadata(kernelEngineTC, kernelHotRestartTCMetadata(rt.attachments)); err != nil {
			log.Printf("kernel dataplane runtime metadata: refresh tc runtime metadata failed after rule drain: %v", err)
		}
	}
	rt.stateLog.Logf("kernel dataplane reconcile: drained active rules, preserving flows for existing connections")
	return nil
}

func (rt *linuxKernelRuleRuntime) reconcileInPlaceLocked(prepared []preparedKernelRule, forwardIfRules map[int][]int64, replyIfRules map[int][]int64, results map[int64]kernelRuleApplyResult) error {
	forwardProg, replyProg, rulesMap, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		return err
	}

	diff := diffPreparedKernelRules(rt.preparedRules, prepared)
	plans := desiredKernelAttachmentPlans(forwardIfRules, replyIfRules, forwardProg, replyProg)
	currentAttachments := make(map[kernelAttachmentKey]kernelAttachment, len(rt.attachments))
	for _, att := range rt.attachments {
		if att.filter == nil {
			continue
		}
		currentAttachments[kernelAttachmentKeyForFilter(att.filter)] = att
	}
	plannedKeys := make([]kernelAttachmentKey, 0, len(plans))
	for _, plan := range plans {
		plannedKeys = append(plannedKeys, plan.key)
	}
	existingAttachments := kernelAttachmentPresence(plannedKeys)

	newAttachments := make([]kernelAttachment, 0, len(plans))
	createdAttachments := make([]kernelAttachment, 0, len(plans))
	forwardReady := make(map[int]bool, len(forwardIfRules))
	replyReady := make(map[int]bool, len(replyIfRules))

	for _, plan := range plans {
		if current, ok := currentAttachments[plan.key]; ok && existingAttachments[plan.key] {
			newAttachments = append(newAttachments, current)
		} else {
			if err := rt.attachProgramLocked(&createdAttachments, plan.ifindex, plan.priority, plan.handleMinor, plan.name, plan.prog); err != nil {
				rt.discardAttachmentsLocked(createdAttachments)
				return fmt.Errorf("attach %s on ifindex %d: %w", plan.name, plan.ifindex, err)
			}
			newAttachments = append(newAttachments, createdAttachments[len(createdAttachments)-1])
		}
		switch plan.name {
		case kernelForwardProgramName:
			forwardReady[plan.ifindex] = true
		case kernelReplyProgramName:
			replyReady[plan.ifindex] = true
		}
	}

	if err := applyKernelRuleMapDiff(rulesMap, diff); err != nil {
		rt.discardAttachmentsLocked(createdAttachments)
		return err
	}

	oldAttachments := append([]kernelAttachment(nil), rt.attachments...)
	mergedAttachments := mergeKernelAttachments(oldAttachments, newAttachments)

	runningAny := false
	for _, item := range prepared {
		if current, ok := results[item.rule.ID]; ok && current.Error != "" {
			continue
		}
		if !forwardReady[item.inIfIndex] {
			results[item.rule.ID] = kernelRuleApplyResult{Error: "kernel forward hook is not attached"}
			continue
		}
		if !replyReady[item.outIfIndex] {
			results[item.rule.ID] = kernelRuleApplyResult{Error: "kernel reply hook is not attached"}
			continue
		}
		results[item.rule.ID] = kernelRuleApplyResult{Running: true, Engine: kernelEngineTC}
		runningAny = true
	}
	if !runningAny {
		rt.discardAttachmentsLocked(createdAttachments)
		return fmt.Errorf("no rules reached running state after in-place update")
	}

	actualCapacities := rt.currentMapCapacitiesLocked()
	rt.attachments = mergedAttachments
	rt.preparedRules = clonePreparedKernelRules(prepared)
	rt.rulesMapCapacity = actualCapacities.Rules
	rt.flowsMapCapacity = actualCapacities.Flows
	rt.natMapCapacity = actualCapacities.NATPorts
	rt.flowPruneState.reset()
	rt.lastReconcileMode = "in_place"
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	if err := writeKernelRuntimeMetadata(kernelEngineTC, kernelHotRestartTCMetadata(rt.attachments)); err != nil {
		log.Printf("kernel dataplane runtime metadata: write tc runtime metadata failed after in-place update: %v", err)
	}
	rt.stateLog.Logf(
		"kernel dataplane reconcile: updated %d active kernel entry(s) in-place (upsert=%d delete=%d attach=%d detach=%d preserve=%d)",
		len(prepared),
		len(diff.upserts),
		len(diff.deletes),
		len(createdAttachments),
		0,
		len(mergedAttachments)-len(newAttachments),
	)
	return nil
}

func kernelAttachmentDeleteCount(oldAttachments, newAttachments []kernelAttachment) int {
	if len(oldAttachments) == 0 {
		return 0
	}
	newKeys := make(map[kernelAttachmentKey]struct{}, len(newAttachments))
	for _, att := range newAttachments {
		if att.filter == nil {
			continue
		}
		newKeys[kernelAttachmentKeyForFilter(att.filter)] = struct{}{}
	}
	count := 0
	for _, att := range oldAttachments {
		if att.filter == nil {
			continue
		}
		if _, ok := newKeys[kernelAttachmentKeyForFilter(att.filter)]; ok {
			continue
		}
		count++
	}
	return count
}

func (rt *linuxKernelRuleRuntime) discardAttachmentsLocked(attachments []kernelAttachment) {
	for i := len(attachments) - 1; i >= 0; i-- {
		if attachments[i].filter == nil {
			continue
		}
		_ = netlink.FilterDel(attachments[i].filter)
	}
}

func (rt *linuxKernelRuleRuntime) deleteStaleAttachmentsLocked(oldAttachments, newAttachments []kernelAttachment) {
	newKeys := make(map[kernelAttachmentKey]struct{}, len(newAttachments))
	for _, att := range newAttachments {
		if att.filter == nil {
			continue
		}
		newKeys[kernelAttachmentKeyForFilter(att.filter)] = struct{}{}
	}

	for _, att := range oldAttachments {
		if att.filter == nil {
			continue
		}
		if _, ok := newKeys[kernelAttachmentKeyForFilter(att.filter)]; ok {
			continue
		}
		_ = netlink.FilterDel(att.filter)
	}
}

func (rt *linuxKernelRuleRuntime) attachProgramLocked(dst *[]kernelAttachment, ifindex int, priority uint16, handleMinor uint16, name string, prog *ebpf.Program) error {
	if err := ensureClsactQdisc(ifindex); err != nil {
		return err
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0, handleMinor),
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Priority:  priority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return err
	}

	*dst = append(*dst, kernelAttachment{filter: filter})
	return nil
}

func ensureClsactQdisc(ifindex int) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	return netlink.QdiscReplace(qdisc)
}

func loadEmbeddedKernelCollectionSpec(enableTrafficStats bool) (*ebpf.CollectionSpec, error) {
	objectBytes := embeddedForwardTCObject
	objectName := "internal/app/ebpf/forward-tc-bpf.o"
	if enableTrafficStats {
		objectBytes = embeddedForwardTCStatsObject
		objectName = "internal/app/ebpf/forward-tc-bpf-stats.o"
	}
	if len(objectBytes) == 0 {
		return nil, fmt.Errorf("embedded tc eBPF object is empty; build %s before compiling", objectName)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objectBytes))
	if err != nil {
		return nil, fmt.Errorf("load embedded tc eBPF object: %w", err)
	}
	return spec, nil
}

func validateKernelCollectionSpec(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return fmt.Errorf("embedded tc eBPF object is missing")
	}
	if _, ok := spec.Programs[kernelForwardProgramName]; !ok {
		return fmt.Errorf("embedded tc eBPF object is missing program %q", kernelForwardProgramName)
	}
	if _, ok := spec.Programs[kernelReplyProgramName]; !ok {
		return fmt.Errorf("embedded tc eBPF object is missing program %q", kernelReplyProgramName)
	}
	if _, ok := spec.Maps[kernelRulesMapName]; !ok {
		return fmt.Errorf("embedded tc eBPF object is missing map %q", kernelRulesMapName)
	}
	if _, ok := spec.Maps[kernelFlowsMapName]; !ok {
		return fmt.Errorf("embedded tc eBPF object is missing map %q", kernelFlowsMapName)
	}
	if _, ok := spec.Maps[kernelNatPortsMapName]; !ok {
		return fmt.Errorf("embedded tc eBPF object is missing map %q", kernelNatPortsMapName)
	}
	if _, ok := spec.Maps[kernelStatsMapName]; !ok {
		return fmt.Errorf("embedded tc eBPF object is missing map %q", kernelStatsMapName)
	}
	return nil
}

func lookupKernelCollectionPieces(coll *ebpf.Collection) (*ebpf.Program, *ebpf.Program, *ebpf.Map, error) {
	forwardProg := coll.Programs[kernelForwardProgramName]
	replyProg := coll.Programs[kernelReplyProgramName]
	rulesMap := coll.Maps[kernelRulesMapName]
	flowsMap := coll.Maps[kernelFlowsMapName]
	if forwardProg == nil || replyProg == nil || rulesMap == nil || flowsMap == nil {
		return nil, nil, nil, fmt.Errorf("kernel object is missing required programs or maps")
	}
	return forwardProg, replyProg, rulesMap, nil
}

func prepareKernelRule(ctx *kernelPrepareContext, rule Rule) ([]preparedKernelRule, error) {
	inLink, err := ctx.linkByName(rule.InInterface)
	if err != nil {
		return nil, fmt.Errorf("resolve inbound interface %q: %w", rule.InInterface, err)
	}
	outLink, err := ctx.linkByName(rule.OutInterface)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound interface %q: %w", rule.OutInterface, err)
	}

	if rule.ID <= 0 || rule.ID > int64(^uint32(0)) {
		return nil, fmt.Errorf("kernel dataplane requires a rule id in uint32 range")
	}
	if !kernelProtocolSupported(rule.Protocol) {
		return nil, fmt.Errorf("kernel dataplane currently supports only single-protocol TCP/UDP rules")
	}

	inAddr, err := parseKernelInboundIPv4Uint32(rule.InIP)
	if err != nil {
		return nil, fmt.Errorf("parse inbound ip %q: %w", rule.InIP, err)
	}
	outAddr, err := parseIPv4Uint32(rule.OutIP)
	if err != nil {
		return nil, fmt.Errorf("parse outbound ip %q: %w", rule.OutIP, err)
	}

	inLinks, err := resolveTCInboundLinks(inLink)
	if err != nil {
		return nil, fmt.Errorf("resolve inbound kernel interfaces for %q: %w", rule.InInterface, err)
	}

	path, err := ctx.resolveOutboundPath(outLink, rule)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound path on %q: %w", rule.OutInterface, err)
	}

	natAddr := uint32(0)
	if !rule.Transparent {
		natAddr, err = ctx.resolveSNATIPv4(outLink, rule.OutIP, rule.OutSourceIP)
		if err != nil {
			return nil, fmt.Errorf("resolve outbound nat ip on %q: %w", rule.OutInterface, err)
		}
		path.flags |= kernelRuleFlagFullNAT
	}
	if ctx != nil && ctx.enableTrafficStats {
		path.flags |= kernelRuleFlagTrafficStats
	}

	prepared := make([]preparedKernelRule, 0, len(inLinks))
	for _, currentInLink := range inLinks {
		if currentInLink == nil || currentInLink.Attrs() == nil {
			continue
		}
		prepared = append(prepared, preparedKernelRule{
			rule:       rule,
			inIfIndex:  currentInLink.Attrs().Index,
			outIfIndex: path.outIfIndex,
			key: tcRuleKeyV4{
				IfIndex: uint32(currentInLink.Attrs().Index),
				DstAddr: inAddr,
				DstPort: uint16(rule.InPort),
				Proto:   kernelRuleProtocol(rule.Protocol),
			},
			value: tcRuleValueV4{
				RuleID:      uint32(rule.ID),
				BackendAddr: outAddr,
				BackendPort: uint16(rule.OutPort),
				Flags:       path.flags,
				OutIfIndex:  uint32(path.outIfIndex),
				NATAddr:     natAddr,
				SrcMAC:      path.srcMAC,
				DstMAC:      path.dstMAC,
			},
		})
	}
	if len(prepared) == 0 {
		return nil, fmt.Errorf("kernel dataplane bridge ingress expansion produced no attachable member interfaces")
	}
	return prepared, nil
}

func prepareKernelRules(rules []Rule, previous []preparedKernelRule, allowTransientReuse bool, enableTrafficStats bool) ([]preparedKernelRule, map[int][]int64, map[int][]int64, map[int64]kernelRuleApplyResult, map[string]struct{}) {
	prepared := make([]preparedKernelRule, 0, len(rules))
	forwardIfRules := make(map[int][]int64)
	replyIfRules := make(map[int][]int64)
	results := make(map[int64]kernelRuleApplyResult, len(rules))
	skipLogger := newKernelSkipLogger("kernel")
	prepareCtx := newKernelPrepareContext(enableTrafficStats)
	previousByKey := groupPreparedKernelRulesByMatchKey(previous)

	for _, rule := range rules {
		items, err := prepareKernelRule(prepareCtx, rule)
		if err != nil {
			if reused, ok := reusablePreparedKernelRules(rule, err, previousByKey, allowTransientReuse); ok {
				prepared = append(prepared, reused...)
				for _, item := range reused {
					forwardIfRules[item.inIfIndex] = append(forwardIfRules[item.inIfIndex], rule.ID)
					replyIfRules[item.outIfIndex] = append(replyIfRules[item.outIfIndex], rule.ID)
				}
				continue
			}
			skipLogger.Add(rule, err)
			results[rule.ID] = kernelRuleApplyResult{Error: err.Error()}
			continue
		}
		prepared = append(prepared, items...)
		for _, item := range items {
			forwardIfRules[item.inIfIndex] = append(forwardIfRules[item.inIfIndex], rule.ID)
			replyIfRules[item.outIfIndex] = append(replyIfRules[item.outIfIndex], rule.ID)
		}
	}

	sortPreparedKernelRules(prepared)
	return prepared, forwardIfRules, replyIfRules, results, skipLogger.Snapshot()
}

func groupPreparedKernelRulesByMatchKey(items []preparedKernelRule) map[kernelRuleMatchKey][]preparedKernelRule {
	if len(items) == 0 {
		return nil
	}
	grouped := make(map[kernelRuleMatchKey][]preparedKernelRule)
	for _, item := range items {
		grouped[kernelRuleMatchKeyFor(item.rule)] = append(grouped[kernelRuleMatchKeyFor(item.rule)], item)
	}
	return grouped
}

func reusablePreparedKernelRules(rule Rule, err error, previousByKey map[kernelRuleMatchKey][]preparedKernelRule, allowTransientReuse bool) ([]preparedKernelRule, bool) {
	if len(previousByKey) == 0 || err == nil {
		return nil, false
	}
	items := previousByKey[kernelRuleMatchKeyFor(rule)]
	if len(items) == 0 || !shouldReuseKernelRuleAfterPrepareFailure(rule, items[0].rule, err.Error(), allowTransientReuse) {
		return nil, false
	}
	return clonePreparedKernelRules(items), true
}

func (rt *linuxKernelRuleRuntime) samePreparedRulesLocked(next []preparedKernelRule, forwardIfRules map[int][]int64, replyIfRules map[int][]int64) bool {
	if rt.coll == nil || len(rt.attachments) == 0 {
		return false
	}
	if len(rt.preparedRules) != len(next) {
		return false
	}
	for i := range next {
		if !samePreparedKernelRuleDataplane(rt.preparedRules[i], next[i]) {
			return false
		}
	}
	return rt.attachmentsHealthyLocked(forwardIfRules, replyIfRules)
}

func clonePreparedKernelRules(src []preparedKernelRule) []preparedKernelRule {
	if len(src) == 0 {
		return nil
	}
	dst := make([]preparedKernelRule, len(src))
	copy(dst, src)
	return dst
}

func sortPreparedKernelRules(items []preparedKernelRule) {
	sort.Slice(items, func(i, j int) bool {
		a := items[i]
		b := items[j]
		if a.key.IfIndex != b.key.IfIndex {
			return a.key.IfIndex < b.key.IfIndex
		}
		if a.key.DstAddr != b.key.DstAddr {
			return a.key.DstAddr < b.key.DstAddr
		}
		if a.key.DstPort != b.key.DstPort {
			return a.key.DstPort < b.key.DstPort
		}
		if a.key.Proto != b.key.Proto {
			return a.key.Proto < b.key.Proto
		}
		if a.value.BackendAddr != b.value.BackendAddr {
			return a.value.BackendAddr < b.value.BackendAddr
		}
		if a.value.BackendPort != b.value.BackendPort {
			return a.value.BackendPort < b.value.BackendPort
		}
		if a.value.Flags != b.value.Flags {
			return a.value.Flags < b.value.Flags
		}
		if a.value.OutIfIndex != b.value.OutIfIndex {
			return a.value.OutIfIndex < b.value.OutIfIndex
		}
		if a.value.NATAddr != b.value.NATAddr {
			return a.value.NATAddr < b.value.NATAddr
		}
		return a.rule.ID < b.rule.ID
	})
}

func (rt *linuxKernelRuleRuntime) attachmentsHealthyLocked(forwardIfRules map[int][]int64, replyIfRules map[int][]int64) bool {
	return kernelAttachmentsHealthy(forwardIfRules, replyIfRules, rt.attachments)
}

func kernelAttachmentExists(key kernelAttachmentKey) bool {
	return kernelAttachmentPresence([]kernelAttachmentKey{key})[key]
}

func updateKernelMapEntries[K any, V any](m *ebpf.Map, keys []K, values []V) error {
	if m == nil {
		return fmt.Errorf("kernel map is nil")
	}
	if len(keys) != len(values) {
		return fmt.Errorf("kernel map batch update requires the same number of keys and values")
	}
	if len(keys) == 0 {
		return nil
	}

	const batchSize = 4096
	batchErr := batchUpdateKernelMapEntries(m, keys, values, batchSize)
	if batchErr == nil {
		return nil
	}

	for i := range keys {
		if err := m.Put(keys[i], values[i]); err != nil {
			return fmt.Errorf("fallback map update[%d]: %w", i, err)
		}
	}
	return nil
}

func applyKernelRuleMapDiff(m *ebpf.Map, diff kernelRuleMapDiff) error {
	if m == nil {
		return fmt.Errorf("kernel map is nil")
	}
	if len(diff.upserts) == 0 && len(diff.deletes) == 0 {
		return nil
	}

	snapshots := make([]kernelRuleMapSnapshot, 0, len(diff.upserts)+len(diff.deletes))
	seen := make(map[tcRuleKeyV4]struct{}, len(diff.upserts)+len(diff.deletes))
	snapshotKey := func(key tcRuleKeyV4) error {
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		var value tcRuleValueV4
		err := m.Lookup(key, &value)
		if err == nil {
			snapshots = append(snapshots, kernelRuleMapSnapshot{
				key:    key,
				value:  value,
				exists: true,
			})
			return nil
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			snapshots = append(snapshots, kernelRuleMapSnapshot{key: key})
			return nil
		}
		return fmt.Errorf("lookup rule key before in-place update: %w", err)
	}

	for _, item := range diff.upserts {
		if err := snapshotKey(item.key); err != nil {
			return err
		}
	}
	for _, key := range diff.deletes {
		if err := snapshotKey(key); err != nil {
			return err
		}
	}

	rollback := func() {
		for i := len(snapshots) - 1; i >= 0; i-- {
			item := snapshots[i]
			if item.exists {
				_ = m.Put(item.key, item.value)
				continue
			}
			_ = deleteKernelMapEntry(m, item.key)
		}
	}

	for _, item := range diff.upserts {
		if err := m.Put(item.key, item.value); err != nil {
			rollback()
			return fmt.Errorf("upsert kernel rule key during in-place update: %w", err)
		}
	}
	for _, key := range diff.deletes {
		if err := deleteKernelMapEntry(m, key); err != nil {
			rollback()
			return fmt.Errorf("delete stale kernel rule key during in-place update: %w", err)
		}
	}
	return nil
}

func deleteKernelMapEntry[K any](m *ebpf.Map, key K) error {
	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func batchUpdateKernelMapEntries[K any, V any](m *ebpf.Map, keys []K, values []V, batchSize int) error {
	if batchSize <= 0 {
		batchSize = len(keys)
	}
	for start := 0; start < len(keys); start += batchSize {
		end := min(start+batchSize, len(keys))
		if _, err := m.BatchUpdate(keys[start:end], values[start:end], nil); err != nil {
			return err
		}
	}
	return nil
}

func kernelMonotonicNowNS() (uint64, bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, false
	}
	return uint64(ts.Sec)*1000000000 + uint64(ts.Nsec), true
}

func kernelRuleProtocol(protocol string) uint8 {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "udp":
		return unix.IPPROTO_UDP
	default:
		return unix.IPPROTO_TCP
	}
}

func kernelProtocolSupported(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "tcp", "udp":
		return true
	default:
		return false
	}
}

func parseIPv4Uint32(text string) (uint32, error) {
	ip := net.ParseIP(text)
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 address")
	}
	ip = ip.To4()
	if ip == nil || ip.String() == "0.0.0.0" {
		return 0, fmt.Errorf("must be an explicit IPv4 address")
	}
	return ipv4ToUint32(text), nil
}

func parseKernelInboundIPv4Uint32(text string) (uint32, error) {
	ip := net.ParseIP(text)
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 address")
	}
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 address")
	}
	if ip.String() == "0.0.0.0" {
		return 0, nil
	}
	return ipv4ToUint32(text), nil
}

func resolveKernelSNATIPv4(link netlink.Link, backendIP string, preferredIP string) (uint32, error) {
	if link == nil || link.Attrs() == nil {
		return 0, fmt.Errorf("invalid outbound interface")
	}

	if preferredIP = strings.TrimSpace(preferredIP); preferredIP != "" {
		ip := net.ParseIP(preferredIP)
		if ip == nil {
			return 0, fmt.Errorf("invalid IPv4 address %q", preferredIP)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return 0, fmt.Errorf("invalid IPv4 address %q", preferredIP)
		}
		if ip4.IsLoopback() || ip4.IsUnspecified() {
			return 0, fmt.Errorf("preferred source IPv4 %q must be a specific non-loopback address", preferredIP)
		}
		addrs, err := netlink.AddrList(link, unix.AF_INET)
		if err != nil {
			return 0, err
		}
		for _, addr := range addrs {
			if addr.IP == nil {
				continue
			}
			if current := addr.IP.To4(); current != nil && current.Equal(ip4) {
				return ipv4BytesToUint32(ip4), nil
			}
		}
		return 0, fmt.Errorf("preferred source IPv4 %q is not assigned", preferredIP)
	}

	backendIPv4 := net.ParseIP(strings.TrimSpace(backendIP)).To4()
	if backendIPv4 == nil {
		return 0, fmt.Errorf("invalid backend IPv4 address %q", backendIP)
	}

	if routeSource, err := resolveKernelRouteSourceIPv4(link, backendIPv4); err == nil {
		return ipv4BytesToUint32(routeSource), nil
	}

	addrs, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return 0, err
	}

	usable := make([]net.IP, 0, len(addrs))
	linkLocal := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}
		ip4 := addr.IP.To4()
		if ip4 == nil || ip4.IsLoopback() {
			continue
		}
		if ip4.IsLinkLocalUnicast() {
			linkLocal = append(linkLocal, ip4)
			continue
		}
		usable = append(usable, ip4)
	}

	if len(usable) == 1 {
		return ipv4BytesToUint32(usable[0]), nil
	}
	if len(usable) > 1 {
		return 0, fmt.Errorf("auto outbound source IPv4 on %q is ambiguous (%d IPv4 addresses assigned); set out_source_ip explicitly", link.Attrs().Name, len(usable))
	}
	if len(linkLocal) == 1 {
		return ipv4BytesToUint32(linkLocal[0]), nil
	}
	if len(linkLocal) > 1 {
		return 0, fmt.Errorf("auto outbound source IPv4 on %q is ambiguous (%d link-local IPv4 addresses assigned); set out_source_ip explicitly", link.Attrs().Name, len(linkLocal))
	}
	return 0, fmt.Errorf("no IPv4 address is assigned")
}

func resolveKernelRouteSourceIPv4(link netlink.Link, backendIP net.IP) (net.IP, error) {
	if link == nil || link.Attrs() == nil {
		return nil, fmt.Errorf("invalid outbound interface")
	}
	if backendIP == nil || backendIP.To4() == nil {
		return nil, fmt.Errorf("invalid backend IPv4 address")
	}

	routes, err := netlink.RouteGetWithOptions(backendIP, &netlink.RouteGetOptions{
		OifIndex: link.Attrs().Index,
	})
	if err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no matching route")
	}

	for _, route := range routes {
		if route.LinkIndex != 0 && route.LinkIndex != link.Attrs().Index {
			continue
		}
		src := route.Src.To4()
		if src == nil || src.IsLoopback() || src.IsUnspecified() {
			continue
		}
		return src, nil
	}

	return nil, fmt.Errorf("route lookup returned no usable source IPv4")
}

func ipv4BytesToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func ipv4ToUint32(text string) uint32 {
	ip := net.ParseIP(text)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
