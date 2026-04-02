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
	"github.com/vishvananda/netlink/nl"
)

const kernelXDPProgramName = "forward_xdp"

const (
	xdpRuleFlagBridgeL2        = 0x2
	xdpRuleFlagBridgeIngressL2 = 0x4
	xdpRuleFlagTrafficStats    = 0x8
	xdpRuleFlagPreparedL2      = 0x10
)

type xdpPrepareOptions struct {
	enableBridge       bool
	enableTrafficStats bool
}

type xdpRuleValueV4 struct {
	RuleID      uint32
	BackendAddr uint32
	BackendPort uint16
	Flags       uint16
	OutIfIndex  uint32
	NATAddr     uint32
	SrcMAC      [6]byte
	DstMAC      [6]byte
}

type preparedXDPKernelRule struct {
	rule       Rule
	inIfIndex  int
	outIfIndex int
	key        tcRuleKeyV4
	value      xdpRuleValueV4
}

//go:embed ebpf/forward-xdp-bpf.o
var embeddedForwardXDPObject []byte

//go:embed ebpf/forward-xdp-bpf-stats.o
var embeddedForwardXDPStatsObject []byte

type xdpAttachment struct {
	ifindex int
	flags   int
}

type xdpKernelRuleRuntime struct {
	mu                sync.Mutex
	availableOnce     sync.Once
	available         bool
	availableReason   string
	rulesMapLimit     int
	flowsMapLimit     int
	rulesMapCapacity  int
	flowsMapCapacity  int
	memlockOnce       sync.Once
	memlockErr        error
	coll              *ebpf.Collection
	attachments       []xdpAttachment
	preparedRules     []preparedXDPKernelRule
	programID         uint32
	prepareOptions    xdpPrepareOptions
	lastSkipLog       map[string]struct{}
	lastBridgeLog     map[string]struct{}
	lastReconcileMode string
	stateLog          kernelStateLogger
	pressureState     kernelRuntimePressureState
	statsCorrection   map[uint32]kernelRuleStats
	flowPruneState    kernelFlowPruneState
	runtimeMapCounts  kernelRuntimeMapCountSnapshot
}

func newXDPKernelRuleRuntime(cfg *Config) kernelRuleRuntime {
	opts := xdpPrepareOptions{}
	rulesLimit := 0
	flowsLimit := 0
	if cfg != nil && cfg.ExperimentalFeatureEnabled(experimentalFeatureBridgeXDP) {
		opts.enableBridge = true
	}
	if cfg != nil && cfg.ExperimentalFeatureEnabled(experimentalFeatureKernelTraffic) {
		opts.enableTrafficStats = true
	}
	if cfg != nil {
		rulesLimit = cfg.KernelRulesMapLimit
		flowsLimit = cfg.KernelFlowsMapLimit
	}
	return &xdpKernelRuleRuntime{
		prepareOptions:  opts,
		rulesMapLimit:   rulesLimit,
		flowsMapLimit:   flowsLimit,
		statsCorrection: make(map[uint32]kernelRuleStats),
	}
}

func (rt *xdpKernelRuleRuntime) Available() (bool, string) {
	rt.availableOnce.Do(func() {
		spec, err := loadEmbeddedXDPCollectionSpec(rt.prepareOptions.enableTrafficStats)
		if err != nil {
			rt.available = false
			rt.availableReason = err.Error()
			log.Printf("kernel dataplane unavailable: %s", rt.availableReason)
			return
		}
		if err := validateXDPCollectionSpec(spec); err != nil {
			rt.available = false
			rt.availableReason = err.Error()
			log.Printf("kernel dataplane unavailable: %s", rt.availableReason)
			return
		}
		if err := rt.ensureMemlock(); err != nil {
			rt.available = true
			rt.availableReason = fmt.Sprintf("embedded xdp eBPF object available; memlock auto-raise unavailable: %v (%s)", err, kernelMemlockStatus())
			log.Printf("kernel dataplane warning: %s", rt.availableReason)
			return
		}
		rt.available = true
		rt.availableReason = "embedded xdp eBPF object available"
		if rt.prepareOptions.enableBridge {
			rt.availableReason += "; bridge_xdp experimental path enabled"
		}
		if rt.prepareOptions.enableTrafficStats {
			rt.availableReason += "; kernel_traffic_stats experimental path enabled"
		}
	})
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.currentAvailabilityLocked(time.Now())
}

func (rt *xdpKernelRuleRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	results := make(map[int64]kernelRuleApplyResult, len(rules))
	if rt.coll == nil && !kernelHotRestartStateExists(kernelEngineXDP) {
		if err := cleanupOrphanXDPKernelRuntimeState(); err != nil {
			log.Printf("xdp dataplane startup cleanup: xdp orphan cleanup failed: %v", err)
		}
	}
	if len(rules) == 0 {
		if err := rt.clearActiveRulesLockedPreserveFlows(); err != nil {
			rt.cleanupLocked()
			return results, err
		}
		return results, nil
	}

	prepared, _, _, prepareResults, skipLines := prepareXDPKernelRules(rules, rt.prepareOptions, rt.preparedRules, rt.coll != nil)
	rt.lastSkipLog = logKernelLineSetOnce(rt.lastSkipLog, skipLines)
	for id, result := range prepareResults {
		results[id] = result
	}
	if len(prepared) == 0 {
		rt.stateLog.Logf("xdp dataplane reconcile: no entries passed xdp preparation")
		rt.lastBridgeLog = logKernelLineSetDelta(rt.lastBridgeLog, nil)
		if err := rt.clearActiveRulesLockedPreserveFlows(); err != nil {
			rt.cleanupLocked()
			for _, rule := range rules {
				results[rule.ID] = kernelRuleApplyResult{Error: err.Error()}
			}
		}
		return results, nil
	}

	requiredIfIndices := collectXDPInterfaces(prepared)
	if rt.samePreparedRulesLocked(prepared, requiredIfIndices) {
		rt.lastReconcileMode = "steady"
		rt.stateLog.Logf("xdp dataplane reconcile: entry set unchanged, keeping %d active kernel entry(s)", len(prepared))
		for _, rule := range rules {
			if current, ok := results[rule.ID]; ok && current.Error != "" {
				continue
			}
			results[rule.ID] = kernelRuleApplyResult{Running: true, Engine: kernelEngineXDP}
		}
		return results, nil
	}

	spec, err := loadEmbeddedXDPCollectionSpec(rt.prepareOptions.enableTrafficStats)
	if err != nil {
		msg := err.Error()
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("xdp dataplane reconcile: load embedded object failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if err := validateXDPCollectionSpec(spec); err != nil {
		msg := err.Error()
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("xdp dataplane reconcile: object validation failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	desiredCapacities, err := applyKernelMapCapacities(spec, rt.rulesMapLimit, rt.flowsMapLimit, 0, len(prepared), false)
	if err != nil {
		msg := err.Error()
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("xdp dataplane reconcile: map capacity setup failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}

	memlockErr := rt.ensureMemlock()
	if memlockErr != nil {
		log.Printf("xdp dataplane reconcile: memlock auto-raise unavailable: %v (%s); continuing with current limit", memlockErr, kernelMemlockStatus())
	}
	if rt.rulesMapCapacity != desiredCapacities.Rules || rt.flowsMapCapacity != desiredCapacities.Flows {
		log.Printf(
			"xdp dataplane reconcile: rules/stats=%d(%s) flows=%d(%s) requested_entries=%d",
			desiredCapacities.Rules,
			kernelRulesMapCapacityMode(rt.rulesMapLimit),
			desiredCapacities.Flows,
			kernelFlowsMapCapacityMode(rt.flowsMapLimit),
			len(prepared),
		)
	}

	var coll *ebpf.Collection
	flowMapReplacement := map[string]*ebpf.Map(nil)
	actualCapacities := desiredCapacities
	var oldStatsMap *ebpf.Map
	var hotRestartState *kernelHotRestartMapState
	if rt.coll != nil && rt.coll.Maps != nil {
		if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
			if flowMapReplacement == nil {
				flowMapReplacement = make(map[string]*ebpf.Map, 2)
			}
			flowMapReplacement[kernelFlowsMapName] = flowsMap
			actualCapacities.Flows = int(flowsMap.MaxEntries())
			if actualCapacities.Flows < desiredCapacities.Flows {
				log.Printf(
					"xdp dataplane reconcile: keeping existing %s map capacity=%d below desired=%d until restart to preserve active sessions",
					kernelFlowsMapName,
					actualCapacities.Flows,
					desiredCapacities.Flows,
				)
			}
		}
		if statsMap := rt.coll.Maps[kernelStatsMapName]; statsMap != nil {
			if kernelMapReusableWithCapacity(statsMap, desiredCapacities.Rules) {
				if flowMapReplacement == nil {
					flowMapReplacement = make(map[string]*ebpf.Map, 2)
				}
				flowMapReplacement[kernelStatsMapName] = statsMap
			} else {
				oldStatsMap = statsMap
				log.Printf(
					"xdp dataplane reconcile: recreating %s map with capacity=%d (existing=%d too small)",
					kernelStatsMapName,
					desiredCapacities.Rules,
					statsMap.MaxEntries(),
				)
			}
		}
	} else if state, err := loadXDPKernelHotRestartState(desiredCapacities); err != nil {
		log.Printf("xdp dataplane hot restart: load xdp state failed, cleaning stale hot restart state: %v", err)
		if cleanupErr := cleanupStaleXDPKernelHotRestartState(); cleanupErr != nil {
			log.Printf("xdp dataplane hot restart: cleanup stale xdp state failed, discarding pinned state only: %v", cleanupErr)
			clearKernelHotRestartState(kernelEngineXDP)
		}
	} else if state != nil {
		hotRestartState = state
		if len(state.replacements) > 0 {
			flowMapReplacement = state.replacements
		}
		oldStatsMap = state.oldStatsMap
		actualCapacities = state.actualCapacities
		if actualCapacities.Flows < desiredCapacities.Flows {
			log.Printf(
				"xdp dataplane hot restart: keeping pinned %s map capacity=%d below desired=%d until restart to preserve active sessions",
				kernelFlowsMapName,
				actualCapacities.Flows,
				desiredCapacities.Flows,
			)
		}
		if oldStatsMap != nil {
			log.Printf(
				"xdp dataplane hot restart: recreating %s map with capacity=%d (pinned=%d too small)",
				kernelStatsMapName,
				desiredCapacities.Rules,
				oldStatsMap.MaxEntries(),
			)
		}
		log.Printf(
			"xdp dataplane hot restart: adopting pinned xdp maps=%s from %s",
			strings.Join(state.replacementMapNames(), ","),
			kernelHotRestartEngineDir(kernelEngineXDP),
		)
	}
	if len(flowMapReplacement) > 0 {
		coll, err = ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(flowMapReplacement))
	} else {
		coll, err = ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(nil))
	}
	if err != nil && hotRestartState != nil {
		log.Printf("xdp dataplane hot restart: adopt xdp state failed, retrying with fresh maps: %v", err)
		hotRestartState.close()
		hotRestartState = nil
		flowMapReplacement = nil
		oldStatsMap = nil
		actualCapacities = desiredCapacities
		if cleanupErr := cleanupStaleXDPKernelHotRestartState(); cleanupErr != nil {
			log.Printf("xdp dataplane hot restart: cleanup stale xdp state failed, discarding pinned state only: %v", cleanupErr)
			clearKernelHotRestartState(kernelEngineXDP)
		}
		coll, err = ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(nil))
	}
	if err != nil {
		logKernelVerifierDetails(err)
		msg := kernelProgramLoadError("xdp", err, memlockErr)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		rt.disableLocked(kernelProgramUnavailableReason("xdp", err))
		rt.cleanupLocked()
		log.Printf("xdp dataplane reconcile: collection load failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}

	prog, rulesMap, err := lookupXDPCollectionPieces(coll)
	if err != nil {
		coll.Close()
		msg := err.Error()
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("xdp dataplane reconcile: object lookup failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if oldStatsMap != nil {
		if err := copyKernelStatsMap(coll.Maps[kernelStatsMapName], oldStatsMap); err != nil {
			log.Printf("xdp dataplane reconcile: copy %s contents failed: %v", kernelStatsMapName, err)
			rt.statsCorrection = make(map[uint32]kernelRuleStats)
		}
		if hotRestartState != nil {
			_ = oldStatsMap.Close()
			hotRestartState.oldStatsMap = nil
		}
	}

	keys := make([]tcRuleKeyV4, 0, len(prepared))
	values := make([]xdpRuleValueV4, 0, len(prepared))
	for _, item := range prepared {
		keys = append(keys, item.key)
		values = append(values, item.value)
	}
	if err := updateKernelMapEntries(rulesMap, keys, values); err != nil {
		coll.Close()
		msg := fmt.Sprintf("update xdp rule map: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("xdp dataplane rule map bulk update failed: %v", err)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}

	programID := kernelProgramID(prog)
	oldAttachments := append([]xdpAttachment(nil), rt.attachments...)
	newAttachments := make([]xdpAttachment, 0, len(requiredIfIndices))
	for _, ifindex := range requiredIfIndices {
		att, err := rt.attachProgramLocked(ifindex, prog, oldAttachments)
		if err != nil {
			rt.discardAttachmentsLocked(newAttachments)
			coll.Close()
			msg := fmt.Sprintf("attach xdp program on ifindex %d: %v", ifindex, err)
			if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
				return results, nil
			}
			log.Printf("xdp dataplane attach failed: ifindex=%d err=%v", ifindex, err)
			for _, rule := range rules {
				results[rule.ID] = kernelRuleApplyResult{Error: msg}
			}
			return results, nil
		}
		newAttachments = append(newAttachments, att)
	}

	if len(newAttachments) == 0 {
		coll.Close()
		msg := "xdp dataplane did not attach to any interface"
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}

	for _, item := range prepared {
		if current, ok := results[item.rule.ID]; ok && current.Error != "" {
			continue
		}
		results[item.rule.ID] = kernelRuleApplyResult{Running: true, Engine: kernelEngineXDP}
	}

	rt.stateLog.Logf("xdp dataplane reconcile: applied %d/%d kernel entry(s) attachments=%d mode=%s",
		len(prepared),
		len(rules),
		len(newAttachments),
		describeXDPAttachmentModes(newAttachments),
	)
	rt.lastBridgeLog = logKernelLineSetDelta(rt.lastBridgeLog, snapshotPreparedXDPBridgeEntries(prepared))
	rt.deleteStaleAttachmentsLocked(oldAttachments, newAttachments)
	if rt.coll != nil {
		rt.coll.Close()
	}
	rt.coll = coll
	rt.attachments = newAttachments
	rt.preparedRules = clonePreparedXDPKernelRules(prepared)
	rt.programID = programID
	rt.rulesMapCapacity = actualCapacities.Rules
	rt.flowsMapCapacity = actualCapacities.Flows
	rt.flowPruneState.reset()
	rt.lastReconcileMode = "rebuild"
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	if err := writeKernelRuntimeMetadata(kernelEngineXDP, kernelHotRestartXDPMetadata(rt.attachments)); err != nil {
		log.Printf("xdp dataplane runtime metadata: write xdp runtime metadata failed: %v", err)
	}
	if hotRestartState != nil {
		clearKernelHotRestartState(kernelEngineXDP)
	}
	return results, nil
}

func (rt *xdpKernelRuleRuntime) ensureMemlock() error {
	rt.memlockOnce.Do(func() {
		rt.memlockErr = rlimit.RemoveMemlock()
	})
	return rt.memlockErr
}

func (rt *xdpKernelRuleRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return snapshotKernelStatsFromCollection(rt.coll, cloneKernelStatsCorrections(rt.statsCorrection))
}

func (rt *xdpKernelRuleRuntime) Maintain() error {
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

func (rt *xdpKernelRuleRuntime) SnapshotAssignments() map[int64]string {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	assignments := make(map[int64]string, len(rt.preparedRules))
	for _, item := range rt.preparedRules {
		assignments[item.rule.ID] = kernelEngineXDP
	}
	return assignments
}

func (rt *xdpKernelRuleRuntime) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.prepareHotRestartLocked() {
		return nil
	}
	rt.cleanupLocked()
	return nil
}

func (rt *xdpKernelRuleRuntime) prepareHotRestartLocked() bool {
	if !kernelHotRestartRequested() {
		return false
	}
	if rt.coll == nil || rt.coll.Maps == nil || len(rt.attachments) == 0 {
		return false
	}
	if err := pinKernelHotRestartMaps(kernelEngineXDP, map[string]*ebpf.Map{
		kernelFlowsMapName: rt.coll.Maps[kernelFlowsMapName],
		kernelStatsMapName: rt.coll.Maps[kernelStatsMapName],
	}); err != nil {
		log.Printf("xdp dataplane hot restart: preserve xdp maps failed, falling back to full cleanup: %v", err)
		rt.cleanupLocked()
		return true
	}
	if err := writeKernelHotRestartMetadata(kernelEngineXDP, kernelHotRestartXDPMetadata(rt.attachments)); err != nil {
		clearKernelHotRestartState(kernelEngineXDP)
		log.Printf("xdp dataplane hot restart: write xdp metadata failed, falling back to full cleanup: %v", err)
		rt.cleanupLocked()
		return true
	}
	log.Printf(
		"xdp dataplane hot restart: preserved xdp session state at %s, leaving %d attachment(s) active for successor",
		kernelHotRestartEngineDir(kernelEngineXDP),
		len(rt.attachments),
	)
	rt.attachments = nil
	rt.preparedRules = nil
	rt.programID = 0
	rt.rulesMapCapacity = 0
	rt.flowsMapCapacity = 0
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

func (rt *xdpKernelRuleRuntime) cleanupLocked() {
	for i := len(rt.attachments) - 1; i >= 0; i-- {
		if err := detachXDPAttachment(rt.attachments[i]); err != nil {
			log.Printf("xdp dataplane cleanup: detach ifindex=%d mode=%s failed: %v", rt.attachments[i].ifindex, xdpAttachFlagsLabel(rt.attachments[i].flags), err)
		}
	}
	clearKernelRuntimeMetadata(kernelEngineXDP)
	rt.attachments = nil
	rt.preparedRules = nil
	rt.programID = 0
	rt.rulesMapCapacity = 0
	rt.flowsMapCapacity = 0
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

func (rt *xdpKernelRuleRuntime) applyRetainedRulesOnFailureLocked(results map[int64]kernelRuleApplyResult, rules []Rule, reason string) bool {
	retained, err := rt.retainMatchingRulesLocked(rules)
	if err != nil {
		log.Printf("xdp dataplane reconcile: failed to retain active xdp rules after rebuild failure: %v", err)
		rt.cleanupLocked()
		return false
	}
	if len(retained) == 0 {
		return false
	}
	log.Printf("xdp dataplane reconcile: rebuild failed, preserving %d active xdp rule(s): %s", len(retained), reason)
	for _, rule := range rules {
		if _, ok := retained[rule.ID]; ok {
			results[rule.ID] = kernelRuleApplyResult{Running: true, Engine: kernelEngineXDP}
			continue
		}
		if current, ok := results[rule.ID]; ok && current.Running {
			continue
		}
		results[rule.ID] = kernelRuleApplyResult{Error: reason}
	}
	return true
}

func (rt *xdpKernelRuleRuntime) retainMatchingRulesLocked(rules []Rule) (map[int64]struct{}, error) {
	retained := make(map[int64]struct{})
	if rt.coll == nil || rt.coll.Maps == nil || len(rt.preparedRules) == 0 {
		return retained, nil
	}
	rulesMap := rt.coll.Maps[kernelRulesMapName]
	if rulesMap == nil {
		return retained, nil
	}

	desiredByKey := indexKernelRulesByMatchKey(rules)

	kept := make([]preparedXDPKernelRule, 0, len(rt.preparedRules))
	for _, item := range rt.preparedRules {
		desired, ok := matchDesiredKernelRule(desiredByKey, item.rule)
		if ok {
			kept = append(kept, item)
			retained[desired.ID] = struct{}{}
			continue
		}
		if err := deleteKernelMapEntry(rulesMap, item.key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("delete stale preserved xdp rule %d: %w", item.rule.ID, err)
		}
	}
	rt.preparedRules = kept
	if rulesMap != nil {
		rt.rulesMapCapacity = int(rulesMap.MaxEntries())
	}
	if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
		rt.flowsMapCapacity = int(flowsMap.MaxEntries())
	}
	rt.flowPruneState.reset()
	rt.invalidatePressureStateLocked()
	return retained, nil
}

func (rt *xdpKernelRuleRuntime) clearActiveRulesLockedPreserveFlows() error {
	if rt.coll == nil || rt.coll.Maps == nil {
		if !kernelHotRestartStateExists(kernelEngineXDP) {
			if err := cleanupOrphanXDPKernelRuntimeState(); err != nil {
				return fmt.Errorf("cleanup xdp orphan runtime state: %w", err)
			}
		}
		if err := cleanupStaleXDPKernelHotRestartState(); err != nil {
			return fmt.Errorf("cleanup stale xdp hot restart state: %w", err)
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
			return fmt.Errorf("clear xdp rule key during drain: %w", err)
		}
	}
	rt.preparedRules = nil
	if rulesMap != nil {
		rt.rulesMapCapacity = int(rulesMap.MaxEntries())
	}
	if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
		rt.flowsMapCapacity = int(flowsMap.MaxEntries())
	}
	rt.lastReconcileMode = "cleared"
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	if len(rt.attachments) > 0 {
		if err := writeKernelRuntimeMetadata(kernelEngineXDP, kernelHotRestartXDPMetadata(rt.attachments)); err != nil {
			log.Printf("xdp dataplane runtime metadata: refresh xdp runtime metadata failed after rule drain: %v", err)
		}
	}
	rt.stateLog.Logf("xdp dataplane reconcile: drained active rules, preserving flows for existing connections")
	return nil
}

func (rt *xdpKernelRuleRuntime) flowMaintenanceBudgetLocked() int {
	if rt.coll != nil && rt.coll.Maps != nil {
		if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
			return kernelFlowMaintenanceBudgetForCapacity(int(flowsMap.MaxEntries()))
		}
	}
	return kernelFlowMaintenanceBudgetForCapacity(rt.flowsMapCapacity)
}

func (rt *xdpKernelRuleRuntime) disableLocked(reason string) {
	if strings.TrimSpace(reason) == "" {
		return
	}
	rt.available = false
	rt.availableReason = reason
}

func (rt *xdpKernelRuleRuntime) samePreparedRulesLocked(next []preparedXDPKernelRule, requiredIfIndices []int) bool {
	if rt.coll == nil || len(rt.attachments) == 0 {
		return false
	}
	if len(rt.preparedRules) != len(next) {
		return false
	}
	for i := range next {
		if !samePreparedXDPKernelRuleDataplane(rt.preparedRules[i], next[i]) {
			return false
		}
	}
	return rt.attachmentsHealthyLocked(requiredIfIndices)
}

func (rt *xdpKernelRuleRuntime) attachmentsHealthyLocked(requiredIfIndices []int) bool {
	return xdpAttachmentsHealthy(requiredIfIndices, rt.attachments, rt.programID)
}

func (rt *xdpKernelRuleRuntime) attachProgramLocked(ifindex int, prog *ebpf.Program, oldAttachments []xdpAttachment) (xdpAttachment, error) {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return xdpAttachment{}, fmt.Errorf("resolve interface by index %d: %w", ifindex, err)
	}

	var errs []string
	for _, flags := range xdpAttachOrder(link, oldAttachments) {
		if err := netlink.LinkSetXdpFdWithFlags(link, prog.FD(), flags); err == nil {
			return xdpAttachment{ifindex: ifindex, flags: flags}, nil
		} else {
			errs = append(errs, fmt.Sprintf("%s=%v", xdpAttachFlagsLabel(flags), err))
		}
	}
	return xdpAttachment{}, errors.New(strings.Join(errs, "; "))
}

func (rt *xdpKernelRuleRuntime) discardAttachmentsLocked(attachments []xdpAttachment) {
	for i := len(attachments) - 1; i >= 0; i-- {
		if err := detachXDPAttachment(attachments[i]); err != nil {
			log.Printf("xdp dataplane discard: detach ifindex=%d mode=%s failed: %v", attachments[i].ifindex, xdpAttachFlagsLabel(attachments[i].flags), err)
		}
	}
}

func (rt *xdpKernelRuleRuntime) deleteStaleAttachmentsLocked(oldAttachments, newAttachments []xdpAttachment) {
	newIfIndices := make(map[int]struct{}, len(newAttachments))
	for _, att := range newAttachments {
		newIfIndices[att.ifindex] = struct{}{}
	}
	for _, att := range oldAttachments {
		if _, ok := newIfIndices[att.ifindex]; ok {
			continue
		}
		if err := detachXDPAttachment(att); err != nil {
			log.Printf("xdp dataplane detach stale ifindex=%d mode=%s failed: %v", att.ifindex, xdpAttachFlagsLabel(att.flags), err)
		}
	}
}

func loadEmbeddedXDPCollectionSpec(enableTrafficStats bool) (*ebpf.CollectionSpec, error) {
	objectBytes := embeddedForwardXDPObject
	objectName := "internal/app/ebpf/forward-xdp-bpf.o"
	if enableTrafficStats {
		objectBytes = embeddedForwardXDPStatsObject
		objectName = "internal/app/ebpf/forward-xdp-bpf-stats.o"
	}
	if len(objectBytes) == 0 {
		return nil, fmt.Errorf("embedded xdp eBPF object is empty; build %s before compiling", objectName)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objectBytes))
	if err != nil {
		return nil, fmt.Errorf("load embedded xdp eBPF object: %w", err)
	}
	return spec, nil
}

func validateXDPCollectionSpec(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return fmt.Errorf("embedded xdp eBPF object is missing")
	}
	if _, ok := spec.Programs[kernelXDPProgramName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing program %q", kernelXDPProgramName)
	}
	if _, ok := spec.Maps[kernelRulesMapName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelRulesMapName)
	}
	if _, ok := spec.Maps[kernelFlowsMapName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelFlowsMapName)
	}
	if _, ok := spec.Maps[kernelStatsMapName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelStatsMapName)
	}
	return nil
}

func lookupXDPCollectionPieces(coll *ebpf.Collection) (*ebpf.Program, *ebpf.Map, error) {
	prog := coll.Programs[kernelXDPProgramName]
	rulesMap := coll.Maps[kernelRulesMapName]
	flowsMap := coll.Maps[kernelFlowsMapName]
	if prog == nil || rulesMap == nil || flowsMap == nil {
		return nil, nil, fmt.Errorf("xdp object is missing required program or maps")
	}
	return prog, rulesMap, nil
}

func collectXDPInterfaces(prepared []preparedXDPKernelRule) []int {
	seen := make(map[int]struct{}, len(prepared)*2)
	for _, item := range prepared {
		seen[item.inIfIndex] = struct{}{}
		seen[item.outIfIndex] = struct{}{}
	}

	out := make([]int, 0, len(seen))
	for ifindex := range seen {
		out = append(out, ifindex)
	}
	sort.Ints(out)
	return out
}

func xdpAttachOrder(link netlink.Link, oldAttachments []xdpAttachment) []int {
	preferred := []int{nl.XDP_FLAGS_DRV_MODE, nl.XDP_FLAGS_SKB_MODE}
	if link != nil && strings.EqualFold(strings.TrimSpace(link.Type()), "veth") {
		preferred = []int{nl.XDP_FLAGS_SKB_MODE, nl.XDP_FLAGS_DRV_MODE}
	}
	if link == nil || link.Attrs() == nil {
		return preferred
	}
	ifindex := link.Attrs().Index
	for _, att := range oldAttachments {
		if att.ifindex != ifindex {
			continue
		}
		if att.flags == nl.XDP_FLAGS_DRV_MODE {
			return preferred
		}
		if att.flags == nl.XDP_FLAGS_SKB_MODE {
			return []int{nl.XDP_FLAGS_SKB_MODE, nl.XDP_FLAGS_DRV_MODE}
		}
	}
	return preferred
}

func xdpAttachFlagsLabel(flags int) string {
	switch flags {
	case nl.XDP_FLAGS_DRV_MODE:
		return "driver"
	case nl.XDP_FLAGS_SKB_MODE:
		return "generic"
	default:
		return fmt.Sprintf("flags=%d", flags)
	}
}

func describeXDPAttachmentModes(attachments []xdpAttachment) string {
	if len(attachments) == 0 {
		return "none"
	}
	counts := make(map[string]int)
	for _, att := range attachments {
		counts[xdpAttachFlagsLabel(att.flags)]++
	}
	if len(counts) == 1 {
		for label := range counts {
			return label
		}
	}
	labels := make([]string, 0, len(counts))
	for label, count := range counts {
		labels = append(labels, fmt.Sprintf("%s=%d", label, count))
	}
	sort.Strings(labels)
	return strings.Join(labels, ", ")
}

func xdpAttachmentExists(att xdpAttachment, programID uint32) bool {
	link, err := netlink.LinkByIndex(att.ifindex)
	if err != nil {
		return false
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Xdp == nil || !attrs.Xdp.Attached {
		return false
	}
	if programID != 0 && attrs.Xdp.ProgId != programID {
		return false
	}
	modeMask := uint32(nl.XDP_FLAGS_DRV_MODE | nl.XDP_FLAGS_SKB_MODE)
	if (attrs.Xdp.Flags & modeMask) != (uint32(att.flags) & modeMask) {
		return false
	}
	return true
}

func detachXDPAttachment(att xdpAttachment) error {
	link, err := netlink.LinkByIndex(att.ifindex)
	if err != nil {
		return err
	}
	return netlink.LinkSetXdpFdWithFlags(link, -1, att.flags)
}

func kernelProgramID(prog *ebpf.Program) uint32 {
	if prog == nil {
		return 0
	}
	info, err := prog.Info()
	if err != nil {
		return 0
	}
	id, ok := info.ID()
	if !ok {
		return 0
	}
	return uint32(id)
}

func kernelProgramLoadError(engine string, err error, memlockErr error) string {
	msg := fmt.Sprintf("create %s kernel collection: %v", engine, err)
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

func kernelProgramUnavailableReason(engine string, err error) string {
	if kernelVerifierBugDetected(err) {
		return fmt.Sprintf("kernel verifier bug on %s blocked %s eBPF program load", kernelRelease(), engine)
	}
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		return fmt.Sprintf("kernel verifier rejected the %s eBPF program on %s", engine, kernelRelease())
	}
	errText := strings.ToLower(err.Error())
	if strings.Contains(errText, "prohibited for !root") || strings.Contains(errText, "operation not permitted") || strings.Contains(errText, "permission denied") {
		return fmt.Sprintf("kernel %s eBPF load is unavailable in the current service context on %s", engine, kernelRelease())
	}
	return ""
}

func prepareXDPKernelRules(rules []Rule, opts xdpPrepareOptions, previous []preparedXDPKernelRule, allowTransientReuse bool) ([]preparedXDPKernelRule, map[int][]int64, map[int][]int64, map[int64]kernelRuleApplyResult, map[string]struct{}) {
	prepared := make([]preparedXDPKernelRule, 0, len(rules))
	forwardIfRules := make(map[int][]int64)
	replyIfRules := make(map[int][]int64)
	results := make(map[int64]kernelRuleApplyResult, len(rules))
	skipLogger := newKernelSkipLogger("xdp")
	previousByKey := groupPreparedXDPKernelRulesByMatchKey(previous)

	for _, rule := range rules {
		if !rule.Transparent {
			err := fmt.Errorf("xdp dataplane currently supports only transparent rules")
			skipLogger.Add(rule, err)
			results[rule.ID] = kernelRuleApplyResult{Error: err.Error()}
			continue
		}
		items, err := prepareXDPKernelRule(rule, opts)
		if err != nil {
			if reused, ok := reusablePreparedXDPKernelRules(rule, err, previousByKey, allowTransientReuse); ok {
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

	sortPreparedXDPKernelRules(prepared)
	return prepared, forwardIfRules, replyIfRules, results, skipLogger.Snapshot()
}

func groupPreparedXDPKernelRulesByMatchKey(items []preparedXDPKernelRule) map[kernelRuleMatchKey][]preparedXDPKernelRule {
	if len(items) == 0 {
		return nil
	}
	grouped := make(map[kernelRuleMatchKey][]preparedXDPKernelRule)
	for _, item := range items {
		grouped[kernelRuleMatchKeyFor(item.rule)] = append(grouped[kernelRuleMatchKeyFor(item.rule)], item)
	}
	return grouped
}

func reusablePreparedXDPKernelRules(rule Rule, err error, previousByKey map[kernelRuleMatchKey][]preparedXDPKernelRule, allowTransientReuse bool) ([]preparedXDPKernelRule, bool) {
	if len(previousByKey) == 0 || err == nil {
		return nil, false
	}
	items := previousByKey[kernelRuleMatchKeyFor(rule)]
	if len(items) == 0 || !shouldReuseKernelRuleAfterPrepareFailure(rule, items[0].rule, err.Error(), allowTransientReuse) {
		return nil, false
	}
	return clonePreparedXDPKernelRules(items), true
}

func prepareXDPKernelRule(rule Rule, opts xdpPrepareOptions) ([]preparedXDPKernelRule, error) {
	inLink, err := netlink.LinkByName(rule.InInterface)
	if err != nil {
		return nil, fmt.Errorf("resolve inbound interface %q: %w", rule.InInterface, err)
	}

	outLink, err := netlink.LinkByName(rule.OutInterface)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound interface %q: %w", rule.OutInterface, err)
	}

	if rule.ID <= 0 || rule.ID > int64(^uint32(0)) {
		return nil, fmt.Errorf("xdp dataplane requires a rule id in uint32 range")
	}
	if !kernelProtocolSupported(rule.Protocol) {
		return nil, fmt.Errorf("xdp dataplane currently supports only single-protocol TCP/UDP rules")
	}

	inAddr, err := parseKernelInboundIPv4Uint32(rule.InIP)
	if err != nil {
		return nil, fmt.Errorf("parse inbound ip %q: %w", rule.InIP, err)
	}
	outAddr, err := parseIPv4Uint32(rule.OutIP)
	if err != nil {
		return nil, fmt.Errorf("parse outbound ip %q: %w", rule.OutIP, err)
	}

	value := xdpRuleValueV4{
		RuleID:      uint32(rule.ID),
		BackendAddr: outAddr,
		BackendPort: uint16(rule.OutPort),
	}
	if opts.enableTrafficStats {
		value.Flags |= xdpRuleFlagTrafficStats
	}
	outIfIndex := 0

	if xdpLinkTypeAllowed(outLink.Type()) {
		outIfIndex = outLink.Attrs().Index
		if xdpPreparedL2LinkTypeAllowed(outLink.Type()) {
			target, err := resolveXDPDirectTarget(outLink, rule)
			if err != nil {
				return nil, err
			}
			outIfIndex = target.outIfIndex
			value.Flags |= xdpRuleFlagPreparedL2
			value.SrcMAC = target.srcMAC
			value.DstMAC = target.dstMAC
		} else {
			if err := validateXDPDirectTarget(outLink, rule); err != nil {
				return nil, err
			}
		}
	} else {
		target, err := resolveXDPBridgeTarget(outLink, rule, opts)
		if err != nil {
			return nil, err
		}
		outIfIndex = target.outIfIndex
		value.Flags |= xdpRuleFlagBridgeL2
		value.SrcMAC = target.srcMAC
		value.DstMAC = target.dstMAC
	}
	value.OutIfIndex = uint32(outIfIndex)

	inLinks, err := resolveXDPInboundLinks(inLink, rule, opts)
	if err != nil {
		return nil, err
	}
	if isXDPBridgeLink(inLink) {
		value.Flags |= xdpRuleFlagBridgeIngressL2
	}
	prepared := make([]preparedXDPKernelRule, 0, len(inLinks))
	for _, currentInLink := range inLinks {
		if currentInLink == nil || currentInLink.Attrs() == nil {
			continue
		}
		prepared = append(prepared, preparedXDPKernelRule{
			rule:       rule,
			inIfIndex:  currentInLink.Attrs().Index,
			outIfIndex: outIfIndex,
			key: tcRuleKeyV4{
				IfIndex: uint32(currentInLink.Attrs().Index),
				DstAddr: inAddr,
				DstPort: uint16(rule.InPort),
				Proto:   kernelRuleProtocol(rule.Protocol),
			},
			value: value,
		})
	}
	if len(prepared) == 0 {
		return nil, fmt.Errorf("xdp dataplane bridge ingress expansion produced no attachable member interfaces")
	}
	return prepared, nil
}

func xdpLinkTypeAllowed(linkType string) bool {
	switch strings.ToLower(strings.TrimSpace(linkType)) {
	case "device", "veth":
		return true
	default:
		return false
	}
}

func xdpPreparedL2LinkTypeAllowed(linkType string) bool {
	return strings.EqualFold(strings.TrimSpace(linkType), "veth")
}

func clonePreparedXDPKernelRules(src []preparedXDPKernelRule) []preparedXDPKernelRule {
	if len(src) == 0 {
		return nil
	}
	dst := make([]preparedXDPKernelRule, len(src))
	copy(dst, src)
	return dst
}

func sortPreparedXDPKernelRules(items []preparedXDPKernelRule) {
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
		if a.value.SrcMAC != b.value.SrcMAC {
			return string(a.value.SrcMAC[:]) < string(b.value.SrcMAC[:])
		}
		if a.value.DstMAC != b.value.DstMAC {
			return string(a.value.DstMAC[:]) < string(b.value.DstMAC[:])
		}
		return a.rule.ID < b.rule.ID
	})
}

func snapshotPreparedXDPBridgeEntries(prepared []preparedXDPKernelRule) map[string]struct{} {
	lines := make(map[string]struct{})
	for _, item := range prepared {
		if item.value.Flags&(xdpRuleFlagBridgeL2|xdpRuleFlagBridgeIngressL2|xdpRuleFlagPreparedL2) == 0 {
			continue
		}
		line := fmt.Sprintf(
			"xdp dataplane %s l2 plan: in_if=%s out_if=%s ingress_bridge=%t egress_bridge=%t prepared_l2=%t backend=%s:%d src_mac=%s dst_mac=%s",
			kernelRuleLogLabel(item.rule),
			xdpInterfaceLabel(item.inIfIndex),
			xdpInterfaceLabel(item.outIfIndex),
			(item.value.Flags&xdpRuleFlagBridgeIngressL2) != 0,
			(item.value.Flags&xdpRuleFlagBridgeL2) != 0,
			(item.value.Flags&xdpRuleFlagPreparedL2) != 0,
			net.IPv4(
				byte(item.value.BackendAddr>>24),
				byte(item.value.BackendAddr>>16),
				byte(item.value.BackendAddr>>8),
				byte(item.value.BackendAddr),
			).String(),
			item.value.BackendPort,
			formatXDPMAC(item.value.SrcMAC),
			formatXDPMAC(item.value.DstMAC),
		)
		lines[line] = struct{}{}
	}
	return lines
}

func xdpInterfaceLabel(ifindex int) string {
	if ifindex <= 0 {
		return fmt.Sprintf("ifindex=%d", ifindex)
	}
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil || link == nil || link.Attrs() == nil {
		return fmt.Sprintf("ifindex=%d", ifindex)
	}
	return fmt.Sprintf("%s(%d)", link.Attrs().Name, ifindex)
}

func formatXDPMAC(mac [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
