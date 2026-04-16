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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

const (
	kernelXDPProgramName                 = "forward_xdp"
	kernelXDPProgramV4Name               = "forward_xdp_v4"
	kernelXDPProgramV6Name               = "forward_xdp_v6"
	kernelXDPProgramV4TransparentName    = "forward_xdp_v4_transparent"
	kernelXDPProgramV4FullNATForwardName = "forward_xdp_v4_fullnat_forward"
	kernelXDPProgramV4FullNATReplyName   = "forward_xdp_v4_fullnat_reply"
	kernelXDPProgramV6FullNATForwardName = "forward_xdp_v6_fullnat_forward"
	kernelXDPProgramV6FullNATReplyName   = "forward_xdp_v6_fullnat_reply"
	kernelXDPRedirectMapName             = "xdp_redirect_map"
	kernelXDPProgramChainMapName         = "xdp_prog_chain"
	kernelXDPFIBScratchMapName           = "xdp_fib_scratch"
	kernelXDPFlowScratchV4MapName        = "xdp_flow_scratch_v4"
	kernelXDPFlowAuxScratchV4MapName     = "xdp_flow_aux_scratch_v4"
	kernelXDPFlowScratchV6MapName        = "xdp_flow_scratch_v6"
	kernelXDPFlowAuxScratchV6MapName     = "xdp_flow_aux_scratch_v6"
	kernelXDPDispatchScratchV4MapName    = "xdp_dispatch_scratch_v4"
	kernelXDPDispatchScratchV6MapName    = "xdp_dispatch_scratch_v6"
	kernelXDPFlowsOldMapNameV4           = "flows_old_v4"
	kernelXDPFlowsOldMapNameV6           = "flows_old_v6"
	kernelXDPFlowMigrationStateMapName   = "xdp_flow_migration_state"
	xdpProgramChainIndexV4               = 0
	xdpProgramChainIndexV6               = 1
	xdpProgramChainIndexV4Transparent    = 2
	xdpProgramChainIndexV4FullNATForward = 3
	xdpProgramChainIndexV4FullNATReply   = 4
	xdpProgramChainIndexV6FullNATForward = 5
	xdpProgramChainIndexV6FullNATReply   = 6
)

const (
	xdpRuleFlagFullNAT         = 0x1
	xdpRuleFlagBridgeL2        = 0x2
	xdpRuleFlagBridgeIngressL2 = 0x4
	xdpRuleFlagTrafficStats    = 0x8
	xdpRuleFlagPreparedL2      = 0x10
	xdpRuleFlagEgressNAT       = 0x20
	xdpRuleFlagFullCone        = 0x40
)

const (
	xdpVethNATRedirectMinKernelMajor = 5
	xdpVethNATRedirectMinKernelMinor = 11
)

const (
	xdpFlowMigrationFlagV4Old = 0x1
	xdpFlowMigrationFlagV6Old = 0x2
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

type xdpRuleValueV6 struct {
	RuleID      uint32
	BackendAddr [16]byte
	BackendPort uint16
	Flags       uint16
	OutIfIndex  uint32
	NATAddr     [16]byte
	SrcMAC      [6]byte
	DstMAC      [6]byte
}

type xdpFlowValueV4 struct {
	RuleID           uint32
	FrontAddr        uint32
	ClientAddr       uint32
	NATAddr          uint32
	InIfIndex        uint32
	FrontPort        uint16
	ClientPort       uint16
	NATPort          uint16
	Flags            uint16
	FrontMAC         [6]byte
	ClientMAC        [6]byte
	LastSeenNS       uint64
	FrontCloseSeenNS uint64
}

type preparedXDPKernelRule struct {
	rule       Rule
	inIfIndex  int
	outIfIndex int
	spec       kernelPreparedRuleSpec
	keyV4      tcRuleKeyV4
	valueV4    xdpRuleValueV4
	keyV6      tcRuleKeyV6
	valueV6    xdpRuleValueV6
}

type xdpCollectionPieces struct {
	prog                 *ebpf.Program
	progV4               *ebpf.Program
	progV6               *ebpf.Program
	progV4Transparent    *ebpf.Program
	progV4FullNATForward *ebpf.Program
	progV4FullNATReply   *ebpf.Program
	progV6FullNATForward *ebpf.Program
	progV6FullNATReply   *ebpf.Program
	redirectMap          *ebpf.Map
	progChain            *ebpf.Map
	rulesV4              *ebpf.Map
	rulesV6              *ebpf.Map
	flowsV4              *ebpf.Map
	flowsV6              *ebpf.Map
	flowsOldV4           *ebpf.Map
	flowsOldV6           *ebpf.Map
	natV4                *ebpf.Map
	natV6                *ebpf.Map
	natConfigV4          *ebpf.Map
	natOldV4             *ebpf.Map
	natOldV6             *ebpf.Map
	flowMigrationState   *ebpf.Map
	localIPv4s           *ebpf.Map
}

type preparedXDPKernelRuleBatches struct {
	v4Keys   []tcRuleKeyV4
	v4Values []xdpRuleValueV4
	v6Keys   []tcRuleKeyV6
	v6Values []xdpRuleValueV6
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
	mu                 sync.Mutex
	availableOnce      sync.Once
	available          bool
	availableReason    string
	allowGenericAttach bool
	rulesMapLimit      int
	flowsMapLimit      int
	natMapLimit        int
	natPortMin         int
	natPortMax         int
	rulesMapCapacity   int
	flowsMapCapacity   int
	natMapCapacity     int
	memlockOnce        sync.Once
	memlockErr         error
	coll               *ebpf.Collection
	attachments        []xdpAttachment
	preparedRules      []preparedXDPKernelRule
	programID          uint32
	prepareOptions     xdpPrepareOptions
	lastSkipLog        map[string]struct{}
	lastBridgeLog      map[string]struct{}
	lastReconcileMode  string
	degradedSource     string
	stateLog           kernelStateLogger
	pressureState      kernelRuntimePressureState
	observability      kernelRuntimeObservabilityState
	maintenanceState   kernelAdaptiveMaintenanceState
	statsCorrection    map[uint32]kernelRuleStats
	flowPruneState     kernelFlowPruneState
	oldFlowPruneState  kernelFlowPruneState
	runtimeMapCounts   kernelRuntimeMapCountSnapshot
}

func newXDPKernelRuleRuntime(cfg *Config) kernelRuleRuntime {
	opts := xdpPrepareOptions{}
	allowGeneric := false
	rulesLimit := 0
	flowsLimit := 0
	natLimit := 0
	natPortMin, natPortMax := effectiveKernelNATPortRange(0, 0)
	if cfg != nil && cfg.ExperimentalFeatureEnabled(experimentalFeatureBridgeXDP) {
		opts.enableBridge = true
	}
	if cfg != nil && cfg.ExperimentalFeatureEnabled(experimentalFeatureXDPGeneric) {
		allowGeneric = true
	}
	if cfg != nil && cfg.ExperimentalFeatureEnabled(experimentalFeatureKernelTraffic) {
		opts.enableTrafficStats = true
	}
	if cfg != nil {
		rulesLimit = cfg.KernelRulesMapLimit
		flowsLimit = cfg.KernelFlowsMapLimit
		natLimit = cfg.KernelNATMapLimit
		natPortMin, natPortMax = effectiveKernelNATPortRange(cfg.KernelNATPortMin, cfg.KernelNATPortMax)
	}
	return &xdpKernelRuleRuntime{
		prepareOptions:     opts,
		allowGenericAttach: allowGeneric,
		rulesMapLimit:      rulesLimit,
		flowsMapLimit:      flowsLimit,
		natMapLimit:        natLimit,
		natPortMin:         natPortMin,
		natPortMax:         natPortMax,
		statsCorrection:    make(map[uint32]kernelRuleStats),
	}
}

func (rt *xdpKernelRuleRuntime) ensureAvailabilityInitialized() {
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
		if rt.allowGenericAttach {
			rt.availableReason += "; xdp_generic experimental path enabled"
		} else {
			rt.availableReason += fmt.Sprintf("; generic/mixed attachment requires experimental feature %q", experimentalFeatureXDPGeneric)
		}
		if rt.prepareOptions.enableTrafficStats {
			rt.availableReason += "; kernel_traffic_stats experimental path enabled"
		}
	})
}

func (rt *xdpKernelRuleRuntime) Available() (bool, string) {
	rt.ensureAvailabilityInitialized()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.currentAvailabilityLocked(time.Now())
}

func (rt *xdpKernelRuleRuntime) SupportsRule(rule Rule) (bool, string) {
	_, err := prepareXDPKernelRule(rule, rt.prepareOptions)
	if err != nil {
		return false, err.Error()
	}
	return true, ""
}

func (rt *xdpKernelRuleRuntime) Reconcile(rules []Rule) (results map[int64]kernelRuleApplyResult, reconcileErr error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	reconcileStartedAt := time.Now()
	reconcileMetrics := kernelReconcileMetrics{RequestEntries: len(rules)}
	defer func() {
		rt.observability.recordReconcile(reconcileStartedAt, time.Since(reconcileStartedAt), reconcileMetrics, reconcileErr, results)
	}()

	results = make(map[int64]kernelRuleApplyResult, len(rules))
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

	prepareStartedAt := time.Now()
	prepared, _, _, prepareResults, skipLines := prepareXDPKernelRules(rules, rt.prepareOptions, rt.preparedRules, rt.coll != nil)
	reconcileMetrics.PrepareDuration = time.Since(prepareStartedAt)
	reconcileMetrics.PreparedEntries = len(prepared)
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
	samePrepared := rt.samePreparedRulesLocked(prepared, requiredIfIndices)
	desiredLocalIPv4s, localIPv4Err := buildKernelEgressNATLocalIPv4Set(rules)
	if localIPv4Err != nil && !samePrepared {
		msg := fmt.Sprintf("build xdp egress nat local IPv4 inventory: %v", localIPv4Err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("xdp dataplane reconcile: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if samePrepared {
		if localIPv4Err != nil {
			log.Printf("xdp dataplane reconcile: keep current local IPv4 bypass inventory after refresh failure: %v", localIPv4Err)
		} else if pieces, err := lookupXDPCollectionPieces(rt.coll); err != nil {
			log.Printf("xdp dataplane reconcile: refresh local IPv4 bypass inventory skipped: %v", err)
		} else if pieces.localIPv4s == nil {
			if len(desiredLocalIPv4s) > 0 {
				log.Printf("xdp dataplane reconcile: refresh local IPv4 bypass inventory skipped: embedded xdp eBPF object is missing map %q", kernelLocalIPv4MapName)
			}
		} else if err := syncKernelLocalIPv4Map(pieces.localIPv4s, desiredLocalIPv4s); err != nil {
			log.Printf("xdp dataplane reconcile: refresh local IPv4 bypass inventory failed: %v", err)
		}
		rt.lastReconcileMode = "steady"
		reconcileMetrics.AppliedEntries = len(prepared)
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
	currentCounts := rt.currentRuntimeMapCountsLocked(time.Now())
	currentNATEntries := currentCounts.natEntries
	if rt.coll != nil && rt.coll.Maps != nil {
		currentNATEntries = xdpExactNATEntriesForPreservation(
			kernelRuntimeMapRefsFromCollection(rt.coll),
			currentNATEntries,
			"xdp dataplane reconcile",
		)
	}
	currentCounts.natEntries = currentNATEntries
	useNATMaps := preparedXDPKernelRulesNeedFullConeNATMap(prepared) || currentNATEntries > 0
	desiredCapacities, err := applyKernelMapCapacitiesWithOccupancy(
		spec,
		rt.rulesMapLimit,
		rt.flowsMapLimit,
		rt.natMapLimit,
		len(prepared),
		currentCounts,
		useNATMaps,
		normalizeKernelFlowsMapLimit(rt.flowsMapLimit) == 0,
		useNATMaps && normalizeKernelNATMapLimit(rt.natMapLimit) == 0,
	)
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
	preferFreshMapGrowth := rt.shouldPreferFreshMapGrowthLocked(desiredCapacities)
	if preferFreshMapGrowth {
		log.Printf("xdp dataplane reconcile: flow maps are idle and below desired capacity, rebuilding xdp collection to clear degraded state")
	}

	memlockErr := rt.ensureMemlock()
	if memlockErr != nil {
		log.Printf("xdp dataplane reconcile: memlock auto-raise unavailable: %v (%s); continuing with current limit", memlockErr, kernelMemlockStatus())
	}
	if rt.rulesMapCapacity != desiredCapacities.Rules || rt.flowsMapCapacity != desiredCapacities.Flows || rt.natMapCapacity != desiredCapacities.NATPorts {
		if useNATMaps {
			log.Printf(
				"xdp dataplane reconcile: rules/stats=%d(%s) flows=%d(%s) nat=%d(%s) requested_entries=%d",
				desiredCapacities.Rules,
				kernelRulesMapCapacityMode(rt.rulesMapLimit),
				desiredCapacities.Flows,
				kernelFlowsMapCapacityMode(rt.flowsMapLimit),
				desiredCapacities.NATPorts,
				kernelNATMapCapacityMode(rt.natMapLimit),
				len(prepared),
			)
		} else {
			log.Printf(
				"xdp dataplane reconcile: rules/stats=%d(%s) flows=%d(%s) requested_entries=%d",
				desiredCapacities.Rules,
				kernelRulesMapCapacityMode(rt.rulesMapLimit),
				desiredCapacities.Flows,
				kernelFlowsMapCapacityMode(rt.flowsMapLimit),
				len(prepared),
			)
		}
	}

	var coll *ebpf.Collection
	flowMapReplacement := map[string]*ebpf.Map(nil)
	actualCapacities := desiredCapacities
	var oldStatsMap *ebpf.Map
	var hotRestartState *kernelHotRestartMapState
	hotRestartStatsCorrection := map[uint32]kernelRuleStats{}
	flowMigrationFlags := uint32(0)
	ensureFlowMapReplacement := func() {
		if flowMapReplacement == nil {
			flowMapReplacement = make(map[string]*ebpf.Map, 7)
		}
	}
	if rt.coll != nil && rt.coll.Maps != nil {
		if !preferFreshMapGrowth {
			existingMigrationFlags, flowStateErr := xdpEffectiveOldFlowMigrationFlagsFromCollection(rt.coll)
			if flowStateErr != nil {
				msg := fmt.Sprintf("inspect xdp old-bank flow state: %v", flowStateErr)
				if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
					return results, nil
				}
				log.Printf("xdp dataplane reconcile: %s", msg)
				for _, rule := range rules {
					results[rule.ID] = kernelRuleApplyResult{Error: msg}
				}
				return results, nil
			}
			if existingMigrationFlags != 0 {
				if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
					ensureFlowMapReplacement()
					flowMapReplacement[kernelFlowsMapName] = flowsMap
					if flowCapacity := int(flowsMap.MaxEntries()); flowCapacity < actualCapacities.Flows {
						actualCapacities.Flows = flowCapacity
					}
				}
				if flowsMapV6 := rt.coll.Maps[kernelFlowsMapNameV6]; flowsMapV6 != nil {
					ensureFlowMapReplacement()
					flowMapReplacement[kernelFlowsMapNameV6] = flowsMapV6
					if flowCapacity := int(flowsMapV6.MaxEntries()); flowCapacity < actualCapacities.Flows {
						actualCapacities.Flows = flowCapacity
					}
				}
				if existingMigrationFlags&xdpFlowMigrationFlagV4Old != 0 {
					if flowsOldMap := rt.coll.Maps[kernelXDPFlowsOldMapNameV4]; flowsOldMap != nil {
						ensureFlowMapReplacement()
						flowMapReplacement[kernelXDPFlowsOldMapNameV4] = flowsOldMap
					}
					if currentNATEntries > 0 {
						if natOldMap := rt.coll.Maps[kernelTCNatPortsOldMapNameV4]; natOldMap != nil {
							ensureFlowMapReplacement()
							flowMapReplacement[kernelTCNatPortsOldMapNameV4] = natOldMap
						}
					}
				}
				if existingMigrationFlags&xdpFlowMigrationFlagV6Old != 0 {
					if flowsOldMapV6 := rt.coll.Maps[kernelXDPFlowsOldMapNameV6]; flowsOldMapV6 != nil {
						ensureFlowMapReplacement()
						flowMapReplacement[kernelXDPFlowsOldMapNameV6] = flowsOldMapV6
					}
					if currentNATEntries > 0 {
						if natOldMapV6 := rt.coll.Maps[kernelTCNatPortsOldMapNameV6]; natOldMapV6 != nil {
							ensureFlowMapReplacement()
							flowMapReplacement[kernelTCNatPortsOldMapNameV6] = natOldMapV6
						}
					}
				}
				if currentNATEntries > 0 {
					if natMap := rt.coll.Maps[kernelNatPortsMapNameV4]; natMap != nil {
						ensureFlowMapReplacement()
						flowMapReplacement[kernelNatPortsMapNameV4] = natMap
						if natCapacity := int(natMap.MaxEntries()); natCapacity < actualCapacities.NATPorts {
							actualCapacities.NATPorts = natCapacity
						}
					}
					if natMapV6 := rt.coll.Maps[kernelNatPortsMapNameV6]; natMapV6 != nil {
						ensureFlowMapReplacement()
						flowMapReplacement[kernelNatPortsMapNameV6] = natMapV6
						if natCapacity := int(natMapV6.MaxEntries()); natCapacity < actualCapacities.NATPorts {
							actualCapacities.NATPorts = natCapacity
						}
					}
				}
				flowMigrationFlags = existingMigrationFlags
				if actualCapacities.Flows < desiredCapacities.Flows {
					log.Printf(
						"xdp dataplane reconcile: preserving active/old flow banks while migration is still draining; active flow map capacity=%d remains below desired=%d",
						actualCapacities.Flows,
						desiredCapacities.Flows,
					)
				}
				if useNATMaps && actualCapacities.NATPorts > 0 && actualCapacities.NATPorts < desiredCapacities.NATPorts {
					log.Printf(
						"xdp dataplane reconcile: preserving active/old nat banks while migration is still draining; active nat map capacity=%d remains below desired=%d",
						actualCapacities.NATPorts,
						desiredCapacities.NATPorts,
					)
				}
			} else {
				if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
					ensureFlowMapReplacement()
					flowMapReplacement[kernelXDPFlowsOldMapNameV4] = flowsMap
					flowMigrationFlags |= xdpFlowMigrationFlagV4Old
				}
				if flowsMapV6 := rt.coll.Maps[kernelFlowsMapNameV6]; flowsMapV6 != nil {
					ensureFlowMapReplacement()
					flowMapReplacement[kernelXDPFlowsOldMapNameV6] = flowsMapV6
					flowMigrationFlags |= xdpFlowMigrationFlagV6Old
				}
				if currentNATEntries > 0 {
					if natMap := rt.coll.Maps[kernelNatPortsMapNameV4]; natMap != nil {
						ensureFlowMapReplacement()
						flowMapReplacement[kernelTCNatPortsOldMapNameV4] = natMap
					}
					if natMapV6 := rt.coll.Maps[kernelNatPortsMapNameV6]; natMapV6 != nil {
						ensureFlowMapReplacement()
						flowMapReplacement[kernelTCNatPortsOldMapNameV6] = natMapV6
					}
				}
			}
		}
		if statsMap := rt.coll.Maps[kernelStatsMapName]; statsMap != nil {
			if kernelMapReusableWithCapacity(statsMap, desiredCapacities.Rules) {
				ensureFlowMapReplacement()
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
	} else if objectHash, hashErr := kernelXDPHotRestartObjectHash(rt.prepareOptions.enableTrafficStats); hashErr != nil {
		log.Printf(
			"xdp dataplane hot restart: xdp handoff unavailable because current object fingerprint could not be calculated; falling back to fresh maps (cold restart): %v",
			hashErr,
		)
		if cleanupErr := cleanupStaleXDPKernelHotRestartState(); cleanupErr != nil {
			log.Printf("xdp dataplane hot restart: cleanup stale xdp state failed, discarding pinned state only: %v", cleanupErr)
			clearKernelHotRestartState(kernelEngineXDP)
		}
	} else if state, err := loadXDPKernelHotRestartState(
		desiredCapacities,
		kernelXDPHotRestartValidationOptions(objectHash, rt.prepareOptions.enableTrafficStats),
	); err != nil {
		if isKernelHotRestartIncompatible(err) {
			log.Printf(
				"xdp dataplane hot restart: preserved xdp handoff is incompatible, abandoning handoff and falling back to fresh maps (cold restart): %s",
				kernelHotRestartIncompatibilityReason(err),
			)
		} else {
			log.Printf("xdp dataplane hot restart: load xdp state failed, cleaning stale hot restart state: %v", err)
		}
		if cleanupErr := cleanupStaleXDPKernelHotRestartState(); cleanupErr != nil {
			log.Printf("xdp dataplane hot restart: cleanup stale xdp state failed, discarding pinned state only: %v", cleanupErr)
			clearKernelHotRestartState(kernelEngineXDP)
		}
	} else if state != nil {
		if err := validateKernelHotRestartMapReplacements(spec, state.replacements, map[string]bool{
			kernelFlowsMapName:           true,
			kernelFlowsMapNameV6:         true,
			kernelXDPFlowsOldMapNameV4:   true,
			kernelXDPFlowsOldMapNameV6:   true,
			kernelNatPortsMapName:        true,
			kernelNatPortsMapNameV6:      true,
			kernelTCNatPortsOldMapNameV4: true,
			kernelTCNatPortsOldMapNameV6: true,
		}); err != nil {
			log.Printf(
				"xdp dataplane hot restart: preserved xdp maps are incompatible, abandoning handoff and falling back to fresh maps (cold restart): %s",
				kernelHotRestartIncompatibilityReason(err),
			)
			state.close()
			if cleanupErr := cleanupStaleXDPKernelHotRestartState(); cleanupErr != nil {
				log.Printf("xdp dataplane hot restart: cleanup stale xdp state failed, discarding pinned state only: %v", cleanupErr)
				clearKernelHotRestartState(kernelEngineXDP)
			}
		} else {
			hotRestartState = state
			if len(state.replacements) > 0 {
				flowMapReplacement = state.replacements
			}
			oldStatsMap = state.oldStatsMap
			actualCapacities = state.actualCapacities
			flowMigrationFlags = state.xdpFlowMigrationFlags
			if !useNATMaps && (state.replacements[kernelNatPortsMapName] != nil ||
				state.replacements[kernelNatPortsMapNameV6] != nil ||
				state.replacements[kernelTCNatPortsOldMapNameV4] != nil ||
				state.replacements[kernelTCNatPortsOldMapNameV6] != nil) {
				useNATMaps = true
			}
			if actualCapacities.Flows < desiredCapacities.Flows {
				log.Printf(
					"xdp dataplane hot restart: preserving pinned active/old flow banks while migration is still draining; active flow map capacity=%d remains below desired=%d",
					actualCapacities.Flows,
					desiredCapacities.Flows,
				)
			}
			if useNATMaps && actualCapacities.NATPorts > 0 && actualCapacities.NATPorts < desiredCapacities.NATPorts {
				log.Printf(
					"xdp dataplane hot restart: preserving pinned active/old nat banks while migration is still draining; active nat map capacity=%d remains below desired=%d",
					actualCapacities.NATPorts,
					desiredCapacities.NATPorts,
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
	}
	loadSpec := spec
	if len(flowMapReplacement) > 0 {
		loadSpec, err = kernelCollectionSpecWithReplacementMapCapacities(spec, flowMapReplacement)
		if err == nil {
			coll, err = ebpf.NewCollectionWithOptions(loadSpec, kernelCollectionOptions(flowMapReplacement))
		} else {
			err = fmt.Errorf("prepare xdp collection replacement maps: %w", err)
		}
	} else {
		coll, err = ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(nil))
	}
	if err != nil && hotRestartState != nil {
		log.Printf(
			"xdp dataplane hot restart: xdp handoff failed during collection load, abandoning handoff and falling back to fresh maps (cold restart): %v",
			err,
		)
		hotRestartState.close()
		hotRestartState = nil
		flowMapReplacement = nil
		oldStatsMap = nil
		actualCapacities = desiredCapacities
		flowMigrationFlags = 0
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

	pieces, err := lookupXDPCollectionPieces(coll)
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
	if err := configureXDPProgramChain(pieces); err != nil {
		coll.Close()
		msg := fmt.Sprintf("configure xdp program chain: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("xdp dataplane program chain setup failed: %v", err)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if err := configureXDPFlowMigrationState(pieces, flowMigrationFlags); err != nil {
		coll.Close()
		msg := fmt.Sprintf("configure xdp flow migration state: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("xdp dataplane flow migration state setup failed: %v", err)
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
	if hotRestartState != nil {
		if correction, err := reconcileKernelStatsCorrectionFromRuntimeMaps(coll.Maps[kernelStatsMapName], kernelRuntimeMapRefsFromCollection(coll)); err != nil {
			log.Printf("xdp dataplane hot restart: reconcile xdp stats against flows failed: %v", err)
		} else {
			hotRestartStatsCorrection = correction
		}
	}
	if err := syncKernelOccupancyMapFromCollectionExact(coll, useNATMaps); err != nil {
		log.Printf("xdp dataplane reconcile: sync xdp occupancy counters failed before attach: %v", err)
	}
	if err := syncKernelNATConfigMap(pieces.natConfigV4, rt.natPortMin, rt.natPortMax); err != nil {
		coll.Close()
		msg := fmt.Sprintf("sync xdp nat config map: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("xdp dataplane nat config map sync failed: %v", err)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if pieces.localIPv4s != nil {
		if err := syncKernelLocalIPv4Map(pieces.localIPv4s, desiredLocalIPv4s); err != nil {
			coll.Close()
			msg := fmt.Sprintf("sync xdp local IPv4 bypass map: %v", err)
			if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
				return results, nil
			}
			log.Printf("xdp dataplane local IPv4 bypass map sync failed: %v", err)
			for _, rule := range rules {
				results[rule.ID] = kernelRuleApplyResult{Error: msg}
			}
			return results, nil
		}
	} else if len(desiredLocalIPv4s) > 0 {
		coll.Close()
		msg := fmt.Sprintf("embedded xdp eBPF object is missing map %q; rebuild the xdp eBPF object", kernelLocalIPv4MapName)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("xdp dataplane local IPv4 bypass map sync failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if err := syncXDPRedirectMap(pieces.redirectMap, requiredIfIndices); err != nil {
		coll.Close()
		msg := fmt.Sprintf("sync xdp redirect map: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("xdp dataplane redirect map sync failed: %v", err)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}

	if err := syncPreparedXDPKernelRuleMaps(pieces, prepared); err != nil {
		coll.Close()
		msg := fmt.Sprintf("sync xdp rule maps: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("xdp dataplane rule map sync failed: %v", err)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}

	programID := kernelProgramID(pieces.prog)
	oldAttachments := append([]xdpAttachment(nil), rt.attachments...)
	oldProg := xdpCollectionProgram(rt.coll)
	newAttachments := make([]xdpAttachment, 0, len(requiredIfIndices))
	attachStartedAt := time.Now()
	for _, ifindex := range requiredIfIndices {
		att, err := rt.attachProgramLocked(ifindex, pieces.prog, oldProg, oldAttachments)
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
	reconcileMetrics.AttachDuration = time.Since(attachStartedAt)
	reconcileMetrics.Attaches = len(newAttachments)

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
	reconcileMetrics.AppliedEntries = len(prepared)
	reconcileMetrics.Upserts = len(prepared)
	reconcileMetrics.Detaches = xdpAttachmentDeleteCount(oldAttachments, newAttachments)

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
	rt.natMapCapacity = actualCapacities.NATPorts
	if hotRestartState != nil && kernelRuntimeNeedsMapGrowth(actualCapacities, desiredCapacities, useNATMaps) {
		rt.degradedSource = kernelRuntimeDegradedSourceHotRestart
	} else if kernelRuntimeNeedsMapGrowth(actualCapacities, desiredCapacities, useNATMaps) {
		rt.degradedSource = kernelRuntimeDegradedSourceLivePreserve
	} else {
		rt.degradedSource = kernelRuntimeDegradedSourceNone
	}
	rt.flowPruneState.reset()
	rt.oldFlowPruneState.reset()
	rt.lastReconcileMode = "rebuild"
	rt.maintenanceState.requestFull()
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	if hotRestartState != nil {
		rt.statsCorrection = hotRestartStatsCorrection
	}
	if err := writeKernelRuntimeMetadata(kernelEngineXDP, kernelHotRestartXDPMetadata(rt.attachments, "")); err != nil {
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
	statsMap, err := cloneKernelRuntimeMap(snapshotCollectionMap(rt.coll, kernelStatsMapName), kernelStatsMapName)
	corrections := cloneKernelStatsCorrections(rt.statsCorrection)
	rt.mu.Unlock()
	if err != nil {
		return emptyKernelRuleStatsSnapshot(), err
	}
	if statsMap != nil {
		defer statsMap.Close()
	}
	return snapshotKernelStatsFromMap(statsMap, corrections)
}

func (rt *xdpKernelRuleRuntime) Maintain() error {
	startedAt := time.Now()
	rt.mu.Lock()
	pressureActive := rt.pressureState.active
	runFull := rt.maintenanceState.shouldRunFull(pressureActive)
	mapSnapshot, err := snapshotKernelRuntimeMaps(rt.coll, runFull, false)
	if err != nil {
		rt.observability.recordMaintain(startedAt, time.Since(startedAt), kernelFlowPruneMetrics{}, err)
		rt.mu.Unlock()
		return err
	}
	refs := mapSnapshot.refs
	v4Budget, v6Budget := rt.flowMaintenanceBudgetsLocked(refs)
	flowPruneState := rt.flowPruneState
	oldFlowPruneState := rt.oldFlowPruneState
	statsCorrection := cloneKernelStatsCorrections(rt.statsCorrection)
	rt.mu.Unlock()
	defer mapSnapshot.Close()

	matchRefs := mapSnapshot.source
	splitFamilyBudget := func(total int, primaryPresent bool, oldPresent bool) (int, int) {
		switch {
		case primaryPresent && oldPresent:
			primary := total / 2
			if primary <= 0 {
				primary = 1
			}
			return primary, total - primary
		case primaryPresent:
			return total, 0
		case oldPresent:
			return 0, total
		default:
			return 0, 0
		}
	}
	v4ActiveBudget, v4OldBudget := splitFamilyBudget(v4Budget, refs.flowsV4 != nil, refs.flowsOldV4 != nil)
	v6ActiveBudget, v6OldBudget := splitFamilyBudget(v6Budget, refs.flowsV6 != nil, refs.flowsOldV6 != nil)
	corrections := map[uint32]kernelRuleStats{}
	pruneMetrics := kernelFlowPruneMetrics{}
	var maintainErr error
	fullSuccess := true
	driftDetected := false

	if refs.flowsV4 != nil {
		v4Corrections, v4Metrics, err := pruneStaleXDPFlowsMap(refs.rulesV4, refs.flowsV4, refs.natV4, &flowPruneState, v4ActiveBudget)
		pruneMetrics.Budget += v4Metrics.Budget
		pruneMetrics.Scanned += v4Metrics.Scanned
		pruneMetrics.Deleted += v4Metrics.Deleted
		if err != nil {
			maintainErr = err
			goto done
		}
		mergeKernelStatsCorrections(corrections, v4Corrections)
	}
	if refs.flowsOldV4 != nil {
		v4Corrections, v4Metrics, err := pruneStaleXDPFlowsMap(refs.rulesV4, refs.flowsOldV4, refs.natOldV4, &oldFlowPruneState, v4OldBudget)
		pruneMetrics.Budget += v4Metrics.Budget
		pruneMetrics.Scanned += v4Metrics.Scanned
		pruneMetrics.Deleted += v4Metrics.Deleted
		if err != nil {
			maintainErr = err
			goto done
		}
		mergeKernelStatsCorrections(corrections, v4Corrections)
	}
	if refs.flowsV6 != nil {
		v6Corrections, v6Metrics, err := pruneStaleKernelFlowsV6InCollection(refs.rulesV6, refs.flowsV6, refs.natV6, &flowPruneState, v6ActiveBudget)
		pruneMetrics.Budget += v6Metrics.Budget
		pruneMetrics.Scanned += v6Metrics.Scanned
		pruneMetrics.Deleted += v6Metrics.Deleted
		if err != nil {
			maintainErr = err
			goto done
		}
		mergeKernelStatsCorrections(corrections, v6Corrections)
	}
	if refs.flowsOldV6 != nil {
		v6Corrections, v6Metrics, err := pruneStaleKernelFlowsV6InCollection(refs.rulesV6, refs.flowsOldV6, refs.natOldV6, &oldFlowPruneState, v6OldBudget)
		pruneMetrics.Budget += v6Metrics.Budget
		pruneMetrics.Scanned += v6Metrics.Scanned
		pruneMetrics.Deleted += v6Metrics.Deleted
		if err != nil {
			maintainErr = err
			goto done
		}
		mergeKernelStatsCorrections(corrections, v6Corrections)
	}
	if currentFlags, err := xdpOldFlowMigrationFlagsFromRuntimeMapRefs(refs); err != nil {
		log.Printf("xdp dataplane maintenance: inspect old-bank flow state failed: %v", err)
	} else if refs.xdpFlowMigrationState != nil {
		if err := refs.xdpFlowMigrationState.Put(uint32(0), currentFlags); err != nil {
			log.Printf("xdp dataplane maintenance: update flow migration state failed: %v", err)
		}
	}
	mergeKernelStatsCorrections(statsCorrection, corrections)
	if runFull {
		if refs.hasFlows() || refs.hasNAT() || mapSnapshot.stats != nil {
			live, liveErr := snapshotXDPKernelLiveStateFromRuntimeMapRefs(refs, true)
			if liveErr != nil {
				fullSuccess = false
				log.Printf("xdp dataplane maintenance: snapshot live xdp flow state failed: %v", liveErr)
			} else {
				exact, correctionErr := reconcileKernelStatsCorrectionFromCandidates(mapSnapshot.stats, live.ByRuleID, statsCorrection)
				if correctionErr != nil {
					fullSuccess = false
					log.Printf("xdp dataplane maintenance: reconcile xdp stats correction failed: %v", correctionErr)
				} else {
					driftDetected = !kernelStatsCorrectionsEqual(statsCorrection, exact)
					syncKernelLiveStatsCorrections(statsCorrection, exact)
				}
				deleted := 0
				natEntries := 0
				for _, natMap := range []*ebpf.Map{refs.natV4, refs.natOldV4} {
					itemRemaining, itemDeleted, natErr := pruneOrphanKernelNATReservations(natMap, live.UsedNATV4)
					if natErr != nil {
						fullSuccess = false
						log.Printf("xdp dataplane maintenance: prune orphan xdp nat reservations failed: %v", natErr)
						deleted = 0
						natEntries = 0
						break
					}
					natEntries += itemRemaining
					deleted += itemDeleted
				}
				for _, natMap := range []*ebpf.Map{refs.natV6, refs.natOldV6} {
					itemRemaining, itemDeleted, natErr := pruneOrphanKernelNATReservationsV6(natMap, live.UsedNATV6)
					if natErr != nil {
						fullSuccess = false
						log.Printf("xdp dataplane maintenance: prune orphan xdp IPv6 nat reservations failed: %v", natErr)
						deleted = 0
						natEntries = 0
						break
					}
					natEntries += itemRemaining
					deleted += itemDeleted
				}
				if fullSuccess && deleted > 0 {
					driftDetected = true
					log.Printf("xdp dataplane maintenance: pruned %d orphan xdp nat reservation(s)", deleted)
				}
				if fullSuccess {
					if syncErr := syncKernelOccupancyMapForRuntimeRefs(refs, live.FlowEntries, natEntries); syncErr != nil {
						fullSuccess = false
						log.Printf("xdp dataplane maintenance: sync xdp occupancy counters failed: %v", syncErr)
					}
				}
			}
		}
	}

done:
	duration := time.Since(startedAt)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if !kernelRuntimeMapRefsEqual(matchRefs, kernelRuntimeMapRefsFromCollection(rt.coll)) {
		return maintainErr
	}
	rt.observability.recordMaintain(startedAt, duration, pruneMetrics, maintainErr)
	if maintainErr != nil {
		return maintainErr
	}
	rt.flowPruneState = flowPruneState
	rt.oldFlowPruneState = oldFlowPruneState
	rt.statsCorrection = statsCorrection
	if runFull {
		rt.maintenanceState.observeFull(pressureActive, fullSuccess, driftDetected)
	}
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
	objectHash, err := kernelXDPHotRestartObjectHash(rt.prepareOptions.enableTrafficStats)
	if err != nil {
		log.Printf("xdp dataplane hot restart: fingerprint xdp object failed, falling back to full cleanup: %v", err)
		rt.cleanupLocked()
		return true
	}
	existingMigrationFlags, err := xdpEffectiveOldFlowMigrationFlagsFromCollection(rt.coll)
	if err != nil {
		log.Printf("xdp dataplane hot restart: inspect old-bank flow state failed, falling back to full cleanup: %v", err)
		rt.cleanupLocked()
		return true
	}
	currentCounts := rt.currentRuntimeMapCountsLocked(time.Now())
	currentNATEntries := xdpExactNATEntriesForPreservation(
		kernelRuntimeMapRefsFromCollection(rt.coll),
		currentCounts.natEntries,
		"xdp dataplane hot restart",
	)
	maps := map[string]*ebpf.Map{
		kernelFlowsMapName: rt.coll.Maps[kernelFlowsMapName],
	}
	if rt.coll.Maps[kernelFlowsMapNameV6] != nil {
		maps[kernelFlowsMapNameV6] = rt.coll.Maps[kernelFlowsMapNameV6]
	}
	if currentNATEntries > 0 {
		maps[kernelNatPortsMapName] = rt.coll.Maps[kernelNatPortsMapName]
		if rt.coll.Maps[kernelNatPortsMapNameV6] != nil {
			maps[kernelNatPortsMapNameV6] = rt.coll.Maps[kernelNatPortsMapNameV6]
		}
	}
	if existingMigrationFlags&xdpFlowMigrationFlagV4Old != 0 {
		maps[kernelXDPFlowsOldMapNameV4] = rt.coll.Maps[kernelXDPFlowsOldMapNameV4]
		if currentNATEntries > 0 {
			maps[kernelTCNatPortsOldMapNameV4] = rt.coll.Maps[kernelTCNatPortsOldMapNameV4]
		}
	}
	if existingMigrationFlags&xdpFlowMigrationFlagV6Old != 0 {
		maps[kernelXDPFlowsOldMapNameV6] = rt.coll.Maps[kernelXDPFlowsOldMapNameV6]
		if currentNATEntries > 0 {
			if m := rt.coll.Maps[kernelTCNatPortsOldMapNameV6]; m != nil {
				maps[kernelTCNatPortsOldMapNameV6] = m
			}
		}
	}
	if kernelHotRestartSkipStatsRequested() {
		log.Printf("xdp dataplane hot restart: preserving flow map without %s as requested", kernelStatsMapName)
	} else {
		maps[kernelStatsMapName] = rt.coll.Maps[kernelStatsMapName]
	}
	if err := pinKernelHotRestartMaps(kernelEngineXDP, maps); err != nil {
		log.Printf("xdp dataplane hot restart: preserve xdp maps failed, falling back to full cleanup: %v", err)
		rt.cleanupLocked()
		return true
	}
	if err := writeKernelHotRestartMetadata(
		kernelEngineXDP,
		kernelHotRestartXDPMetadataForHotRestart(rt.attachments, objectHash, rt.prepareOptions.enableTrafficStats),
	); err != nil {
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
	rt.natMapCapacity = 0
	rt.lastReconcileMode = ""
	rt.degradedSource = kernelRuntimeDegradedSourceNone
	rt.statsCorrection = make(map[uint32]kernelRuleStats)
	rt.flowPruneState = kernelFlowPruneState{}
	rt.oldFlowPruneState = kernelFlowPruneState{}
	rt.maintenanceState.reset()
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
	rt.natMapCapacity = 0
	rt.lastReconcileMode = ""
	rt.degradedSource = kernelRuntimeDegradedSourceNone
	rt.statsCorrection = make(map[uint32]kernelRuleStats)
	rt.flowPruneState = kernelFlowPruneState{}
	rt.oldFlowPruneState = kernelFlowPruneState{}
	rt.maintenanceState.reset()
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
	pieces, err := lookupXDPCollectionPieces(rt.coll)
	if err != nil {
		return nil, err
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
		if err := deletePreparedXDPKernelRuleMapEntry(pieces, item); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("delete stale preserved xdp rule %d: %w", item.rule.ID, err)
		}
	}
	rt.preparedRules = kept
	rt.rulesMapCapacity = kernelRuntimeRuleMapCapacity(kernelRuntimeMapRefsFromCollection(rt.coll))
	rt.flowsMapCapacity = kernelRuntimeFlowMapCapacity(kernelRuntimeMapRefsFromCollection(rt.coll))
	rt.natMapCapacity = kernelRuntimeNATMapCapacity(kernelRuntimeMapRefsFromCollection(rt.coll))
	rt.flowPruneState.reset()
	rt.oldFlowPruneState.reset()
	rt.maintenanceState.requestFull()
	rt.invalidateRuntimeMapCountCacheLocked()
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
	pieces, err := lookupXDPCollectionPieces(rt.coll)
	if err != nil {
		return err
	}
	for _, item := range rt.preparedRules {
		if err := deletePreparedXDPKernelRuleMapEntry(pieces, item); err != nil {
			return fmt.Errorf("clear xdp rule key during drain: %w", err)
		}
	}
	rt.preparedRules = nil
	rt.rulesMapCapacity = kernelRuntimeRuleMapCapacity(kernelRuntimeMapRefsFromCollection(rt.coll))
	rt.flowsMapCapacity = kernelRuntimeFlowMapCapacity(kernelRuntimeMapRefsFromCollection(rt.coll))
	rt.natMapCapacity = kernelRuntimeNATMapCapacity(kernelRuntimeMapRefsFromCollection(rt.coll))
	rt.lastReconcileMode = "cleared"
	rt.degradedSource = kernelRuntimeDegradedSourceNone
	rt.maintenanceState.reset()
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	if len(rt.attachments) > 0 {
		if err := writeKernelRuntimeMetadata(kernelEngineXDP, kernelHotRestartXDPMetadata(rt.attachments, "")); err != nil {
			log.Printf("xdp dataplane runtime metadata: refresh xdp runtime metadata failed after rule drain: %v", err)
		}
	}
	rt.stateLog.Logf("xdp dataplane reconcile: drained active rules, preserving flows for existing connections")
	return nil
}

func (rt *xdpKernelRuleRuntime) flowMaintenanceBudgetLocked() int {
	if rt.coll != nil && rt.coll.Maps != nil {
		if totalCapacity := kernelRuntimeFlowMapCapacity(kernelRuntimeMapRefsFromCollection(rt.coll)); totalCapacity > 0 {
			return kernelFlowMaintenanceBudgetForCapacity(totalCapacity)
		}
	}
	return kernelFlowMaintenanceBudgetForCapacity(rt.flowsMapCapacity)
}

func (rt *xdpKernelRuleRuntime) flowMaintenanceBudgetsLocked(refs kernelRuntimeMapRefs) (int, int) {
	baseBudget := rt.flowMaintenanceBudgetLocked()
	haveV4 := refs.flowsV4 != nil || refs.flowsOldV4 != nil
	haveV6 := refs.flowsV6 != nil || refs.flowsOldV6 != nil
	switch {
	case haveV4 && haveV6:
		v4Budget := baseBudget / 2
		if v4Budget <= 0 {
			v4Budget = 1
		}
		return v4Budget, baseBudget - v4Budget
	case haveV4:
		return baseBudget, 0
	case haveV6:
		return 0, baseBudget
	default:
		return baseBudget, 0
	}
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

func (rt *xdpKernelRuleRuntime) attachProgramLocked(ifindex int, prog *ebpf.Program, oldProg *ebpf.Program, oldAttachments []xdpAttachment) (xdpAttachment, error) {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return xdpAttachment{}, fmt.Errorf("resolve interface by index %d: %w", ifindex, err)
	}

	order := xdpAttachOrder(link, oldAttachments, rt.allowGenericAttach)
	var errs []string
	for _, flags := range order {
		if err := netlink.LinkSetXdpFdWithFlags(link, prog.FD(), flags); err == nil {
			if len(errs) > 0 {
				rt.stateLog.Logf("xdp dataplane attach: %s attached in %s mode after fallback (%s)",
					xdpInterfaceLabel(ifindex),
					xdpAttachFlagsLabel(flags),
					strings.Join(errs, "; "),
				)
			}
			return xdpAttachment{ifindex: ifindex, flags: flags}, nil
		} else {
			errs = append(errs, fmt.Sprintf("%s=%v", xdpAttachFlagsLabel(flags), err))
		}
	}
	if stale, ok := xdpModeSwitchAttachment(oldAttachments, ifindex, order); ok && oldProg != nil {
		if err := detachXDPAttachment(stale); err != nil {
			errs = append(errs, fmt.Sprintf("detach existing %s=%v", xdpAttachFlagsLabel(stale.flags), err))
		} else {
			switchErrs := make([]string, 0, len(order))
			for _, flags := range order {
				if err := netlink.LinkSetXdpFdWithFlags(link, prog.FD(), flags); err == nil {
					if len(errs) > 0 || len(switchErrs) > 0 {
						details := append([]string{}, errs...)
						details = append(details, switchErrs...)
						rt.stateLog.Logf("xdp dataplane attach: %s switched from %s to %s after retry (%s)",
							xdpInterfaceLabel(ifindex),
							xdpAttachFlagsLabel(stale.flags),
							xdpAttachFlagsLabel(flags),
							strings.Join(details, "; "),
						)
					}
					return xdpAttachment{ifindex: ifindex, flags: flags}, nil
				} else {
					switchErrs = append(switchErrs, fmt.Sprintf("retry %s=%v", xdpAttachFlagsLabel(flags), err))
				}
			}
			if rollbackErr := netlink.LinkSetXdpFdWithFlags(link, oldProg.FD(), stale.flags); rollbackErr != nil {
				errs = append(errs, fmt.Sprintf("mode switch retry failed (%s); rollback %s=%v", strings.Join(switchErrs, "; "), xdpAttachFlagsLabel(stale.flags), rollbackErr))
			} else {
				errs = append(errs, fmt.Sprintf("mode switch retry failed (%s); rolled back to %s", strings.Join(switchErrs, "; "), xdpAttachFlagsLabel(stale.flags)))
			}
		}
	}
	if !rt.allowGenericAttach {
		errs = append(errs, "generic skipped: "+xdpGenericAttachmentExperimentalReason())
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
	for _, name := range []string{
		kernelXDPProgramName,
		kernelXDPProgramV4Name,
		kernelXDPProgramV6Name,
		kernelXDPProgramV4TransparentName,
		kernelXDPProgramV4FullNATForwardName,
		kernelXDPProgramV4FullNATReplyName,
		kernelXDPProgramV6FullNATForwardName,
		kernelXDPProgramV6FullNATReplyName,
	} {
		if _, ok := spec.Programs[name]; !ok {
			return fmt.Errorf("embedded xdp eBPF object is missing program %q", name)
		}
	}
	if _, ok := spec.Maps[kernelRulesMapName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelRulesMapName)
	}
	if _, ok := spec.Maps[kernelFlowsMapName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelFlowsMapName)
	}
	if _, ok := spec.Maps[kernelNatPortsMapName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelNatPortsMapName)
	}
	if _, ok := spec.Maps[kernelNATConfigMapName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelNATConfigMapName)
	}
	if _, ok := spec.Maps[kernelStatsMapName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelStatsMapName)
	}
	if _, ok := spec.Maps[kernelOccupancyMapName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelOccupancyMapName)
	}
	if _, ok := spec.Maps[kernelXDPRedirectMapName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelXDPRedirectMapName)
	}
	if _, ok := spec.Maps[kernelXDPProgramChainMapName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelXDPProgramChainMapName)
	}
	if _, ok := spec.Maps[kernelXDPFIBScratchMapName]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelXDPFIBScratchMapName)
	}
	for _, name := range []string{
		kernelXDPFlowScratchV4MapName,
		kernelXDPFlowAuxScratchV4MapName,
		kernelXDPFlowScratchV6MapName,
		kernelXDPFlowAuxScratchV6MapName,
		kernelXDPDispatchScratchV4MapName,
		kernelXDPDispatchScratchV6MapName,
		kernelXDPFlowMigrationStateMapName,
	} {
		if _, ok := spec.Maps[name]; !ok {
			return fmt.Errorf("embedded xdp eBPF object is missing map %q", name)
		}
	}
	if _, ok := spec.Maps[kernelRulesMapNameV6]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelRulesMapNameV6)
	}
	if _, ok := spec.Maps[kernelFlowsMapNameV6]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelFlowsMapNameV6)
	}
	if _, ok := spec.Maps[kernelNatPortsMapNameV6]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelNatPortsMapNameV6)
	}
	if _, ok := spec.Maps[kernelXDPFlowsOldMapNameV4]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelXDPFlowsOldMapNameV4)
	}
	if _, ok := spec.Maps[kernelTCNatPortsOldMapNameV4]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelTCNatPortsOldMapNameV4)
	}
	if _, ok := spec.Maps[kernelXDPFlowsOldMapNameV6]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelXDPFlowsOldMapNameV6)
	}
	if _, ok := spec.Maps[kernelTCNatPortsOldMapNameV6]; !ok {
		return fmt.Errorf("embedded xdp eBPF object is missing map %q", kernelTCNatPortsOldMapNameV6)
	}
	for _, name := range []string{
		kernelFlowsMapNameV4,
		kernelNatPortsMapNameV4,
		kernelFlowsMapNameV6,
		kernelNatPortsMapNameV6,
		kernelXDPFlowsOldMapNameV4,
		kernelTCNatPortsOldMapNameV4,
		kernelXDPFlowsOldMapNameV6,
		kernelTCNatPortsOldMapNameV6,
	} {
		if spec.Maps[name].Type != ebpf.Hash {
			return fmt.Errorf(
				"embedded xdp eBPF object map %q has type %v, want %v",
				name,
				spec.Maps[name].Type,
				ebpf.Hash,
			)
		}
	}
	return nil
}

func lookupXDPCollectionPieces(coll *ebpf.Collection) (xdpCollectionPieces, error) {
	if coll == nil {
		return xdpCollectionPieces{}, fmt.Errorf("xdp object is missing")
	}
	pieces := xdpCollectionPieces{
		prog:                 coll.Programs[kernelXDPProgramName],
		progV4:               coll.Programs[kernelXDPProgramV4Name],
		progV6:               coll.Programs[kernelXDPProgramV6Name],
		progV4Transparent:    coll.Programs[kernelXDPProgramV4TransparentName],
		progV4FullNATForward: coll.Programs[kernelXDPProgramV4FullNATForwardName],
		progV4FullNATReply:   coll.Programs[kernelXDPProgramV4FullNATReplyName],
		progV6FullNATForward: coll.Programs[kernelXDPProgramV6FullNATForwardName],
		progV6FullNATReply:   coll.Programs[kernelXDPProgramV6FullNATReplyName],
		redirectMap:          coll.Maps[kernelXDPRedirectMapName],
		progChain:            coll.Maps[kernelXDPProgramChainMapName],
		rulesV4:              coll.Maps[kernelRulesMapNameV4],
		rulesV6:              coll.Maps[kernelRulesMapNameV6],
		flowsV4:              coll.Maps[kernelFlowsMapNameV4],
		flowsV6:              coll.Maps[kernelFlowsMapNameV6],
		flowsOldV4:           coll.Maps[kernelXDPFlowsOldMapNameV4],
		flowsOldV6:           coll.Maps[kernelXDPFlowsOldMapNameV6],
		natV4:                coll.Maps[kernelNatPortsMapNameV4],
		natV6:                coll.Maps[kernelNatPortsMapNameV6],
		natConfigV4:          coll.Maps[kernelNATConfigMapName],
		natOldV4:             coll.Maps[kernelTCNatPortsOldMapNameV4],
		natOldV6:             coll.Maps[kernelTCNatPortsOldMapNameV6],
		flowMigrationState:   coll.Maps[kernelXDPFlowMigrationStateMapName],
		localIPv4s:           coll.Maps[kernelLocalIPv4MapName],
	}
	if pieces.prog == nil ||
		pieces.progV4 == nil ||
		pieces.progV6 == nil ||
		pieces.progV4Transparent == nil ||
		pieces.progV4FullNATForward == nil ||
		pieces.progV4FullNATReply == nil ||
		pieces.progV6FullNATForward == nil ||
		pieces.progV6FullNATReply == nil ||
		pieces.redirectMap == nil ||
		pieces.progChain == nil ||
		pieces.rulesV4 == nil ||
		pieces.flowsV4 == nil ||
		pieces.natV4 == nil ||
		pieces.natConfigV4 == nil ||
		pieces.flowsOldV4 == nil ||
		pieces.natOldV4 == nil ||
		pieces.flowMigrationState == nil {
		return xdpCollectionPieces{}, fmt.Errorf("xdp object is missing required program or maps")
	}
	if pieces.rulesV6 == nil || pieces.flowsV6 == nil || pieces.natV6 == nil || pieces.flowsOldV6 == nil || pieces.natOldV6 == nil {
		return xdpCollectionPieces{}, fmt.Errorf("xdp object has incomplete IPv6 map set")
	}
	return pieces, nil
}

func configureXDPProgramChain(pieces xdpCollectionPieces) error {
	if pieces.progChain == nil ||
		pieces.progV4 == nil ||
		pieces.progV6 == nil ||
		pieces.progV4Transparent == nil ||
		pieces.progV4FullNATForward == nil ||
		pieces.progV4FullNATReply == nil ||
		pieces.progV6FullNATForward == nil ||
		pieces.progV6FullNATReply == nil {
		return fmt.Errorf("xdp object is missing program chain pieces")
	}
	if err := pieces.progChain.Put(uint32(xdpProgramChainIndexV4), uint32(pieces.progV4.FD())); err != nil {
		return fmt.Errorf("install xdp IPv4 tail-call target: %w", err)
	}
	if err := pieces.progChain.Put(uint32(xdpProgramChainIndexV6), uint32(pieces.progV6.FD())); err != nil {
		return fmt.Errorf("install xdp IPv6 tail-call target: %w", err)
	}
	if err := pieces.progChain.Put(uint32(xdpProgramChainIndexV4Transparent), uint32(pieces.progV4Transparent.FD())); err != nil {
		return fmt.Errorf("install xdp IPv4 transparent tail-call target: %w", err)
	}
	if err := pieces.progChain.Put(uint32(xdpProgramChainIndexV4FullNATForward), uint32(pieces.progV4FullNATForward.FD())); err != nil {
		return fmt.Errorf("install xdp IPv4 full-nat forward tail-call target: %w", err)
	}
	if err := pieces.progChain.Put(uint32(xdpProgramChainIndexV4FullNATReply), uint32(pieces.progV4FullNATReply.FD())); err != nil {
		return fmt.Errorf("install xdp IPv4 full-nat reply tail-call target: %w", err)
	}
	if err := pieces.progChain.Put(uint32(xdpProgramChainIndexV6FullNATForward), uint32(pieces.progV6FullNATForward.FD())); err != nil {
		return fmt.Errorf("install xdp IPv6 full-nat forward tail-call target: %w", err)
	}
	if err := pieces.progChain.Put(uint32(xdpProgramChainIndexV6FullNATReply), uint32(pieces.progV6FullNATReply.FD())); err != nil {
		return fmt.Errorf("install xdp IPv6 full-nat reply tail-call target: %w", err)
	}
	return nil
}

func configureXDPFlowMigrationState(pieces xdpCollectionPieces, flags uint32) error {
	if pieces.flowMigrationState == nil {
		return fmt.Errorf("xdp object is missing flow migration state map")
	}
	key := uint32(0)
	if err := pieces.flowMigrationState.Put(key, flags); err != nil {
		return fmt.Errorf("update xdp flow migration state: %w", err)
	}
	return nil
}

func xdpEffectiveOldFlowMigrationFlagsFromCollection(coll *ebpf.Collection) (uint32, error) {
	if coll == nil || coll.Maps == nil {
		return 0, nil
	}
	return xdpEffectiveOldFlowMigrationFlagsFromRuntimeMapRefs(kernelRuntimeMapRefsFromCollection(coll))
}

func xdpEffectiveOldFlowMigrationFlagsFromRuntimeMapRefs(refs kernelRuntimeMapRefs) (uint32, error) {
	flags, ok, err := lookupKernelFlowMigrationStateFlags(refs.xdpFlowMigrationState)
	if err != nil {
		return 0, fmt.Errorf("lookup xdp flow migration state: %w", err)
	}
	if ok {
		return flags & (xdpFlowMigrationFlagV4Old | xdpFlowMigrationFlagV6Old), nil
	}
	return xdpOldFlowMigrationFlagsFromRuntimeMapRefs(refs)
}

func xdpOldFlowMigrationFlagsFromCollection(coll *ebpf.Collection) (uint32, error) {
	if coll == nil || coll.Maps == nil {
		return 0, nil
	}
	var flags uint32
	if m := coll.Maps[kernelXDPFlowsOldMapNameV4]; m != nil {
		count, err := countXDPFlowMapEntries(m)
		if err != nil {
			return 0, fmt.Errorf("count old xdp IPv4 flows: %w", err)
		}
		if count > 0 {
			flags |= xdpFlowMigrationFlagV4Old
		}
	}
	if m := coll.Maps[kernelXDPFlowsOldMapNameV6]; m != nil {
		count, err := countKernelFlowMapEntriesV6(m)
		if err != nil {
			return 0, fmt.Errorf("count old xdp IPv6 flows: %w", err)
		}
		if count > 0 {
			flags |= xdpFlowMigrationFlagV6Old
		}
	}
	return flags, nil
}

func xdpOldFlowMigrationFlagsFromRuntimeMapRefs(refs kernelRuntimeMapRefs) (uint32, error) {
	var flags uint32
	if refs.flowsOldV4 != nil {
		count, err := countXDPFlowMapEntries(refs.flowsOldV4)
		if err != nil {
			return 0, fmt.Errorf("count old xdp IPv4 flows: %w", err)
		}
		if count > 0 {
			flags |= xdpFlowMigrationFlagV4Old
		}
	}
	if refs.flowsOldV6 != nil {
		count, err := countKernelFlowMapEntriesV6(refs.flowsOldV6)
		if err != nil {
			return 0, fmt.Errorf("count old xdp IPv6 flows: %w", err)
		}
		if count > 0 {
			flags |= xdpFlowMigrationFlagV6Old
		}
	}
	return flags, nil
}

func xdpPreparedRuleFamily(item preparedXDPKernelRule) string {
	if item.spec.Family != "" {
		return normalizedKernelPreparedRuleFamily(item.spec.Family)
	}
	if family := ipLiteralFamily(item.rule.InIP); family != "" {
		return normalizedKernelPreparedRuleFamily(family)
	}
	if family := ipLiteralFamily(item.rule.OutIP); family != "" {
		return normalizedKernelPreparedRuleFamily(family)
	}
	return ipFamilyIPv4
}

func preparedXDPKernelRulesNeedFullConeNATMap(prepared []preparedXDPKernelRule) bool {
	for _, item := range prepared {
		switch xdpPreparedRuleFamily(item) {
		case ipFamilyIPv6:
			if item.valueV6.Flags&xdpRuleFlagFullNAT != 0 {
				return true
			}
		default:
			if item.valueV4.Flags&xdpRuleFlagFullCone != 0 {
				return true
			}
		}
	}
	return false
}

func xdpRuntimeNATStateForDecision(prepared []preparedXDPKernelRule, refs kernelRuntimeMapRefs, counts kernelRuntimeMapCountSnapshot, context string) (kernelRuntimeMapCountSnapshot, bool) {
	counts.natEntries = xdpExactNATEntriesForPreservation(refs, counts.natEntries, context)
	return counts, preparedXDPKernelRulesNeedFullConeNATMap(prepared) || counts.natEntries > 0
}

func xdpExactNATEntriesForPreservation(refs kernelRuntimeMapRefs, fallback int, context string) int {
	if fallback > 0 {
		return fallback
	}
	count, err := countKernelRuntimeNATEntriesExact(refs)
	if err != nil {
		log.Printf("%s: exact nat entry count failed, using cached nat count=%d: %v", context, fallback, err)
		return fallback
	}
	if count > fallback {
		log.Printf("%s: nat entry cache stale, preserving exact nat state entries=%d", context, count)
	}
	return count
}

func buildPreparedXDPKernelRuleBatches(prepared []preparedXDPKernelRule) (preparedXDPKernelRuleBatches, error) {
	batches := preparedXDPKernelRuleBatches{
		v4Keys:   make([]tcRuleKeyV4, 0, len(prepared)),
		v4Values: make([]xdpRuleValueV4, 0, len(prepared)),
		v6Keys:   make([]tcRuleKeyV6, 0, len(prepared)),
		v6Values: make([]xdpRuleValueV6, 0, len(prepared)),
	}
	for _, item := range prepared {
		switch xdpPreparedRuleFamily(item) {
		case ipFamilyIPv6:
			batches.v6Keys = append(batches.v6Keys, item.keyV6)
			batches.v6Values = append(batches.v6Values, item.valueV6)
		default:
			batches.v4Keys = append(batches.v4Keys, item.keyV4)
			batches.v4Values = append(batches.v4Values, item.valueV4)
		}
	}
	return batches, nil
}

func syncPreparedXDPKernelRuleMaps(pieces xdpCollectionPieces, prepared []preparedXDPKernelRule) error {
	batches, err := buildPreparedXDPKernelRuleBatches(prepared)
	if err != nil {
		return err
	}
	if err := updateKernelMapEntries(pieces.rulesV4, batches.v4Keys, batches.v4Values); err != nil {
		return fmt.Errorf("update IPv4 xdp rule map: %w", err)
	}
	if err := updateKernelMapEntries(pieces.rulesV6, batches.v6Keys, batches.v6Values); err != nil {
		return fmt.Errorf("update IPv6 xdp rule map: %w", err)
	}
	return nil
}

func syncXDPRedirectMap(m *ebpf.Map, requiredIfIndices []int) error {
	if m == nil {
		return fmt.Errorf("xdp redirect map is nil")
	}

	desired := make(map[uint32]uint32, len(requiredIfIndices))
	for _, ifindex := range requiredIfIndices {
		if ifindex <= 0 {
			continue
		}
		desired[uint32(ifindex)] = uint32(ifindex)
	}

	existing := make(map[uint32]uint32)
	iter := m.Iterate()
	var key uint32
	var value uint32
	for iter.Next(&key, &value) {
		existing[key] = value
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate xdp redirect map: %w", err)
	}

	for ifindex, target := range desired {
		if current, ok := existing[ifindex]; ok && current == target {
			delete(existing, ifindex)
			continue
		}
		if err := m.Put(ifindex, target); err != nil {
			return fmt.Errorf("update xdp redirect map entry %d=>%d: %w", ifindex, target, err)
		}
		delete(existing, ifindex)
	}
	for ifindex := range existing {
		if err := m.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale xdp redirect map entry %d: %w", ifindex, err)
		}
	}
	return nil
}

func deletePreparedXDPKernelRuleMapEntry(pieces xdpCollectionPieces, item preparedXDPKernelRule) error {
	switch xdpPreparedRuleFamily(item) {
	case ipFamilyIPv6:
		return deleteKernelMapEntry(pieces.rulesV6, item.keyV6)
	default:
		return deleteKernelMapEntry(pieces.rulesV4, item.keyV4)
	}
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

func xdpGenericAttachmentExperimentalReason() string {
	return fmt.Sprintf("xdp dataplane generic/mixed attachment requires experimental feature %q", experimentalFeatureXDPGeneric)
}

func xdpAttachOrder(link netlink.Link, oldAttachments []xdpAttachment, allowGeneric bool) []int {
	if !allowGeneric {
		return []int{nl.XDP_FLAGS_DRV_MODE}
	}
	preferred := []int{nl.XDP_FLAGS_DRV_MODE, nl.XDP_FLAGS_SKB_MODE}
	if xdpPreferGenericAttach(link) {
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

func xdpCollectionProgram(coll *ebpf.Collection) *ebpf.Program {
	if coll == nil || coll.Programs == nil {
		return nil
	}
	return coll.Programs[kernelXDPProgramName]
}

func xdpModeSwitchAttachment(oldAttachments []xdpAttachment, ifindex int, attachOrder []int) (xdpAttachment, bool) {
	for _, att := range oldAttachments {
		if att.ifindex != ifindex {
			continue
		}
		for _, flags := range attachOrder {
			if xdpAttachModeEqual(att.flags, flags) {
				return xdpAttachment{}, false
			}
		}
		return att, true
	}
	return xdpAttachment{}, false
}

func xdpAttachModeEqual(a int, b int) bool {
	modeMask := nl.XDP_FLAGS_DRV_MODE | nl.XDP_FLAGS_SKB_MODE
	return (a & modeMask) == (b & modeMask)
}

func xdpPreferGenericAttach(link netlink.Link) bool {
	if link == nil || link.Attrs() == nil {
		return false
	}
	// veth native XDP devmap redirects are still inconsistent across kernels;
	// prefer skb mode when available so direct NAT test topologies remain viable.
	if strings.EqualFold(strings.TrimSpace(link.Type()), "veth") {
		return true
	}
	return link.Attrs().MasterIndex > 0
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
	modeMask := uint32(nl.XDP_FLAGS_DRV_MODE | nl.XDP_FLAGS_SKB_MODE)
	observedMode := attrs.Xdp.Flags & modeMask
	if observedMode == 0 {
		switch attrs.Xdp.AttachMode {
		case nl.XDP_ATTACHED_DRV:
			observedMode = uint32(nl.XDP_FLAGS_DRV_MODE)
		case nl.XDP_ATTACHED_SKB:
			observedMode = uint32(nl.XDP_FLAGS_SKB_MODE)
		}
	}
	if observedMode != (uint32(att.flags) & modeMask) {
		return false
	}
	if programID == 0 || attrs.Xdp.ProgId == programID {
		return true
	}
	return xdpQueryProgramAttached(att.ifindex, programID)
}

func xdpQueryProgramAttached(ifindex int, programID uint32) bool {
	if ifindex <= 0 || programID == 0 {
		return false
	}
	result, err := ebpflink.QueryPrograms(ebpflink.QueryOptions{
		Target: ifindex,
		Attach: ebpf.AttachXDP,
	})
	if err != nil {
		return false
	}
	for _, prog := range result.Programs {
		if uint32(prog.ID) == programID {
			return true
		}
	}
	return false
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
	return prepareXDPKernelRuleRef(&rule, opts)
}

func prepareXDPKernelRuleRef(rule *Rule, opts xdpPrepareOptions) ([]preparedXDPKernelRule, error) {
	if rule == nil {
		return nil, fmt.Errorf("xdp dataplane requires a rule")
	}
	if rule.ID <= 0 || rule.ID > int64(^uint32(0)) {
		return nil, fmt.Errorf("xdp dataplane requires a rule id in uint32 range")
	}
	inLink, err := netlink.LinkByName(rule.InInterface)
	if err != nil {
		return nil, fmt.Errorf("resolve inbound interface %q: %w", rule.InInterface, err)
	}

	outLink, err := netlink.LinkByName(rule.OutInterface)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound interface %q: %w", rule.OutInterface, err)
	}

	if isKernelEgressNATRule(*rule) {
		return prepareXDPEgressNATRule(*rule, opts, inLink, outLink)
	}
	if !kernelProtocolSupported(rule.Protocol) {
		return nil, fmt.Errorf("xdp dataplane currently supports only single-protocol TCP/UDP rules")
	}
	if !rule.Transparent {
		if reason := xdpVethNATRedirectGuardReason(inLink, outLink); reason != "" {
			return nil, errors.New(reason)
		}
	}

	spec, err := buildKernelPreparedForwardRuleSpec(*rule, func(family string) (net.IP, error) {
		if rule.Transparent {
			return nil, nil
		}
		if family == ipFamilyIPv6 {
			natIP, resolveErr := resolveKernelSNATIPv6(outLink, rule.OutIP, rule.OutSourceIP)
			if resolveErr != nil {
				return nil, fmt.Errorf("resolve outbound source ip on %q: %w", rule.OutInterface, resolveErr)
			}
			return natIP, nil
		}
		natAddr, resolveErr := resolveKernelSNATIPv4(outLink, rule.OutIP, rule.OutSourceIP)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve outbound source ip on %q: %w", rule.OutInterface, resolveErr)
		}
		return net.IPv4(
			byte(natAddr>>24),
			byte(natAddr>>16),
			byte(natAddr>>8),
			byte(natAddr),
		), nil
	})
	if err != nil {
		return nil, err
	}

	valueV4 := xdpRuleValueV4{
		RuleID:      uint32(rule.ID),
		BackendPort: uint16(rule.OutPort),
	}
	valueV6 := xdpRuleValueV6{
		RuleID:      uint32(rule.ID),
		BackendPort: uint16(rule.OutPort),
	}
	switch spec.Family {
	case ipFamilyIPv6:
		valueV6.BackendAddr = spec.BackendAddr
		if !rule.Transparent {
			valueV6.Flags |= xdpRuleFlagFullNAT
			valueV6.NATAddr = spec.NATAddr
		}
	default:
		outAddr, convErr := spec.BackendAddr.ipv4Uint32()
		if convErr != nil {
			return nil, fmt.Errorf("prepare outbound IPv4 address: %w", convErr)
		}
		valueV4.BackendAddr = outAddr
		if !rule.Transparent {
			natAddr, convErr := spec.NATAddr.ipv4Uint32()
			if convErr != nil {
				return nil, fmt.Errorf("prepare outbound source IPv4 address: %w", convErr)
			}
			valueV4.Flags |= xdpRuleFlagFullNAT
			valueV4.NATAddr = natAddr
		}
	}
	if opts.enableTrafficStats {
		valueV4.Flags |= xdpRuleFlagTrafficStats
		valueV6.Flags |= xdpRuleFlagTrafficStats
	}
	outIfIndex := 0

	if xdpLinkTypeAllowed(outLink.Type()) {
		if spec.Family == ipFamilyIPv6 && !xdpPreparedL2LinkTypeAllowed(outLink.Type()) {
			return nil, fmt.Errorf("xdp dataplane IPv6 currently supports only veth outbound interfaces")
		}
		outIfIndex = outLink.Attrs().Index
		if xdpPreparedL2LinkTypeAllowed(outLink.Type()) {
			target, err := resolveXDPDirectTarget(outLink, *rule, spec.Family)
			if err != nil {
				return nil, err
			}
			outIfIndex = target.outIfIndex
			valueV4.Flags |= xdpRuleFlagPreparedL2
			valueV4.SrcMAC = target.srcMAC
			valueV4.DstMAC = target.dstMAC
			valueV6.Flags |= xdpRuleFlagPreparedL2
			valueV6.SrcMAC = target.srcMAC
			valueV6.DstMAC = target.dstMAC
		} else {
			if err := validateXDPDirectTarget(outLink, *rule, spec.Family); err != nil {
				return nil, err
			}
		}
	} else {
		target, err := resolveXDPBridgeTarget(outLink, *rule, opts)
		if err != nil {
			return nil, err
		}
		outIfIndex = target.outIfIndex
		valueV4.Flags |= xdpRuleFlagBridgeL2
		valueV4.SrcMAC = target.srcMAC
		valueV4.DstMAC = target.dstMAC
		valueV6.Flags |= xdpRuleFlagBridgeL2
		valueV6.SrcMAC = target.srcMAC
		valueV6.DstMAC = target.dstMAC
	}
	valueV4.OutIfIndex = uint32(outIfIndex)
	valueV6.OutIfIndex = uint32(outIfIndex)

	inLinks, err := resolveXDPInboundLinks(inLink, *rule, opts)
	if err != nil {
		return nil, err
	}
	prepared := make([]preparedXDPKernelRule, 0, len(inLinks))
	for _, currentInLink := range inLinks {
		if currentInLink == nil || currentInLink.Attrs() == nil {
			continue
		}
		item := preparedXDPKernelRule{
			rule:       *rule,
			inIfIndex:  currentInLink.Attrs().Index,
			outIfIndex: outIfIndex,
			spec:       spec,
		}
		switch spec.Family {
		case ipFamilyIPv6:
			item.keyV6 = tcRuleKeyV6{
				IfIndex: uint32(currentInLink.Attrs().Index),
				DstAddr: spec.DstAddr,
				DstPort: uint16(rule.InPort),
				Proto:   kernelRuleProtocol(rule.Protocol),
			}
			item.valueV6 = valueV6
		default:
			inAddr, convErr := spec.DstAddr.ipv4Uint32()
			if convErr != nil {
				return nil, fmt.Errorf("prepare inbound IPv4 address: %w", convErr)
			}
			item.keyV4 = tcRuleKeyV4{
				IfIndex: uint32(currentInLink.Attrs().Index),
				DstAddr: inAddr,
				DstPort: uint16(rule.InPort),
				Proto:   kernelRuleProtocol(rule.Protocol),
			}
			item.valueV4 = valueV4
		}
		prepared = append(prepared, item)
	}
	if len(prepared) == 0 {
		return nil, fmt.Errorf("xdp dataplane bridge ingress expansion produced no attachable member interfaces")
	}
	return prepared, nil
}

func prepareXDPEgressNATRule(rule Rule, opts xdpPrepareOptions, inLink netlink.Link, outLink netlink.Link) ([]preparedXDPKernelRule, error) {
	inAddr, err := parseKernelInboundIPv4Uint32(rule.InIP)
	if err != nil {
		return nil, fmt.Errorf("parse inbound ip %q: %w", rule.InIP, err)
	}
	if inAddr != 0 {
		return nil, fmt.Errorf("xdp dataplane egress nat takeover requires wildcard inbound IPv4 0.0.0.0")
	}
	if rule.InPort != 0 || rule.OutPort != 0 {
		return nil, fmt.Errorf("xdp dataplane egress nat takeover requires wildcard inbound port/identifier matching")
	}
	if rule.Transparent {
		return nil, fmt.Errorf("xdp dataplane egress nat takeover does not support transparent mode")
	}
	if !kernelEgressProtocolSupported(rule.Protocol) {
		return nil, fmt.Errorf("xdp dataplane currently supports only single-protocol TCP/UDP/ICMP egress nat rules")
	}
	natType := normalizeEgressNATType(rule.kernelNATType)
	if natType != egressNATTypeSymmetric && natType != egressNATTypeFullCone {
		return nil, fmt.Errorf("xdp dataplane currently supports only symmetric or full-cone egress nat takeover")
	}
	if outLink == nil || outLink.Attrs() == nil || outLink.Attrs().Index <= 0 {
		return nil, fmt.Errorf("resolve outbound interface %q: invalid link", rule.OutInterface)
	}
	if !xdpLinkTypeAllowed(outLink.Type()) {
		return nil, fmt.Errorf("xdp dataplane egress nat takeover currently supports only native-capable outbound interfaces (device/veth); got %q", outLink.Type())
	}
	if reason := xdpUnsupportedEgressNATInboundReason(inLink); reason != "" {
		return nil, errors.New(reason)
	}
	if reason := xdpVethNATRedirectGuardReason(inLink, outLink); reason != "" {
		return nil, errors.New(reason)
	}

	inLinks, err := resolveXDPInboundLinks(inLink, rule, opts)
	if err != nil {
		return nil, err
	}
	natAddr, err := resolveKernelEgressSNATIPv4(outLink, rule.OutSourceIP)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound nat ip on %q: %w", rule.OutInterface, err)
	}

	flags := uint16(xdpRuleFlagFullNAT | xdpRuleFlagEgressNAT)
	if natType == egressNATTypeFullCone {
		flags |= xdpRuleFlagFullCone
	}
	if opts.enableTrafficStats {
		flags |= xdpRuleFlagTrafficStats
	}
	outIfIndex := outLink.Attrs().Index
	var srcMAC [6]byte
	var dstMAC [6]byte
	// Egress NAT destinations are dynamic, so precomputing a single L2 next hop
	// is fragile even on veth-backed test topologies. Keep the redirect on the
	// FIB path and let the dataplane resolve the current destination per packet.
	spec := kernelPreparedRuleSpec{
		Family:  ipFamilyIPv4,
		NATAddr: kernelPreparedAddrFromIPv4Uint32(natAddr),
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
			spec:       spec,
			keyV4: tcRuleKeyV4{
				IfIndex: uint32(currentInLink.Attrs().Index),
				DstAddr: 0,
				DstPort: 0,
				Proto:   kernelRuleProtocol(rule.Protocol),
			},
			valueV4: xdpRuleValueV4{
				RuleID:     uint32(rule.ID),
				Flags:      flags,
				OutIfIndex: uint32(outIfIndex),
				NATAddr:    natAddr,
				SrcMAC:     srcMAC,
				DstMAC:     dstMAC,
			},
		})
	}
	if len(prepared) == 0 {
		return nil, fmt.Errorf("xdp dataplane bridge ingress expansion produced no attachable member interfaces")
	}
	return prepared, nil
}

func xdpUnsupportedEgressNATInboundReason(inLink netlink.Link) string {
	if inLink == nil || inLink.Attrs() == nil {
		return ""
	}
	if inLink.Attrs().MasterIndex > 0 {
		return "xdp dataplane egress nat takeover does not support bridge-enslaved inbound interfaces; use tc for managed-network bridge members"
	}
	return ""
}

func xdpVethNATRedirectGuardReason(inLink netlink.Link, outLink netlink.Link) string {
	if !xdpLinkIsVeth(inLink) && !xdpLinkIsVeth(outLink) {
		return ""
	}
	return xdpVethNATRedirectGuardReasonForRelease(kernelRelease())
}

func xdpVethNATRedirectGuardReasonForRelease(release string) string {
	major, minor, ok := parseKernelReleaseMajorMinor(release)
	if !ok {
		return ""
	}
	if major > xdpVethNATRedirectMinKernelMajor || (major == xdpVethNATRedirectMinKernelMajor && minor >= xdpVethNATRedirectMinKernelMinor) {
		return ""
	}
	return fmt.Sprintf(
		"xdp dataplane nat redirect over veth is disabled on %s; use tc or upgrade to kernel %d.%d+",
		release,
		xdpVethNATRedirectMinKernelMajor,
		xdpVethNATRedirectMinKernelMinor,
	)
}

func parseKernelReleaseMajorMinor(release string) (major int, minor int, ok bool) {
	release = strings.TrimSpace(release)
	if release == "" {
		return 0, 0, false
	}
	firstDot := strings.IndexByte(release, '.')
	if firstDot <= 0 {
		return 0, 0, false
	}
	majorValue, err := strconv.Atoi(release[:firstDot])
	if err != nil {
		return 0, 0, false
	}
	rest := release[firstDot+1:]
	minorDigits := 0
	for minorDigits < len(rest) && rest[minorDigits] >= '0' && rest[minorDigits] <= '9' {
		minorDigits++
	}
	if minorDigits == 0 {
		return 0, 0, false
	}
	minorValue, err := strconv.Atoi(rest[:minorDigits])
	if err != nil {
		return 0, 0, false
	}
	return majorValue, minorValue, true
}

func xdpLinkIsVeth(link netlink.Link) bool {
	if link == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(link.Type()), "veth")
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
		if a.inIfIndex != b.inIfIndex {
			return a.inIfIndex < b.inIfIndex
		}
		if a.outIfIndex != b.outIfIndex {
			return a.outIfIndex < b.outIfIndex
		}
		if aFamily, bFamily := xdpPreparedRuleFamily(a), xdpPreparedRuleFamily(b); aFamily != bFamily {
			return aFamily < bFamily
		}
		if cmp := compareKernelPreparedAddr(a.spec.DstAddr, b.spec.DstAddr); cmp != 0 {
			return cmp < 0
		}
		if a.rule.InPort != b.rule.InPort {
			return a.rule.InPort < b.rule.InPort
		}
		if aProto, bProto := kernelRuleProtocol(a.rule.Protocol), kernelRuleProtocol(b.rule.Protocol); aProto != bProto {
			return aProto < bProto
		}
		if cmp := compareKernelPreparedAddr(a.spec.BackendAddr, b.spec.BackendAddr); cmp != 0 {
			return cmp < 0
		}
		if a.rule.OutPort != b.rule.OutPort {
			return a.rule.OutPort < b.rule.OutPort
		}
		switch xdpPreparedRuleFamily(a) {
		case ipFamilyIPv6:
			if a.valueV6.Flags != b.valueV6.Flags {
				return a.valueV6.Flags < b.valueV6.Flags
			}
			if a.valueV6.OutIfIndex != b.valueV6.OutIfIndex {
				return a.valueV6.OutIfIndex < b.valueV6.OutIfIndex
			}
			if cmp := compareKernelPreparedAddr(kernelPreparedAddr(a.valueV6.NATAddr), kernelPreparedAddr(b.valueV6.NATAddr)); cmp != 0 {
				return cmp < 0
			}
			if a.valueV6.SrcMAC != b.valueV6.SrcMAC {
				return string(a.valueV6.SrcMAC[:]) < string(b.valueV6.SrcMAC[:])
			}
			if a.valueV6.DstMAC != b.valueV6.DstMAC {
				return string(a.valueV6.DstMAC[:]) < string(b.valueV6.DstMAC[:])
			}
		default:
			if a.valueV4.Flags != b.valueV4.Flags {
				return a.valueV4.Flags < b.valueV4.Flags
			}
			if a.valueV4.OutIfIndex != b.valueV4.OutIfIndex {
				return a.valueV4.OutIfIndex < b.valueV4.OutIfIndex
			}
			if a.valueV4.NATAddr != b.valueV4.NATAddr {
				return a.valueV4.NATAddr < b.valueV4.NATAddr
			}
			if a.valueV4.SrcMAC != b.valueV4.SrcMAC {
				return string(a.valueV4.SrcMAC[:]) < string(b.valueV4.SrcMAC[:])
			}
			if a.valueV4.DstMAC != b.valueV4.DstMAC {
				return string(a.valueV4.DstMAC[:]) < string(b.valueV4.DstMAC[:])
			}
		}
		return a.rule.ID < b.rule.ID
	})
}

func snapshotPreparedXDPBridgeEntries(prepared []preparedXDPKernelRule) map[string]struct{} {
	lines := make(map[string]struct{})
	for _, item := range prepared {
		flags := item.valueV4.Flags
		srcMAC := item.valueV4.SrcMAC
		dstMAC := item.valueV4.DstMAC
		backendPort := item.valueV4.BackendPort
		if xdpPreparedRuleFamily(item) == ipFamilyIPv6 {
			flags = item.valueV6.Flags
			srcMAC = item.valueV6.SrcMAC
			dstMAC = item.valueV6.DstMAC
			backendPort = item.valueV6.BackendPort
		}
		if flags&(xdpRuleFlagBridgeL2|xdpRuleFlagBridgeIngressL2|xdpRuleFlagPreparedL2) == 0 {
			continue
		}
		line := fmt.Sprintf(
			"xdp dataplane %s l2 plan: in_if=%s out_if=%s ingress_bridge=%t egress_bridge=%t prepared_l2=%t backend=%s:%d src_mac=%s dst_mac=%s",
			kernelRuleLogLabel(item.rule),
			xdpInterfaceLabel(item.inIfIndex),
			xdpInterfaceLabel(item.outIfIndex),
			(flags&xdpRuleFlagBridgeIngressL2) != 0,
			(flags&xdpRuleFlagBridgeL2) != 0,
			(flags&xdpRuleFlagPreparedL2) != 0,
			formatXDPPreparedAddr(item.spec.BackendAddr, xdpPreparedRuleFamily(item)),
			backendPort,
			formatXDPMAC(srcMAC),
			formatXDPMAC(dstMAC),
		)
		lines[line] = struct{}{}
	}
	return lines
}

func formatXDPPreparedAddr(addr kernelPreparedAddr, family string) string {
	if family == ipFamilyIPv6 {
		return canonicalIPLiteral(net.IP(addr[:]))
	}
	return canonicalIPLiteral(net.IP(addr[12:16]))
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
