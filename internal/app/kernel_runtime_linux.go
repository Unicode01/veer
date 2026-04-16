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
	kernelForwardProgramName                = "forward_ingress"
	kernelReplyProgramName                  = "reply_ingress"
	kernelForwardProgramNameV6              = "forward_ingress_v6"
	kernelReplyProgramNameV6                = "reply_ingress_v6"
	kernelForwardDispatchProgramName        = "forward_ingress_dispatch"
	kernelForwardTransparentProgramName     = "forward_ingress_v4_transparent"
	kernelForwardFullNATProgramName         = "forward_ingress_v4_fullnat"
	kernelForwardFullNATExistingProgramName = "forward_ingress_v4_fullnat_existing"
	kernelForwardFullNATNewProgramName      = "forward_ingress_v4_fullnat_new"
	kernelForwardEgressNATProgramName       = "forward_ingress_v4_egress_nat"
	kernelReplyDispatchProgramName          = "reply_ingress_dispatch"
	kernelReplyTransparentProgramName       = "reply_ingress_v4_transparent"
	kernelReplyFullNATProgramName           = "reply_ingress_v4_fullnat"
	kernelRulesMapName                      = kernelRulesMapNameV4
	kernelFlowsMapName                      = kernelFlowsMapNameV4
	kernelNatPortsMapName                   = kernelNatPortsMapNameV4
	kernelIfParentMapName                   = "if_parent_v4"
	kernelLocalIPv4MapName                  = "local_ipv4s_v4"
	kernelEgressWildcardFastMapName         = "egress_wildcard_fast_v4"
	kernelNATConfigMapName                  = "nat_config_v4"
	kernelStatsMapName                      = "stats_v4"
	kernelDiagMapName                       = "diag_v4"
	kernelOccupancyMapName                  = "occupancy_v4"
	kernelTCProgramChainMapName             = "tc_prog_chain_v4"
	kernelTCFlowsOldMapNameV4               = "flows_old_v4"
	kernelTCFlowsOldMapNameV6               = "flows_old_v6"
	kernelTCNatPortsOldMapNameV4            = "nat_ports_old_v4"
	kernelTCNatPortsOldMapNameV6            = "nat_ports_old_v6"
	kernelTCFlowMigrationStateMapName       = "tc_flow_migration_state"
	kernelReplyFilterPrio                   = 10
	kernelReplyFilterPrioV6                 = 11
	kernelForwardFilterPrio                 = 20
	kernelForwardFilterPrioV6               = 21
	kernelForwardFilterHandle               = 10
	kernelForwardFilterHandleV6             = 11
	kernelReplyFilterHandle                 = 20
	kernelReplyFilterHandleV6               = 21
	kernelVerifierLogSize                   = 4 * 1024 * 1024
	kernelTCPClosingGraceNS                 = 15 * 1000000000
	kernelTCPUnrepliedTimeout               = 30 * 1000000000
	kernelTCPFlowIdleTimeout                = 10 * 60 * 1000000000
	kernelICMPFlowIdleTimeout               = 30 * 1000000000
	kernelUDPFlowIdleTimeout                = 300 * 1000000000
	kernelOrphanNATPruneLogEvery            = 10 * time.Minute
	tcProgramChainIndexV4Transparent        = 0
	tcProgramChainIndexV4FullNATForward     = 1
	tcProgramChainIndexV4EgressNATForward   = 2
	tcProgramChainIndexV4ReplyTransparent   = 3
	tcProgramChainIndexV4ReplyFullNAT       = 4
	tcProgramChainIndexV4FullNATExisting    = 5
	tcProgramChainIndexV4FullNATNew         = 6
)

const (
	kernelFlowFlagFrontClosing = 0x1
	kernelFlowFlagReplySeen    = 0x2
	kernelFlowFlagFullNAT      = 0x4
	kernelFlowFlagFrontEntry   = 0x8
	kernelFlowFlagEgressNAT    = 0x10
	kernelFlowFlagCounted      = 0x20
	kernelFlowFlagFullCone     = 0x80
)

const (
	kernelRuleFlagFullNAT      = 0x1
	kernelRuleFlagBridgeL2     = 0x2
	kernelRuleFlagTrafficStats = 0x4
	kernelRuleFlagEgressNAT    = 0x8
	kernelRuleFlagPassthrough  = 0x10
	kernelRuleFlagFullCone     = 0x20
)

const (
	tcFlowMigrationFlagV4Old = 0x1
	tcFlowMigrationFlagV6Old = 0x2
)

type kernelTCAttachmentProgramMode string

const (
	kernelTCAttachmentProgramModeLegacy     kernelTCAttachmentProgramMode = "legacy"
	kernelTCAttachmentProgramModeDispatchV4 kernelTCAttachmentProgramMode = "dispatch_v4"
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

type tcNATConfigValueV4 struct {
	PortMin uint32
	PortMax uint32
	Pad0    uint32
	Pad1    uint32
}

type tcEgressWildcardKeyV4 = tcRuleKeyV4

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

type kernelRuleMapEntryV6 struct {
	key   tcRuleKeyV6
	value tcRuleValueV6
}

type kernelRuleMapDiffV6 struct {
	upserts []kernelRuleMapEntryV6
	deletes []tcRuleKeyV6
}

type kernelRuleMapSnapshotV6 struct {
	key    tcRuleKeyV6
	value  tcRuleValueV6
	exists bool
}

type kernelDualStackRuleMapDiff struct {
	v4 kernelRuleMapDiff
	v6 kernelRuleMapDiffV6
}

type kernelCollectionPieces struct {
	forwardProg                *ebpf.Program
	replyProg                  *ebpf.Program
	forwardProgV6              *ebpf.Program
	replyProgV6                *ebpf.Program
	forwardDispatchProg        *ebpf.Program
	forwardTransparentProg     *ebpf.Program
	forwardFullNATProg         *ebpf.Program
	forwardFullNATExistingProg *ebpf.Program
	forwardFullNATNewProg      *ebpf.Program
	forwardEgressNATProg       *ebpf.Program
	replyDispatchProg          *ebpf.Program
	replyTransparentProg       *ebpf.Program
	replyFullNATProg           *ebpf.Program
	progChainV4                *ebpf.Map
	rulesV4                    *ebpf.Map
	rulesV6                    *ebpf.Map
	flowsV4                    *ebpf.Map
	flowsV6                    *ebpf.Map
	flowsOldV4                 *ebpf.Map
	flowsOldV6                 *ebpf.Map
	natV4                      *ebpf.Map
	natV6                      *ebpf.Map
	natOldV4                   *ebpf.Map
	natOldV6                   *ebpf.Map
	flowMigrationState         *ebpf.Map
}

type kernelAttachmentPrograms struct {
	forwardProg   *ebpf.Program
	replyProg     *ebpf.Program
	forwardProgV6 *ebpf.Program
	replyProgV6   *ebpf.Program
	mode          kernelTCAttachmentProgramMode
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
	rule           Rule
	inIfIndex      int
	outIfIndex     int
	replyIfIndexes []int
	replyIfParents []kernelIfParentMapping
	spec           kernelPreparedRuleSpec
	key            tcRuleKeyV4
	value          tcRuleValueV4
}

type kernelIfParentMapping struct {
	ifindex       int
	parentIfIndex int
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

type cachedKernelSNATIP struct {
	addr net.IP
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
	snatIPs            map[string]cachedKernelSNATIP
	outPaths           map[string]cachedKernelPath
}

func newKernelPrepareContext(enableTrafficStats bool) *kernelPrepareContext {
	return &kernelPrepareContext{
		enableTrafficStats: enableTrafficStats,
		links:              make(map[string]cachedKernelLink),
		snatAddrs:          make(map[string]cachedKernelSNAT),
		snatIPs:            make(map[string]cachedKernelSNATIP),
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

func (ctx *kernelPrepareContext) resolveEgressSNATIPv4(link netlink.Link, preferredIP string) (uint32, error) {
	if link == nil || link.Attrs() == nil {
		return 0, fmt.Errorf("invalid outbound interface")
	}
	key := fmt.Sprintf("egress|%d|%s", link.Attrs().Index, strings.TrimSpace(preferredIP))
	if ctx != nil {
		if item, ok := ctx.snatAddrs[key]; ok {
			return item.addr, item.err
		}
	}
	addr, err := resolveKernelEgressSNATIPv4(link, preferredIP)
	if ctx != nil {
		ctx.snatAddrs[key] = cachedKernelSNAT{addr: addr, err: err}
	}
	return addr, err
}

func (ctx *kernelPrepareContext) resolveSNATIPv6(link netlink.Link, backendIP string, preferredIP string) (net.IP, error) {
	if link == nil || link.Attrs() == nil {
		return nil, fmt.Errorf("invalid outbound interface")
	}
	key := fmt.Sprintf("v6|%d|%s|%s", link.Attrs().Index, strings.TrimSpace(backendIP), strings.TrimSpace(preferredIP))
	if ctx != nil {
		if item, ok := ctx.snatIPs[key]; ok {
			if item.addr == nil {
				return nil, item.err
			}
			return append(net.IP(nil), item.addr...), item.err
		}
	}
	addr, err := resolveKernelSNATIPv6(link, backendIP, preferredIP)
	if ctx != nil {
		ctx.snatIPs[key] = cachedKernelSNATIP{addr: append(net.IP(nil), addr...), err: err}
	}
	if addr == nil {
		return nil, err
	}
	return append(net.IP(nil), addr...), err
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
	natPortMin         int
	natPortMax         int
	rulesMapCapacity   int
	flowsMapCapacity   int
	natMapCapacity     int
	memlockOnce        sync.Once
	memlockErr         error
	coll               *ebpf.Collection
	attachments        []kernelAttachment
	preparedRules      []preparedKernelRule
	attachmentMode     kernelTCAttachmentProgramMode
	lastSkipLog        map[string]struct{}
	lastReconcileMode  string
	degradedSource     string
	stateLog           kernelStateLogger
	pressureState      kernelRuntimePressureState
	observability      kernelRuntimeObservabilityState
	maintenanceState   kernelAdaptiveMaintenanceState
	orphanNATPruneLog  kernelCountLogState
	statsCorrection    map[uint32]kernelRuleStats
	flowPruneState     kernelFlowPruneState
	oldFlowPruneState  kernelFlowPruneState
	runtimeMapCounts   kernelRuntimeMapCountSnapshot
	enableTrafficStats bool
	enableDiagnostics  bool
	enableDiagVerbose  bool
}

func newTCKernelRuleRuntime(cfg *Config) *linuxKernelRuleRuntime {
	rulesLimit := 0
	flowsLimit := 0
	natLimit := 0
	natPortMin, natPortMax := effectiveKernelNATPortRange(0, 0)
	enableTrafficStats := false
	enableDiagnostics := false
	enableDiagVerbose := false
	if cfg != nil {
		rulesLimit = cfg.KernelRulesMapLimit
		flowsLimit = cfg.KernelFlowsMapLimit
		natLimit = cfg.KernelNATMapLimit
		natPortMin, natPortMax = effectiveKernelNATPortRange(cfg.KernelNATPortMin, cfg.KernelNATPortMax)
		enableTrafficStats = cfg.ExperimentalFeatureEnabled(experimentalFeatureKernelTraffic)
		enableDiagnostics = cfg.ExperimentalFeatureEnabled(experimentalFeatureKernelTCDiag)
		enableDiagVerbose = cfg.ExperimentalFeatureEnabled(experimentalFeatureKernelTCDiagVerbose)
	}
	if enableDiagVerbose {
		enableDiagnostics = true
	}
	return &linuxKernelRuleRuntime{
		rulesMapLimit:      rulesLimit,
		flowsMapLimit:      flowsLimit,
		natMapLimit:        natLimit,
		natPortMin:         natPortMin,
		natPortMax:         natPortMax,
		statsCorrection:    make(map[uint32]kernelRuleStats),
		attachmentMode:     kernelTCAttachmentProgramModeLegacy,
		enableTrafficStats: enableTrafficStats,
		enableDiagnostics:  enableDiagnostics,
		enableDiagVerbose:  enableDiagVerbose,
	}
}

func newKernelRuleRuntime(cfg *Config) kernelRuleRuntime {
	if cfg == nil {
		return newOrderedKernelRuleRuntime(nil, nil)
	}
	return newOrderedKernelRuleRuntime(cfg.KernelEngineOrder, cfg)
}

func (rt *linuxKernelRuleRuntime) ensureAvailabilityInitialized() {
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
		if rt.enableDiagnostics {
			rt.availableReason += "; kernel_tc_diag experimental path enabled"
		}
		if rt.enableDiagVerbose {
			rt.availableReason += "; kernel_tc_diag_verbose experimental path enabled"
		}
	})
}

func (rt *linuxKernelRuleRuntime) Available() (bool, string) {
	rt.ensureAvailabilityInitialized()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.currentAvailabilityLocked(time.Now())
}

func (rt *linuxKernelRuleRuntime) SupportsRule(rule Rule) (bool, string) {
	prepared, err := prepareKernelRule(newKernelPrepareContext(rt.enableTrafficStats), rule)
	if err != nil {
		return false, err.Error()
	}
	if kernelPreparedRulesIncludeIPv6(prepared) {
		spec, specErr := loadEmbeddedKernelCollectionSpec(rt.enableTrafficStats)
		if specErr != nil {
			return false, specErr.Error()
		}
		if validateErr := validateKernelCollectionSpec(spec); validateErr != nil {
			return false, validateErr.Error()
		}
		if !kernelCollectionSpecSupportsIPv6(spec) {
			return false, "kernel dataplane embedded object is missing IPv6 tc maps; rebuild the tc eBPF object"
		}
	}
	return true, ""
}

func (rt *linuxKernelRuleRuntime) Reconcile(rules []Rule) (results map[int64]kernelRuleApplyResult, reconcileErr error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	reconcileStartedAt := time.Now()
	reconcileMetrics := kernelReconcileMetrics{RequestEntries: len(rules)}
	defer func() {
		rt.observability.recordReconcile(reconcileStartedAt, time.Since(reconcileStartedAt), reconcileMetrics, reconcileErr, results)
	}()

	results = make(map[int64]kernelRuleApplyResult, len(rules))
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

	prepareStartedAt := time.Now()
	prepared, forwardIfRules, replyIfRules, parentIfMap, prepareResults, skipLines := prepareKernelRules(rules, rt.preparedRules, rt.coll != nil, rt.enableTrafficStats)
	reconcileMetrics.PrepareDuration = time.Since(prepareStartedAt)
	reconcileMetrics.PreparedEntries = len(prepared)
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

	samePrepared := rt.samePreparedRulesLocked(prepared, forwardIfRules, replyIfRules)
	desiredEgressWildcardFast := buildKernelEgressWildcardFastMap(prepared)
	desiredLocalIPv4s, localIPv4Err := buildKernelEgressNATLocalIPv4Set(rules)
	if localIPv4Err != nil && !samePrepared {
		msg := fmt.Sprintf("build kernel egress nat local IPv4 inventory: %v", localIPv4Err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane reconcile: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if samePrepared {
		if err := syncKernelEgressWildcardFastMap(rt.coll.Maps[kernelEgressWildcardFastMapName], desiredEgressWildcardFast); err != nil {
			log.Printf("kernel dataplane reconcile: refresh egress wildcard fast map failed: %v", err)
		}
		if localIPv4Err != nil {
			log.Printf("kernel dataplane reconcile: keep current local IPv4 bypass inventory after refresh failure: %v", localIPv4Err)
		} else if err := syncKernelLocalIPv4Map(rt.coll.Maps[kernelLocalIPv4MapName], desiredLocalIPv4s); err != nil {
			log.Printf("kernel dataplane reconcile: refresh local IPv4 bypass inventory failed: %v", err)
		}
		rt.lastReconcileMode = "steady"
		reconcileMetrics.AppliedEntries = len(prepared)
		rt.stateLog.Logf("kernel dataplane reconcile: entry set unchanged, keeping %d active kernel entry(s)", len(prepared))
		for _, rule := range rules {
			if current, ok := results[rule.ID]; ok && current.Error != "" {
				continue
			}
			results[rule.ID] = kernelRuleApplyResult{Running: true, Engine: kernelEngineTC}
		}
		return results, nil
	}

	rulesMapLimit, flowsMapLimit, natMapLimit := tcKernelRuntimeConfiguredMapLimits(
		rt.rulesMapLimit,
		rt.flowsMapLimit,
		rt.natMapLimit,
		preparedKernelRulesNeedEgressNATAutoMapFloors(prepared),
	)
	currentCounts := rt.currentRuntimeMapCountsLocked(time.Now())
	desiredCapacities := desiredKernelMapCapacitiesWithOccupancy(
		rulesMapLimit,
		flowsMapLimit,
		natMapLimit,
		len(prepared),
		currentCounts,
		true,
		normalizeKernelFlowsMapLimit(rt.flowsMapLimit) == 0,
		normalizeKernelNATMapLimit(rt.natMapLimit) == 0,
	)
	preferFreshMapGrowth := rt.shouldPreferFreshMapGrowthLocked(desiredCapacities)
	if preferFreshMapGrowth {
		log.Printf(
			"kernel dataplane reconcile: flows/nat maps are idle and below desired capacity, rebuilding tc collection to clear degraded state",
		)
	}
	if rt.canReconcileInPlaceLocked(desiredCapacities) && !preferFreshMapGrowth {
		if err := rt.reconcileInPlaceLocked(prepared, forwardIfRules, replyIfRules, parentIfMap, desiredEgressWildcardFast, desiredLocalIPv4s, results, &reconcileMetrics); err == nil {
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
	if kernelPreparedRulesIncludeIPv6(prepared) && !kernelCollectionSpecSupportsIPv6(spec) {
		msg := "kernel dataplane embedded object is missing IPv6 tc maps; rebuild the tc eBPF object"
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane reconcile: object validation failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	desiredCapacities, err = applyKernelMapCapacitiesWithOccupancy(
		spec,
		rulesMapLimit,
		flowsMapLimit,
		natMapLimit,
		len(prepared),
		currentCounts,
		true,
		normalizeKernelFlowsMapLimit(rt.flowsMapLimit) == 0,
		normalizeKernelNATMapLimit(rt.natMapLimit) == 0,
	)
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
	hotRestartStatsCorrection := map[uint32]kernelRuleStats{}
	tcFlowMigrationFlags := uint32(0)
	ensureMapReplacements := func() {
		if mapReplacements == nil {
			mapReplacements = make(map[string]*ebpf.Map, 9)
		}
	}
	if rt.coll != nil && rt.coll.Maps != nil {
		existingMigrationFlags, flowStateErr := tcEffectiveOldFlowMigrationFlagsFromCollection(rt.coll)
		if flowStateErr != nil {
			msg := fmt.Sprintf("inspect tc old-bank flow state: %v", flowStateErr)
			if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
				return results, nil
			}
			log.Printf("kernel dataplane reconcile: %s", msg)
			for _, rule := range rules {
				results[rule.ID] = kernelRuleApplyResult{Error: msg}
			}
			return results, nil
		}
		if existingMigrationFlags != 0 {
			for _, item := range []struct {
				name   string
				m      *ebpf.Map
				isFlow bool
				isNAT  bool
			}{
				{name: kernelFlowsMapName, m: rt.coll.Maps[kernelFlowsMapName], isFlow: true},
				{name: kernelFlowsMapNameV6, m: rt.coll.Maps[kernelFlowsMapNameV6], isFlow: true},
				{name: kernelNatPortsMapName, m: rt.coll.Maps[kernelNatPortsMapName], isNAT: true},
				{name: kernelNatPortsMapNameV6, m: rt.coll.Maps[kernelNatPortsMapNameV6], isNAT: true},
			} {
				if item.m == nil {
					continue
				}
				ensureMapReplacements()
				mapReplacements[item.name] = item.m
				if item.isFlow {
					if capacity := int(item.m.MaxEntries()); capacity < actualCapacities.Flows {
						actualCapacities.Flows = capacity
					}
				}
				if item.isNAT {
					if capacity := int(item.m.MaxEntries()); capacity < actualCapacities.NATPorts {
						actualCapacities.NATPorts = capacity
					}
				}
			}
			if existingMigrationFlags&tcFlowMigrationFlagV4Old != 0 {
				if old := rt.coll.Maps[kernelTCFlowsOldMapNameV4]; old != nil {
					ensureMapReplacements()
					mapReplacements[kernelTCFlowsOldMapNameV4] = old
				}
				if old := rt.coll.Maps[kernelTCNatPortsOldMapNameV4]; old != nil {
					ensureMapReplacements()
					mapReplacements[kernelTCNatPortsOldMapNameV4] = old
				}
			}
			if existingMigrationFlags&tcFlowMigrationFlagV6Old != 0 {
				if old := rt.coll.Maps[kernelTCFlowsOldMapNameV6]; old != nil {
					ensureMapReplacements()
					mapReplacements[kernelTCFlowsOldMapNameV6] = old
				}
				if old := rt.coll.Maps[kernelTCNatPortsOldMapNameV6]; old != nil {
					ensureMapReplacements()
					mapReplacements[kernelTCNatPortsOldMapNameV6] = old
				}
			}
			tcFlowMigrationFlags = existingMigrationFlags
			if actualCapacities.Flows < desiredCapacities.Flows {
				log.Printf(
					"kernel dataplane reconcile: preserving active/old tc flow banks while migration is still draining; active flow map capacity=%d remains below desired=%d",
					actualCapacities.Flows,
					desiredCapacities.Flows,
				)
			}
			if actualCapacities.NATPorts < desiredCapacities.NATPorts {
				log.Printf(
					"kernel dataplane reconcile: preserving active/old tc nat banks while migration is still draining; active nat map capacity=%d remains below desired=%d",
					actualCapacities.NATPorts,
					desiredCapacities.NATPorts,
				)
			}
		} else {
			if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
				ensureMapReplacements()
				mapReplacements[kernelTCFlowsOldMapNameV4] = flowsMap
				tcFlowMigrationFlags |= tcFlowMigrationFlagV4Old
			}
			if natMap := rt.coll.Maps[kernelNatPortsMapName]; natMap != nil {
				ensureMapReplacements()
				mapReplacements[kernelTCNatPortsOldMapNameV4] = natMap
			}
			if flowsMap := rt.coll.Maps[kernelFlowsMapNameV6]; flowsMap != nil {
				if natMap := rt.coll.Maps[kernelNatPortsMapNameV6]; natMap != nil {
					ensureMapReplacements()
					mapReplacements[kernelTCFlowsOldMapNameV6] = flowsMap
					mapReplacements[kernelTCNatPortsOldMapNameV6] = natMap
					tcFlowMigrationFlags |= tcFlowMigrationFlagV6Old
				}
			}
		}
		if statsMap := rt.coll.Maps[kernelStatsMapName]; statsMap != nil {
			if kernelMapReusableWithCapacity(statsMap, desiredCapacities.Rules) {
				ensureMapReplacements()
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
	} else if objectHash, hashErr := kernelTCHotRestartObjectHash(rt.enableTrafficStats); hashErr != nil {
		log.Printf(
			"kernel dataplane hot restart: tc handoff unavailable because current object fingerprint could not be calculated; falling back to fresh maps (cold restart): %v",
			hashErr,
		)
		if cleanupErr := cleanupStaleTCKernelHotRestartState(); cleanupErr != nil {
			log.Printf("kernel dataplane hot restart: cleanup stale tc state failed, discarding pinned state only: %v", cleanupErr)
			clearKernelHotRestartState(kernelEngineTC)
		}
	} else if state, err := loadTCKernelHotRestartState(
		desiredCapacities,
		kernelTCHotRestartValidationOptions(objectHash, rt.enableTrafficStats),
	); err != nil {
		if isKernelHotRestartIncompatible(err) {
			log.Printf(
				"kernel dataplane hot restart: preserved tc handoff is incompatible, abandoning handoff and falling back to fresh maps (cold restart): %s",
				kernelHotRestartIncompatibilityReason(err),
			)
		} else {
			log.Printf("kernel dataplane hot restart: load tc state failed, cleaning stale hot restart state: %v", err)
		}
		if cleanupErr := cleanupStaleTCKernelHotRestartState(); cleanupErr != nil {
			log.Printf("kernel dataplane hot restart: cleanup stale tc state failed, discarding pinned state only: %v", cleanupErr)
			clearKernelHotRestartState(kernelEngineTC)
		}
	} else if state != nil {
		if err := validateKernelHotRestartMapReplacements(spec, state.replacements, map[string]bool{
			kernelFlowsMapName:           true,
			kernelFlowsMapNameV6:         true,
			kernelNatPortsMapName:        true,
			kernelNatPortsMapNameV6:      true,
			kernelTCFlowsOldMapNameV4:    true,
			kernelTCFlowsOldMapNameV6:    true,
			kernelTCNatPortsOldMapNameV4: true,
			kernelTCNatPortsOldMapNameV6: true,
		}); err != nil {
			log.Printf(
				"kernel dataplane hot restart: preserved tc maps are incompatible, abandoning handoff and falling back to fresh maps (cold restart): %s",
				kernelHotRestartIncompatibilityReason(err),
			)
			state.close()
			if cleanupErr := cleanupStaleTCKernelHotRestartState(); cleanupErr != nil {
				log.Printf("kernel dataplane hot restart: cleanup stale tc state failed, discarding pinned state only: %v", cleanupErr)
				clearKernelHotRestartState(kernelEngineTC)
			}
		} else {
			hotRestartState = state
			if len(state.replacements) > 0 {
				mapReplacements = state.replacements
			}
			oldStatsMap = state.oldStatsMap
			actualCapacities = state.actualCapacities
			tcFlowMigrationFlags = state.tcFlowMigrationFlags
			if actualCapacities.Flows < desiredCapacities.Flows {
				log.Printf(
					"kernel dataplane hot restart: preserving pinned active/old tc flow banks while migration is still draining; active flow map capacity=%d remains below desired=%d",
					actualCapacities.Flows,
					desiredCapacities.Flows,
				)
			}
			if actualCapacities.NATPorts < desiredCapacities.NATPorts {
				log.Printf(
					"kernel dataplane hot restart: preserving pinned active/old tc nat banks while migration is still draining; active nat map capacity=%d remains below desired=%d",
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
	}
	loadSpec := spec
	if len(mapReplacements) > 0 {
		loadSpec, err = kernelCollectionSpecWithReplacementMapCapacities(spec, mapReplacements)
		if err == nil {
			coll, err = ebpf.NewCollectionWithOptions(loadSpec, kernelCollectionOptions(mapReplacements))
		} else {
			err = fmt.Errorf("prepare tc collection replacement maps: %w", err)
		}
	} else {
		coll, err = ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(nil))
	}
	if err != nil && hotRestartState != nil {
		log.Printf(
			"kernel dataplane hot restart: tc handoff failed during collection load, abandoning handoff and falling back to fresh maps (cold restart): %v",
			err,
		)
		hotRestartState.close()
		hotRestartState = nil
		mapReplacements = nil
		oldStatsMap = nil
		actualCapacities = desiredCapacities
		tcFlowMigrationFlags = 0
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

	pieces, err := lookupKernelCollectionPieces(coll)
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
	attachmentPrograms, err := configureKernelAttachmentPrograms(pieces, prepared)
	if err != nil {
		coll.Close()
		msg := err.Error()
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane reconcile: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if err := configureTCFlowMigrationState(pieces, tcFlowMigrationFlags); err != nil {
		coll.Close()
		msg := fmt.Sprintf("configure tc flow migration state: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane flow migration state setup failed: %v", err)
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
	if hotRestartState != nil {
		if correction, err := reconcileKernelStatsCorrectionFromRuntimeMaps(coll.Maps[kernelStatsMapName], kernelRuntimeMapRefsFromCollection(coll)); err != nil {
			log.Printf("kernel dataplane hot restart: reconcile tc stats against flows failed: %v", err)
		} else {
			hotRestartStatsCorrection = correction
		}
	}
	if err := syncKernelOccupancyMapFromCollectionExact(coll, true); err != nil {
		log.Printf("kernel dataplane reconcile: sync tc occupancy counters failed before attach: %v", err)
	}
	if err := syncKernelNATConfigMap(coll.Maps[kernelNATConfigMapName], rt.natPortMin, rt.natPortMax); err != nil {
		coll.Close()
		msg := fmt.Sprintf("sync kernel nat config map: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane nat config map sync failed: %v", err)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}

	if err := syncPreparedKernelRuleMaps(pieces, prepared); err != nil {
		coll.Close()
		msg := fmt.Sprintf("sync kernel rule maps: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane rule map sync failed: %v", err)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if err := syncKernelEgressWildcardFastMap(coll.Maps[kernelEgressWildcardFastMapName], desiredEgressWildcardFast); err != nil {
		coll.Close()
		msg := fmt.Sprintf("sync kernel egress wildcard fast map: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane egress wildcard fast map sync failed: %v", err)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if err := syncKernelIfParentMap(coll.Maps[kernelIfParentMapName], parentIfMap); err != nil {
		coll.Close()
		msg := fmt.Sprintf("sync kernel reply parent map: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane reply parent map sync failed: %v", err)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if err := syncKernelLocalIPv4Map(coll.Maps[kernelLocalIPv4MapName], desiredLocalIPv4s); err != nil {
		coll.Close()
		msg := fmt.Sprintf("sync kernel local IPv4 bypass map: %v", err)
		if rt.applyRetainedRulesOnFailureLocked(results, rules, msg) {
			return results, nil
		}
		log.Printf("kernel dataplane local IPv4 bypass map sync failed: %v", err)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}

	oldAttachments := append([]kernelAttachment(nil), rt.attachments...)
	forwardReady := make(map[int]bool)
	replyReady := make(map[int]bool)
	attachmentPlans := desiredKernelAttachmentPlansDualStack(
		forwardIfRules,
		replyIfRules,
		attachmentPrograms.forwardProg,
		attachmentPrograms.replyProg,
		attachmentPrograms.forwardProgV6,
		attachmentPrograms.replyProgV6,
	)
	newAttachments := make([]kernelAttachment, 0, len(attachmentPlans))
	attachFailure := ""
	attachStartedAt := time.Now()

	for _, plan := range attachmentPlans {
		ruleIDs := forwardIfRules[plan.ifindex]
		if plan.name == kernelReplyProgramName || plan.name == kernelReplyProgramNameV6 {
			ruleIDs = replyIfRules[plan.ifindex]
		}
		if err := rt.attachProgramLocked(&newAttachments, plan.ifindex, plan.priority, plan.handleMinor, plan.name, plan.prog); err != nil {
			log.Printf("kernel dataplane attach failed: program=%s ifindex=%d rules=%v err=%v", plan.name, plan.ifindex, ruleIDs, err)
			label := "forward"
			switch plan.name {
			case kernelReplyProgramName, kernelReplyProgramNameV6:
				label = "reply"
			}
			for _, id := range ruleIDs {
				results[id] = kernelRuleApplyResult{Error: fmt.Sprintf("attach %s program on ifindex %d: %v", label, plan.ifindex, err)}
			}
			if attachFailure == "" {
				attachFailure = fmt.Sprintf("attach %s program on ifindex %d: %v", label, plan.ifindex, err)
			}
			break
		}
		switch plan.name {
		case kernelForwardProgramName, kernelForwardProgramNameV6:
			forwardReady[plan.ifindex] = true
		case kernelReplyProgramName, kernelReplyProgramNameV6:
			replyReady[plan.ifindex] = true
		}
	}
	reconcileMetrics.AttachDuration = time.Since(attachStartedAt)
	reconcileMetrics.Attaches = len(newAttachments)

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

	flowPurgeIDs := collectPreparedKernelRuleFlowPurgeIDs(rt.preparedRules, prepared)
	purgeCorrections := map[uint32]kernelRuleStats{}
	purgedFlows := 0
	if len(flowPurgeIDs) > 0 {
		flowPurgeStartedAt := time.Now()
		purgeCorrections, purgedFlows, err = purgeKernelFlowsForRuleIDs(kernelRuntimeMapRefsFromCollection(coll), flowPurgeIDs)
		reconcileMetrics.FlowPurgeDuration = time.Since(flowPurgeStartedAt)
		if err != nil {
			log.Printf("kernel dataplane reconcile: purge stale tc flow state after rebuild failed: %v", err)
			purgeCorrections = map[uint32]kernelRuleStats{}
			purgedFlows = 0
		} else if syncErr := syncKernelOccupancyMapFromCollectionExact(coll, true); syncErr != nil {
			log.Printf("kernel dataplane reconcile: resync tc occupancy counters after rebuild purge failed: %v", syncErr)
		}
	}
	reconcileMetrics.AppliedEntries = len(prepared)
	reconcileMetrics.Upserts = len(prepared)
	reconcileMetrics.FlowPurgeDeleted = purgedFlows

	rt.stateLog.Logf("kernel dataplane reconcile: applied %d/%d kernel entry(s)", len(prepared), len(rules))
	reconcileMetrics.Detaches = kernelAttachmentDeleteCount(oldAttachments, newAttachments)
	rt.deleteStaleAttachmentsLocked(oldAttachments, newAttachments)
	if rt.coll != nil {
		rt.coll.Close()
	}
	rt.coll = coll
	rt.attachments = newAttachments
	rt.preparedRules = clonePreparedKernelRules(prepared)
	rt.attachmentMode = attachmentPrograms.mode
	rt.rulesMapCapacity = actualCapacities.Rules
	rt.flowsMapCapacity = actualCapacities.Flows
	rt.natMapCapacity = actualCapacities.NATPorts
	if hotRestartState != nil && kernelRuntimeNeedsMapGrowth(actualCapacities, desiredCapacities, true) {
		rt.degradedSource = kernelRuntimeDegradedSourceHotRestart
	} else if kernelRuntimeNeedsMapGrowth(actualCapacities, desiredCapacities, true) {
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
	if purgedFlows > 0 {
		mergeKernelStatsCorrections(rt.statsCorrection, purgeCorrections)
		log.Printf("kernel dataplane reconcile: purged %d stale tc flow entry(s) for %d changed kernel rule id(s)", purgedFlows, len(flowPurgeIDs))
	}
	if err := writeKernelRuntimeMetadata(kernelEngineTC, kernelHotRestartTCMetadata(rt.attachments, "")); err != nil {
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

func (rt *linuxKernelRuleRuntime) Maintain() error {
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
	baseBudget := rt.flowMaintenanceBudgetLocked()
	flowPruneState := rt.flowPruneState
	oldFlowPruneState := rt.oldFlowPruneState
	statsCorrection := cloneKernelStatsCorrections(rt.statsCorrection)
	rt.mu.Unlock()
	defer mapSnapshot.Close()

	refs := mapSnapshot.refs
	matchRefs := mapSnapshot.source
	haveV4 := refs.flowsV4 != nil || refs.flowsOldV4 != nil
	haveV6 := refs.flowsV6 != nil || refs.flowsOldV6 != nil
	v4Budget, v6Budget := baseBudget, 0
	switch {
	case haveV4 && haveV6:
		v4Budget = baseBudget / 2
		if v4Budget <= 0 {
			v4Budget = 1
		}
		v6Budget = baseBudget - v4Budget
	case haveV6:
		v4Budget = 0
		v6Budget = baseBudget
	}
	splitBankBudget := func(total int, activePresent bool, oldPresent bool) (int, int) {
		switch {
		case activePresent && oldPresent:
			active := total / 2
			if active <= 0 {
				active = 1
			}
			return active, total - active
		case activePresent:
			return total, 0
		case oldPresent:
			return 0, total
		default:
			return 0, 0
		}
	}
	v4ActiveBudget, v4OldBudget := splitBankBudget(v4Budget, refs.flowsV4 != nil, refs.flowsOldV4 != nil)
	v6ActiveBudget, v6OldBudget := splitBankBudget(v6Budget, refs.flowsV6 != nil, refs.flowsOldV6 != nil)
	corrections := map[uint32]kernelRuleStats{}
	pruneMetrics := kernelFlowPruneMetrics{}
	var maintainErr error
	fullSuccess := true
	driftDetected := false

	if refs.flowsV4 != nil {
		v4Corrections, v4Metrics, err := pruneStaleKernelFlowsMap(refs.rulesV4, refs.flowsV4, refs.natV4, &flowPruneState, v4ActiveBudget)
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
		v4Corrections, v4Metrics, err := pruneStaleKernelFlowsMap(refs.rulesV4, refs.flowsOldV4, refs.natOldV4, &oldFlowPruneState, v4OldBudget)
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
	if currentFlags, err := tcOldFlowMigrationFlagsFromRuntimeMapRefs(refs); err != nil {
		log.Printf("kernel dataplane maintenance: inspect old-bank tc flow state failed: %v", err)
	} else if refs.tcFlowMigrationState != nil {
		if err := refs.tcFlowMigrationState.Put(uint32(0), currentFlags); err != nil {
			log.Printf("kernel dataplane maintenance: update tc flow migration state failed: %v", err)
		}
	}
	mergeKernelStatsCorrections(statsCorrection, corrections)
	if runFull {
		if refs.hasFlows() || refs.hasNAT() || mapSnapshot.stats != nil {
			live, liveErr := snapshotKernelLiveStateFromRuntimeMapRefs(refs, true)
			if liveErr != nil {
				fullSuccess = false
				log.Printf("kernel dataplane maintenance: snapshot live tc flow state failed: %v", liveErr)
			} else {
				exact, correctionErr := reconcileKernelStatsCorrectionFromSnapshot(mapSnapshot.stats, live.ByRuleID)
				if correctionErr != nil {
					fullSuccess = false
					log.Printf("kernel dataplane maintenance: reconcile tc stats correction failed: %v", correctionErr)
				} else {
					driftDetected = !kernelStatsCorrectionsEqual(statsCorrection, exact)
					syncKernelLiveStatsCorrections(statsCorrection, exact)
				}
				deleted := 0
				for _, natMap := range []*ebpf.Map{refs.natV4, refs.natOldV4} {
					itemDeleted, natErr := pruneOrphanKernelNATReservations(natMap, live.UsedNATV4)
					if natErr != nil {
						fullSuccess = false
						log.Printf("kernel dataplane maintenance: prune orphan tc nat reservations failed: %v", natErr)
						deleted = 0
						break
					}
					deleted += itemDeleted
				}
				for _, natMap := range []*ebpf.Map{refs.natV6, refs.natOldV6} {
					itemDeleted, natErr := pruneOrphanKernelNATReservationsV6(natMap, live.UsedNATV6)
					if natErr != nil {
						fullSuccess = false
						log.Printf("kernel dataplane maintenance: prune orphan tc IPv6 nat reservations failed: %v", natErr)
						deleted = 0
						break
					}
					deleted += itemDeleted
				}
				if fullSuccess && deleted > 0 {
					driftDetected = true
					if rt.orphanNATPruneLog.ShouldLog(deleted, startedAt, kernelOrphanNATPruneLogEvery) {
						log.Printf("kernel dataplane maintenance: pruned %d orphan tc nat reservation(s)", deleted)
					}
				} else if fullSuccess {
					rt.orphanNATPruneLog.Reset()
				}
				if fullSuccess {
					natEntries, countErr := countKernelRuntimeNATEntriesExact(refs)
					if countErr != nil {
						fullSuccess = false
						log.Printf("kernel dataplane maintenance: count exact tc nat occupancy failed: %v", countErr)
					} else if syncErr := syncKernelOccupancyMapForRuntimeRefs(refs, live.FlowEntries, natEntries); syncErr != nil {
						fullSuccess = false
						log.Printf("kernel dataplane maintenance: sync tc occupancy counters failed: %v", syncErr)
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
	objectHash, err := kernelTCHotRestartObjectHash(rt.enableTrafficStats)
	if err != nil {
		log.Printf("kernel dataplane hot restart: fingerprint tc object failed, falling back to full cleanup: %v", err)
		rt.cleanupLocked()
		return true
	}
	existingMigrationFlags, err := tcEffectiveOldFlowMigrationFlagsFromCollection(rt.coll)
	if err != nil {
		log.Printf("kernel dataplane hot restart: inspect tc old-bank flow state failed, falling back to full cleanup: %v", err)
		rt.cleanupLocked()
		return true
	}
	maps := map[string]*ebpf.Map{
		kernelFlowsMapName:    rt.coll.Maps[kernelFlowsMapName],
		kernelNatPortsMapName: rt.coll.Maps[kernelNatPortsMapName],
	}
	if rt.coll.Maps[kernelFlowsMapNameV6] != nil {
		maps[kernelFlowsMapNameV6] = rt.coll.Maps[kernelFlowsMapNameV6]
	}
	if rt.coll.Maps[kernelNatPortsMapNameV6] != nil {
		maps[kernelNatPortsMapNameV6] = rt.coll.Maps[kernelNatPortsMapNameV6]
	}
	if existingMigrationFlags&tcFlowMigrationFlagV4Old != 0 {
		if m := rt.coll.Maps[kernelTCFlowsOldMapNameV4]; m != nil {
			maps[kernelTCFlowsOldMapNameV4] = m
		}
		if m := rt.coll.Maps[kernelTCNatPortsOldMapNameV4]; m != nil {
			maps[kernelTCNatPortsOldMapNameV4] = m
		}
	}
	if existingMigrationFlags&tcFlowMigrationFlagV6Old != 0 {
		if m := rt.coll.Maps[kernelTCFlowsOldMapNameV6]; m != nil {
			maps[kernelTCFlowsOldMapNameV6] = m
		}
		if m := rt.coll.Maps[kernelTCNatPortsOldMapNameV6]; m != nil {
			maps[kernelTCNatPortsOldMapNameV6] = m
		}
	}
	if kernelHotRestartSkipStatsRequested() {
		log.Printf("kernel dataplane hot restart: preserving tc flow/nat maps without %s as requested", kernelStatsMapName)
	} else {
		maps[kernelStatsMapName] = rt.coll.Maps[kernelStatsMapName]
	}
	if err := pinKernelHotRestartMaps(kernelEngineTC, maps); err != nil {
		log.Printf("kernel dataplane hot restart: preserve tc maps failed, falling back to full cleanup: %v", err)
		rt.cleanupLocked()
		return true
	}
	if rt.attachmentMode == kernelTCAttachmentProgramModeDispatchV4 {
		programs := map[string]*ebpf.Program{
			kernelForwardTransparentProgramName:     rt.coll.Programs[kernelForwardTransparentProgramName],
			kernelForwardFullNATProgramName:         rt.coll.Programs[kernelForwardFullNATProgramName],
			kernelForwardFullNATExistingProgramName: rt.coll.Programs[kernelForwardFullNATExistingProgramName],
			kernelForwardFullNATNewProgramName:      rt.coll.Programs[kernelForwardFullNATNewProgramName],
			kernelForwardEgressNATProgramName:       rt.coll.Programs[kernelForwardEgressNATProgramName],
			kernelReplyTransparentProgramName:       rt.coll.Programs[kernelReplyTransparentProgramName],
			kernelReplyFullNATProgramName:           rt.coll.Programs[kernelReplyFullNATProgramName],
		}
		if err := pinKernelHotRestartPrograms(kernelEngineTC, programs); err != nil {
			clearKernelHotRestartState(kernelEngineTC)
			log.Printf("kernel dataplane hot restart: preserve tc tail-call programs failed, falling back to full cleanup: %v", err)
			rt.cleanupLocked()
			return true
		}
	}
	if err := writeKernelHotRestartMetadata(
		kernelEngineTC,
		kernelHotRestartTCMetadataForHotRestart(rt.attachments, objectHash, rt.enableTrafficStats),
	); err != nil {
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
	rt.attachmentMode = kernelTCAttachmentProgramModeLegacy
	rt.lastReconcileMode = ""
	rt.degradedSource = kernelRuntimeDegradedSourceNone
	rt.statsCorrection = make(map[uint32]kernelRuleStats)
	rt.flowPruneState = kernelFlowPruneState{}
	rt.oldFlowPruneState = kernelFlowPruneState{}
	rt.maintenanceState.reset()
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	// Keep the predecessor collection alive until process exit so attached tc
	// filters retain all program and map references throughout the handoff
	// window before the successor finishes attaching.
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
	rt.attachmentMode = kernelTCAttachmentProgramModeLegacy
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
	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		return nil, err
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
		if err := deletePreparedKernelRuleMapEntry(pieces, item); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("delete stale preserved kernel rule %d: %w", item.rule.ID, err)
		}
	}
	rt.preparedRules = kept
	capacities := rt.currentMapCapacitiesLocked()
	rt.rulesMapCapacity = capacities.Rules
	rt.flowsMapCapacity = capacities.Flows
	rt.natMapCapacity = capacities.NATPorts
	rt.flowPruneState.reset()
	rt.oldFlowPruneState.reset()
	rt.maintenanceState.requestFull()
	rt.invalidatePressureStateLocked()
	return retained, nil
}

func (rt *linuxKernelRuleRuntime) flowMaintenanceBudgetLocked() int {
	if rt.coll != nil && rt.coll.Maps != nil {
		if totalCapacity := kernelRuntimeFlowMapCapacity(kernelRuntimeMapRefsFromCollection(rt.coll)); totalCapacity > 0 {
			return kernelFlowMaintenanceBudgetForCapacity(totalCapacity)
		}
	}
	if capacities := rt.currentMapCapacitiesLocked(); capacities.Flows > 0 {
		return kernelFlowMaintenanceBudgetForCapacity(capacities.Flows)
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
	return desiredKernelAttachmentPlansDualStack(forwardIfRules, replyIfRules, forwardProg, replyProg, nil, nil)
}

func desiredKernelAttachmentPlansDualStack(forwardIfRules map[int][]int64, replyIfRules map[int][]int64, forwardProg *ebpf.Program, replyProg *ebpf.Program, forwardProgV6 *ebpf.Program, replyProgV6 *ebpf.Program) []kernelAttachmentPlan {
	plans := make([]kernelAttachmentPlan, 0, (len(forwardIfRules)+len(replyIfRules))*2)
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
		if forwardProgV6 != nil {
			plans = append(plans, kernelAttachmentPlan{
				key: kernelAttachmentKey{
					linkIndex: ifindex,
					parent:    netlink.HANDLE_MIN_INGRESS,
					priority:  kernelForwardFilterPrioV6,
					handle:    netlink.MakeHandle(0, kernelForwardFilterHandleV6),
				},
				ifindex:     ifindex,
				priority:    kernelForwardFilterPrioV6,
				handleMinor: kernelForwardFilterHandleV6,
				name:        kernelForwardProgramNameV6,
				prog:        forwardProgV6,
			})
		}
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
		if replyProgV6 != nil {
			plans = append(plans, kernelAttachmentPlan{
				key: kernelAttachmentKey{
					linkIndex: ifindex,
					parent:    netlink.HANDLE_MIN_INGRESS,
					priority:  kernelReplyFilterPrioV6,
					handle:    netlink.MakeHandle(0, kernelReplyFilterHandleV6),
				},
				ifindex:     ifindex,
				priority:    kernelReplyFilterPrioV6,
				handleMinor: kernelReplyFilterHandleV6,
				name:        kernelReplyProgramNameV6,
				prog:        replyProgV6,
			})
		}
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

func diffPreparedKernelRules(oldItems []preparedKernelRule, nextItems []preparedKernelRule) (kernelDualStackRuleMapDiff, error) {
	v4, err := diffPreparedKernelRulesV4(oldItems, nextItems)
	if err != nil {
		return kernelDualStackRuleMapDiff{}, err
	}
	v6, err := diffPreparedKernelRulesV6(oldItems, nextItems)
	if err != nil {
		return kernelDualStackRuleMapDiff{}, err
	}
	return kernelDualStackRuleMapDiff{v4: v4, v6: v6}, nil
}

func diffPreparedKernelRulesV4(oldItems []preparedKernelRule, nextItems []preparedKernelRule) (kernelRuleMapDiff, error) {
	oldByKey := make(map[tcRuleKeyV4]tcRuleValueV4)
	nextByKey := make(map[tcRuleKeyV4]tcRuleValueV4)
	filteredOld := filterPreparedKernelRules(oldItems, func(item preparedKernelRule) bool {
		return kernelPreparedRuleFamily(item) == ipFamilyIPv4
	})
	filteredNext := filterPreparedKernelRules(nextItems, func(item preparedKernelRule) bool {
		return kernelPreparedRuleFamily(item) == ipFamilyIPv4
	})
	for _, item := range filteredOld {
		key, value, err := encodePreparedKernelRuleV4(item)
		if err != nil {
			return kernelRuleMapDiff{}, fmt.Errorf("encode IPv4 prepared kernel rule %d for diff: %w", item.rule.ID, err)
		}
		oldByKey[key] = value
	}
	for _, item := range filteredNext {
		key, value, err := encodePreparedKernelRuleV4(item)
		if err != nil {
			return kernelRuleMapDiff{}, fmt.Errorf("encode IPv4 prepared kernel rule %d for diff: %w", item.rule.ID, err)
		}
		nextByKey[key] = value
	}

	diff := kernelRuleMapDiff{
		upserts: make([]kernelRuleMapEntry, 0, len(filteredNext)),
		deletes: make([]tcRuleKeyV4, 0, len(filteredOld)),
	}
	for _, item := range filteredNext {
		key, value, err := encodePreparedKernelRuleV4(item)
		if err != nil {
			return kernelRuleMapDiff{}, fmt.Errorf("encode IPv4 prepared kernel rule %d for diff: %w", item.rule.ID, err)
		}
		oldValue, ok := oldByKey[key]
		if ok && oldValue == value {
			continue
		}
		diff.upserts = append(diff.upserts, kernelRuleMapEntry{key: key, value: value})
		delete(oldByKey, key)
	}
	for _, item := range filteredOld {
		key, _, err := encodePreparedKernelRuleV4(item)
		if err != nil {
			return kernelRuleMapDiff{}, fmt.Errorf("encode IPv4 prepared kernel rule %d for diff: %w", item.rule.ID, err)
		}
		if _, ok := nextByKey[key]; ok {
			continue
		}
		diff.deletes = append(diff.deletes, key)
	}
	return diff, nil
}

func diffPreparedKernelRulesV6(oldItems []preparedKernelRule, nextItems []preparedKernelRule) (kernelRuleMapDiffV6, error) {
	oldByKey := make(map[tcRuleKeyV6]tcRuleValueV6)
	nextByKey := make(map[tcRuleKeyV6]tcRuleValueV6)
	filteredOld := filterPreparedKernelRules(oldItems, func(item preparedKernelRule) bool {
		return kernelPreparedRuleFamily(item) == ipFamilyIPv6
	})
	filteredNext := filterPreparedKernelRules(nextItems, func(item preparedKernelRule) bool {
		return kernelPreparedRuleFamily(item) == ipFamilyIPv6
	})
	for _, item := range filteredOld {
		key, value, err := encodePreparedKernelRuleV6(item)
		if err != nil {
			return kernelRuleMapDiffV6{}, fmt.Errorf("encode IPv6 prepared kernel rule %d for diff: %w", item.rule.ID, err)
		}
		oldByKey[key] = value
	}
	for _, item := range filteredNext {
		key, value, err := encodePreparedKernelRuleV6(item)
		if err != nil {
			return kernelRuleMapDiffV6{}, fmt.Errorf("encode IPv6 prepared kernel rule %d for diff: %w", item.rule.ID, err)
		}
		nextByKey[key] = value
	}

	diff := kernelRuleMapDiffV6{
		upserts: make([]kernelRuleMapEntryV6, 0, len(filteredNext)),
		deletes: make([]tcRuleKeyV6, 0, len(filteredOld)),
	}
	for _, item := range filteredNext {
		key, value, err := encodePreparedKernelRuleV6(item)
		if err != nil {
			return kernelRuleMapDiffV6{}, fmt.Errorf("encode IPv6 prepared kernel rule %d for diff: %w", item.rule.ID, err)
		}
		oldValue, ok := oldByKey[key]
		if ok && oldValue == value {
			continue
		}
		diff.upserts = append(diff.upserts, kernelRuleMapEntryV6{key: key, value: value})
		delete(oldByKey, key)
	}
	for _, item := range filteredOld {
		key, _, err := encodePreparedKernelRuleV6(item)
		if err != nil {
			return kernelRuleMapDiffV6{}, fmt.Errorf("encode IPv6 prepared kernel rule %d for diff: %w", item.rule.ID, err)
		}
		if _, ok := nextByKey[key]; ok {
			continue
		}
		diff.deletes = append(diff.deletes, key)
	}
	return diff, nil
}

func kernelDualStackRuleMapDiffUpsertCount(diff kernelDualStackRuleMapDiff) int {
	return len(diff.v4.upserts) + len(diff.v6.upserts)
}

func kernelDualStackRuleMapDiffDeleteCount(diff kernelDualStackRuleMapDiff) int {
	return len(diff.v4.deletes) + len(diff.v6.deletes)
}

func collectPreparedKernelRuleFlowPurgeIDs(oldItems []preparedKernelRule, nextItems []preparedKernelRule) map[uint32]struct{} {
	if len(oldItems) == 0 {
		return nil
	}

	oldByKey := indexPreparedKernelRulesByMatchKey(oldItems)
	nextByKey := indexPreparedKernelRulesByMatchKey(nextItems)

	var purgeIDs map[uint32]struct{}
	for key, oldGroup := range oldByKey {
		if preparedKernelRuleGroupsEqualBy(oldGroup, nextByKey[key], samePreparedKernelRuleFlowContinuity) {
			continue
		}
		for _, item := range oldGroup {
			if item.rule.ID <= 0 || item.rule.ID > int64(^uint32(0)) {
				continue
			}
			if purgeIDs == nil {
				purgeIDs = make(map[uint32]struct{})
			}
			purgeIDs[uint32(item.rule.ID)] = struct{}{}
		}
	}
	return purgeIDs
}

func preparedKernelRulesNeedAttachmentReset(oldItems []preparedKernelRule, nextItems []preparedKernelRule) bool {
	if preparedKernelRulesNeedDispatchV4(oldItems) != preparedKernelRulesNeedDispatchV4(nextItems) {
		return true
	}
	return !preparedKernelRuleSetsEqualByMatchKey(
		filterPreparedKernelRules(oldItems, isPreparedKernelEgressRule),
		filterPreparedKernelRules(nextItems, isPreparedKernelEgressRule),
		samePreparedKernelRuleDataplaneIgnoringRuleID,
	)
}

func indexPreparedKernelRulesByMatchKey(items []preparedKernelRule) map[kernelRuleMatchKey][]preparedKernelRule {
	if len(items) == 0 {
		return nil
	}
	index := make(map[kernelRuleMatchKey][]preparedKernelRule)
	for _, item := range items {
		index[kernelRuleMatchKeyFor(item.rule)] = append(index[kernelRuleMatchKeyFor(item.rule)], item)
	}
	return index
}

func filterPreparedKernelRules(items []preparedKernelRule, keep func(preparedKernelRule) bool) []preparedKernelRule {
	if len(items) == 0 {
		return nil
	}
	filtered := make([]preparedKernelRule, 0, len(items))
	for _, item := range items {
		if keep != nil && !keep(item) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func isPreparedKernelEgressRule(item preparedKernelRule) bool {
	return isKernelEgressNATRule(item.rule) || isKernelEgressNATPassthroughRule(item.rule)
}

func preparedKernelRulesNeedDispatchV4(items []preparedKernelRule) bool {
	for _, item := range items {
		if kernelPreparedRuleFamily(item) != ipFamilyIPv4 {
			continue
		}
		if (item.value.Flags & (kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT)) != 0 {
			return true
		}
	}
	return false
}

func preparedKernelRuleSetsEqualByMatchKey(oldItems []preparedKernelRule, nextItems []preparedKernelRule, equal func(preparedKernelRule, preparedKernelRule) bool) bool {
	oldByKey := indexPreparedKernelRulesByMatchKey(oldItems)
	nextByKey := indexPreparedKernelRulesByMatchKey(nextItems)
	if len(oldByKey) != len(nextByKey) {
		return false
	}
	for key, oldGroup := range oldByKey {
		if !preparedKernelRuleGroupsEqualBy(oldGroup, nextByKey[key], equal) {
			return false
		}
	}
	return true
}

func preparedKernelRuleGroupsEqual(a []preparedKernelRule, b []preparedKernelRule) bool {
	return preparedKernelRuleGroupsEqualBy(a, b, samePreparedKernelRuleDataplane)
}

func preparedKernelRuleGroupsEqualBy(a []preparedKernelRule, b []preparedKernelRule, equal func(preparedKernelRule, preparedKernelRule) bool) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	if equal == nil {
		equal = samePreparedKernelRuleDataplane
	}

	used := make([]bool, len(b))
	for _, oldItem := range a {
		matched := false
		for idx, nextItem := range b {
			if used[idx] {
				continue
			}
			if !equal(oldItem, nextItem) {
				continue
			}
			used[idx] = true
			matched = true
			break
		}
		if !matched {
			return false
		}
	}
	return true
}

func purgeKernelFlowsForRuleIDs(refs kernelRuntimeMapRefs, ruleIDs map[uint32]struct{}) (map[uint32]kernelRuleStats, int, error) {
	corrections := make(map[uint32]kernelRuleStats)
	if len(ruleIDs) == 0 {
		return corrections, 0, nil
	}

	deleted := 0

	v4Corrections, v4Deleted, err := purgeKernelFlowsForRuleIDsV4(refs.rulesV4, refs.flowsV4, refs.natV4, ruleIDs)
	if err != nil {
		return nil, 0, err
	}
	mergeKernelStatsCorrections(corrections, v4Corrections)
	deleted += v4Deleted

	v6Corrections, v6Deleted, err := purgeKernelFlowsForRuleIDsV6(refs.rulesV6, refs.flowsV6, refs.natV6, ruleIDs)
	if err != nil {
		return nil, 0, err
	}
	mergeKernelStatsCorrections(corrections, v6Corrections)
	deleted += v6Deleted

	return corrections, deleted, nil
}

func purgeKernelFlowsForRuleIDsV4(rulesMap, flowsMap, natPortsMap *ebpf.Map, ruleIDs map[uint32]struct{}) (map[uint32]kernelRuleStats, int, error) {
	corrections := make(map[uint32]kernelRuleStats)
	if flowsMap == nil || len(ruleIDs) == 0 {
		return corrections, 0, nil
	}

	iter := flowsMap.Iterate()
	stale := make([]staleKernelFlow, 0)
	var key tcFlowKeyV4
	var value tcFlowValueV4
	for iter.Next(&key, &value) {
		if _, ok := ruleIDs[value.RuleID]; !ok {
			continue
		}
		stale = append(stale, staleKernelFlow{key: key, value: value})
	}
	if err := iter.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate kernel flows map for targeted purge: %w", err)
	}

	for _, item := range stale {
		deleteStaleKernelFlow(rulesMap, flowsMap, natPortsMap, item, corrections)
	}
	return corrections, len(stale), nil
}

func purgeKernelFlowsForRuleIDsV6(rulesMap, flowsMap, natPortsMap *ebpf.Map, ruleIDs map[uint32]struct{}) (map[uint32]kernelRuleStats, int, error) {
	corrections := make(map[uint32]kernelRuleStats)
	if flowsMap == nil || len(ruleIDs) == 0 {
		return corrections, 0, nil
	}

	iter := flowsMap.Iterate()
	stale := make([]staleKernelFlowV6, 0)
	var key tcFlowKeyV6
	var value tcFlowValueV6
	for iter.Next(&key, &value) {
		if _, ok := ruleIDs[value.RuleID]; !ok {
			continue
		}
		stale = append(stale, staleKernelFlowV6{key: key, value: value})
	}
	if err := iter.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate kernel IPv6 flows map for targeted purge: %w", err)
	}

	for _, item := range stale {
		deleteStaleKernelFlowV6(rulesMap, flowsMap, natPortsMap, item, corrections)
	}
	return corrections, len(stale), nil
}

func purgeAllKernelConnectionState(refs kernelRuntimeMapRefs) (map[uint32]kernelRuleStats, int, int, error) {
	corrections := make(map[uint32]kernelRuleStats)
	deletedFlows := 0
	deletedNAT := 0

	v4Corrections, v4DeletedFlows, v4DeletedNAT, err := purgeAllKernelConnectionStateV4(refs.rulesV4, refs.flowsV4, refs.natV4)
	if err != nil {
		return nil, 0, 0, err
	}
	mergeKernelStatsCorrections(corrections, v4Corrections)
	deletedFlows += v4DeletedFlows
	deletedNAT += v4DeletedNAT

	v6Corrections, v6DeletedFlows, v6DeletedNAT, err := purgeAllKernelConnectionStateV6(refs.rulesV6, refs.flowsV6, refs.natV6)
	if err != nil {
		return nil, 0, 0, err
	}
	mergeKernelStatsCorrections(corrections, v6Corrections)
	deletedFlows += v6DeletedFlows
	deletedNAT += v6DeletedNAT

	return corrections, deletedFlows, deletedNAT, nil
}

func purgeAllKernelConnectionStateV4(rulesMap, flowsMap, natPortsMap *ebpf.Map) (map[uint32]kernelRuleStats, int, int, error) {
	corrections := make(map[uint32]kernelRuleStats)
	if flowsMap == nil {
		deletedNAT, err := pruneOrphanKernelNATReservations(natPortsMap, nil)
		return corrections, 0, deletedNAT, err
	}

	iter := flowsMap.Iterate()
	stale := make([]staleKernelFlow, 0)
	var key tcFlowKeyV4
	var value tcFlowValueV4
	for iter.Next(&key, &value) {
		stale = append(stale, staleKernelFlow{key: key, value: value})
	}
	if err := iter.Err(); err != nil {
		return nil, 0, 0, fmt.Errorf("iterate kernel flows map for full purge: %w", err)
	}

	for _, item := range stale {
		deleteStaleKernelFlow(rulesMap, flowsMap, natPortsMap, item, corrections)
	}
	deletedNAT, err := pruneOrphanKernelNATReservations(natPortsMap, nil)
	if err != nil {
		return nil, len(stale), 0, err
	}
	return corrections, len(stale), deletedNAT, nil
}

func purgeAllKernelConnectionStateV6(rulesMap, flowsMap, natPortsMap *ebpf.Map) (map[uint32]kernelRuleStats, int, int, error) {
	corrections := make(map[uint32]kernelRuleStats)
	if flowsMap == nil {
		deletedNAT, err := pruneOrphanKernelNATReservationsV6(natPortsMap, nil)
		return corrections, 0, deletedNAT, err
	}

	iter := flowsMap.Iterate()
	stale := make([]staleKernelFlowV6, 0)
	var key tcFlowKeyV6
	var value tcFlowValueV6
	for iter.Next(&key, &value) {
		stale = append(stale, staleKernelFlowV6{key: key, value: value})
	}
	if err := iter.Err(); err != nil {
		return nil, 0, 0, fmt.Errorf("iterate kernel IPv6 flows map for full purge: %w", err)
	}

	for _, item := range stale {
		deleteStaleKernelFlowV6(rulesMap, flowsMap, natPortsMap, item, corrections)
	}
	deletedNAT, err := pruneOrphanKernelNATReservationsV6(natPortsMap, nil)
	if err != nil {
		return nil, len(stale), 0, err
	}
	return corrections, len(stale), deletedNAT, nil
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
	if natMap := rt.coll.Maps[kernelNatPortsMapName]; natMap != nil {
		capacities.NATPorts = int(natMap.MaxEntries())
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
	if kernelPreparedRulesIncludeIPv6(rt.preparedRules) {
		if rt.coll.Programs[kernelForwardProgramNameV6] == nil || rt.coll.Programs[kernelReplyProgramNameV6] == nil {
			return false
		}
	}
	rulesMap := rt.coll.Maps[kernelRulesMapName]
	flowsMap := rt.coll.Maps[kernelFlowsMapName]
	natPortsMap := rt.coll.Maps[kernelNatPortsMapName]
	egressWildcardFastMap := rt.coll.Maps[kernelEgressWildcardFastMapName]
	statsMap := rt.coll.Maps[kernelStatsMapName]
	if rulesMap == nil || flowsMap == nil || natPortsMap == nil || egressWildcardFastMap == nil || statsMap == nil {
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
	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		return err
	}
	for _, item := range rt.preparedRules {
		if err := deletePreparedKernelRuleMapEntry(pieces, item); err != nil {
			return fmt.Errorf("clear kernel rule key during drain: %w", err)
		}
	}
	if err := syncKernelEgressWildcardFastMap(rt.coll.Maps[kernelEgressWildcardFastMapName], nil); err != nil {
		return fmt.Errorf("clear kernel egress wildcard fast map during drain: %w", err)
	}
	if err := syncKernelLocalIPv4Map(rt.coll.Maps[kernelLocalIPv4MapName], nil); err != nil {
		return fmt.Errorf("clear kernel local IPv4 bypass map during drain: %w", err)
	}
	capacities := rt.currentMapCapacitiesLocked()
	rt.preparedRules = nil
	rt.rulesMapCapacity = capacities.Rules
	rt.flowsMapCapacity = capacities.Flows
	rt.natMapCapacity = capacities.NATPorts
	rt.lastReconcileMode = "cleared"
	rt.degradedSource = kernelRuntimeDegradedSourceNone
	rt.maintenanceState.reset()
	rt.oldFlowPruneState.reset()
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	if len(rt.attachments) > 0 {
		if err := writeKernelRuntimeMetadata(kernelEngineTC, kernelHotRestartTCMetadata(rt.attachments, "")); err != nil {
			log.Printf("kernel dataplane runtime metadata: refresh tc runtime metadata failed after rule drain: %v", err)
		}
	}
	rt.stateLog.Logf("kernel dataplane reconcile: drained active rules, preserving flows for existing connections")
	return nil
}

func (rt *linuxKernelRuleRuntime) reconcileInPlaceLocked(prepared []preparedKernelRule, forwardIfRules map[int][]int64, replyIfRules map[int][]int64, parentIfMap map[uint32]uint32, egressWildcardFast map[tcEgressWildcardKeyV4]uint8, localIPv4s map[uint32]uint8, results map[int64]kernelRuleApplyResult, metrics *kernelReconcileMetrics) error {
	flowPurgeIDs := collectPreparedKernelRuleFlowPurgeIDs(rt.preparedRules, prepared)
	attachmentReset := preparedKernelRulesNeedAttachmentReset(rt.preparedRules, prepared)
	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		return err
	}
	attachmentPrograms, err := configureKernelAttachmentPrograms(pieces, prepared)
	if err != nil {
		return err
	}

	diff, err := diffPreparedKernelRules(rt.preparedRules, prepared)
	if err != nil {
		return err
	}
	plans := desiredKernelAttachmentPlansDualStack(
		forwardIfRules,
		replyIfRules,
		attachmentPrograms.forwardProg,
		attachmentPrograms.replyProg,
		attachmentPrograms.forwardProgV6,
		attachmentPrograms.replyProgV6,
	)
	currentAttachments := make(map[kernelAttachmentKey]kernelAttachment, len(rt.attachments))
	for _, att := range rt.attachments {
		if att.filter == nil {
			continue
		}
		currentAttachments[kernelAttachmentKeyForFilter(att.filter)] = att
	}
	plannedKeys := make([]kernelAttachmentKey, 0, len(plans))
	expectedAttachments := make(map[kernelAttachmentKey]kernelAttachmentExpectation, len(plans))
	for _, plan := range plans {
		plannedKeys = append(plannedKeys, plan.key)
		expectedAttachments[plan.key] = kernelAttachmentExpectationForPlan(plan)
	}
	observedAttachments := kernelAttachmentObservations(plannedKeys)

	newAttachments := make([]kernelAttachment, 0, len(plans))
	createdAttachments := make([]kernelAttachment, 0, len(plans))
	forwardReady := make(map[int]bool, len(forwardIfRules))
	replyReady := make(map[int]bool, len(replyIfRules))
	attachStartedAt := time.Now()

	for _, plan := range plans {
		if current, ok := currentAttachments[plan.key]; ok && kernelAttachmentObservationMatchesExpectation(observedAttachments[plan.key], expectedAttachments[plan.key]) {
			newAttachments = append(newAttachments, current)
		} else {
			if err := rt.attachProgramLocked(&createdAttachments, plan.ifindex, plan.priority, plan.handleMinor, plan.name, plan.prog); err != nil {
				rt.discardAttachmentsLocked(createdAttachments)
				return fmt.Errorf("attach %s on ifindex %d: %w", plan.name, plan.ifindex, err)
			}
			newAttachments = append(newAttachments, createdAttachments[len(createdAttachments)-1])
		}
		switch plan.name {
		case kernelForwardProgramName, kernelForwardProgramNameV6:
			forwardReady[plan.ifindex] = true
		case kernelReplyProgramName, kernelReplyProgramNameV6:
			replyReady[plan.ifindex] = true
		}
	}
	attachDuration := time.Since(attachStartedAt)

	if len(localIPv4s) > 0 {
		if err := syncKernelLocalIPv4Map(rt.coll.Maps[kernelLocalIPv4MapName], localIPv4s); err != nil {
			rt.discardAttachmentsLocked(createdAttachments)
			return fmt.Errorf("sync kernel local IPv4 bypass map: %w", err)
		}
	}
	conservativeFast := intersectKernelEgressWildcardFastMaps(buildKernelEgressWildcardFastMap(rt.preparedRules), egressWildcardFast)
	if err := syncKernelEgressWildcardFastMap(rt.coll.Maps[kernelEgressWildcardFastMapName], conservativeFast); err != nil {
		rt.discardAttachmentsLocked(createdAttachments)
		return fmt.Errorf("sync kernel egress wildcard fast map: %w", err)
	}
	if err := syncKernelNATConfigMap(rt.coll.Maps[kernelNATConfigMapName], rt.natPortMin, rt.natPortMax); err != nil {
		rt.discardAttachmentsLocked(createdAttachments)
		return fmt.Errorf("sync kernel nat config map: %w", err)
	}
	if err := applyKernelDualStackRuleMapDiff(pieces, diff); err != nil {
		rt.discardAttachmentsLocked(createdAttachments)
		return err
	}
	if err := syncKernelIfParentMap(rt.coll.Maps[kernelIfParentMapName], parentIfMap); err != nil {
		rt.discardAttachmentsLocked(createdAttachments)
		return fmt.Errorf("sync kernel reply parent map: %w", err)
	}
	if err := syncKernelEgressWildcardFastMap(rt.coll.Maps[kernelEgressWildcardFastMapName], egressWildcardFast); err != nil {
		rt.discardAttachmentsLocked(createdAttachments)
		return fmt.Errorf("sync kernel egress wildcard fast map: %w", err)
	}
	if len(localIPv4s) == 0 {
		if err := syncKernelLocalIPv4Map(rt.coll.Maps[kernelLocalIPv4MapName], nil); err != nil {
			rt.discardAttachmentsLocked(createdAttachments)
			return fmt.Errorf("sync kernel local IPv4 bypass map: %w", err)
		}
	}

	oldAttachments := append([]kernelAttachment(nil), rt.attachments...)
	mergedAttachments := mergeKernelAttachments(oldAttachments, newAttachments)
	finalAttachments := mergedAttachments
	detachedAttachments := 0
	preservedAttachments := len(mergedAttachments) - len(newAttachments)
	if attachmentReset {
		finalAttachments = append([]kernelAttachment(nil), newAttachments...)
		detachedAttachments = kernelAttachmentDeleteCount(oldAttachments, newAttachments)
		preservedAttachments = 0
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
		rt.discardAttachmentsLocked(createdAttachments)
		return fmt.Errorf("no rules reached running state after in-place update")
	}

	actualCapacities := rt.currentMapCapacitiesLocked()
	rt.attachments = finalAttachments
	rt.preparedRules = clonePreparedKernelRules(prepared)
	rt.attachmentMode = attachmentPrograms.mode
	rt.rulesMapCapacity = actualCapacities.Rules
	rt.flowsMapCapacity = actualCapacities.Flows
	rt.natMapCapacity = actualCapacities.NATPorts
	_, flowsMapLimit, natMapLimit := tcKernelRuntimeConfiguredMapLimits(
		rt.rulesMapLimit,
		rt.flowsMapLimit,
		rt.natMapLimit,
		preparedKernelRulesNeedEgressNATAutoMapFloors(prepared),
	)
	currentCounts := rt.currentRuntimeMapCountsLocked(time.Now())
	desiredCapacities := desiredKernelMapCapacitiesWithOccupancy(
		rt.rulesMapLimit,
		flowsMapLimit,
		natMapLimit,
		len(prepared),
		currentCounts,
		true,
		normalizeKernelFlowsMapLimit(rt.flowsMapLimit) == 0,
		normalizeKernelNATMapLimit(rt.natMapLimit) == 0,
	)
	if kernelRuntimeNeedsMapGrowth(actualCapacities, desiredCapacities, true) {
		rt.degradedSource = kernelRuntimeDegradedSourceLivePreserve
	} else {
		rt.degradedSource = kernelRuntimeDegradedSourceNone
	}
	rt.flowPruneState.reset()
	rt.lastReconcileMode = "in_place"
	rt.maintenanceState.requestFull()
	rt.invalidateRuntimeMapCountCacheLocked()
	rt.invalidatePressureStateLocked()
	flowPurgeDeleted := 0
	flowPurgeDuration := time.Duration(0)
	if len(flowPurgeIDs) > 0 {
		flowPurgeStartedAt := time.Now()
		corrections, deleted, purgeErr := purgeKernelFlowsForRuleIDs(kernelRuntimeMapRefsFromCollection(rt.coll), flowPurgeIDs)
		flowPurgeDuration = time.Since(flowPurgeStartedAt)
		if purgeErr != nil {
			log.Printf("kernel dataplane reconcile: purge stale tc flow state after in-place update failed: %v", purgeErr)
		} else if deleted > 0 {
			flowPurgeDeleted = deleted
			mergeKernelStatsCorrections(rt.statsCorrection, corrections)
			log.Printf("kernel dataplane reconcile: purged %d stale tc flow entry(s) for %d changed kernel rule id(s)", deleted, len(flowPurgeIDs))
			if syncErr := syncKernelOccupancyMapFromCollectionExact(rt.coll, true); syncErr != nil {
				log.Printf("kernel dataplane reconcile: resync tc occupancy counters after in-place purge failed: %v", syncErr)
			}
		}
	}
	if metrics != nil {
		metrics.AppliedEntries = len(prepared)
		metrics.Upserts = kernelDualStackRuleMapDiffUpsertCount(diff)
		metrics.Deletes = kernelDualStackRuleMapDiffDeleteCount(diff)
		metrics.Attaches = len(createdAttachments)
		metrics.Detaches = detachedAttachments
		metrics.Preserved = preservedAttachments
		metrics.FlowPurgeDeleted = flowPurgeDeleted
		metrics.AttachDuration = attachDuration
		metrics.FlowPurgeDuration = flowPurgeDuration
	}
	if err := writeKernelRuntimeMetadata(kernelEngineTC, kernelHotRestartTCMetadata(rt.attachments, "")); err != nil {
		log.Printf("kernel dataplane runtime metadata: write tc runtime metadata failed after in-place update: %v", err)
	}
	if attachmentReset && detachedAttachments > 0 {
		rt.deleteStaleAttachmentsLocked(oldAttachments, newAttachments)
		log.Printf("kernel dataplane reconcile: detached %d stale tc attachment(s) after egress attachment reset", detachedAttachments)
	}
	rt.stateLog.Logf(
		"kernel dataplane reconcile: updated %d active kernel entry(s) in-place (upsert=%d delete=%d attach=%d detach=%d preserve=%d)",
		len(prepared),
		kernelDualStackRuleMapDiffUpsertCount(diff),
		kernelDualStackRuleMapDiffDeleteCount(diff),
		len(createdAttachments),
		detachedAttachments,
		preservedAttachments,
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

func kernelCollectionSpecSupportsIPv6(spec *ebpf.CollectionSpec) bool {
	if spec == nil || spec.Maps == nil {
		return false
	}
	return spec.Maps[kernelRulesMapNameV6] != nil &&
		spec.Maps[kernelFlowsMapNameV6] != nil &&
		spec.Maps[kernelNatPortsMapNameV6] != nil
}

func kernelPreparedRulesIncludeIPv6(items []preparedKernelRule) bool {
	for _, item := range items {
		if kernelPreparedRuleFamily(item) == ipFamilyIPv6 {
			return true
		}
	}
	return false
}

func kernelAttachmentProgramsForPreparedRules(coll *ebpf.Collection, prepared []preparedKernelRule, mode kernelTCAttachmentProgramMode) kernelAttachmentPrograms {
	if coll == nil {
		return kernelAttachmentPrograms{mode: kernelTCAttachmentProgramModeLegacy}
	}
	pieces, err := lookupKernelCollectionPieces(coll)
	if err != nil {
		return kernelAttachmentPrograms{mode: kernelTCAttachmentProgramModeLegacy}
	}
	if mode == kernelTCAttachmentProgramModeDispatchV4 && !preparedKernelRulesNeedDispatchV4(prepared) {
		mode = kernelTCAttachmentProgramModeLegacy
	}
	return kernelAttachmentProgramsFromPieces(pieces, kernelPreparedRulesIncludeIPv6(prepared), mode)
}

func kernelAttachmentProgramsFromPieces(pieces kernelCollectionPieces, includeIPv6 bool, mode kernelTCAttachmentProgramMode) kernelAttachmentPrograms {
	programs := kernelAttachmentPrograms{
		forwardProg: pieces.forwardProg,
		replyProg:   pieces.replyProg,
		mode:        kernelTCAttachmentProgramModeLegacy,
	}
	if includeIPv6 {
		programs.forwardProgV6 = pieces.forwardProgV6
		programs.replyProgV6 = pieces.replyProgV6
	}
	if mode == kernelTCAttachmentProgramModeDispatchV4 && kernelCollectionPiecesSupportDispatchV4(pieces) {
		programs.forwardProg = pieces.forwardDispatchProg
		programs.replyProg = pieces.replyDispatchProg
		programs.mode = kernelTCAttachmentProgramModeDispatchV4
	}
	return programs
}

func kernelCollectionPiecesSupportDispatchV4(pieces kernelCollectionPieces) bool {
	return pieces.forwardDispatchProg != nil &&
		pieces.forwardTransparentProg != nil &&
		pieces.forwardFullNATProg != nil &&
		pieces.forwardEgressNATProg != nil &&
		pieces.replyDispatchProg != nil &&
		pieces.replyTransparentProg != nil &&
		pieces.replyFullNATProg != nil &&
		pieces.progChainV4 != nil
}

func kernelCollectionPiecesSupportFullNATSplitV4(pieces kernelCollectionPieces) bool {
	return pieces.forwardFullNATExistingProg != nil &&
		pieces.forwardFullNATNewProg != nil
}

func configureTCKernelProgramChain(pieces kernelCollectionPieces) error {
	if !kernelCollectionPiecesSupportDispatchV4(pieces) {
		return fmt.Errorf("tc object is missing IPv4 dispatcher chain pieces")
	}
	if err := pieces.progChainV4.Put(uint32(tcProgramChainIndexV4Transparent), uint32(pieces.forwardTransparentProg.FD())); err != nil {
		return fmt.Errorf("install tc IPv4 transparent tail-call target: %w", err)
	}
	if err := pieces.progChainV4.Put(uint32(tcProgramChainIndexV4FullNATForward), uint32(pieces.forwardFullNATProg.FD())); err != nil {
		return fmt.Errorf("install tc IPv4 full-nat forward tail-call target: %w", err)
	}
	if err := pieces.progChainV4.Put(uint32(tcProgramChainIndexV4EgressNATForward), uint32(pieces.forwardEgressNATProg.FD())); err != nil {
		return fmt.Errorf("install tc IPv4 egress-nat forward tail-call target: %w", err)
	}
	if err := pieces.progChainV4.Put(uint32(tcProgramChainIndexV4ReplyTransparent), uint32(pieces.replyTransparentProg.FD())); err != nil {
		return fmt.Errorf("install tc IPv4 reply transparent tail-call target: %w", err)
	}
	if err := pieces.progChainV4.Put(uint32(tcProgramChainIndexV4ReplyFullNAT), uint32(pieces.replyFullNATProg.FD())); err != nil {
		return fmt.Errorf("install tc IPv4 reply full-nat tail-call target: %w", err)
	}
	if kernelCollectionPiecesSupportFullNATSplitV4(pieces) {
		if err := pieces.progChainV4.Put(uint32(tcProgramChainIndexV4FullNATExisting), uint32(pieces.forwardFullNATExistingProg.FD())); err != nil {
			return fmt.Errorf("install tc IPv4 full-nat existing tail-call target: %w", err)
		}
		if err := pieces.progChainV4.Put(uint32(tcProgramChainIndexV4FullNATNew), uint32(pieces.forwardFullNATNewProg.FD())); err != nil {
			return fmt.Errorf("install tc IPv4 full-nat new tail-call target: %w", err)
		}
	}
	return nil
}

func configureTCFlowMigrationState(pieces kernelCollectionPieces, flags uint32) error {
	if pieces.flowMigrationState == nil {
		return fmt.Errorf("kernel object is missing tc flow migration state map")
	}
	key := uint32(0)
	if err := pieces.flowMigrationState.Put(key, flags); err != nil {
		return fmt.Errorf("update tc flow migration state: %w", err)
	}
	return nil
}

func tcEffectiveOldFlowMigrationFlagsFromCollection(coll *ebpf.Collection) (uint32, error) {
	if coll == nil || coll.Maps == nil {
		return 0, nil
	}
	return tcEffectiveOldFlowMigrationFlagsFromRuntimeMapRefs(kernelRuntimeMapRefsFromCollection(coll))
}

func tcEffectiveOldFlowMigrationFlagsFromRuntimeMapRefs(refs kernelRuntimeMapRefs) (uint32, error) {
	flags, ok, err := lookupKernelFlowMigrationStateFlags(refs.tcFlowMigrationState)
	if err != nil {
		return 0, fmt.Errorf("lookup tc flow migration state: %w", err)
	}
	if ok {
		return flags & (tcFlowMigrationFlagV4Old | tcFlowMigrationFlagV6Old), nil
	}
	return tcOldFlowMigrationFlagsFromRuntimeMapRefs(refs)
}

func tcOldFlowMigrationFlagsFromCollection(coll *ebpf.Collection) (uint32, error) {
	if coll == nil || coll.Maps == nil {
		return 0, nil
	}
	return tcOldFlowMigrationFlagsFromRuntimeMapRefs(kernelRuntimeMapRefsFromCollection(coll))
}

func tcOldFlowMigrationFlagsFromRuntimeMapRefs(refs kernelRuntimeMapRefs) (uint32, error) {
	var flags uint32
	if refs.flowsOldV4 != nil {
		count, err := countKernelFlowMapEntries(refs.flowsOldV4)
		if err != nil {
			return 0, fmt.Errorf("count old tc IPv4 flows: %w", err)
		}
		if count > 0 {
			flags |= tcFlowMigrationFlagV4Old
		}
	}
	if refs.flowsOldV6 != nil {
		count, err := countKernelFlowMapEntriesV6(refs.flowsOldV6)
		if err != nil {
			return 0, fmt.Errorf("count old tc IPv6 flows: %w", err)
		}
		if count > 0 {
			flags |= tcFlowMigrationFlagV6Old
		}
	}
	return flags, nil
}

func configureKernelAttachmentPrograms(pieces kernelCollectionPieces, prepared []preparedKernelRule) (kernelAttachmentPrograms, error) {
	programs := kernelAttachmentProgramsFromPieces(pieces, kernelPreparedRulesIncludeIPv6(prepared), kernelTCAttachmentProgramModeLegacy)
	if !preparedKernelRulesNeedDispatchV4(prepared) {
		return programs, nil
	}
	if !kernelCollectionPiecesSupportDispatchV4(pieces) {
		return kernelAttachmentPrograms{}, fmt.Errorf("tc IPv4 dispatcher setup required for full-nat/egress rules, but dispatcher chain pieces are unavailable")
	}
	if err := configureTCKernelProgramChain(pieces); err != nil {
		return kernelAttachmentPrograms{}, fmt.Errorf("tc IPv4 dispatcher setup failed: %w", err)
	}
	return kernelAttachmentProgramsFromPieces(pieces, kernelPreparedRulesIncludeIPv6(prepared), kernelTCAttachmentProgramModeDispatchV4), nil
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
	if _, ok := spec.Maps[kernelIfParentMapName]; !ok {
		return fmt.Errorf("embedded tc eBPF object is missing map %q", kernelIfParentMapName)
	}
	if _, ok := spec.Maps[kernelLocalIPv4MapName]; !ok {
		return fmt.Errorf("embedded tc eBPF object is missing map %q", kernelLocalIPv4MapName)
	}
	if _, ok := spec.Maps[kernelEgressWildcardFastMapName]; !ok {
		return fmt.Errorf("embedded tc eBPF object is missing map %q", kernelEgressWildcardFastMapName)
	}
	if _, ok := spec.Maps[kernelNATConfigMapName]; !ok {
		return fmt.Errorf("embedded tc eBPF object is missing map %q", kernelNATConfigMapName)
	}
	if _, ok := spec.Maps[kernelStatsMapName]; !ok {
		return fmt.Errorf("embedded tc eBPF object is missing map %q", kernelStatsMapName)
	}
	if _, ok := spec.Maps[kernelOccupancyMapName]; !ok {
		return fmt.Errorf("embedded tc eBPF object is missing map %q", kernelOccupancyMapName)
	}
	for _, name := range []string{
		kernelTCFlowsOldMapNameV4,
		kernelTCNatPortsOldMapNameV4,
		kernelTCFlowsOldMapNameV6,
		kernelTCNatPortsOldMapNameV6,
		kernelTCFlowMigrationStateMapName,
	} {
		if _, ok := spec.Maps[name]; !ok {
			return fmt.Errorf("embedded tc eBPF object is missing map %q", name)
		}
	}
	hasAnyDispatchV4 := spec.Programs[kernelForwardDispatchProgramName] != nil ||
		spec.Programs[kernelForwardTransparentProgramName] != nil ||
		spec.Programs[kernelForwardFullNATProgramName] != nil ||
		spec.Programs[kernelForwardFullNATExistingProgramName] != nil ||
		spec.Programs[kernelForwardFullNATNewProgramName] != nil ||
		spec.Programs[kernelForwardEgressNATProgramName] != nil ||
		spec.Programs[kernelReplyDispatchProgramName] != nil ||
		spec.Programs[kernelReplyTransparentProgramName] != nil ||
		spec.Programs[kernelReplyFullNATProgramName] != nil ||
		spec.Maps[kernelTCProgramChainMapName] != nil
	if hasAnyDispatchV4 {
		for _, name := range []string{
			kernelForwardDispatchProgramName,
			kernelForwardTransparentProgramName,
			kernelForwardFullNATProgramName,
			kernelForwardEgressNATProgramName,
			kernelReplyDispatchProgramName,
			kernelReplyTransparentProgramName,
			kernelReplyFullNATProgramName,
		} {
			if _, ok := spec.Programs[name]; !ok {
				return fmt.Errorf("embedded tc eBPF object has incomplete IPv4 dispatcher set: missing program %q", name)
			}
		}
		if _, ok := spec.Maps[kernelTCProgramChainMapName]; !ok {
			return fmt.Errorf("embedded tc eBPF object has incomplete IPv4 dispatcher set: missing map %q", kernelTCProgramChainMapName)
		}
	}
	hasAnyFullNATSplitV4 := spec.Programs[kernelForwardFullNATExistingProgramName] != nil ||
		spec.Programs[kernelForwardFullNATNewProgramName] != nil
	if hasAnyFullNATSplitV4 {
		for _, name := range []string{
			kernelForwardFullNATExistingProgramName,
			kernelForwardFullNATNewProgramName,
		} {
			if _, ok := spec.Programs[name]; !ok {
				return fmt.Errorf("embedded tc eBPF object has incomplete IPv4 full-nat split set: missing program %q", name)
			}
		}
	}
	hasRulesV6 := spec.Maps[kernelRulesMapNameV6] != nil
	hasFlowsV6 := spec.Maps[kernelFlowsMapNameV6] != nil
	hasNATV6 := spec.Maps[kernelNatPortsMapNameV6] != nil
	if hasRulesV6 || hasFlowsV6 || hasNATV6 {
		if !hasRulesV6 {
			return fmt.Errorf("embedded tc eBPF object has incomplete IPv6 map set: missing map %q", kernelRulesMapNameV6)
		}
		if !hasFlowsV6 {
			return fmt.Errorf("embedded tc eBPF object has incomplete IPv6 map set: missing map %q", kernelFlowsMapNameV6)
		}
		if !hasNATV6 {
			return fmt.Errorf("embedded tc eBPF object has incomplete IPv6 map set: missing map %q", kernelNatPortsMapNameV6)
		}
		if _, ok := spec.Programs[kernelForwardProgramNameV6]; !ok {
			return fmt.Errorf("embedded tc eBPF object is missing program %q", kernelForwardProgramNameV6)
		}
		if _, ok := spec.Programs[kernelReplyProgramNameV6]; !ok {
			return fmt.Errorf("embedded tc eBPF object is missing program %q", kernelReplyProgramNameV6)
		}
	}
	return nil
}

func lookupKernelCollectionPieces(coll *ebpf.Collection) (kernelCollectionPieces, error) {
	if coll == nil {
		return kernelCollectionPieces{}, fmt.Errorf("kernel object is missing")
	}
	pieces := kernelCollectionPieces{
		forwardProg:                coll.Programs[kernelForwardProgramName],
		replyProg:                  coll.Programs[kernelReplyProgramName],
		forwardProgV6:              coll.Programs[kernelForwardProgramNameV6],
		replyProgV6:                coll.Programs[kernelReplyProgramNameV6],
		forwardDispatchProg:        coll.Programs[kernelForwardDispatchProgramName],
		forwardTransparentProg:     coll.Programs[kernelForwardTransparentProgramName],
		forwardFullNATProg:         coll.Programs[kernelForwardFullNATProgramName],
		forwardFullNATExistingProg: coll.Programs[kernelForwardFullNATExistingProgramName],
		forwardFullNATNewProg:      coll.Programs[kernelForwardFullNATNewProgramName],
		forwardEgressNATProg:       coll.Programs[kernelForwardEgressNATProgramName],
		replyDispatchProg:          coll.Programs[kernelReplyDispatchProgramName],
		replyTransparentProg:       coll.Programs[kernelReplyTransparentProgramName],
		replyFullNATProg:           coll.Programs[kernelReplyFullNATProgramName],
		progChainV4:                coll.Maps[kernelTCProgramChainMapName],
		rulesV4:                    coll.Maps[kernelRulesMapNameV4],
		rulesV6:                    coll.Maps[kernelRulesMapNameV6],
		flowsV4:                    coll.Maps[kernelFlowsMapNameV4],
		flowsV6:                    coll.Maps[kernelFlowsMapNameV6],
		flowsOldV4:                 coll.Maps[kernelTCFlowsOldMapNameV4],
		flowsOldV6:                 coll.Maps[kernelTCFlowsOldMapNameV6],
		natV4:                      coll.Maps[kernelNatPortsMapNameV4],
		natV6:                      coll.Maps[kernelNatPortsMapNameV6],
		natOldV4:                   coll.Maps[kernelTCNatPortsOldMapNameV4],
		natOldV6:                   coll.Maps[kernelTCNatPortsOldMapNameV6],
		flowMigrationState:         coll.Maps[kernelTCFlowMigrationStateMapName],
	}
	if pieces.forwardProg == nil ||
		pieces.replyProg == nil ||
		pieces.rulesV4 == nil ||
		pieces.flowsV4 == nil ||
		pieces.flowsOldV4 == nil ||
		pieces.natV4 == nil ||
		pieces.natOldV4 == nil ||
		pieces.flowMigrationState == nil {
		return kernelCollectionPieces{}, fmt.Errorf("kernel object is missing required programs or maps")
	}
	hasAnyDispatchV4 := pieces.forwardDispatchProg != nil ||
		pieces.forwardTransparentProg != nil ||
		pieces.forwardFullNATProg != nil ||
		pieces.forwardFullNATExistingProg != nil ||
		pieces.forwardFullNATNewProg != nil ||
		pieces.forwardEgressNATProg != nil ||
		pieces.replyDispatchProg != nil ||
		pieces.replyTransparentProg != nil ||
		pieces.replyFullNATProg != nil ||
		pieces.progChainV4 != nil
	if hasAnyDispatchV4 && !kernelCollectionPiecesSupportDispatchV4(pieces) {
		return kernelCollectionPieces{}, fmt.Errorf("kernel object has incomplete IPv4 dispatcher set")
	}
	if (pieces.forwardFullNATExistingProg != nil || pieces.forwardFullNATNewProg != nil) && !kernelCollectionPiecesSupportFullNATSplitV4(pieces) {
		return kernelCollectionPieces{}, fmt.Errorf("kernel object has incomplete IPv4 full-nat split set")
	}
	hasAnyV6 := pieces.rulesV6 != nil || pieces.flowsV6 != nil || pieces.natV6 != nil
	if hasAnyV6 {
		if pieces.rulesV6 == nil || pieces.flowsV6 == nil || pieces.natV6 == nil || pieces.flowsOldV6 == nil || pieces.natOldV6 == nil {
			return kernelCollectionPieces{}, fmt.Errorf("kernel object has incomplete IPv6 map set")
		}
		if pieces.forwardProgV6 == nil || pieces.replyProgV6 == nil {
			return kernelCollectionPieces{}, fmt.Errorf("kernel object has incomplete IPv6 program set")
		}
	} else if pieces.flowsOldV6 == nil || pieces.natOldV6 == nil {
		return kernelCollectionPieces{}, fmt.Errorf("kernel object is missing required IPv6 old-bank maps")
	}
	return pieces, nil
}

func prepareKernelRule(ctx *kernelPrepareContext, rule Rule) ([]preparedKernelRule, error) {
	return prepareKernelRuleRef(ctx, &rule)
}

func prepareKernelRuleRef(ctx *kernelPrepareContext, rule *Rule) ([]preparedKernelRule, error) {
	if rule == nil {
		return nil, fmt.Errorf("kernel dataplane requires a rule")
	}
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
	if isKernelEgressNATPassthroughRule(*rule) || isKernelEgressNATRule(*rule) {
		if !kernelEgressProtocolSupported(rule.Protocol) {
			return nil, fmt.Errorf("kernel dataplane currently supports only single-protocol TCP/UDP/ICMP egress nat rules")
		}
	} else if !kernelProtocolSupported(rule.Protocol) {
		return nil, fmt.Errorf("kernel dataplane currently supports only single-protocol TCP/UDP rules")
	}
	if isKernelEgressNATPassthroughRule(*rule) {
		return prepareKernelEgressNATPassthroughRule(ctx, *rule, inLink, outLink)
	}
	if isKernelEgressNATRule(*rule) {
		return prepareKernelEgressNATRule(ctx, *rule, inLink, outLink)
	}

	spec, err := buildKernelPreparedForwardRuleSpec(*rule, func(family string) (net.IP, error) {
		if rule.Transparent {
			return nil, nil
		}
		if family == ipFamilyIPv6 {
			natIP, resolveErr := ctx.resolveSNATIPv6(outLink, rule.OutIP, rule.OutSourceIP)
			if resolveErr != nil {
				return nil, fmt.Errorf("resolve outbound nat ip on %q: %w", rule.OutInterface, resolveErr)
			}
			return natIP, nil
		}
		natAddr, resolveErr := ctx.resolveSNATIPv4(outLink, rule.OutIP, rule.OutSourceIP)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve outbound nat ip on %q: %w", rule.OutInterface, resolveErr)
		}
		ip := net.IPv4(
			byte(natAddr>>24),
			byte(natAddr>>16),
			byte(natAddr>>8),
			byte(natAddr),
		)
		return ip, nil
	})
	if err != nil {
		return nil, err
	}
	inLinks, err := resolveTCInboundLinks(inLink)
	if err != nil {
		return nil, fmt.Errorf("resolve inbound kernel interfaces for %q: %w", rule.InInterface, err)
	}

	path, err := ctx.resolveOutboundPath(outLink, *rule)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound path on %q: %w", rule.OutInterface, err)
	}
	replyIfIndexes, replyIfParents, err := resolveTCReplyAttachments(outLink, path.outIfIndex)
	if err != nil {
		return nil, fmt.Errorf("resolve reply interfaces on %q: %w", rule.OutInterface, err)
	}

	if !rule.Transparent {
		path.flags |= kernelRuleFlagFullNAT
	}
	if ctx != nil && ctx.enableTrafficStats {
		path.flags |= kernelRuleFlagTrafficStats
	}

	prepared := make([]preparedKernelRule, 0, len(inLinks))
	switch spec.Family {
	case ipFamilyIPv6:
		for _, currentInLink := range inLinks {
			if currentInLink == nil || currentInLink.Attrs() == nil {
				continue
			}
			itemReplyIfParents := append([]kernelIfParentMapping(nil), replyIfParents...)
			if mapping, ok := resolveTCBridgeParentMapping(currentInLink); ok {
				itemReplyIfParents = append(itemReplyIfParents, mapping)
			}
			prepared = append(prepared, preparedKernelRule{
				rule:           *rule,
				inIfIndex:      currentInLink.Attrs().Index,
				outIfIndex:     path.outIfIndex,
				replyIfIndexes: replyIfIndexes,
				replyIfParents: itemReplyIfParents,
				spec:           spec,
				key: tcRuleKeyV4{
					IfIndex: uint32(currentInLink.Attrs().Index),
					DstPort: uint16(rule.InPort),
					Proto:   kernelRuleProtocol(rule.Protocol),
				},
				value: tcRuleValueV4{
					RuleID:      uint32(rule.ID),
					BackendPort: uint16(rule.OutPort),
					Flags:       path.flags,
					OutIfIndex:  uint32(path.outIfIndex),
					SrcMAC:      path.srcMAC,
					DstMAC:      path.dstMAC,
				},
			})
		}
	default:
		inAddr, convErr := spec.DstAddr.ipv4Uint32()
		if convErr != nil {
			return nil, fmt.Errorf("prepare inbound IPv4 address: %w", convErr)
		}
		outAddr, convErr := spec.BackendAddr.ipv4Uint32()
		if convErr != nil {
			return nil, fmt.Errorf("prepare outbound IPv4 address: %w", convErr)
		}
		natAddr := uint32(0)
		if !rule.Transparent {
			natAddr, convErr = spec.NATAddr.ipv4Uint32()
			if convErr != nil {
				return nil, fmt.Errorf("prepare outbound nat IPv4 address: %w", convErr)
			}
		}
		for _, currentInLink := range inLinks {
			if currentInLink == nil || currentInLink.Attrs() == nil {
				continue
			}
			itemReplyIfParents := append([]kernelIfParentMapping(nil), replyIfParents...)
			if mapping, ok := resolveTCBridgeParentMapping(currentInLink); ok {
				itemReplyIfParents = append(itemReplyIfParents, mapping)
			}
			prepared = append(prepared, preparedKernelRule{
				rule:           *rule,
				inIfIndex:      currentInLink.Attrs().Index,
				outIfIndex:     path.outIfIndex,
				replyIfIndexes: replyIfIndexes,
				replyIfParents: itemReplyIfParents,
				spec:           spec,
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
	}
	if len(prepared) == 0 {
		return nil, fmt.Errorf("kernel dataplane bridge ingress expansion produced no attachable member interfaces")
	}
	return prepared, nil
}

func prepareKernelEgressNATRule(ctx *kernelPrepareContext, rule Rule, inLink netlink.Link, outLink netlink.Link) ([]preparedKernelRule, error) {
	inAddr, err := parseKernelInboundIPv4Uint32(rule.InIP)
	if err != nil {
		return nil, fmt.Errorf("parse inbound ip %q: %w", rule.InIP, err)
	}
	if inAddr != 0 {
		return nil, fmt.Errorf("egress nat takeover requires wildcard inbound IPv4 0.0.0.0")
	}
	if rule.InPort != 0 || rule.OutPort != 0 {
		return nil, fmt.Errorf("egress nat takeover requires wildcard inbound port/identifier matching")
	}
	if rule.Transparent {
		return nil, fmt.Errorf("egress nat takeover does not support transparent mode")
	}
	if outLink == nil || outLink.Attrs() == nil || outLink.Attrs().Index <= 0 {
		return nil, fmt.Errorf("resolve outbound interface %q: invalid link", rule.OutInterface)
	}

	inLinks, err := resolveTCInboundLinks(inLink)
	if err != nil {
		return nil, fmt.Errorf("resolve inbound kernel interfaces for %q: %w", rule.InInterface, err)
	}
	natAddr, err := ctx.resolveEgressSNATIPv4(outLink, rule.OutSourceIP)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound nat ip on %q: %w", rule.OutInterface, err)
	}
	replyIfIndexes, replyIfParents, err := resolveTCReplyAttachments(outLink, outLink.Attrs().Index)
	if err != nil {
		return nil, fmt.Errorf("resolve reply interfaces on %q: %w", rule.OutInterface, err)
	}

	flags := uint16(kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT)
	if normalizeEgressNATType(rule.kernelNATType) == egressNATTypeFullCone {
		flags |= kernelRuleFlagFullCone
	}
	if ctx != nil && ctx.enableTrafficStats {
		flags |= kernelRuleFlagTrafficStats
	}

	prepared := make([]preparedKernelRule, 0, len(inLinks))
	for _, currentInLink := range inLinks {
		if currentInLink == nil || currentInLink.Attrs() == nil {
			continue
		}
		itemReplyIfParents := append([]kernelIfParentMapping(nil), replyIfParents...)
		if mapping, ok := resolveTCBridgeParentMapping(currentInLink); ok {
			itemReplyIfParents = append(itemReplyIfParents, mapping)
		}
		prepared = append(prepared, preparedKernelRule{
			rule:           rule,
			inIfIndex:      currentInLink.Attrs().Index,
			outIfIndex:     outLink.Attrs().Index,
			replyIfIndexes: replyIfIndexes,
			replyIfParents: itemReplyIfParents,
			spec: kernelPreparedRuleSpec{
				Family:  ipFamilyIPv4,
				NATAddr: kernelPreparedAddrFromIPv4Uint32(natAddr),
			},
			key: tcRuleKeyV4{
				IfIndex: uint32(currentInLink.Attrs().Index),
				DstAddr: 0,
				DstPort: 0,
				Proto:   kernelRuleProtocol(rule.Protocol),
			},
			value: tcRuleValueV4{
				RuleID:      uint32(rule.ID),
				BackendAddr: 0,
				BackendPort: 0,
				Flags:       flags,
				OutIfIndex:  uint32(outLink.Attrs().Index),
				NATAddr:     natAddr,
			},
		})
	}
	if len(prepared) == 0 {
		return nil, fmt.Errorf("kernel dataplane bridge ingress expansion produced no attachable member interfaces")
	}
	return prepared, nil
}

func prepareKernelEgressNATPassthroughRule(ctx *kernelPrepareContext, rule Rule, inLink netlink.Link, outLink netlink.Link) ([]preparedKernelRule, error) {
	inAddr, err := parseKernelInboundIPv4Uint32(rule.InIP)
	if err != nil {
		return nil, fmt.Errorf("parse inbound ip %q: %w", rule.InIP, err)
	}
	if inAddr == 0 {
		return nil, fmt.Errorf("egress nat passthrough guard requires a specific inbound IPv4 address")
	}
	if rule.InPort != 0 || rule.OutPort != 0 {
		return nil, fmt.Errorf("egress nat passthrough guard requires wildcard inbound port/identifier matching")
	}
	if rule.Transparent {
		return nil, fmt.Errorf("egress nat passthrough guard does not support transparent mode")
	}
	if inLink == nil || inLink.Attrs() == nil || inLink.Attrs().Index <= 0 {
		return nil, fmt.Errorf("resolve inbound interface %q: invalid link", rule.InInterface)
	}
	if outLink == nil || outLink.Attrs() == nil || outLink.Attrs().Index <= 0 {
		return nil, fmt.Errorf("resolve outbound interface %q: invalid link", rule.OutInterface)
	}
	replyIfIndexes, replyIfParents, err := resolveTCReplyAttachments(outLink, outLink.Attrs().Index)
	if err != nil {
		return nil, fmt.Errorf("resolve reply interfaces on %q: %w", rule.OutInterface, err)
	}
	itemReplyIfParents := append([]kernelIfParentMapping(nil), replyIfParents...)
	if mapping, ok := resolveTCBridgeParentMapping(inLink); ok {
		itemReplyIfParents = append(itemReplyIfParents, mapping)
	}

	return []preparedKernelRule{{
		rule:           rule,
		inIfIndex:      inLink.Attrs().Index,
		outIfIndex:     outLink.Attrs().Index,
		replyIfIndexes: replyIfIndexes,
		replyIfParents: itemReplyIfParents,
		spec: kernelPreparedRuleSpec{
			Family:  ipFamilyIPv4,
			DstAddr: kernelPreparedAddrFromIPv4Uint32(inAddr),
		},
		key: tcRuleKeyV4{
			IfIndex: uint32(inLink.Attrs().Index),
			DstAddr: inAddr,
			DstPort: 0,
			Proto:   kernelRuleProtocol(rule.Protocol),
		},
		value: tcRuleValueV4{
			RuleID:     uint32(rule.ID),
			Flags:      kernelRuleFlagPassthrough,
			OutIfIndex: uint32(outLink.Attrs().Index),
		},
	}}, nil
}

func prepareKernelRules(rules []Rule, previous []preparedKernelRule, allowTransientReuse bool, enableTrafficStats bool) ([]preparedKernelRule, map[int][]int64, map[int][]int64, map[uint32]uint32, map[int64]kernelRuleApplyResult, map[string]struct{}) {
	prepared := make([]preparedKernelRule, 0, len(rules))
	forwardIfRules := make(map[int][]int64)
	replyIfRules := make(map[int][]int64)
	parentIfMap := make(map[uint32]uint32)
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
					recordPreparedKernelReplyTargets(replyIfRules, parentIfMap, item, rule.ID)
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
			recordPreparedKernelReplyTargets(replyIfRules, parentIfMap, item, rule.ID)
		}
	}

	sortPreparedKernelRules(prepared)
	return prepared, forwardIfRules, replyIfRules, parentIfMap, results, skipLogger.Snapshot()
}

func recordPreparedKernelReplyTargets(replyIfRules map[int][]int64, parentIfMap map[uint32]uint32, item preparedKernelRule, ruleID int64) {
	replyIfIndexes := item.replyIfIndexes
	if len(replyIfIndexes) == 0 && item.outIfIndex > 0 {
		replyIfIndexes = []int{item.outIfIndex}
	}
	for _, ifindex := range replyIfIndexes {
		if ifindex <= 0 {
			continue
		}
		replyIfRules[ifindex] = append(replyIfRules[ifindex], ruleID)
	}
	for _, mapping := range item.replyIfParents {
		if mapping.ifindex <= 0 || mapping.parentIfIndex <= 0 {
			continue
		}
		parentIfMap[uint32(mapping.ifindex)] = uint32(mapping.parentIfIndex)
	}
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
	for i := range src {
		dst[i] = src[i]
		if len(src[i].replyIfIndexes) > 0 {
			dst[i].replyIfIndexes = append([]int(nil), src[i].replyIfIndexes...)
		}
		if len(src[i].replyIfParents) > 0 {
			dst[i].replyIfParents = append([]kernelIfParentMapping(nil), src[i].replyIfParents...)
		}
	}
	return dst
}

func sortPreparedKernelRules(items []preparedKernelRule) {
	sort.Slice(items, func(i, j int) bool {
		a := items[i]
		b := items[j]
		if a.key.IfIndex != b.key.IfIndex {
			return a.key.IfIndex < b.key.IfIndex
		}
		if aFamily, bFamily := kernelPreparedRuleFamily(a), kernelPreparedRuleFamily(b); aFamily != bFamily {
			return aFamily < bFamily
		}
		if cmp := compareKernelPreparedAddr(a.spec.DstAddr, b.spec.DstAddr); cmp != 0 {
			return cmp < 0
		}
		if a.key.DstPort != b.key.DstPort {
			return a.key.DstPort < b.key.DstPort
		}
		if a.key.Proto != b.key.Proto {
			return a.key.Proto < b.key.Proto
		}
		if cmp := compareKernelPreparedAddr(a.spec.BackendAddr, b.spec.BackendAddr); cmp != 0 {
			return cmp < 0
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
		if cmp := compareKernelPreparedAddr(a.spec.NATAddr, b.spec.NATAddr); cmp != 0 {
			return cmp < 0
		}
		return a.rule.ID < b.rule.ID
	})
}

func kernelEgressWildcardMapKey(ifindex uint32, proto uint8) tcEgressWildcardKeyV4 {
	return tcEgressWildcardKeyV4{
		IfIndex: ifindex,
		DstAddr: 0,
		DstPort: 0,
		Proto:   proto,
	}
}

func buildKernelEgressWildcardFastMap(prepared []preparedKernelRule) map[tcEgressWildcardKeyV4]uint8 {
	if len(prepared) == 0 {
		return map[tcEgressWildcardKeyV4]uint8{}
	}

	type wildcardState struct {
		hasEgress            bool
		hasCompetingWildcard bool
		hasPartial           bool
	}

	states := make(map[tcEgressWildcardKeyV4]wildcardState)
	for _, item := range prepared {
		if kernelPreparedRuleFamily(item) != ipFamilyIPv4 {
			continue
		}
		key := kernelEgressWildcardMapKey(item.key.IfIndex, item.key.Proto)
		state := states[key]
		fullWildcard := item.key.DstAddr == 0 && item.key.DstPort == 0
		if fullWildcard && item.value.Flags&kernelRuleFlagEgressNAT != 0 {
			if state.hasEgress {
				state.hasCompetingWildcard = true
			} else {
				state.hasEgress = true
			}
			states[key] = state
			continue
		}
		if fullWildcard {
			state.hasCompetingWildcard = true
		} else if item.key.DstAddr == 0 || item.key.DstPort == 0 {
			state.hasPartial = true
		}
		states[key] = state
	}

	fast := make(map[tcEgressWildcardKeyV4]uint8)
	for key, state := range states {
		if !state.hasEgress || state.hasCompetingWildcard {
			continue
		}
		if !state.hasPartial {
			fast[key] = 1
		}
	}
	return fast
}

func intersectKernelEgressWildcardFastMaps(current, desired map[tcEgressWildcardKeyV4]uint8) map[tcEgressWildcardKeyV4]uint8 {
	if len(current) == 0 || len(desired) == 0 {
		return map[tcEgressWildcardKeyV4]uint8{}
	}
	out := make(map[tcEgressWildcardKeyV4]uint8)
	for key, currentValue := range current {
		if desiredValue, ok := desired[key]; ok && desiredValue == currentValue {
			out[key] = currentValue
		}
	}
	return out
}

func (rt *linuxKernelRuleRuntime) attachmentsHealthyLocked(forwardIfRules map[int][]int64, replyIfRules map[int][]int64) bool {
	if rt.coll == nil {
		return false
	}
	programs := kernelAttachmentProgramsForPreparedRules(rt.coll, rt.preparedRules, rt.attachmentMode)
	return kernelAttachmentsHealthy(
		forwardIfRules,
		replyIfRules,
		rt.attachments,
		programs.forwardProg,
		programs.replyProg,
		programs.forwardProgV6,
		programs.replyProgV6,
	)
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

func syncKernelIfParentMap(m *ebpf.Map, desired map[uint32]uint32) error {
	if m == nil {
		return fmt.Errorf("kernel reply parent map is nil")
	}
	if desired == nil {
		desired = make(map[uint32]uint32)
	}

	existing := make(map[uint32]uint32)
	iter := m.Iterate()
	var key uint32
	var value uint32
	for iter.Next(&key, &value) {
		existing[key] = value
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate kernel reply parent map: %w", err)
	}

	for child, parent := range desired {
		if current, ok := existing[child]; ok && current == parent {
			delete(existing, child)
			continue
		}
		if err := m.Put(child, parent); err != nil {
			return fmt.Errorf("update reply parent map entry %d->%d: %w", child, parent, err)
		}
		delete(existing, child)
	}
	for child := range existing {
		if err := m.Delete(child); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale reply parent map entry %d: %w", child, err)
		}
	}
	return nil
}

func syncKernelLocalIPv4Map(m *ebpf.Map, desired map[uint32]uint8) error {
	if m == nil {
		return fmt.Errorf("kernel local IPv4 map is nil")
	}
	if desired == nil {
		desired = make(map[uint32]uint8)
	}

	existing := make(map[uint32]uint8)
	iter := m.Iterate()
	var key uint32
	var value uint8
	for iter.Next(&key, &value) {
		existing[key] = value
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate kernel local IPv4 map: %w", err)
	}

	for addr, present := range desired {
		if current, ok := existing[addr]; ok && current == present {
			delete(existing, addr)
			continue
		}
		if err := m.Put(addr, present); err != nil {
			return fmt.Errorf("update local IPv4 map entry %d: %w", addr, err)
		}
		delete(existing, addr)
	}
	for addr := range existing {
		if err := m.Delete(addr); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale local IPv4 map entry %d: %w", addr, err)
		}
	}
	return nil
}

func syncKernelEgressWildcardFastMap(m *ebpf.Map, desired map[tcEgressWildcardKeyV4]uint8) error {
	if m == nil {
		return fmt.Errorf("kernel egress wildcard fast map is nil")
	}
	if desired == nil {
		desired = make(map[tcEgressWildcardKeyV4]uint8)
	}

	existing := make(map[tcEgressWildcardKeyV4]uint8)
	iter := m.Iterate()
	var key tcEgressWildcardKeyV4
	var value uint8
	for iter.Next(&key, &value) {
		existing[key] = value
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate kernel egress wildcard fast map: %w", err)
	}

	for matchKey, present := range desired {
		if current, ok := existing[matchKey]; ok && current == present {
			delete(existing, matchKey)
			continue
		}
		if err := m.Put(matchKey, present); err != nil {
			return fmt.Errorf("update egress wildcard fast map entry %+v: %w", matchKey, err)
		}
		delete(existing, matchKey)
	}
	for matchKey := range existing {
		if err := m.Delete(matchKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale egress wildcard fast map entry %+v: %w", matchKey, err)
		}
	}
	return nil
}

type preparedKernelRuleBatches struct {
	v4Keys   []tcRuleKeyV4
	v4Values []tcRuleValueV4
	v6Keys   []tcRuleKeyV6
	v6Values []tcRuleValueV6
}

func buildPreparedKernelRuleBatches(prepared []preparedKernelRule) (preparedKernelRuleBatches, error) {
	batches := preparedKernelRuleBatches{
		v4Keys:   make([]tcRuleKeyV4, 0, len(prepared)),
		v4Values: make([]tcRuleValueV4, 0, len(prepared)),
		v6Keys:   make([]tcRuleKeyV6, 0, len(prepared)),
		v6Values: make([]tcRuleValueV6, 0, len(prepared)),
	}
	for _, item := range prepared {
		switch kernelPreparedRuleFamily(item) {
		case ipFamilyIPv6:
			key, value, err := encodePreparedKernelRuleV6(item)
			if err != nil {
				return preparedKernelRuleBatches{}, fmt.Errorf("encode IPv6 prepared kernel rule %d: %w", item.rule.ID, err)
			}
			batches.v6Keys = append(batches.v6Keys, key)
			batches.v6Values = append(batches.v6Values, value)
		default:
			key, value, err := encodePreparedKernelRuleV4(item)
			if err != nil {
				return preparedKernelRuleBatches{}, fmt.Errorf("encode IPv4 prepared kernel rule %d: %w", item.rule.ID, err)
			}
			batches.v4Keys = append(batches.v4Keys, key)
			batches.v4Values = append(batches.v4Values, value)
		}
	}
	return batches, nil
}

func syncPreparedKernelRuleMaps(pieces kernelCollectionPieces, prepared []preparedKernelRule) error {
	batches, err := buildPreparedKernelRuleBatches(prepared)
	if err != nil {
		return err
	}
	if err := updateKernelMapEntries(pieces.rulesV4, batches.v4Keys, batches.v4Values); err != nil {
		return fmt.Errorf("update IPv4 kernel rule map: %w", err)
	}
	if len(batches.v6Keys) == 0 {
		return nil
	}
	if pieces.rulesV6 == nil {
		return fmt.Errorf("kernel object is missing IPv6 rules map")
	}
	if err := updateKernelMapEntries(pieces.rulesV6, batches.v6Keys, batches.v6Values); err != nil {
		return fmt.Errorf("update IPv6 kernel rule map: %w", err)
	}
	return nil
}

func deletePreparedKernelRuleMapEntry(pieces kernelCollectionPieces, item preparedKernelRule) error {
	switch kernelPreparedRuleFamily(item) {
	case ipFamilyIPv6:
		if pieces.rulesV6 == nil {
			return fmt.Errorf("kernel object is missing IPv6 rules map")
		}
		key, _, err := encodePreparedKernelRuleV6(item)
		if err != nil {
			return fmt.Errorf("encode IPv6 prepared kernel rule %d for delete: %w", item.rule.ID, err)
		}
		return deleteKernelMapEntry(pieces.rulesV6, key)
	default:
		key, _, err := encodePreparedKernelRuleV4(item)
		if err != nil {
			return fmt.Errorf("encode IPv4 prepared kernel rule %d for delete: %w", item.rule.ID, err)
		}
		return deleteKernelMapEntry(pieces.rulesV4, key)
	}
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

func applyKernelRuleMapDiffV6(m *ebpf.Map, diff kernelRuleMapDiffV6) error {
	if len(diff.upserts) == 0 && len(diff.deletes) == 0 {
		return nil
	}
	if m == nil {
		return fmt.Errorf("kernel IPv6 rule map is nil")
	}

	snapshots := make([]kernelRuleMapSnapshotV6, 0, len(diff.upserts)+len(diff.deletes))
	seen := make(map[tcRuleKeyV6]struct{}, len(diff.upserts)+len(diff.deletes))
	snapshotKey := func(key tcRuleKeyV6) error {
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		var value tcRuleValueV6
		err := m.Lookup(key, &value)
		if err == nil {
			snapshots = append(snapshots, kernelRuleMapSnapshotV6{
				key:    key,
				value:  value,
				exists: true,
			})
			return nil
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			snapshots = append(snapshots, kernelRuleMapSnapshotV6{key: key})
			return nil
		}
		return fmt.Errorf("lookup IPv6 rule key before in-place update: %w", err)
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
			return fmt.Errorf("upsert IPv6 kernel rule key during in-place update: %w", err)
		}
	}
	for _, key := range diff.deletes {
		if err := deleteKernelMapEntry(m, key); err != nil {
			rollback()
			return fmt.Errorf("delete stale IPv6 kernel rule key during in-place update: %w", err)
		}
	}
	return nil
}

func applyKernelDualStackRuleMapDiff(pieces kernelCollectionPieces, diff kernelDualStackRuleMapDiff) error {
	if err := applyKernelRuleMapDiff(pieces.rulesV4, diff.v4); err != nil {
		return err
	}
	if err := applyKernelRuleMapDiffV6(pieces.rulesV6, diff.v6); err != nil {
		return err
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
	case "icmp":
		return unix.IPPROTO_ICMP
	default:
		return unix.IPPROTO_TCP
	}
}

func kernelEgressProtocolSupported(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "tcp", "udp", "icmp":
		return true
	default:
		return false
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
	ip, err := parseKernelExplicitIP(text, ipFamilyIPv4)
	if err != nil {
		return 0, err
	}
	return ipv4BytesToUint32(ip), nil
}

func parseKernelInboundIPv4Uint32(text string) (uint32, error) {
	ip, wildcard, err := parseKernelInboundIP(text, ipFamilyIPv4)
	if err != nil {
		return 0, err
	}
	if wildcard {
		return 0, nil
	}
	return ipv4BytesToUint32(ip), nil
}

func resolveKernelSNATIPv4(link netlink.Link, backendIP string, preferredIP string) (uint32, error) {
	if link == nil || link.Attrs() == nil {
		return 0, fmt.Errorf("invalid outbound interface")
	}

	if preferredIP = strings.TrimSpace(preferredIP); preferredIP != "" {
		ip4, err := parseKernelExplicitIP(preferredIP, ipFamilyIPv4)
		if err != nil {
			if strings.Contains(err.Error(), "must be an explicit IPv4 address") {
				return 0, fmt.Errorf("preferred source IPv4 %q must be a specific non-loopback address", preferredIP)
			}
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

	allAddrs := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		allAddrs = append(allAddrs, addr.IP)
	}
	usable, linkLocal := splitKernelUsableSourceIPs(allAddrs, ipFamilyIPv4)
	selected, err := selectKernelAutoSourceIP(link.Attrs().Name, ipFamilyIPv4, usable, linkLocal)
	if err != nil {
		return 0, err
	}
	return ipv4BytesToUint32(selected), nil
}

func resolveKernelEgressSNATIPv4(link netlink.Link, preferredIP string) (uint32, error) {
	if link == nil || link.Attrs() == nil {
		return 0, fmt.Errorf("invalid outbound interface")
	}
	if strings.TrimSpace(preferredIP) != "" {
		return resolveKernelSNATIPv4(link, "0.0.0.0", preferredIP)
	}

	addrs, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return 0, err
	}

	allAddrs := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		allAddrs = append(allAddrs, addr.IP)
	}
	usable, linkLocal := splitKernelUsableSourceIPs(allAddrs, ipFamilyIPv4)
	selected, err := selectKernelAutoSourceIP(link.Attrs().Name, ipFamilyIPv4, usable, linkLocal)
	if err != nil {
		return 0, err
	}
	return ipv4BytesToUint32(selected), nil
}

func resolveKernelSNATIPv6(link netlink.Link, backendIP string, preferredIP string) (net.IP, error) {
	if link == nil || link.Attrs() == nil {
		return nil, fmt.Errorf("invalid outbound interface")
	}

	if preferredIP = strings.TrimSpace(preferredIP); preferredIP != "" {
		ip6, err := parseKernelExplicitIP(preferredIP, ipFamilyIPv6)
		if err != nil {
			if strings.Contains(err.Error(), "must be an explicit IPv6 address") {
				return nil, fmt.Errorf("preferred source IPv6 %q must be a specific non-loopback address", preferredIP)
			}
			return nil, fmt.Errorf("invalid IPv6 address %q", preferredIP)
		}
		if ip6.IsLoopback() || ip6.IsUnspecified() {
			return nil, fmt.Errorf("preferred source IPv6 %q must be a specific non-loopback address", preferredIP)
		}
		addrs, err := netlink.AddrList(link, unix.AF_INET6)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if current := normalizeKernelFamilyIP(addr.IP, ipFamilyIPv6); current != nil && current.Equal(ip6) {
				return append(net.IP(nil), ip6...), nil
			}
		}
		return nil, fmt.Errorf("preferred source IPv6 %q is not assigned", preferredIP)
	}

	backendIPv6, err := parseKernelExplicitIP(backendIP, ipFamilyIPv6)
	if err != nil {
		return nil, fmt.Errorf("invalid backend IPv6 address %q", backendIP)
	}

	if routeSource, err := resolveKernelRouteSourceIPv6(link, backendIPv6); err == nil {
		return append(net.IP(nil), routeSource...), nil
	}

	addrs, err := netlink.AddrList(link, unix.AF_INET6)
	if err != nil {
		return nil, err
	}

	allAddrs := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		allAddrs = append(allAddrs, addr.IP)
	}
	usable, linkLocal := splitKernelUsableSourceIPs(allAddrs, ipFamilyIPv6)
	selected, err := selectKernelAutoSourceIP(link.Attrs().Name, ipFamilyIPv6, usable, linkLocal)
	if err != nil {
		return nil, err
	}
	return append(net.IP(nil), selected...), nil
}

func resolveKernelRouteSourceIPv6(link netlink.Link, backendIP net.IP) (net.IP, error) {
	if link == nil || link.Attrs() == nil {
		return nil, fmt.Errorf("invalid outbound interface")
	}
	if backendIP = normalizeKernelFamilyIP(backendIP, ipFamilyIPv6); backendIP == nil {
		return nil, fmt.Errorf("invalid backend IPv6 address")
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
		src := normalizeKernelFamilyIP(route.Src, ipFamilyIPv6)
		if src == nil || src.IsLoopback() || src.IsUnspecified() {
			continue
		}
		return append(net.IP(nil), src...), nil
	}

	return nil, fmt.Errorf("route lookup returned no usable source IPv6")
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
