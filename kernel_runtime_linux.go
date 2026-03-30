//go:build linux

package main

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
	kernelForwardFilterPrio   = 10
	kernelReplyFilterPrio     = 20
	kernelForwardFilterHandle = 10
	kernelReplyFilterHandle   = 20
	kernelVerifierLogSize     = 4 * 1024 * 1024
)

//go:embed ebpf/forward-tc-bpf.o
var embeddedForwardTCObject []byte

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
	Pad         uint16
	OutIfIndex  uint32
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

type preparedKernelRule struct {
	rule       Rule
	inIfIndex  int
	outIfIndex int
	key        tcRuleKeyV4
	value      tcRuleValueV4
}

type linuxKernelRuleRuntime struct {
	mu              sync.Mutex
	availableOnce   sync.Once
	available       bool
	availableReason string
	memlockOnce     sync.Once
	memlockErr      error
	coll            *ebpf.Collection
	attachments     []kernelAttachment
	preparedRules   []preparedKernelRule
}

func newKernelRuleRuntime() kernelRuleRuntime {
	return &linuxKernelRuleRuntime{}
}

func (rt *linuxKernelRuleRuntime) Available() (bool, string) {
	rt.availableOnce.Do(func() {
		spec, err := loadEmbeddedKernelCollectionSpec()
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
	})
	return rt.available, rt.availableReason
}

func (rt *linuxKernelRuleRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	results := make(map[int64]kernelRuleApplyResult, len(rules))
	if len(rules) == 0 {
		rt.cleanupLocked()
		return results, nil
	}

	prepared, forwardIfRules, replyIfRules, prepareResults := rt.prepareKernelRules(rules)
	for id, result := range prepareResults {
		results[id] = result
	}
	if len(prepared) == 0 {
		log.Printf("kernel dataplane reconcile: no rules passed kernel preparation")
		return results, nil
	}
	if rt.samePreparedRulesLocked(prepared, forwardIfRules, replyIfRules) {
		log.Printf("kernel dataplane reconcile: rule set unchanged, keeping %d active kernel rule(s)", len(prepared))
		for _, rule := range rules {
			if current, ok := results[rule.ID]; ok && current.Error != "" {
				continue
			}
			results[rule.ID] = kernelRuleApplyResult{Running: true}
		}
		return results, nil
	}

	spec, err := loadEmbeddedKernelCollectionSpec()
	if err != nil {
		msg := err.Error()
		log.Printf("kernel dataplane reconcile: load embedded object failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	if err := validateKernelCollectionSpec(spec); err != nil {
		msg := err.Error()
		log.Printf("kernel dataplane reconcile: object validation failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}
	memlockErr := rt.ensureMemlock()
	if memlockErr != nil {
		log.Printf("kernel dataplane reconcile: memlock auto-raise unavailable: %v (%s); continuing with current limit", memlockErr, kernelMemlockStatus())
	}

	var coll *ebpf.Collection
	flowMapReplacement := map[string]*ebpf.Map(nil)
	if rt.coll != nil && rt.coll.Maps != nil {
		if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
			flowMapReplacement = map[string]*ebpf.Map{
				kernelFlowsMapName: flowsMap,
			}
		}
	}
	if len(flowMapReplacement) > 0 {
		coll, err = ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(flowMapReplacement))
	} else {
		coll, err = ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(nil))
	}
	if err != nil {
		logKernelVerifierDetails(err)
		msg := kernelCollectionLoadError(err, memlockErr)
		rt.disableLocked(kernelRuntimeUnavailableReason(err))
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
		log.Printf("kernel dataplane reconcile: object lookup failed: %s", msg)
		for _, rule := range rules {
			results[rule.ID] = kernelRuleApplyResult{Error: msg}
		}
		return results, nil
	}

	for _, item := range prepared {
		if err := rulesMap.Put(item.key, item.value); err != nil {
			log.Printf("kernel dataplane rule %d map update failed: %v", item.rule.ID, err)
			results[item.rule.ID] = kernelRuleApplyResult{Error: fmt.Sprintf("update kernel rule map: %v", err)}
		}
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
		rt.rollbackAttachmentsLocked(newAttachments, oldAttachments)
		coll.Close()
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
		results[item.rule.ID] = kernelRuleApplyResult{Running: true}
		runningAny = true
	}

	if !runningAny {
		log.Printf("kernel dataplane reconcile: no rules reached running state")
		coll.Close()
		return results, nil
	}

	log.Printf("kernel dataplane reconcile: applied %d/%d rule(s)", len(prepared), len(rules))
	rt.deleteStaleAttachmentsLocked(oldAttachments, newAttachments)
	if rt.coll != nil {
		rt.coll.Close()
	}
	rt.coll = coll
	rt.attachments = newAttachments
	rt.preparedRules = clonePreparedKernelRules(prepared)
	return results, nil
}

func (rt *linuxKernelRuleRuntime) ensureMemlock() error {
	rt.memlockOnce.Do(func() {
		rt.memlockErr = rlimit.RemoveMemlock()
	})
	return rt.memlockErr
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
	rt.cleanupLocked()
	return nil
}

func (rt *linuxKernelRuleRuntime) cleanupLocked() {
	for i := len(rt.attachments) - 1; i >= 0; i-- {
		if rt.attachments[i].filter != nil {
			_ = netlink.FilterDel(rt.attachments[i].filter)
		}
	}
	rt.attachments = nil
	rt.preparedRules = nil
	if rt.coll != nil {
		rt.coll.Close()
		rt.coll = nil
	}
}

func kernelAttachmentKeyForFilter(filter *netlink.BpfFilter) kernelAttachmentKey {
	return kernelAttachmentKey{
		linkIndex: filter.LinkIndex,
		parent:    filter.Parent,
		priority:  filter.Priority,
		handle:    filter.Handle,
	}
}

func (rt *linuxKernelRuleRuntime) rollbackAttachmentsLocked(newAttachments, oldAttachments []kernelAttachment) {
	oldByKey := make(map[kernelAttachmentKey]kernelAttachment, len(oldAttachments))
	for _, att := range oldAttachments {
		if att.filter == nil {
			continue
		}
		oldByKey[kernelAttachmentKeyForFilter(att.filter)] = att
	}

	for i := len(newAttachments) - 1; i >= 0; i-- {
		att := newAttachments[i]
		if att.filter == nil {
			continue
		}
		key := kernelAttachmentKeyForFilter(att.filter)
		if old, ok := oldByKey[key]; ok && old.filter != nil {
			_ = netlink.FilterReplace(old.filter)
			continue
		}
		_ = netlink.FilterDel(att.filter)
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

func loadEmbeddedKernelCollectionSpec() (*ebpf.CollectionSpec, error) {
	if len(embeddedForwardTCObject) == 0 {
		return nil, fmt.Errorf("embedded tc eBPF object is empty; build ebpf/forward-tc-bpf.o before compiling")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedForwardTCObject))
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

func prepareKernelRule(rule Rule) (preparedKernelRule, error) {
	inLink, err := netlink.LinkByName(rule.InInterface)
	if err != nil {
		return preparedKernelRule{}, fmt.Errorf("resolve inbound interface %q: %w", rule.InInterface, err)
	}
	outLink, err := netlink.LinkByName(rule.OutInterface)
	if err != nil {
		return preparedKernelRule{}, fmt.Errorf("resolve outbound interface %q: %w", rule.OutInterface, err)
	}

	if rule.ID <= 0 || rule.ID > int64(^uint32(0)) {
		return preparedKernelRule{}, fmt.Errorf("kernel dataplane requires a rule id in uint32 range")
	}

	inAddr, err := parseKernelInboundIPv4Uint32(rule.InIP)
	if err != nil {
		return preparedKernelRule{}, fmt.Errorf("parse inbound ip %q: %w", rule.InIP, err)
	}
	outAddr, err := parseIPv4Uint32(rule.OutIP)
	if err != nil {
		return preparedKernelRule{}, fmt.Errorf("parse outbound ip %q: %w", rule.OutIP, err)
	}

	item := preparedKernelRule{
		rule:       rule,
		inIfIndex:  inLink.Attrs().Index,
		outIfIndex: outLink.Attrs().Index,
		key: tcRuleKeyV4{
			IfIndex: uint32(inLink.Attrs().Index),
			DstAddr: inAddr,
			DstPort: uint16(rule.InPort),
			Proto:   kernelRuleProtocol(rule.Protocol),
		},
		value: tcRuleValueV4{
			RuleID:      uint32(rule.ID),
			BackendAddr: outAddr,
			BackendPort: uint16(rule.OutPort),
			OutIfIndex:  uint32(outLink.Attrs().Index),
		},
	}
	return item, nil
}

func (rt *linuxKernelRuleRuntime) prepareKernelRules(rules []Rule) ([]preparedKernelRule, map[int][]int64, map[int][]int64, map[int64]kernelRuleApplyResult) {
	prepared := make([]preparedKernelRule, 0, len(rules))
	forwardIfRules := make(map[int][]int64)
	replyIfRules := make(map[int][]int64)
	results := make(map[int64]kernelRuleApplyResult, len(rules))

	for _, rule := range rules {
		item, err := prepareKernelRule(rule)
		if err != nil {
			log.Printf("kernel dataplane rule %d skipped: %v", rule.ID, err)
			results[rule.ID] = kernelRuleApplyResult{Error: err.Error()}
			continue
		}
		prepared = append(prepared, item)
		forwardIfRules[item.inIfIndex] = append(forwardIfRules[item.inIfIndex], rule.ID)
		replyIfRules[item.outIfIndex] = append(replyIfRules[item.outIfIndex], rule.ID)
	}

	sortPreparedKernelRules(prepared)
	return prepared, forwardIfRules, replyIfRules, results
}

func (rt *linuxKernelRuleRuntime) samePreparedRulesLocked(next []preparedKernelRule, forwardIfRules map[int][]int64, replyIfRules map[int][]int64) bool {
	if rt.coll == nil || len(rt.attachments) == 0 {
		return false
	}
	if len(rt.preparedRules) != len(next) {
		return false
	}
	for i := range next {
		if rt.preparedRules[i] != next[i] {
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
		if a.value.OutIfIndex != b.value.OutIfIndex {
			return a.value.OutIfIndex < b.value.OutIfIndex
		}
		return a.rule.ID < b.rule.ID
	})
}

func (rt *linuxKernelRuleRuntime) attachmentsHealthyLocked(forwardIfRules map[int][]int64, replyIfRules map[int][]int64) bool {
	expected := make([]kernelAttachmentKey, 0, len(forwardIfRules)+len(replyIfRules))
	for ifindex := range forwardIfRules {
		expected = append(expected, kernelAttachmentKey{
			linkIndex: ifindex,
			parent:    netlink.HANDLE_MIN_INGRESS,
			priority:  kernelForwardFilterPrio,
			handle:    netlink.MakeHandle(0, kernelForwardFilterHandle),
		})
	}
	for ifindex := range replyIfRules {
		expected = append(expected, kernelAttachmentKey{
			linkIndex: ifindex,
			parent:    netlink.HANDLE_MIN_INGRESS,
			priority:  kernelReplyFilterPrio,
			handle:    netlink.MakeHandle(0, kernelReplyFilterHandle),
		})
	}
	if len(expected) != len(rt.attachments) {
		return false
	}
	for _, key := range expected {
		if !kernelAttachmentExists(key) {
			return false
		}
	}
	return true
}

func kernelAttachmentExists(key kernelAttachmentKey) bool {
	link, err := netlink.LinkByIndex(key.linkIndex)
	if err != nil {
		return false
	}
	filters, err := netlink.FilterList(link, key.parent)
	if err != nil {
		return false
	}
	for _, filter := range filters {
		attrs := filter.Attrs()
		if attrs == nil {
			continue
		}
		if attrs.LinkIndex == key.linkIndex && attrs.Parent == key.parent && attrs.Priority == key.priority && attrs.Handle == key.handle {
			return true
		}
	}
	return false
}

func kernelRuleProtocol(protocol string) uint8 {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "udp":
		return unix.IPPROTO_UDP
	default:
		return unix.IPPROTO_TCP
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
