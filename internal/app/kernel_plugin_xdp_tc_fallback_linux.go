//go:build linux

package app

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// An xdp hook may name a tc program of its own object as tc_fallback. On an
// interface without native XDP the host runs those programs at TC ingress
// instead of the dispatcher in generic mode. Generic XDP needs a linear skb
// with XDP headroom, so it copies every GRO aggregate; TC reads the skb in
// place and sees one aggregate once.
//
// Generic XDP runs before TC, so only the tail of an interface's chain can
// move there: the hooks after the last one without a fallback. When every
// hook has one the dispatcher stays off the interface. Otherwise the
// dispatcher runs the head in generic mode and the tail runs at TC beside it,
// left out of the dispatcher's mask for that interface; with native XDP the
// whole chain stays in the dispatcher.
//
// The programs are attached directly, in hook order, ahead of the Veer core:
// tcx at the head of the list on kernels with tcx, where it runs before any
// cls_bpf filter, and cls_bpf filters with priorities below the core's
// otherwise. The choice follows the core's own attach API, so the fallback
// is never on the slower of the two lists. Each program returns
// TC_ACT_UNSPEC (TCX_NEXT) to pass the packet on and TC_ACT_SHOT to drop
// it; no dispatcher or tail call is involved. Plugin pipeline hooks run as
// tail calls of the core and keep their place behind the fallback.
const (
	kernelXDPPluginTCFallbackPriorityBase = 1
	// Priorities 1..8 stay below kernelReplyFilterPrio (10).
	kernelXDPPluginTCFallbackMaxPerInterface = 8
	kernelXDPPluginTCFallbackHandleBase      = 0xfa00
	kernelXDPPluginTCFallbackPinDir          = "tc-fallback-links"
	kernelXDPPluginTCFallbackMode            = "tc"
)

// kernelXDPPluginTCFallback is one tc program position on one interface:
// a cls_bpf filter or a tcx link.
type kernelXDPPluginTCFallback struct {
	key      kernelAttachmentKey
	name     string
	pluginID string
	hookID   string
	filter   *netlink.BpfFilter
	slot     *kernelTCXSlot
}

// kernelXDPPluginTCFallbackSplit is how an interface's hooks may divide
// between the dispatcher and TC: the first inXDP hooks in the dispatcher,
// the tc programs of the rest at TC.
type kernelXDPPluginTCFallbackSplit struct {
	inXDP int
	tc    []loadedKernelXDPPluginProgram
}

// kernelXDPPluginTCFallbackPlan lists the tc programs of one interface in
// hook order.
type kernelXDPPluginTCFallbackPlan struct {
	ifindex  int
	programs []loadedKernelXDPPluginProgram
}

func kernelXDPPluginTCFallbackUseTCX(cfg *Config) bool {
	if cfg != nil && cfg.ExperimentalFeatureEnabled(experimentalFeatureKernelTCLegacyAttach) {
		return false
	}
	return kernelTCXSupported()
}

func kernelXDPPluginTCFallbackKey(ifindex, position int, tcx bool) kernelAttachmentKey {
	return kernelAttachmentKey{
		linkIndex: ifindex,
		parent:    netlink.HANDLE_MIN_INGRESS,
		priority:  uint16(kernelXDPPluginTCFallbackPriorityBase + position),
		handle:    netlink.MakeHandle(0, uint16(kernelXDPPluginTCFallbackHandleBase+position)),
		tcx:       tcx,
	}
}

func kernelXDPPluginTCFallbackPosition(key kernelAttachmentKey) int {
	return int(key.priority) - kernelXDPPluginTCFallbackPriorityBase
}

// kernelXDPPluginTCFallbackCandidates returns, per interface, the longest tail
// of its chain whose hooks all have a tc fallback, at most
// kernelXDPPluginTCFallbackMaxPerInterface of them. programs comes sorted by
// hook order from loadProgramsLocked.
func kernelXDPPluginTCFallbackCandidates(programs []loadedKernelXDPPluginProgram) map[int]kernelXDPPluginTCFallbackSplit {
	byIndex := make(map[int][]loadedKernelXDPPluginProgram)
	for _, item := range programs {
		for _, ifindex := range item.plan.InterfaceIndexes {
			if ifindex > 0 {
				byIndex[int(ifindex)] = append(byIndex[int(ifindex)], item)
			}
		}
	}
	out := make(map[int]kernelXDPPluginTCFallbackSplit, len(byIndex))
	for ifindex, items := range byIndex {
		first := len(items)
		for first > 0 && items[first-1].tcProg != nil && len(items)-first < kernelXDPPluginTCFallbackMaxPerInterface {
			first--
		}
		if first < len(items) {
			out[ifindex] = kernelXDPPluginTCFallbackSplit{inXDP: first, tc: items[first:]}
		}
	}
	return out
}

func kernelXDPPluginTCFallbackHookKey(pluginID, hookID string) string {
	return pluginID + "/" + hookID
}

func kernelXDPPluginTCFallbackPositionKey(pluginID, hookID string, ifindex int) string {
	return fmt.Sprintf("%s/%s@%d", pluginID, hookID, ifindex)
}

// kernelXDPPluginTCFallbackHookSet names the hook and interface of every
// position.
func kernelXDPPluginTCFallbackHookSet(positions []kernelXDPPluginTCFallback) map[string]struct{} {
	out := make(map[string]struct{}, len(positions))
	for _, position := range positions {
		out[kernelXDPPluginTCFallbackPositionKey(position.pluginID, position.hookID, position.key.linkIndex)] = struct{}{}
	}
	return out
}

// kernelXDPPluginTCFallbackExclusions lists, for each interface that also
// runs the dispatcher, the hooks that run at TC there.
func kernelXDPPluginTCFallbackExclusions(attachments []xdpAttachment, positions []kernelXDPPluginTCFallback) map[uint32]map[string]struct{} {
	dispatched := make(map[int]struct{}, len(attachments))
	for _, att := range attachments {
		dispatched[att.ifindex] = struct{}{}
	}
	out := make(map[uint32]map[string]struct{})
	for _, position := range positions {
		ifindex := position.key.linkIndex
		if _, ok := dispatched[ifindex]; !ok {
			continue
		}
		if out[uint32(ifindex)] == nil {
			out[uint32(ifindex)] = make(map[string]struct{})
		}
		out[uint32(ifindex)][kernelXDPPluginTCFallbackHookKey(position.pluginID, position.hookID)] = struct{}{}
	}
	return out
}

func kernelXDPPluginTCFallbackName(plan kernelXDPPluginHookPlan) string {
	return "veer_xdp_fallback:" + plan.PluginID + "/" + plan.HookID
}

// reconcileTCFallbacksLocked puts the programs of plans into place. A position
// this process or a hot-restart predecessor already holds swaps its program
// atomically; a new one is attached after the positions before it. It
// returns every position of plans and the ones it attached from scratch,
// which a caller rolls back by detaching. Positions in rt.tcFallbacks that
// plans no longer use are left for detachStaleTCFallbacks.
func (rt *kernelXDPPluginPipelineRuntime) reconcileTCFallbacksLocked(plans []kernelXDPPluginTCFallbackPlan, handoff *kernelXDPPluginHandoff) ([]kernelXDPPluginTCFallback, []kernelXDPPluginTCFallback, error) {
	tcx := kernelXDPPluginTCFallbackUseTCX(rt.cfg)
	current := make(map[kernelAttachmentKey]kernelXDPPluginTCFallback, len(rt.tcFallbacks))
	for _, position := range rt.tcFallbacks {
		current[position.key] = position
	}
	result := make([]kernelXDPPluginTCFallback, 0)
	added := make([]kernelXDPPluginTCFallback, 0)
	for _, plan := range plans {
		if len(plan.programs) > kernelXDPPluginTCFallbackMaxPerInterface {
			return result, added, fmt.Errorf("%s has %d xdp hooks with a tc fallback, limit %d", xdpInterfaceLabel(plan.ifindex), len(plan.programs), kernelXDPPluginTCFallbackMaxPerInterface)
		}
		var previous *kernelXDPPluginTCFallback
		for i, item := range plan.programs {
			key := kernelXDPPluginTCFallbackKey(plan.ifindex, i, tcx)
			name := kernelXDPPluginTCFallbackName(item.plan)
			position, ok := current[key]
			if !ok {
				position, ok = handoff.adoptTCFallback(key)
			}
			if ok {
				position.name = name
				position.pluginID, position.hookID = item.plan.PluginID, item.plan.HookID
				if err := position.replace(item.tcProg); err != nil {
					return result, added, fmt.Errorf("replace tc fallback of %s/%s on %s: %w", item.plan.PluginID, item.plan.HookID, xdpInterfaceLabel(plan.ifindex), err)
				}
				result = append(result, position)
				previous = &result[len(result)-1]
				continue
			}
			next := kernelXDPPluginTCFallbackNext(current, key)
			position, err := attachKernelXDPPluginTCFallback(key, name, item.tcProg, previous, next)
			if err != nil {
				return result, added, fmt.Errorf("attach tc fallback of %s/%s on %s: %w", item.plan.PluginID, item.plan.HookID, xdpInterfaceLabel(plan.ifindex), err)
			}
			position.pluginID, position.hookID = item.plan.PluginID, item.plan.HookID
			result = append(result, position)
			added = append(added, position)
			previous = &result[len(result)-1]
		}
	}
	return result, added, nil
}

// kernelXDPPluginTCFallbackNext is the position after key that this process
// already holds, if any: a new tcx link goes before it.
func kernelXDPPluginTCFallbackNext(current map[kernelAttachmentKey]kernelXDPPluginTCFallback, key kernelAttachmentKey) *kernelXDPPluginTCFallback {
	for position := kernelXDPPluginTCFallbackPosition(key) + 1; position < kernelXDPPluginTCFallbackMaxPerInterface; position++ {
		next, ok := current[kernelXDPPluginTCFallbackKey(key.linkIndex, position, key.tcx)]
		if ok && next.slot != nil && next.slot.link != nil {
			return &next
		}
	}
	return nil
}

func attachKernelXDPPluginTCFallback(key kernelAttachmentKey, name string, prog *ebpf.Program, previous, next *kernelXDPPluginTCFallback) (kernelXDPPluginTCFallback, error) {
	if prog == nil {
		return kernelXDPPluginTCFallback{}, fmt.Errorf("tc fallback program is not loaded")
	}
	if key.tcx {
		// The head of the list runs before the core, wherever the core put
		// its own links; later positions keep hook order.
		anchor := link.Head()
		switch {
		case previous != nil && previous.slot != nil && previous.slot.link != nil:
			anchor = link.AfterLinkByID(previous.slot.linkID)
		case next != nil:
			anchor = link.BeforeLinkByID(next.slot.linkID)
		}
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: key.linkIndex,
			Program:   prog,
			Attach:    ebpf.AttachTCXIngress,
			Anchor:    anchor,
		})
		if err != nil {
			return kernelXDPPluginTCFallback{}, err
		}
		slot, err := newKernelTCXSlot(l)
		if err != nil {
			_ = l.Close()
			return kernelXDPPluginTCFallback{}, err
		}
		return kernelXDPPluginTCFallback{key: key, name: name, slot: slot}, nil
	}
	if err := ensureClsactQdisc(key.linkIndex); err != nil {
		return kernelXDPPluginTCFallback{}, err
	}
	position := kernelXDPPluginTCFallback{key: key, name: name, filter: kernelXDPPluginTCFallbackFilter(key)}
	if err := position.replace(prog); err != nil {
		return kernelXDPPluginTCFallback{}, err
	}
	return position, nil
}

func kernelXDPPluginTCFallbackFilter(key kernelAttachmentKey) *netlink.BpfFilter {
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: key.linkIndex,
			Parent:    key.parent,
			Priority:  key.priority,
			Handle:    key.handle,
			Protocol:  unix.ETH_P_ALL,
		},
		DirectAction: true,
	}
}

// replace swaps the program of an existing position in one operation.
func (p *kernelXDPPluginTCFallback) replace(prog *ebpf.Program) error {
	if prog == nil {
		return fmt.Errorf("tc fallback program is not loaded")
	}
	if p.key.tcx {
		if p.slot == nil || p.slot.link == nil {
			return fmt.Errorf("tcx link is closed")
		}
		return p.slot.link.Update(prog)
	}
	if p.filter == nil {
		p.filter = kernelXDPPluginTCFallbackFilter(p.key)
	}
	p.filter.Fd = prog.FD()
	p.filter.Name = p.name
	p.filter.Id = int(kernelProgramID(prog))
	p.filter.DirectAction = true
	return netlink.FilterReplace(p.filter)
}

func (p kernelXDPPluginTCFallback) detach() error {
	if p.key.tcx {
		detachKernelTCXSlot(p.slot)
		return nil
	}
	filter := p.filter
	if filter == nil {
		filter = kernelXDPPluginTCFallbackFilter(p.key)
	}
	err := netlink.FilterDel(filter)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EINVAL) {
		// Gone with its device or never created.
		return nil
	}
	return err
}

func detachKernelXDPPluginTCFallbacks(positions []kernelXDPPluginTCFallback) ([]kernelXDPPluginTCFallback, error) {
	var pending []kernelXDPPluginTCFallback
	var failures []error
	for i := len(positions) - 1; i >= 0; i-- {
		if err := positions[i].detach(); err != nil {
			pending = append(pending, positions[i])
			failures = append(failures, fmt.Errorf("detach tc fallback from %s: %w", xdpInterfaceLabel(positions[i].key.linkIndex), err))
		}
	}
	return pending, errors.Join(failures...)
}

// detachStaleKernelXDPPluginTCFallbacks takes down the positions of old that
// next no longer uses.
func detachStaleKernelXDPPluginTCFallbacks(old, next []kernelXDPPluginTCFallback) ([]kernelXDPPluginTCFallback, error) {
	active := make(map[kernelAttachmentKey]struct{}, len(next))
	for _, position := range next {
		active[position.key] = struct{}{}
	}
	var stale []kernelXDPPluginTCFallback
	for _, position := range old {
		if _, ok := active[position.key]; !ok {
			stale = append(stale, position)
		}
	}
	return detachKernelXDPPluginTCFallbacks(stale)
}

// kernelXDPPluginTCFallbacksPresent reports whether the kernel still runs
// every position, whichever program it holds.
func kernelXDPPluginTCFallbacksPresent(positions []kernelXDPPluginTCFallback) bool {
	tcxLinks := make(map[int]map[link.ID]struct{})
	filters := make(map[int][]netlink.Filter)
	for _, position := range positions {
		ifindex := position.key.linkIndex
		if position.key.tcx {
			if position.slot == nil || position.slot.link == nil {
				return false
			}
			ids, ok := tcxLinks[ifindex]
			if !ok {
				result, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: ebpf.AttachTCXIngress})
				if err != nil {
					return false
				}
				ids = make(map[link.ID]struct{}, len(result.Programs))
				for _, prog := range result.Programs {
					if id, ok := prog.LinkID(); ok {
						ids[id] = struct{}{}
					}
				}
				tcxLinks[ifindex] = ids
			}
			if _, ok := ids[position.slot.linkID]; !ok {
				return false
			}
			continue
		}
		list, ok := filters[ifindex]
		if !ok {
			l, err := netlink.LinkByIndex(ifindex)
			if err != nil {
				return false
			}
			list, err = netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
			if err != nil {
				return false
			}
			filters[ifindex] = list
		}
		found := false
		for _, filter := range list {
			attrs := filter.Attrs()
			if _, bpf := filter.(*netlink.BpfFilter); bpf && attrs.Priority == position.key.priority && attrs.Handle == position.key.handle {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func kernelXDPPluginTCFallbackInterfaces(positions []kernelXDPPluginTCFallback) map[int]struct{} {
	out := make(map[int]struct{}, len(positions))
	for _, position := range positions {
		out[position.key.linkIndex] = struct{}{}
	}
	return out
}

func kernelXDPPluginTCFallbackMetadata(positions []kernelXDPPluginTCFallback) []kernelHotRestartTCAttachment {
	out := make([]kernelHotRestartTCAttachment, 0, len(positions))
	for _, position := range positions {
		out = append(out, kernelHotRestartTCAttachment{
			LinkIndex: position.key.linkIndex,
			Parent:    position.key.parent,
			Priority:  position.key.priority,
			Handle:    position.key.handle,
			TCX:       position.key.tcx,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LinkIndex != out[j].LinkIndex {
			return out[i].LinkIndex < out[j].LinkIndex
		}
		return out[i].Priority < out[j].Priority
	})
	return out
}

func kernelXDPPluginTCFallbackKeyFromMetadata(item kernelHotRestartTCAttachment) (kernelAttachmentKey, bool) {
	key := kernelAttachmentKey{
		linkIndex: item.LinkIndex,
		parent:    item.Parent,
		priority:  item.Priority,
		handle:    item.Handle,
		tcx:       item.TCX,
	}
	position := kernelXDPPluginTCFallbackPosition(key)
	if item.LinkIndex <= 0 || item.Parent != netlink.HANDLE_MIN_INGRESS || position < 0 || position >= kernelXDPPluginTCFallbackMaxPerInterface {
		return kernelAttachmentKey{}, false
	}
	if key != kernelXDPPluginTCFallbackKey(item.LinkIndex, position, item.TCX) {
		return kernelAttachmentKey{}, false
	}
	return key, true
}

func kernelXDPPluginTCFallbackPinPath(key kernelAttachmentKey) string {
	name := fmt.Sprintf("%d-%d", key.linkIndex, kernelXDPPluginTCFallbackPosition(key))
	return filepath.Join(kernelHotRestartEngineDir(kernelXDPPluginRuntimeEngine), kernelXDPPluginTCFallbackPinDir, name)
}

// pinKernelXDPPluginTCFallbacks keeps the tcx links attached after this
// process exits; cls_bpf filters stay on their own. The successor opens the
// pins and swaps the programs in place.
func pinKernelXDPPluginTCFallbacks(positions []kernelXDPPluginTCFallback) error {
	for _, position := range positions {
		if !position.key.tcx || position.slot == nil || position.slot.link == nil {
			continue
		}
		path := kernelXDPPluginTCFallbackPinPath(position.key)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("create tc fallback pin dir: %w", err)
		}
		// A link adopted from a pin still remembers that path.
		_ = position.slot.link.Unpin()
		_ = os.Remove(path)
		if err := position.slot.link.Pin(path); err != nil {
			return fmt.Errorf("pin tc fallback on %s: %w", xdpInterfaceLabel(position.key.linkIndex), err)
		}
	}
	return nil
}

// loadKernelXDPPluginTCFallbackPredecessor opens a position a predecessor
// left for this process.
func loadKernelXDPPluginTCFallbackPredecessor(key kernelAttachmentKey) (kernelXDPPluginTCFallback, bool) {
	if !key.tcx {
		return kernelXDPPluginTCFallback{key: key, filter: kernelXDPPluginTCFallbackFilter(key)}, true
	}
	path := kernelXDPPluginTCFallbackPinPath(key)
	l, err := link.LoadPinnedLink(path, nil)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("xdp plugin pipeline hot restart: open tc fallback pin %s: %v", path, err)
		}
		return kernelXDPPluginTCFallback{}, false
	}
	slot, err := newKernelTCXSlot(l)
	if err != nil {
		_ = l.Close()
		return kernelXDPPluginTCFallback{}, false
	}
	return kernelXDPPluginTCFallback{key: key, slot: slot}, true
}

// detachKernelXDPPluginTCFallbackMetadata takes down positions recorded by a
// predecessor or a crashed owner. A tcx link that no pin keeps went away with
// its process.
func detachKernelXDPPluginTCFallbackMetadata(items []kernelHotRestartTCAttachment) error {
	var failures []error
	for _, item := range items {
		key, ok := kernelXDPPluginTCFallbackKeyFromMetadata(item)
		if !ok {
			continue
		}
		position, ok := loadKernelXDPPluginTCFallbackPredecessor(key)
		if !ok {
			continue
		}
		if err := position.detach(); err != nil {
			failures = append(failures, fmt.Errorf("detach tc fallback from %s: %w", xdpInterfaceLabel(key.linkIndex), err))
		}
	}
	return errors.Join(failures...)
}

func closeKernelXDPPluginTCFallbacks(positions []kernelXDPPluginTCFallback) {
	for _, position := range positions {
		if position.slot != nil && position.slot.link != nil {
			_ = position.slot.link.Close()
			position.slot.link = nil
			position.slot.linkID = 0
		}
	}
}
