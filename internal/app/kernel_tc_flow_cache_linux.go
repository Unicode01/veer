//go:build linux

package app

import (
	"log"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// The experimental flow cache (kernel_tc_flow_cache): tc_flow_cache runs on
// each ingress hook where the core serves rules and no plugin hook runs,
// ahead of the core, and sends packets of established egress NAT flows the
// way the core's fast path last sent them, with one lookup. The core records
// those entries and never records one for an interface where a plugin hook
// runs on ingress, so such interfaces keep the full path. An entry expires
// with its flow's fast-path window.
const (
	kernelFlowCacheProgramName    = "tc_flow_cache"
	kernelTCFlowCacheMapName      = "tc_flow_cache_v4"
	kernelTCFlowCacheStateMapName = "tc_flow_cache_state_v4"
	// Ahead of the reply (10) and forward (20) programs on the same hook.
	kernelFlowCacheFilterPrio   = 5
	kernelFlowCacheFilterHandle = 5
)

type tcFlowCacheValueV4 struct {
	ExpiresNS  uint64
	Generation uint32
	OutIfIndex uint32
	MaxLen     uint32
	SrcAddr    uint32
	DstAddr    uint32
	SrcPort    uint16
	DstPort    uint16
	DMAC       [6]byte
	SMAC       [6]byte
	InIfIndex  uint32
	InDMAC     [6]byte
	Pad        [2]byte
}

type tcFlowCacheStateV4 struct {
	Generation uint32
	Enabled    uint32
}

// completeAttachmentPrograms adds what this runtime attaches on every hook
// besides the core programs: the attach API and the flow cache.
func (rt *linuxKernelRuleRuntime) completeAttachmentPrograms(programs *kernelAttachmentPrograms, coll *ebpf.Collection) {
	programs.tcx = rt.useTCX()
	programs.flowCacheProg = nil
	if rt.enableFlowCache && coll != nil {
		programs.flowCacheProg = coll.Programs[kernelFlowCacheProgramName]
	}
}

// kernelFlowCacheTargets lists the ingress hooks of the core where rules
// receive packets and no plugin hook runs. The core also runs on ingress
// hooks that only plugin hooks need, which carry no rule IDs, and it records
// no entry for packets entering an interface with an ingress plugin hook, so
// a cache on either could only miss.
func kernelFlowCacheTargets(sets kernelAttachmentRuleSets) map[int]struct{} {
	targets := make(map[int]struct{}, len(sets.ForwardIngress)+len(sets.ReplyIngress))
	if sets.PluginIngressHookedAll {
		return targets
	}
	for _, rules := range []map[int][]int64{sets.ForwardIngress, sets.ReplyIngress} {
		for ifindex, ids := range rules {
			if len(ids) == 0 {
				continue
			}
			if _, hooked := sets.PluginIngressHooked[ifindex]; hooked {
				continue
			}
			targets[ifindex] = struct{}{}
		}
	}
	return targets
}

// sameFlowCacheTargets reports whether both sets put the flow cache on the
// same interfaces. sameTargets ignores rule IDs and plugin hooks, so it
// misses an interface that keeps its plugin hooks after its last rule left
// and a rule interface that gains or loses an ingress hook.
func (sets kernelAttachmentRuleSets) sameFlowCacheTargets(other kernelAttachmentRuleSets) bool {
	a, b := kernelFlowCacheTargets(sets), kernelFlowCacheTargets(other)
	if len(a) != len(b) {
		return false
	}
	for ifindex := range a {
		if _, ok := b[ifindex]; !ok {
			return false
		}
	}
	return true
}

// appendFlowCacheAttachmentPlans puts tc_flow_cache on the ingress hooks of
// the core where rules receive packets.
func appendFlowCacheAttachmentPlans(plans []kernelAttachmentPlan, sets kernelAttachmentRuleSets, programs kernelAttachmentPrograms) []kernelAttachmentPlan {
	if programs.flowCacheProg == nil {
		return plans
	}
	for ifindex := range kernelFlowCacheTargets(sets) {
		plans = append(plans, kernelAttachmentPlan{
			key: kernelAttachmentKey{
				linkIndex: ifindex,
				parent:    netlink.HANDLE_MIN_INGRESS,
				priority:  kernelFlowCacheFilterPrio,
				handle:    netlink.MakeHandle(0, kernelFlowCacheFilterHandle),
				tcx:       programs.tcx,
			},
			ifindex:     ifindex,
			priority:    kernelFlowCacheFilterPrio,
			handleMinor: kernelFlowCacheFilterHandle,
			name:        kernelFlowCacheProgramName,
			prog:        programs.flowCacheProg,
			attach:      kernelPluginPipelineAttachIngress,
			flowCache:   true,
		})
	}
	return plans
}

// isFlowCache reports whether key is the flow cache's position on an
// ingress hook.
func (key kernelAttachmentKey) isFlowCache() bool {
	return key.parent == netlink.HANDLE_MIN_INGRESS && key.priority == kernelFlowCacheFilterPrio
}

// withoutUnplannedFlowCache drops the flow caches that planned does not hold
// from attachments. An in-place reconcile keeps the old attachments it no
// longer plans, but no rule depends on the flow cache, and one kept on an
// interface that gained an ingress plugin hook would still run ahead of the
// hook there.
func withoutUnplannedFlowCache(attachments, planned []kernelAttachment) []kernelAttachment {
	plannedKeys := kernelAttachmentKeySet(planned)
	out := make([]kernelAttachment, 0, len(attachments))
	for _, att := range attachments {
		if key, ok := att.key(); ok && key.isFlowCache() {
			if _, ok := plannedKeys[key]; !ok {
				continue
			}
		}
		out = append(out, att)
	}
	return out
}

// configureKernelTCFlowCache lets the core of a freshly loaded collection
// record entries. A new collection starts with an empty cache.
func configureKernelTCFlowCache(m *ebpf.Map, enabled bool) error {
	if m == nil {
		return nil
	}
	state := tcFlowCacheStateV4{Generation: 1}
	if enabled {
		state.Enabled = 1
	}
	return m.Put(uint32(0), state)
}

// kernelTCFlowCacheBumpMu makes each generation bump a single step: the BPF
// programs only read the state, but two bumps from user space that both read
// the same generation would write it once, and a late one could even move it
// back past a bump made in between.
var kernelTCFlowCacheBumpMu sync.Mutex

// invalidateKernelTCFlowCache makes every recorded entry stale and reports
// whether the cache is enabled.
func invalidateKernelTCFlowCache(m *ebpf.Map) bool {
	if m == nil {
		return false
	}
	kernelTCFlowCacheBumpMu.Lock()
	defer kernelTCFlowCacheBumpMu.Unlock()
	var state tcFlowCacheStateV4
	if err := m.Lookup(uint32(0), &state); err != nil || state.Enabled == 0 {
		return false
	}
	state.Generation++
	return m.Put(uint32(0), state) == nil
}

// settleKernelTCFlowCache invalidates now, after a change, and once more when
// the packets that were in flight during it have left the BPF programs. The
// core reads rules, flows and plugin hooks when a packet arrives but the
// generation only when it records the entry, with no ordering between those
// loads, so such a packet can record what it saw before the change under the
// generation the first invalidation set. The second one runs on a timer,
// against its own handle of the map, so callers do not hold their locks
// through the grace period and a collection closed meanwhile does not matter.
func settleKernelTCFlowCache(m *ebpf.Map) {
	if !invalidateKernelTCFlowCache(m) {
		return
	}
	handle, err := m.Clone()
	if err != nil {
		log.Printf("kernel dataplane flow cache: delayed invalidation unavailable, invalidating after the grace period inline: %v", err)
		time.Sleep(kernelPluginPipelineUpdateGrace)
		invalidateKernelTCFlowCache(m)
		return
	}
	time.AfterFunc(kernelPluginPipelineUpdateGrace, func() {
		defer handle.Close()
		invalidateKernelTCFlowCache(handle)
	})
}
