//go:build linux

package app

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// The experimental flow cache (kernel_tc_flow_cache): tc_flow_cache runs on
// each ingress hook of the core, ahead of it, and sends packets of
// established egress NAT flows the way the core's fast path last sent them,
// with one lookup. The core records those entries and never records one for
// an interface where a plugin hook runs on ingress, so such interfaces keep
// the full path. An entry expires with its flow's fast-path window.
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
	Pad        [4]byte
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

// appendFlowCacheAttachmentPlans puts tc_flow_cache on every ingress hook of
// the core.
func appendFlowCacheAttachmentPlans(plans []kernelAttachmentPlan, sets kernelAttachmentRuleSets, programs kernelAttachmentPrograms) []kernelAttachmentPlan {
	if programs.flowCacheProg == nil {
		return plans
	}
	seen := make(map[int]struct{}, len(sets.ForwardIngress)+len(sets.ReplyIngress))
	for _, targets := range []map[int][]int64{sets.ForwardIngress, sets.ReplyIngress} {
		for ifindex := range targets {
			if _, ok := seen[ifindex]; ok {
				continue
			}
			seen[ifindex] = struct{}{}
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
	}
	return plans
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

// invalidateKernelTCFlowCache makes every recorded entry stale and reports
// whether the cache is enabled.
func invalidateKernelTCFlowCache(m *ebpf.Map) bool {
	if m == nil {
		return false
	}
	var state tcFlowCacheStateV4
	if err := m.Lookup(uint32(0), &state); err != nil || state.Enabled == 0 {
		return false
	}
	state.Generation++
	return m.Put(uint32(0), state) == nil
}

// settleKernelTCFlowCache invalidates again once the packets that were in
// flight during a change have left the BPF programs. The core reads rules and
// flows when a packet arrives but the generation only when it records the
// entry, so such a packet can record what it saw before the change under the
// generation that the first invalidation set.
func settleKernelTCFlowCache(m *ebpf.Map) {
	if m == nil {
		return
	}
	var state tcFlowCacheStateV4
	if err := m.Lookup(uint32(0), &state); err != nil || state.Enabled == 0 {
		return
	}
	time.Sleep(kernelPluginPipelineUpdateGrace)
	invalidateKernelTCFlowCache(m)
}
