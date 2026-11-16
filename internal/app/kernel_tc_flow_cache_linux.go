//go:build linux

package app

import (
	"log"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// The flow cache (the kernel_tc_flow_cache setting): the core's fast path
// records in the flow entry of an established egress NAT flow how it sent
// the packet (tcFlowFastV4), and the dispatcher sends the flow's next packets
// the same way straight from its flow lookup, before the rule lookup. The
// core never records for a packet entering an interface where a plugin hook
// runs on ingress, so such interfaces keep the full path. A record lasts
// until its entry's fast-path window ends; bumping the generation in
// tc_flow_cache_state_v4 retires all of them at once.
const (
	kernelTCFlowCacheStateMapName = "tc_flow_cache_state_v4"
	// Earlier releases attached a separate tc_flow_cache program here, ahead
	// of the reply (10) and forward (20) programs. Reconciles drop any such
	// filter they find (withoutUnplannedFlowCache).
	kernelFlowCacheFilterPrio   = 5
	kernelFlowCacheFilterHandle = 5
)

type tcFlowCacheStateV4 struct {
	Generation uint32
	Enabled    uint32
}

// kernelTCFlowCacheDisabledBy names the experimental feature that keeps a
// configured flow cache off, or returns "". With traffic stats, cached packets
// would bypass the per-rule counters. With the reply L2 cache or the neighbour
// redirect, the core's fast paths send packets without a next hop from the
// FIB, so it records no entry and the cache could only miss.
func kernelTCFlowCacheDisabledBy(trafficStats, replyL2Cache, redirectNeighFast bool) string {
	switch {
	case trafficStats:
		return experimentalFeatureKernelTraffic
	case replyL2Cache:
		return experimentalFeatureKernelTCReplyL2Cache
	case redirectNeighFast:
		return experimentalFeatureKernelTCRedirectNeighFast
	default:
		return ""
	}
}

// completeAttachmentPrograms adds what this runtime decides for every hook
// besides the core programs: the attach API.
func (rt *linuxKernelRuleRuntime) completeAttachmentPrograms(programs *kernelAttachmentPrograms, coll *ebpf.Collection) {
	programs.tcx = rt.useTCX()
}

// isFlowCache reports whether key is where earlier releases attached the
// flow cache program on an ingress hook.
func (key kernelAttachmentKey) isFlowCache() bool {
	return key.parent == netlink.HANDLE_MIN_INGRESS && key.priority == kernelFlowCacheFilterPrio
}

// withoutUnplannedFlowCache drops flow cache programs that planned does not
// hold from attachments. An in-place reconcile keeps the old attachments it
// no longer plans, but no rule depends on one, and nothing plans one any more:
// a program left by an earlier release would keep running ahead of the core,
// and of any plugin hook added later, with nothing recording its entries.
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
// record fast-path records. A new collection starts with none usable: flow
// entries carried over from the previous collection keep their records, so
// it starts at a random generation, which those records do not carry.
func configureKernelTCFlowCache(m *ebpf.Map, enabled bool) error {
	if m == nil {
		return nil
	}
	state := tcFlowCacheStateV4{Generation: rand.Uint32()}
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

// invalidateKernelTCFlowCache makes every fast-path record stale and reports
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
// generation only when it records, with no ordering between those loads, so
// such a packet can record what it saw before the change under the
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
