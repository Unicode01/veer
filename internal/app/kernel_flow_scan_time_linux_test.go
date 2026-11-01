//go:build linux

package app

import (
	"bytes"
	"fmt"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// A maintenance pass samples its clock before reading the maps. A packet may
// refresh a flow after that sample, including before a later batch is read.
// Exercise actual map deletion so a fresh entry cannot silently be pruned.
func TestKernelFlowPrunePreservesRefreshAfterScanStart(t *testing.T) {
	for _, engine := range []string{"tc4", "xdp4", "ipv6"} {
		for _, mode := range []string{"full", "batch", "incremental"} {
			for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
				t.Run(fmt.Sprintf("%s/%s/proto%d", engine, mode, proto), func(t *testing.T) {
					keySize, valueSize := uint32(unsafe.Sizeof(tcFlowKeyV4{})), uint32(unsafe.Sizeof(tcFlowValueV4{}))
					if engine == "xdp4" {
						valueSize = uint32(unsafe.Sizeof(xdpFlowValueV4{}))
					} else if engine == "ipv6" {
						keySize, valueSize = uint32(unsafe.Sizeof(tcFlowKeyV6{})), uint32(unsafe.Sizeof(tcFlowValueV6{}))
					}
					flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
						Name: "scan_time_test", Type: ebpf.Hash, KeySize: keySize, ValueSize: valueSize, MaxEntries: 16,
					})
					nowNS := uint64(kernelTCPFlowIdleTimeout + 1000000000)
					entries := []struct {
						name string
						seen uint64
						keep bool
					}{
						{"concurrent refresh", nowNS + 1000000, true},
						{"recent packet", nowNS - 1000000, true},
						{"idle timeout", 1, false},
						{"uninitialized timestamp", 0, false},
					}
					keys := make([]any, len(entries))
					original := make([][]byte, len(entries))
					for i, entry := range entries {
						port := uint16(3389 + i)
						flags := uint16(kernelFlowFlagCounted | kernelFlowFlagReplySeen)
						var value any
						switch engine {
						case "tc4":
							keys[i] = tcFlowKeyV4{IfIndex: 5, SrcAddr: 0xc000020a, DstAddr: 0xc6336402, SrcPort: port, DstPort: 53108, Proto: proto}
							value = tcFlowValueV4{RuleID: 7, Flags: flags, LastSeenNS: entry.seen, RuleRevision: 11, SessionID: uint64(i + 1)}
						case "xdp4":
							keys[i] = tcFlowKeyV4{IfIndex: 5, SrcAddr: 0xc000020a, DstAddr: 0xc6336402, SrcPort: port, DstPort: 53108, Proto: proto}
							value = xdpFlowValueV4{RuleID: 7, Flags: flags, LastSeenNS: entry.seen, RuleRevision: 11, SessionID: uint64(i + 1)}
						case "ipv6":
							keys[i] = tcFlowKeyV6{IfIndex: 5, SrcAddr: [16]byte{0x20, 1, 0xdb, 8, 0, 1}, DstAddr: [16]byte{0x20, 1, 0xdb, 8, 0, 2}, SrcPort: port, DstPort: 53108, Proto: proto}
							value = tcFlowValueV6{RuleID: 7, Flags: flags, LastSeenNS: entry.seen, RuleRevision: 11, SessionID: uint64(i + 1)}
						}
						if err := flows.Put(keys[i], value); err != nil {
							t.Fatal(err)
						}
						var err error
						original[i], err = flows.LookupBytes(keys[i])
						if err != nil {
							t.Fatal(err)
						}
					}
					metrics := kernelFlowPruneMetrics{Budget: 16}
					state := &kernelFlowPruneState{}
					var err error
					switch engine + "/" + mode {
					case "tc4/full":
						_, metrics, err = pruneStaleKernelFlowsFullInCollection(nil, flows, nil, nowNS, true, metrics, kernelTCPFlowIdleTimeout)
					case "tc4/batch":
						_, metrics, err = pruneStaleKernelFlowsBatch(nil, flows, nil, nowNS, true, state, metrics, kernelTCPFlowIdleTimeout)
					case "tc4/incremental":
						_, metrics, err = pruneStaleKernelFlowsIncrementalInCollection(nil, flows, nil, nowNS, true, state, metrics, kernelTCPFlowIdleTimeout)
					case "xdp4/full":
						_, metrics, err = pruneStaleXDPFlowsFullInCollection(nil, flows, nil, nowNS, true, metrics, kernelTCPFlowIdleTimeout)
					case "xdp4/batch":
						_, metrics, err = pruneStaleXDPFlowsBatch(nil, flows, nil, nowNS, true, state, metrics, kernelTCPFlowIdleTimeout)
					case "xdp4/incremental":
						_, metrics, err = pruneStaleXDPFlowsIncrementalInCollection(nil, flows, nil, nowNS, true, state, metrics, kernelTCPFlowIdleTimeout)
					case "ipv6/full":
						_, metrics, err = pruneStaleKernelFlowsV6FullInCollection(nil, flows, nil, nowNS, true, metrics, kernelTCPFlowIdleTimeout)
					case "ipv6/batch":
						_, metrics, err = pruneStaleKernelFlowsBatchV6(nil, flows, nil, nowNS, true, state, metrics, kernelTCPFlowIdleTimeout)
					case "ipv6/incremental":
						_, metrics, err = pruneStaleKernelFlowsIncrementalV6InCollection(nil, flows, nil, nowNS, true, state, metrics, kernelTCPFlowIdleTimeout)
					}
					if err != nil {
						t.Fatal(err)
					}
					for i, entry := range entries {
						got, err := flows.LookupBytes(keys[i])
						if err != nil {
							t.Fatal(err)
						}
						if entry.keep && !bytes.Equal(got, original[i]) {
							t.Errorf("%s: live flow changed or disappeared during maintenance", entry.name)
						} else if !entry.keep && got != nil {
							t.Errorf("%s: stale flow survived maintenance", entry.name)
						}
					}
					if metrics.Deleted != 2 || metrics.Scanned != len(entries) {
						t.Errorf("prune scanned/deleted = %d/%d, want %d/2", metrics.Scanned, metrics.Deleted, len(entries))
					}
				})
			}
		}
	}
}
