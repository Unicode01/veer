//go:build !linux

package kernelcap

import "runtime"

func DetectAdaptiveMapTotalMemory() uint64 {
	return 0
}

func detectKernelCapabilities() KernelCapabilities {
	reason := "kernel dataplane requires Linux"
	check := CapabilityCheck{
		Available: false,
		Reason:    reason,
	}
	return KernelCapabilities{
		OS:                 runtime.GOOS,
		Arch:               runtime.GOARCH,
		BPFMapArray:        check,
		BPFMapHash:         check,
		BPFMapLRUHash:      check,
		BPFMapPerCPUHash:   check,
		BPFMapPerCPUArray:  check,
		BPFMapProgArray:    check,
		BPFMapDevMapHash:   check,
		BPFMapRingBuf:      check,
		BPFSchedCLS:        check,
		BPFXDP:             check,
		BPFNetfilter:       check,
		BPFNetfilterDynptr: check,
		TCAttach:           check,
		XDPGenericAttach:   check,
		NetfilterAttach:    check,
		TC:                 check,
		XDPGeneric:         check,
		Netfilter:          check,
		Netlink: NetlinkCapabilities{
			RouteSocket:       check,
			LinkList:          check,
			RouteList:         check,
			LinkSubscribe:     check,
			AddressSubscribe:  check,
			NeighborSubscribe: check,
			RouteSubscribe:    check,
		},
		IPRoute: IPRouteCapabilities{
			Command:   check,
			RuleShow:  check,
			RouteShow: check,
		},
		Warnings: []string{reason},
	}
}
