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
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		BPFMapArray:       check,
		BPFMapHash:        check,
		BPFMapLRUHash:     check,
		BPFMapPerCPUHash:  check,
		BPFMapPerCPUArray: check,
		BPFMapProgArray:   check,
		BPFMapDevMapHash:  check,
		BPFSchedCLS:       check,
		BPFXDP:            check,
		TCAttach:          check,
		XDPGenericAttach:  check,
		TC:                check,
		XDPGeneric:        check,
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
