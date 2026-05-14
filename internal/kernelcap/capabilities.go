package kernelcap

import (
	"fmt"
	"strings"
	"sync"
)

type CapabilityCheck struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type NetlinkCapabilities struct {
	RouteSocket       CapabilityCheck `json:"route_socket"`
	LinkList          CapabilityCheck `json:"link_list"`
	RouteList         CapabilityCheck `json:"route_list"`
	LinkSubscribe     CapabilityCheck `json:"link_subscribe"`
	AddressSubscribe  CapabilityCheck `json:"address_subscribe"`
	NeighborSubscribe CapabilityCheck `json:"neighbor_subscribe"`
	RouteSubscribe    CapabilityCheck `json:"route_subscribe"`
}

type IPRouteCapabilities struct {
	Command   CapabilityCheck `json:"command"`
	RuleShow  CapabilityCheck `json:"rule_show"`
	RouteShow CapabilityCheck `json:"route_show"`
	Path      string          `json:"path,omitempty"`
}

type KernelCapabilities struct {
	OS                string              `json:"os"`
	Arch              string              `json:"arch"`
	KernelRelease     string              `json:"kernel_release,omitempty"`
	BPFMapArray       CapabilityCheck     `json:"bpf_map_array"`
	BPFMapHash        CapabilityCheck     `json:"bpf_map_hash"`
	BPFMapLRUHash     CapabilityCheck     `json:"bpf_map_lru_hash"`
	BPFMapPerCPUHash  CapabilityCheck     `json:"bpf_map_percpu_hash"`
	BPFMapPerCPUArray CapabilityCheck     `json:"bpf_map_percpu_array"`
	BPFMapProgArray   CapabilityCheck     `json:"bpf_map_prog_array"`
	BPFMapDevMapHash  CapabilityCheck     `json:"bpf_map_devmap_hash"`
	BPFSchedCLS       CapabilityCheck     `json:"bpf_sched_cls"`
	BPFXDP            CapabilityCheck     `json:"bpf_xdp"`
	TCAttach          CapabilityCheck     `json:"tc_attach"`
	XDPGenericAttach  CapabilityCheck     `json:"xdp_generic_attach"`
	TC                CapabilityCheck     `json:"tc"`
	XDPGeneric        CapabilityCheck     `json:"xdp_generic"`
	Netlink           NetlinkCapabilities `json:"netlink"`
	IPRoute           IPRouteCapabilities `json:"ip_route"`
	Warnings          []string            `json:"warnings,omitempty"`
}

var (
	kernelCapabilitiesOnce sync.Once
	kernelCapabilities     KernelCapabilities
)

func DetectKernelCapabilities() KernelCapabilities {
	kernelCapabilitiesOnce.Do(func() {
		kernelCapabilities = detectKernelCapabilities()
	})
	return kernelCapabilities
}

func combineCapability(label string, checks ...CapabilityCheck) CapabilityCheck {
	var reasons []string
	for _, check := range checks {
		if check.Available {
			continue
		}
		reason := strings.TrimSpace(check.Reason)
		if reason == "" {
			reason = "required capability is unavailable"
		}
		reasons = append(reasons, reason)
	}
	if len(reasons) == 0 {
		return CapabilityCheck{Available: true}
	}
	return CapabilityCheck{
		Available: false,
		Reason:    fmt.Sprintf("%s unavailable: %s", label, strings.Join(reasons, "; ")),
	}
}

func kernelCapabilityWarnings(caps KernelCapabilities) []string {
	var warnings []string
	if !caps.TC.Available {
		warnings = append(warnings, "tc kernel dataplane unavailable: "+caps.TC.Reason)
	}
	if !caps.TCAttach.Available && caps.TCAttach.Reason != "" {
		warnings = append(warnings, "tc attach probe unavailable: "+caps.TCAttach.Reason)
	}
	if !caps.XDPGeneric.Available {
		warnings = append(warnings, "xdp kernel dataplane unavailable: "+caps.XDPGeneric.Reason)
	}
	if !caps.XDPGenericAttach.Available && caps.XDPGenericAttach.Reason != "" {
		warnings = append(warnings, "xdp generic attach probe unavailable: "+caps.XDPGenericAttach.Reason)
	}
	if !caps.Netlink.RouteSocket.Available {
		warnings = append(warnings, "netlink route socket unavailable: "+caps.Netlink.RouteSocket.Reason)
	}
	if !caps.Netlink.LinkList.Available || !caps.Netlink.RouteList.Available {
		warnings = append(warnings, "netlink inventory is incomplete; interface and route detection may fail")
	}
	if !caps.Netlink.LinkSubscribe.Available || !caps.Netlink.AddressSubscribe.Available || !caps.Netlink.NeighborSubscribe.Available {
		warnings = append(warnings, "netlink subscriptions are incomplete; hotplug/self-heal may need manual refresh")
	}
	if !caps.IPRoute.Command.Available {
		warnings = append(warnings, "ip command unavailable: "+caps.IPRoute.Command.Reason)
	} else if !caps.IPRoute.RuleShow.Available || !caps.IPRoute.RouteShow.Available {
		warnings = append(warnings, "ip route command support is incomplete; transparent routing setup may fail")
	}
	return warnings
}
