//go:build linux

package app

import "github.com/Unicode01/veer/internal/kernelcap"

var detectKernelRuntimeCapabilities = kernelcap.DetectKernelCapabilities

func tcKernelRuntimeCapabilityUnavailableReason() string {
	caps := detectKernelRuntimeCapabilities()
	if caps.TC.Available {
		return ""
	}
	if caps.TC.Reason != "" {
		return caps.TC.Reason
	}
	return "TC dataplane unavailable on this kernel"
}

// xdpKernelRuntimeCapabilityUnavailableReason checks the XDP dataplane for
// the attach modes the runtime may use. Without generic mode it attaches in
// driver mode only, which the generic attach probe on lo says nothing about.
func xdpKernelRuntimeCapabilityUnavailableReason(allowGeneric bool) string {
	caps := detectKernelRuntimeCapabilities()
	check, label := caps.XDPGeneric, "XDP generic dataplane"
	if !allowGeneric {
		check, label = caps.XDPDriverDataplane(), "XDP driver dataplane"
	}
	if check.Available {
		return ""
	}
	if check.Reason != "" {
		return check.Reason
	}
	return label + " unavailable on this kernel"
}
