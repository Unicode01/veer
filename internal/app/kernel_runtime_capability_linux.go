//go:build linux

package app

import "forward/internal/kernelcap"

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

func xdpKernelRuntimeCapabilityUnavailableReason() string {
	caps := detectKernelRuntimeCapabilities()
	if caps.XDPGeneric.Available {
		return ""
	}
	if caps.XDPGeneric.Reason != "" {
		return caps.XDPGeneric.Reason
	}
	return "XDP generic dataplane unavailable on this kernel"
}
