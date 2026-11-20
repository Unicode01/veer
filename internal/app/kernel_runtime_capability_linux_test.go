//go:build linux

package app

import (
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/kernelcap"
)

func TestTCKernelRuntimeUnavailableWhenCapabilitiesMissing(t *testing.T) {
	restore := setKernelRuntimeCapabilitiesForTest(t, kernelcap.KernelCapabilities{
		TC: kernelcap.CapabilityCheck{
			Available: false,
			Reason:    "TC dataplane unavailable: missing sched_cls",
		},
		XDPGeneric: kernelcap.CapabilityCheck{Available: true},
	})
	defer restore()

	rt := newTCKernelRuleRuntime(&Config{})
	available, reason := rt.Available()
	if available {
		t.Fatal("Available() = true, want false when TC capability is missing")
	}
	if !strings.Contains(reason, "missing sched_cls") {
		t.Fatalf("Available() reason = %q, want capability reason", reason)
	}
}

func TestXDPKernelRuntimeUnavailableWhenCapabilitiesMissing(t *testing.T) {
	restore := setKernelRuntimeCapabilitiesForTest(t, kernelcap.KernelCapabilities{
		TC: kernelcap.CapabilityCheck{Available: true},
		XDPGeneric: kernelcap.CapabilityCheck{
			Available: false,
			Reason:    "XDP generic dataplane unavailable: missing devmap hash",
		},
	})
	defer restore()

	rt, ok := newXDPKernelRuleRuntime(&Config{}).(*xdpKernelRuleRuntime)
	if !ok {
		t.Fatal("newXDPKernelRuleRuntime() did not return *xdpKernelRuleRuntime")
	}
	available, reason := rt.Available()
	if available {
		t.Fatal("Available() = true, want false when XDP capability is missing")
	}
	if !strings.Contains(reason, "missing devmap hash") {
		t.Fatalf("Available() reason = %q, want capability reason", reason)
	}
}

func setKernelRuntimeCapabilitiesForTest(t *testing.T, caps kernelcap.KernelCapabilities) func() {
	t.Helper()
	old := detectKernelRuntimeCapabilities
	detectKernelRuntimeCapabilities = func() kernelcap.KernelCapabilities {
		return caps
	}
	return func() {
		detectKernelRuntimeCapabilities = old
	}
}

func TestXDPKernelRuntimeDriverOnlyIgnoresTheGenericAttachProbe(t *testing.T) {
	ok := kernelcap.CapabilityCheck{Available: true}
	probe := kernelcap.CapabilityCheck{Reason: "XDP generic attach unavailable: operation not permitted"}
	restore := setKernelRuntimeCapabilitiesForTest(t, kernelcap.KernelCapabilities{
		BPFMapArray:       ok,
		BPFMapHash:        ok,
		BPFMapPerCPUHash:  ok,
		BPFMapPerCPUArray: ok,
		BPFMapProgArray:   ok,
		BPFMapDevMapHash:  ok,
		BPFXDP:            ok,
		XDPGenericAttach:  probe,
		XDPGeneric:        kernelcap.CapabilityCheck{Reason: "XDP generic dataplane unavailable: " + probe.Reason},
		Netlink: kernelcap.NetlinkCapabilities{
			RouteSocket: ok,
			LinkList:    ok,
			RouteList:   ok,
		},
	})
	defer restore()

	if reason := xdpKernelRuntimeCapabilityUnavailableReason(false); reason != "" {
		t.Fatalf("driver-only XDP unavailable: %q, want available", reason)
	}
	if reason := xdpKernelRuntimeCapabilityUnavailableReason(true); !strings.Contains(reason, "operation not permitted") {
		t.Fatalf("XDP with generic mode = %q, want the attach probe's reason", reason)
	}
}
