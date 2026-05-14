package kernelcap

import (
	"strings"
	"testing"
)

func TestCombineCapabilityReportsAllMissingReasons(t *testing.T) {
	got := combineCapability(
		"TC dataplane",
		CapabilityCheck{Available: true},
		CapabilityCheck{Reason: "missing sched_cls"},
		CapabilityCheck{},
	)
	if got.Available {
		t.Fatal("combined capability = available, want unavailable")
	}
	if !strings.Contains(got.Reason, "TC dataplane unavailable") {
		t.Fatalf("reason = %q, want combined label", got.Reason)
	}
	if !strings.Contains(got.Reason, "missing sched_cls") || !strings.Contains(got.Reason, "required capability is unavailable") {
		t.Fatalf("reason = %q, want all missing reasons", got.Reason)
	}
}

func TestKernelCapabilityWarningsSummarizeCriticalFailures(t *testing.T) {
	caps := KernelCapabilities{
		TC:         CapabilityCheck{Reason: "tc missing"},
		XDPGeneric: CapabilityCheck{Reason: "xdp missing"},
		Netlink: NetlinkCapabilities{
			RouteSocket:       CapabilityCheck{Available: true},
			LinkList:          CapabilityCheck{Available: true},
			RouteList:         CapabilityCheck{Reason: "route list failed"},
			LinkSubscribe:     CapabilityCheck{Available: true},
			AddressSubscribe:  CapabilityCheck{Available: true},
			NeighborSubscribe: CapabilityCheck{Reason: "neighbor subscribe failed"},
		},
	}

	warnings := strings.Join(kernelCapabilityWarnings(caps), "\n")
	for _, want := range []string{
		"tc kernel dataplane unavailable",
		"xdp kernel dataplane unavailable",
		"netlink inventory is incomplete",
		"netlink subscriptions are incomplete",
	} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("warnings = %q, missing %q", warnings, want)
		}
	}
}
