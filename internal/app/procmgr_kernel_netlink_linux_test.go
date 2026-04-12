//go:build linux

package app

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestHandleVisibleInterfaceAddrUpdateIPv6QueuesRuntimeReloadAndRedistribute(t *testing.T) {
	pm := &ProcessManager{
		ipv6AssignmentsConfigured: true,
		ipv6AssignmentInterfaces: map[string]struct{}{
			"vmbr0": {},
		},
		managedRuntimeReloadWake: make(chan struct{}, 1),
		redistributeWake:         make(chan struct{}, 1),
	}

	pm.handleVisibleInterfaceAddrUpdate(unix.AF_INET6, "vmbr0", "vmbr0")

	if !pm.managedRuntimeReloadPending {
		t.Fatal("managedRuntimeReloadPending = false, want true after IPv6 address change")
	}
	if !pm.redistributePending {
		t.Fatal("redistributePending = false, want true after IPv6 address change")
	}
	if pm.managedRuntimeReloadLastRequestSource != "link_change" {
		t.Fatalf("managedRuntimeReloadLastRequestSource = %q, want link_change", pm.managedRuntimeReloadLastRequestSource)
	}
	if pm.managedRuntimeReloadLastRequestSummary != "vmbr0" {
		t.Fatalf("managedRuntimeReloadLastRequestSummary = %q, want vmbr0", pm.managedRuntimeReloadLastRequestSummary)
	}
}

func TestHandleVisibleInterfaceAddrUpdateIPv4SkipsRedistribute(t *testing.T) {
	pm := &ProcessManager{
		ipv6AssignmentsConfigured: true,
		ipv6AssignmentInterfaces: map[string]struct{}{
			"vmbr0": {},
		},
		managedRuntimeReloadWake: make(chan struct{}, 1),
		redistributeWake:         make(chan struct{}, 1),
	}

	pm.handleVisibleInterfaceAddrUpdate(unix.AF_INET, "vmbr0", "vmbr0")

	if !pm.managedRuntimeReloadPending {
		t.Fatal("managedRuntimeReloadPending = false, want true after IPv4 address change")
	}
	if pm.redistributePending {
		t.Fatal("redistributePending = true, want false after IPv4 address change")
	}
}
