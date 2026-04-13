//go:build linux

package app

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestHandleVisibleInterfaceAddrUpdateIPv6QueuesAddrRuntimeReloadWithoutRedistribute(t *testing.T) {
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
	if pm.redistributePending {
		t.Fatal("redistributePending = true, want false after IPv6 address change")
	}
	if pm.managedRuntimeReloadLastRequestSource != "addr_change" {
		t.Fatalf("managedRuntimeReloadLastRequestSource = %q, want addr_change", pm.managedRuntimeReloadLastRequestSource)
	}
	if pm.managedRuntimeReloadLastRequestSummary != "vmbr0" {
		t.Fatalf("managedRuntimeReloadLastRequestSummary = %q, want vmbr0", pm.managedRuntimeReloadLastRequestSummary)
	}
}

func TestHandleVisibleInterfaceAddrUpdateIPv6ManagedNetworkOnlySkipsFullRedistribute(t *testing.T) {
	pm := &ProcessManager{
		managedNetworkInterfaces: map[string]struct{}{
			"vmbr1": {},
		},
		managedRuntimeReloadWake: make(chan struct{}, 1),
		redistributeWake:         make(chan struct{}, 1),
	}

	pm.handleVisibleInterfaceAddrUpdate(unix.AF_INET6, "vmbr1", "vmbr1")

	if !pm.managedRuntimeReloadPending {
		t.Fatal("managedRuntimeReloadPending = false, want true after managed-network IPv6 address change")
	}
	if pm.redistributePending {
		t.Fatal("redistributePending = true, want false for managed-network address change")
	}
	if pm.managedRuntimeReloadLastRequestSource != "addr_change" {
		t.Fatalf("managedRuntimeReloadLastRequestSource = %q, want addr_change", pm.managedRuntimeReloadLastRequestSource)
	}
	if pm.managedRuntimeReloadLastRequestSummary != "vmbr1" {
		t.Fatalf("managedRuntimeReloadLastRequestSummary = %q, want vmbr1", pm.managedRuntimeReloadLastRequestSummary)
	}
}

func TestHandleVisibleInterfaceAddrUpdateIPv4QueuesAddrRuntimeReloadWithoutRedistribute(t *testing.T) {
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
	if pm.managedRuntimeReloadLastRequestSource != "addr_change" {
		t.Fatalf("managedRuntimeReloadLastRequestSource = %q, want addr_change", pm.managedRuntimeReloadLastRequestSource)
	}
}
