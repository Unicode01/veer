package app

import (
	"testing"
	"time"
)

func TestProcessManagerShouldReloadManagedNetworkRuntimeForInterface(t *testing.T) {
	t.Parallel()

	pm := &ProcessManager{
		managedNetworkInterfaces: map[string]struct{}{
			"vmbr1": {},
			"eno1":  {},
		},
		ipv6AssignmentsConfigured: true,
		ipv6AssignmentInterfaces: map[string]struct{}{
			"vmbr0":    {},
			"tap100i0": {},
		},
	}

	if !pm.shouldReloadManagedNetworkRuntimeForInterface("vmbr1") {
		t.Fatal("shouldReloadManagedNetworkRuntimeForInterface(vmbr1) = false, want true")
	}
	if !pm.shouldReloadManagedNetworkRuntimeForInterface("vmbr0") {
		t.Fatal("shouldReloadManagedNetworkRuntimeForInterface(vmbr0) = false, want true")
	}
	if pm.shouldReloadManagedNetworkRuntimeForInterface("eno9") {
		t.Fatal("shouldReloadManagedNetworkRuntimeForInterface(eno9) = true, want false")
	}
	if !pm.shouldReloadManagedNetworkRuntimeForInterface("fwpr100p0") {
		t.Fatal("shouldReloadManagedNetworkRuntimeForInterface(fwpr100p0) = false, want true for dynamic guest link")
	}
	if !pm.shouldReloadManagedNetworkRuntimeForInterface("tap200i0") {
		t.Fatal("shouldReloadManagedNetworkRuntimeForInterface(tap200i0) = false, want true for dynamic guest link")
	}
	if !pm.shouldReloadManagedNetworkRuntimeForInterface("") {
		t.Fatal("shouldReloadManagedNetworkRuntimeForInterface(\"\") = false, want true when interface name is unavailable")
	}
}

func TestRequestManagedNetworkRuntimeReloadDebounce(t *testing.T) {
	t.Parallel()

	pm := &ProcessManager{
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
	}

	pm.requestManagedNetworkRuntimeReload(50*time.Millisecond, "vmbr1")
	pm.mu.Lock()
	firstDueAt := pm.managedRuntimeReloadDueAt
	firstPending := pm.managedRuntimeReloadPending
	_, firstHasVMBr1 := pm.managedRuntimeReloadInterfaces["vmbr1"]
	pm.mu.Unlock()
	if !firstPending {
		t.Fatal("managedRuntimeReloadPending = false, want true after first request")
	}
	if !firstHasVMBr1 {
		t.Fatal("managedRuntimeReloadInterfaces missing vmbr1 after first request")
	}

	time.Sleep(10 * time.Millisecond)
	pm.requestManagedNetworkRuntimeReload(50*time.Millisecond, "tap100i0")
	pm.mu.Lock()
	secondDueAt := pm.managedRuntimeReloadDueAt
	_, secondHasTap := pm.managedRuntimeReloadInterfaces["tap100i0"]
	pm.mu.Unlock()
	if !secondDueAt.After(firstDueAt) {
		t.Fatalf("second dueAt = %v, want after first dueAt %v for trailing-edge debounce", secondDueAt, firstDueAt)
	}
	if !secondHasTap {
		t.Fatal("managedRuntimeReloadInterfaces missing tap100i0 after second request")
	}

	pm.requestManagedNetworkRuntimeReload(0)
	pm.mu.Lock()
	thirdDueAt := pm.managedRuntimeReloadDueAt
	pm.mu.Unlock()
	if thirdDueAt.After(secondDueAt) {
		t.Fatalf("third dueAt = %v, want immediate request to keep or pull in schedule from %v", thirdDueAt, secondDueAt)
	}
}

func TestSnapshotManagedNetworkRuntimeReloadStatus(t *testing.T) {
	t.Parallel()

	pm := &ProcessManager{
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
	}

	pm.requestManagedNetworkRuntimeReloadWithSource(50*time.Millisecond, "link_change", "vmbr1", "tap100i0")

	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if !status.Pending {
		t.Fatal("Pending = false, want true")
	}
	if status.LastRequestSource != "link_change" {
		t.Fatalf("LastRequestSource = %q, want link_change", status.LastRequestSource)
	}
	if status.LastRequestSummary != "tap100i0,vmbr1" {
		t.Fatalf("LastRequestSummary = %q, want tap100i0,vmbr1", status.LastRequestSummary)
	}
	if status.LastRequestedAt.IsZero() {
		t.Fatal("LastRequestedAt = zero, want recorded request time")
	}
	if status.DueAt.IsZero() {
		t.Fatal("DueAt = zero, want scheduled due time")
	}
}

func TestSummarizeManagedRuntimeReloadInterfaces(t *testing.T) {
	t.Parallel()

	if got := summarizeManagedRuntimeReloadInterfaces(map[string]struct{}{
		"tap100i0":  {},
		"vmbr1":     {},
		"eno1":      {},
		"fwpr100p0": {},
	}); got != "eno1,fwpr100p0,tap100i0,+1" {
		t.Fatalf("summarizeManagedRuntimeReloadInterfaces() = %q", got)
	}
}

func TestUniqueManagedNetworkRuntimeInterfaceNames(t *testing.T) {
	t.Parallel()

	got := uniqueManagedNetworkRuntimeInterfaceNames(" vmbr1 ", "tap100i0", "vmbr1", "", "tap100i0", "eno1")
	if len(got) != 3 {
		t.Fatalf("len(uniqueManagedNetworkRuntimeInterfaceNames()) = %d, want 3 (%v)", len(got), got)
	}
	if got[0] != "vmbr1" || got[1] != "tap100i0" || got[2] != "eno1" {
		t.Fatalf("uniqueManagedNetworkRuntimeInterfaceNames() = %v, want [vmbr1 tap100i0 eno1]", got)
	}
}

func TestRequestManagedNetworkRuntimeReloadForRelevantInterfacesQueuesTrackedInterfaces(t *testing.T) {
	t.Parallel()

	pm := &ProcessManager{
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedNetworkInterfaces: map[string]struct{}{
			"vmbr1": {},
		},
		ipv6AssignmentsConfigured: true,
		ipv6AssignmentInterfaces: map[string]struct{}{
			"eno1": {},
		},
	}

	if !pm.requestManagedNetworkRuntimeReloadForRelevantInterfaces("link_change", "tap100i0", "vmbr1", "vmbr1") {
		t.Fatal("requestManagedNetworkRuntimeReloadForRelevantInterfaces() = false, want true")
	}

	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if !status.Pending {
		t.Fatal("Pending = false, want true")
	}
	if status.LastRequestSource != "link_change" {
		t.Fatalf("LastRequestSource = %q, want link_change", status.LastRequestSource)
	}
	if status.LastRequestSummary != "tap100i0,vmbr1" {
		t.Fatalf("LastRequestSummary = %q, want tap100i0,vmbr1", status.LastRequestSummary)
	}
}

func TestRequestManagedNetworkRuntimeReloadForRelevantInterfacesIgnoresUntrackedInterfaces(t *testing.T) {
	t.Parallel()

	pm := &ProcessManager{
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedNetworkInterfaces: map[string]struct{}{
			"vmbr1": {},
		},
	}

	if pm.requestManagedNetworkRuntimeReloadForRelevantInterfaces("link_change", "eno9", "eno10") {
		t.Fatal("requestManagedNetworkRuntimeReloadForRelevantInterfaces() = true, want false")
	}

	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if status.Pending {
		t.Fatal("Pending = true, want false")
	}
}

func TestRequestManagedNetworkRuntimeReloadForRelevantInterfacesIgnoresSuppressedTrackedInterfaces(t *testing.T) {
	t.Parallel()

	pm := &ProcessManager{
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedNetworkInterfaces: map[string]struct{}{
			"vmbr1": {}},
		managedRuntimeReloadSuppressUntil: make(map[string]time.Time),
	}
	pm.suppressManagedNetworkRuntimeReloadForInterfaces(time.Minute, "vmbr1", "tap100i0")

	if pm.requestManagedNetworkRuntimeReloadForRelevantInterfaces("link_change", "tap100i0", "vmbr1") {
		t.Fatal("requestManagedNetworkRuntimeReloadForRelevantInterfaces() = true, want false while interfaces are suppressed")
	}

	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if status.Pending {
		t.Fatal("Pending = true, want false")
	}
}

func TestRequestManagedNetworkRuntimeReloadForRelevantInterfacesQueuesUnsuppressedTrackedInterfaces(t *testing.T) {
	t.Parallel()

	pm := &ProcessManager{
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedNetworkInterfaces: map[string]struct{}{
			"vmbr1": {}},
		managedRuntimeReloadSuppressUntil: make(map[string]time.Time),
	}
	pm.suppressManagedNetworkRuntimeReloadForInterfaces(time.Minute, "vmbr1")

	if !pm.requestManagedNetworkRuntimeReloadForRelevantInterfaces("link_change", "tap100i0", "vmbr1") {
		t.Fatal("requestManagedNetworkRuntimeReloadForRelevantInterfaces() = false, want true for unsuppressed tap100i0")
	}

	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if !status.Pending {
		t.Fatal("Pending = false, want true")
	}
	if status.LastRequestSummary != "tap100i0" {
		t.Fatalf("LastRequestSummary = %q, want tap100i0", status.LastRequestSummary)
	}
}
