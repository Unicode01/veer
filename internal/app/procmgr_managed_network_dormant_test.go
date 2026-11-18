package app

import (
	"errors"
	"testing"
	"time"
)

// returningDormantIPv6Runtime reports dormant assignment targets that exist
// again, as after a guest restart recreated its tap under the same name.
type returningDormantIPv6Runtime struct {
	*fakeIPv6AssignmentRuntime
	returned []string
}

func (rt *returningDormantIPv6Runtime) ReturnedDormantTargets() []string {
	return append([]string(nil), rt.returned...)
}

func TestDetectManagedNetworkRuntimeDriftReloadsReturnedDormantTargets(t *testing.T) {
	db := openTestDB(t)
	runtime := &returningDormantIPv6Runtime{fakeIPv6AssignmentRuntime: &fakeIPv6AssignmentRuntime{}}
	pm := &ProcessManager{
		db:                        db,
		cfg:                       &Config{DefaultEngine: ruleEngineAuto},
		ipv6Runtime:               runtime,
		ipv6AssignmentsConfigured: true,
		managedRuntimeReloadWake:  make(chan struct{}, 1),
	}

	// Nothing came back and nothing was applied yet: no reload.
	pm.detectManagedNetworkRuntimeDrift()
	if pm.managedRuntimeReloadPending {
		t.Fatal("drift check queued a reload with no returned dormant target")
	}

	// The effective state is unchanged (no applied fingerprint to compare
	// against even), yet the returned target must bring a reload.
	runtime.returned = []string{"tap101i0"}
	pm.detectManagedNetworkRuntimeDrift()
	if !pm.managedRuntimeReloadPending || pm.managedRuntimeReloadLastRequestSource != "drift_check" {
		t.Fatalf("pending=%v source=%q, want a drift_check reload queued", pm.managedRuntimeReloadPending, pm.managedRuntimeReloadLastRequestSource)
	}
	if _, ok := pm.managedRuntimeReloadInterfaces["tap101i0"]; !ok {
		t.Fatalf("queued reload interfaces = %v, want tap101i0", pm.managedRuntimeReloadInterfaces)
	}
}

func TestScheduleManagedNetworkRuntimeRetryBacksOffAndResets(t *testing.T) {
	pm := &ProcessManager{managedRuntimeReloadWake: make(chan struct{}, 1)}
	failure := errors.New("ipv6 assignment runtime reconcile: route via tap101i0: Link not found")

	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, time.Minute, time.Minute}
	for i, delay := range want {
		before := time.Now()
		pm.scheduleManagedNetworkRuntimeRetry(failure)
		if !pm.managedRuntimeReloadPending || pm.managedRuntimeReloadLastRequestSource != "retry" {
			t.Fatalf("attempt %d: pending=%v source=%q, want a retry queued", i+1, pm.managedRuntimeReloadPending, pm.managedRuntimeReloadLastRequestSource)
		}
		if due := pm.managedRuntimeReloadDueAt; due.Before(before.Add(delay)) || due.After(time.Now().Add(delay)) {
			t.Fatalf("attempt %d: retry due in %s, want %s", i+1, due.Sub(before), delay)
		}
		pm.managedRuntimeReloadPending = false
		pm.managedRuntimeReloadDueAt = time.Time{}
	}

	// A reload already queued is not pushed back by a retry.
	pm.managedRuntimeReloadPending = true
	due := time.Now().Add(time.Second)
	pm.managedRuntimeReloadDueAt = due
	pm.scheduleManagedNetworkRuntimeRetry(failure)
	if !pm.managedRuntimeReloadDueAt.Equal(due) {
		t.Fatalf("queued reload moved to %v, want it kept at %v", pm.managedRuntimeReloadDueAt, due)
	}

	pm.managedRuntimeReloadPending = false
	pm.scheduleManagedNetworkRuntimeRetry(nil)
	if pm.managedRuntimeReloadPending || pm.managedRuntimeReloadRetryDelay != 0 {
		t.Fatalf("after a clean reload pending=%v delay=%s, want no retry and the backoff reset", pm.managedRuntimeReloadPending, pm.managedRuntimeReloadRetryDelay)
	}
}

func TestNoteManagedRuntimeLinkLifecycleSpotsNewInstances(t *testing.T) {
	pm := &ProcessManager{}
	steps := []struct {
		name        string
		ifindex     int
		master      int
		deleted     bool
		want        bool
		description string
	}{
		{"tap101i0", 46, 0, false, true, "first sight"},
		{"tap101i0", 46, 0, false, false, "same instance again"},
		{"tap101i0", 46, 7, false, true, "enslaved to a bridge"},
		{"tap101i0", 46, 7, false, false, "up/down on the same instance"},
		{"tap101i0", 46, 7, true, true, "removed"},
		{"tap101i0", 52, 0, false, true, "recreated under the same name"},
		{"tap101i0", 52, 7, false, true, "recreated tap enslaved"},
		{"", 9, 0, false, false, "no name"},
	}
	for _, step := range steps {
		if got := pm.noteManagedRuntimeLinkLifecycle(step.name, step.ifindex, step.master, step.deleted); got != step.want {
			t.Fatalf("%s: noteManagedRuntimeLinkLifecycle() = %v, want %v", step.description, got, step.want)
		}
	}
}

func TestClearManagedNetworkRuntimeReloadSuppressionLetsNameThrough(t *testing.T) {
	pm := &ProcessManager{managedRuntimeReloadSuppressUntil: map[string]time.Time{}}
	pm.suppressManagedNetworkRuntimeReloadForInterfaces(managedNetworkLinkChangeSuppressFor, "tap101i0", "vmbr1")
	pm.clearManagedNetworkRuntimeReloadSuppression("tap101i0")
	got := pm.filterSuppressedManagedNetworkRuntimeInterfaces("tap101i0", "vmbr1")
	if len(got) != 1 || got[0] != "tap101i0" {
		t.Fatalf("unsuppressed interfaces = %v, want only tap101i0", got)
	}
}
