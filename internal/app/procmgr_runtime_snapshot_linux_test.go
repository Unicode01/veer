//go:build linux

package app

import (
	"sync"
	"testing"
	"time"
)

type blockingKernelRuntimeSnapshotRuntime struct {
	started       chan struct{}
	release       chan struct{}
	mu            sync.Mutex
	startedClosed bool
	availableCall int
}

func (rt *blockingKernelRuntimeSnapshotRuntime) Available() (bool, string) {
	rt.mu.Lock()
	rt.availableCall++
	if !rt.startedClosed && rt.started != nil {
		close(rt.started)
		rt.startedClosed = true
	}
	rt.mu.Unlock()
	if rt.release != nil {
		<-rt.release
	}
	return true, "ok"
}

func (rt *blockingKernelRuntimeSnapshotRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return map[int64]kernelRuleApplyResult{}, nil
}

func (rt *blockingKernelRuntimeSnapshotRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (rt *blockingKernelRuntimeSnapshotRuntime) Maintain() error {
	return nil
}

func (rt *blockingKernelRuntimeSnapshotRuntime) SnapshotAssignments() map[int64]string {
	return map[int64]string{}
}

func (rt *blockingKernelRuntimeSnapshotRuntime) Close() error {
	return nil
}

func (rt *blockingKernelRuntimeSnapshotRuntime) AvailableCalls() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.availableCall
}

func TestSnapshotKernelRuntimeSharedDeduplicatesConcurrentSnapshots(t *testing.T) {
	rt := &blockingKernelRuntimeSnapshotRuntime{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	pm := &ProcessManager{
		cfg:           &Config{DefaultEngine: ruleEngineAuto},
		kernelRuntime: rt,
	}

	const callers = 4
	var wg sync.WaitGroup
	results := make([]KernelRuntimeResponse, callers)
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func(index int) {
			defer wg.Done()
			results[index] = pm.snapshotKernelRuntimeShared(time.Time{}, false)
		}(i)
	}

	select {
	case <-rt.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for runtime snapshot to start")
	}

	close(rt.release)
	wg.Wait()

	if got := rt.AvailableCalls(); got != 1 {
		t.Fatalf("Available() calls after concurrent shared snapshots = %d, want 1", got)
	}
	for i, result := range results {
		if !result.Available || result.AvailableReason != "ok" {
			t.Fatalf("result[%d] = %+v, want available runtime snapshot", i, result)
		}
	}

	cached := pm.snapshotKernelRuntimeShared(time.Time{}, false)
	if !cached.Available || cached.AvailableReason != "ok" {
		t.Fatalf("cached snapshot = %+v, want available runtime snapshot", cached)
	}
	if got := rt.AvailableCalls(); got != 1 {
		t.Fatalf("Available() calls after cached snapshot = %d, want 1", got)
	}

	fresh := pm.snapshotKernelRuntimeShared(time.Time{}, true)
	if !fresh.Available || fresh.AvailableReason != "ok" {
		t.Fatalf("fresh snapshot = %+v, want available runtime snapshot", fresh)
	}
	if got := rt.AvailableCalls(); got != 2 {
		t.Fatalf("Available() calls after forced fresh snapshot = %d, want 2", got)
	}
}

func TestSnapshotKernelRuntimeSharedDeduplicatesConcurrentForcedSnapshots(t *testing.T) {
	rt := &blockingKernelRuntimeSnapshotRuntime{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	pm := &ProcessManager{
		cfg:           &Config{DefaultEngine: ruleEngineAuto},
		kernelRuntime: rt,
	}

	const callers = 4
	var wg sync.WaitGroup
	results := make([]KernelRuntimeResponse, callers)

	// Start one forced refresh first so the remaining callers deterministically
	// join an in-flight snapshot instead of racing to start a second refresh
	// after the first one has already completed.
	wg.Add(1)
	go func() {
		defer wg.Done()
		results[0] = pm.snapshotKernelRuntimeShared(time.Time{}, true)
	}()

	select {
	case <-rt.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for forced runtime snapshot to start")
	}

	startQueued := make(chan struct{})
	for i := 1; i < callers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-startQueued
			results[index] = pm.snapshotKernelRuntimeShared(time.Time{}, true)
		}(i)
	}
	close(startQueued)

	// Give queued callers a chance to observe the in-flight refresh and block on
	// the shared wait channel before the runtime is released.
	time.Sleep(50 * time.Millisecond)

	close(rt.release)
	wg.Wait()

	if got := rt.AvailableCalls(); got != 1 {
		t.Fatalf("Available() calls while forced callers join an in-flight snapshot = %d, want 1", got)
	}
	for i, result := range results {
		if !result.Available || result.AvailableReason != "ok" {
			t.Fatalf("result[%d] = %+v, want available runtime snapshot", i, result)
		}
	}
}
