//go:build linux

package app

import (
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
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

func TestSnapshotKernelRuntimeSharedForceRefreshBypassesKernelPressureTTL(t *testing.T) {
	occupancy := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelOccupancyMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(kernelOccupancyValueV4{})),
		MaxEntries: 1,
	})
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 1,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err := flows.Put(tcFlowKeyV4{IfIndex: 1}, tcFlowValueV4{RuleID: 1}); err != nil {
		t.Fatalf("flows.Put() error = %v", err)
	}
	if err := nat.Put(tcNATPortKeyV4{IfIndex: 1}, uint32(1)); err != nil {
		t.Fatalf("nat.Put() error = %v", err)
	}

	now := time.Now()
	rt := &linuxKernelRuleRuntime{
		available:        true,
		availableReason:  "ready",
		coll:             &ebpf.Collection{Maps: map[string]*ebpf.Map{kernelOccupancyMapName: occupancy, kernelFlowsMapNameV4: flows, kernelNatPortsMapNameV4: nat}},
		preparedRules:    []preparedKernelRule{{rule: Rule{ID: 1}}},
		flowsMapCapacity: 1,
		natMapCapacity:   1,
		runtimeMapCounts: kernelRuntimeMapCountSnapshot{
			sampledAt:    now,
			flowsEntries: 0,
			natEntries:   0,
		},
		pressureState: kernelRuntimePressureState{
			sampledAt: now,
		},
	}
	pm := &ProcessManager{
		cfg: &Config{
			DefaultEngine:     ruleEngineKernel,
			KernelEngineOrder: []string{kernelEngineTC},
		},
		kernelRuntime: rt,
	}

	stale := pm.snapshotKernelRuntimeShared(time.Time{}, false)
	staleEngine, ok := dataplanePerfFindKernelEngine(stale.Engines, kernelEngineTC)
	if !ok {
		t.Fatal("tc engine missing from stale runtime snapshot")
	}
	if staleEngine.PressureActive {
		t.Fatalf("stale snapshot pressure_active = true, want false while cached pressure sample is still fresh")
	}
	if staleEngine.FlowsMapEntries != 1 || staleEngine.NATMapEntries != 1 {
		t.Fatalf("stale snapshot entries = flows:%d nat:%d, want 1/1 from runtime map detail refresh", staleEngine.FlowsMapEntries, staleEngine.NATMapEntries)
	}
	if !stale.Available {
		t.Fatalf("stale snapshot available = false, want true before forced refresh observes full pressure")
	}

	fresh := pm.snapshotKernelRuntimeShared(time.Time{}, true)
	freshEngine, ok := dataplanePerfFindKernelEngine(fresh.Engines, kernelEngineTC)
	if !ok {
		t.Fatal("tc engine missing from forced runtime snapshot")
	}
	if !freshEngine.PressureActive {
		t.Fatal("forced snapshot pressure_active = false, want true after bypassing pressure TTL")
	}
	if freshEngine.PressureLevel != string(kernelRuntimePressureLevelFull) {
		t.Fatalf("forced snapshot pressure_level = %q, want %q", freshEngine.PressureLevel, kernelRuntimePressureLevelFull)
	}
	if !strings.Contains(freshEngine.PressureReason, "saturation watermark") {
		t.Fatalf("forced snapshot pressure_reason = %q, want saturation detail", freshEngine.PressureReason)
	}
	if fresh.Available {
		t.Fatal("forced snapshot available = true, want false once full pressure is refreshed")
	}
	if !strings.Contains(fresh.AvailableReason, "selected tc kernel engine") && !strings.Contains(fresh.AvailableReason, "saturation watermark") {
		t.Fatalf("forced snapshot available_reason = %q, want refreshed engine availability detail", fresh.AvailableReason)
	}
}
