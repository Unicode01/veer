package app

import (
	"sync/atomic"
	"testing"
	"time"
)

// reconcilingKernelRuntimeTest counts the reads that would take the runtime's
// lock, and reports a reconcile while reconciling is set.
type reconcilingKernelRuntimeTest struct {
	reconciling atomic.Bool
	reads       atomic.Int32
}

func (rt *reconcilingKernelRuntimeTest) Available() (bool, string) {
	rt.reads.Add(1)
	return true, ""
}

func (rt *reconcilingKernelRuntimeTest) Reconcile([]Rule) (map[int64]kernelRuleApplyResult, error) {
	return map[int64]kernelRuleApplyResult{}, nil
}

func (rt *reconcilingKernelRuntimeTest) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	rt.reads.Add(1)
	return kernelRuleStatsSnapshot{ByRuleID: map[uint32]kernelRuleStats{7: {TCPActiveConns: 3}}}, nil
}

func (rt *reconcilingKernelRuntimeTest) Maintain() error                       { return nil }
func (rt *reconcilingKernelRuntimeTest) SnapshotAssignments() map[int64]string { return nil }
func (rt *reconcilingKernelRuntimeTest) Close() error                          { return nil }
func (rt *reconcilingKernelRuntimeTest) reconcileInProgress() bool             { return rt.reconciling.Load() }

func TestKernelReconcileGateCountsNestedReconciles(t *testing.T) {
	var gate kernelReconcileGate
	if gate.active() {
		t.Fatal("a fresh gate is active")
	}
	endOuter := gate.begin()
	endInner := gate.begin()
	endInner()
	if !gate.active() {
		t.Fatal("the gate went inactive while the outer reconcile still runs")
	}
	endOuter()
	if gate.active() {
		t.Fatal("the gate stayed active after every reconcile ended")
	}
}

// The panel's kernel views must not wait seconds behind a reconcile, which
// holds the runtime's lock throughout: they answer from the last result.
func TestKernelViewsAnswerFromTheLastResultWhileAReconcileRuns(t *testing.T) {
	rt := &reconcilingKernelRuntimeTest{}
	pm := &ProcessManager{cfg: &Config{DefaultEngine: ruleEngineAuto}, kernelRuntime: rt}

	view := pm.snapshotKernelRuntimeShared(time.Time{}, false)
	stats, sampledAt, err := pm.snapshotKernelStatsShared(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	reads := rt.reads.Load()
	if reads == 0 {
		t.Fatal("the first views did not read the runtime")
	}

	rt.reconciling.Store(true)
	later := time.Now().Add(time.Hour)
	if got := pm.snapshotKernelRuntimeShared(later, true); got.Available != view.Available || got.DefaultEngine != view.DefaultEngine {
		t.Fatalf("runtime view during a reconcile = %+v, want the last one", got)
	}
	gotStats, gotAt, err := pm.snapshotKernelStatsShared(later)
	if err != nil {
		t.Fatal(err)
	}
	if !gotAt.Equal(sampledAt) || gotStats.ByRuleID[7] != stats.ByRuleID[7] {
		t.Fatalf("stats during a reconcile = %v at %v, want the last sample at %v", gotStats.ByRuleID, gotAt, sampledAt)
	}
	if rt.reads.Load() != reads {
		t.Fatalf("the views read the runtime %d more times during a reconcile", rt.reads.Load()-reads)
	}

	rt.reconciling.Store(false)
	pm.snapshotKernelRuntimeShared(later, true)
	if _, _, err := pm.snapshotKernelStatsShared(later); err != nil {
		t.Fatal(err)
	}
	if rt.reads.Load() == reads {
		t.Fatal("the views kept the old result after the reconcile ended")
	}
}

// With nothing to fall back on, a view still waits for the runtime.
func TestKernelViewsReadTheRuntimeWhenNothingIsCachedYet(t *testing.T) {
	rt := &reconcilingKernelRuntimeTest{}
	rt.reconciling.Store(true)
	pm := &ProcessManager{cfg: &Config{DefaultEngine: ruleEngineAuto}, kernelRuntime: rt}
	stats, _, err := pm.snapshotKernelStatsShared(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if rt.reads.Load() != 1 || stats.ByRuleID[7].TCPActiveConns != 3 {
		t.Fatalf("first stats during a reconcile = %v after %d reads, want the runtime's", stats.ByRuleID, rt.reads.Load())
	}
}
