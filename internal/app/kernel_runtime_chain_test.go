//go:build linux

package app

import "testing"

type mockKernelRuntime struct {
	available       bool
	reason          string
	reconcileResult map[int64]kernelRuleApplyResult
	reconcileErr    error
	assignments     map[int64]string
	reconcileCalls  [][]Rule
}

func (m *mockKernelRuntime) Available() (bool, string) {
	return m.available, m.reason
}

func (m *mockKernelRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	copied := append([]Rule(nil), rules...)
	m.reconcileCalls = append(m.reconcileCalls, copied)
	if len(rules) == 0 {
		return map[int64]kernelRuleApplyResult{}, nil
	}
	out := make(map[int64]kernelRuleApplyResult, len(m.reconcileResult))
	for id, result := range m.reconcileResult {
		out[id] = result
	}
	return out, m.reconcileErr
}

func (m *mockKernelRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (m *mockKernelRuntime) Maintain() error {
	return nil
}

func (m *mockKernelRuntime) SnapshotAssignments() map[int64]string {
	out := make(map[int64]string, len(m.assignments))
	for id, engine := range m.assignments {
		out[id] = engine
	}
	return out
}

func (m *mockKernelRuntime) Close() error {
	return nil
}

func assertReconcileCallPrefix(t *testing.T, got [][]Rule, want ...[]int64) {
	t.Helper()
	if len(got) < len(want) {
		t.Fatalf("reconcile calls = %#v, want at least %d call(s)", got, len(want))
	}
	for i, wantIDs := range want {
		if len(got[i]) != len(wantIDs) {
			t.Fatalf("reconcile calls[%d] = %#v, want %d rule(s)", i, got[i], len(wantIDs))
		}
		for j, wantID := range wantIDs {
			if got[i][j].ID != wantID {
				t.Fatalf("reconcile calls[%d][%d] = %+v, want rule %d", i, j, got[i][j], wantID)
			}
		}
	}
	for i := len(want); i < len(got); i++ {
		if len(got[i]) != 0 {
			t.Fatalf("reconcile calls[%d] = %#v, want only optional empty cleanup calls after primary requests", i, got[i])
		}
	}
}

func TestOrderedKernelRuleRuntimeFallsBackToTC(t *testing.T) {
	xdp := &mockKernelRuntime{
		available: true,
		reconcileResult: map[int64]kernelRuleApplyResult{
			1: {Error: "xdp dataplane currently supports only transparent rules"},
		},
	}
	tc := &mockKernelRuntime{
		available: true,
		reconcileResult: map[int64]kernelRuleApplyResult{
			1: {Running: true, Engine: kernelEngineTC},
		},
		assignments: map[int64]string{1: kernelEngineTC},
	}
	rt := &orderedKernelRuleRuntime{
		entries: []orderedKernelRuntimeEntry{
			{name: kernelEngineXDP, rt: xdp},
			{name: kernelEngineTC, rt: tc},
		},
	}

	results, err := rt.Reconcile([]Rule{{ID: 1}})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	result, ok := results[1]
	if !ok {
		t.Fatalf("missing reconcile result for rule 1")
	}
	if !result.Running || result.Engine != kernelEngineTC {
		t.Fatalf("result = %+v, want running tc", result)
	}
	assertReconcileCallPrefix(t, xdp.reconcileCalls, []int64{1})
	assertReconcileCallPrefix(t, tc.reconcileCalls, []int64{1})
}

func TestOrderedKernelRuleRuntimeSelectsTCWhenXDPUnavailable(t *testing.T) {
	xdp := &mockKernelRuntime{
		available: false,
		reason:    "xdp unavailable",
	}
	tc := &mockKernelRuntime{
		available: true,
		reason:    "tc ready",
	}
	rt := &orderedKernelRuleRuntime{
		entries: []orderedKernelRuntimeEntry{
			{name: kernelEngineXDP, rt: xdp},
			{name: kernelEngineTC, rt: tc},
		},
	}

	available, reason := rt.Available()
	if !available {
		t.Fatalf("Available() = false, want true")
	}
	if reason != "selected tc kernel engine: tc ready (skipped: xdp=xdp unavailable)" {
		t.Fatalf("Available() reason = %q", reason)
	}
}

func TestOrderedKernelRuleRuntimeReconcileRetainingAssignmentsKeepsPinnedOwnersOffHigherPriorityEngine(t *testing.T) {
	xdp := &mockKernelRuntime{
		available: true,
		reconcileResult: map[int64]kernelRuleApplyResult{
			2: {Error: "xdp neighbor missing"},
		},
	}
	tc := &mockKernelRuntime{
		available: true,
		reconcileResult: map[int64]kernelRuleApplyResult{
			1: {Running: true, Engine: kernelEngineTC},
			2: {Running: true, Engine: kernelEngineTC},
		},
		assignments: map[int64]string{
			1: kernelEngineTC,
			2: kernelEngineTC,
		},
	}
	rt := &orderedKernelRuleRuntime{
		entries: []orderedKernelRuntimeEntry{
			{name: kernelEngineXDP, rt: xdp},
			{name: kernelEngineTC, rt: tc},
		},
	}

	results, err := rt.ReconcileRetainingAssignments(
		map[string][]Rule{
			kernelEngineTC: {
				{ID: 1},
			},
		},
		[]Rule{{ID: 2}},
	)
	if err != nil {
		t.Fatalf("ReconcileRetainingAssignments() error = %v", err)
	}
	assertReconcileCallPrefix(t, xdp.reconcileCalls, []int64{2})
	assertReconcileCallPrefix(t, tc.reconcileCalls, []int64{1, 2})
	result, ok := results[2]
	if !ok || !result.Running || result.Engine != kernelEngineTC {
		t.Fatalf("retry rule result = %+v, want running tc", result)
	}
	if _, ok := results[1]; ok {
		t.Fatalf("retained rule unexpectedly reported as a new result: %+v", results[1])
	}
}
