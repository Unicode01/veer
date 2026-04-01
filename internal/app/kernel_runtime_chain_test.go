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
	if len(xdp.reconcileCalls) != 1 || len(xdp.reconcileCalls[0]) != 1 {
		t.Fatalf("xdp reconcile calls = %#v, want one call with one rule", xdp.reconcileCalls)
	}
	if len(tc.reconcileCalls) != 1 || len(tc.reconcileCalls[0]) != 1 {
		t.Fatalf("tc reconcile calls = %#v, want one call with one rule", tc.reconcileCalls)
	}
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
