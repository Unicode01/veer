package app

import (
	"testing"
	"time"
)

type stubKernelStatsRuntime struct {
	snapshot kernelRuleStatsSnapshot
}

func (rt stubKernelStatsRuntime) Available() (bool, string) {
	return true, "ok"
}

func (rt stubKernelStatsRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return map[int64]kernelRuleApplyResult{}, nil
}

func (rt stubKernelStatsRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return rt.snapshot, nil
}

func (rt stubKernelStatsRuntime) Maintain() error {
	return nil
}

func (rt stubKernelStatsRuntime) SnapshotAssignments() map[int64]string {
	return map[int64]string{}
}

func (rt stubKernelStatsRuntime) Close() error {
	return nil
}

func TestRefreshKernelStatsCacheIncludesTrafficWhenExperimentalEnabled(t *testing.T) {
	pm := &ProcessManager{
		cfg: &Config{
			Experimental: map[string]bool{
				experimentalFeatureKernelTraffic: true,
			},
		},
		kernelRuntime: stubKernelStatsRuntime{
			snapshot: kernelRuleStatsSnapshot{
				ByRuleID: map[uint32]kernelRuleStats{
					11: {
						TCPActiveConns: 3,
						UDPNatEntries:  2,
						TotalConns:     9,
						BytesIn:        4000,
						BytesOut:       7000,
					},
				},
			},
		},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			11: {kind: workerKindRule, id: 101},
		},
		kernelRules: map[int64]bool{101: true},
		kernelRuleStats: map[int64]RuleStatsReport{
			101: {
				RuleID:   101,
				BytesIn:  1000,
				BytesOut: 2000,
			},
		},
		kernelRangeStats: make(map[int64]RangeStatsReport),
		kernelStatsAt:    time.Now().Add(-2 * time.Second),
	}

	pm.refreshKernelStatsCache()

	got := pm.kernelRuleStats[101]
	if got.ActiveConns != 3 || got.NatTableSize != 2 || got.TotalConns != 9 {
		t.Fatalf("kernel rule counters = %+v, want active=3 nat=2 total=9", got)
	}
	if got.BytesIn != 4000 || got.BytesOut != 7000 {
		t.Fatalf("kernel traffic totals = %+v, want bytes_in=4000 bytes_out=7000", got)
	}
	if got.SpeedIn <= 0 || got.SpeedOut <= 0 {
		t.Fatalf("kernel traffic speeds = %+v, want positive values", got)
	}
}

func TestRefreshKernelStatsCacheSkipsTrafficWhenExperimentalDisabled(t *testing.T) {
	pm := &ProcessManager{
		cfg: &Config{},
		kernelRuntime: stubKernelStatsRuntime{
			snapshot: kernelRuleStatsSnapshot{
				ByRuleID: map[uint32]kernelRuleStats{
					11: {
						TCPActiveConns: 1,
						UDPNatEntries:  1,
						TotalConns:     5,
						BytesIn:        9000,
						BytesOut:       12000,
					},
				},
			},
		},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			11: {kind: workerKindRule, id: 101},
		},
		kernelRules:      map[int64]bool{101: true},
		kernelRuleStats:  make(map[int64]RuleStatsReport),
		kernelRangeStats: make(map[int64]RangeStatsReport),
	}

	pm.refreshKernelStatsCache()

	got := pm.kernelRuleStats[101]
	if got.ActiveConns != 1 || got.NatTableSize != 1 || got.TotalConns != 5 {
		t.Fatalf("kernel rule counters = %+v, want active=1 nat=1 total=5", got)
	}
	if got.BytesIn != 0 || got.BytesOut != 0 || got.SpeedIn != 0 || got.SpeedOut != 0 {
		t.Fatalf("kernel traffic stats = %+v, want all traffic fields zero when experimental disabled", got)
	}
}
