package app

import "testing"

func TestCollectKernelOwnerFailuresAggregatesAndDeduplicatesReasons(t *testing.T) {
	owner := kernelCandidateOwner{kind: workerKindRule, id: 18}
	candidates := []kernelCandidateRule{
		{owner: owner, rule: Rule{ID: 101}},
		{owner: owner, rule: Rule{ID: 102}},
	}
	results := map[int64]kernelRuleApplyResult{
		101: {Error: `xdp: xdp dataplane outbound bridge support requires experimental feature "bridge_xdp"`},
		102: {Error: `xdp: xdp dataplane outbound bridge support requires experimental feature "bridge_xdp"; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`},
	}

	failures := collectKernelOwnerFailures(candidates, results, nil)
	got := failures[owner]
	want := `xdp: xdp dataplane outbound bridge support requires experimental feature "bridge_xdp"; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`
	if got != want {
		t.Fatalf("collectKernelOwnerFailures() = %q, want %q", got, want)
	}
}

func TestCollectKernelOwnerFailuresSkipsRunningEntries(t *testing.T) {
	owner := kernelCandidateOwner{kind: workerKindRange, id: 2}
	candidates := []kernelCandidateRule{
		{owner: owner, rule: Rule{ID: 201}},
		{owner: owner, rule: Rule{ID: 202}},
	}
	results := map[int64]kernelRuleApplyResult{
		201: {Running: true, Engine: kernelEngineTC},
		202: {Error: `tc: resolve outbound path on "vmbr2": no forwarding database entry matched the backend MAC`},
	}

	failures := collectKernelOwnerFailures(candidates, results, nil)
	got := failures[owner]
	want := `tc: resolve outbound path on "vmbr2": no forwarding database entry matched the backend MAC`
	if got != want {
		t.Fatalf("collectKernelOwnerFailures() = %q, want %q", got, want)
	}
}
