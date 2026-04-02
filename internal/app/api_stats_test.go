package app

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestHandleListRuleStatsPaginatesAndIncludesRemark(t *testing.T) {
	db := openTestDB(t)

	rules := []Rule{
		{InIP: "198.51.100.1", InPort: 10001, OutIP: "203.0.113.1", OutPort: 20001, Protocol: "tcp", Remark: "alpha", Enabled: true},
		{InIP: "198.51.100.2", InPort: 10002, OutIP: "203.0.113.2", OutPort: 20002, Protocol: "udp", Remark: "beta", Enabled: true},
		{InIP: "198.51.100.3", InPort: 10003, OutIP: "203.0.113.3", OutPort: 20003, Protocol: "tcp+udp", Remark: "gamma", Enabled: true},
	}
	var ids []int64
	for i := range rules {
		rule := rules[i]
		id, err := dbAddRule(db, &rule)
		if err != nil {
			t.Fatalf("add rule %d: %v", i, err)
		}
		ids = append(ids, id)
	}

	pm := &ProcessManager{
		ruleWorkers: map[int]*WorkerInfo{
			0: {
				ruleStats: map[int64]RuleStatsReport{
					ids[0]: {RuleID: ids[0], BytesIn: 10, ActiveConns: 1},
					ids[1]: {RuleID: ids[1], BytesIn: 40, NatTableSize: 3},
					ids[2]: {RuleID: ids[2], BytesIn: 30, ActiveConns: 2, NatTableSize: 4},
				},
			},
		},
		rangeWorkers:     map[int]*WorkerInfo{},
		kernelRuleStats:  map[int64]RuleStatsReport{},
		kernelRangeStats: map[int64]RangeStatsReport{},
	}

	req := httptest.NewRequest("GET", "/api/rules/stats?page=2&page_size=1&sort_key=bytes_in&sort_asc=false", nil)
	w := httptest.NewRecorder()

	handleListRuleStats(w, req, db, pm)
	if w.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp RuleStatsListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if resp.Total != 3 {
		t.Fatalf("unexpected total: got %d want 3", resp.Total)
	}
	if resp.Page != 2 || resp.PageSize != 1 {
		t.Fatalf("unexpected page info: page=%d page_size=%d", resp.Page, resp.PageSize)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("unexpected items length: %d", len(resp.Items))
	}
	if resp.Items[0].RuleID != ids[2] {
		t.Fatalf("unexpected rule id on page 2: got %d want %d", resp.Items[0].RuleID, ids[2])
	}
	if resp.Items[0].Remark != "gamma" {
		t.Fatalf("unexpected remark: got %q want %q", resp.Items[0].Remark, "gamma")
	}
}

func TestHandleListRangeStatsRejectsInvalidSortKey(t *testing.T) {
	db := openTestDB(t)
	pm := &ProcessManager{
		ruleWorkers:      map[int]*WorkerInfo{},
		rangeWorkers:     map[int]*WorkerInfo{},
		kernelRuleStats:  map[int64]RuleStatsReport{},
		kernelRangeStats: map[int64]RangeStatsReport{},
	}

	req := httptest.NewRequest("GET", "/api/ranges/stats?sort_key=bad_key", nil)
	w := httptest.NewRecorder()

	handleListRangeStats(w, req, db, pm)
	if w.Code != 400 {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
}

func TestHandleKernelRuntimeIncludesFallbackSummary(t *testing.T) {
	pm := &ProcessManager{
		cfg: &Config{
			DefaultEngine:     ruleEngineAuto,
			KernelEngineOrder: []string{kernelEngineTC},
			Experimental: map[string]bool{
				experimentalFeatureKernelTraffic: true,
			},
		},
		kernelRules:  map[int64]bool{101: true},
		kernelRanges: map[int64]bool{202: true},
		rulePlans: map[int64]ruleDataplanePlan{
			1: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `xdp: skip; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`,
			},
			2: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `xdp: skip; tc: verifier rejected program`,
			},
		},
		rangePlans: map[int64]rangeDataplanePlan{
			3: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 192.0.2.10 on "eno1"; tc: skipped`,
			},
		},
	}

	req := httptest.NewRequest("GET", "/api/kernel/runtime", nil)
	w := httptest.NewRecorder()

	handleKernelRuntime(w, req, pm)
	if w.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp KernelRuntimeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}

	if resp.DefaultEngine != ruleEngineAuto {
		t.Fatalf("default engine = %q, want %q", resp.DefaultEngine, ruleEngineAuto)
	}
	if !reflect.DeepEqual(resp.ConfiguredOrder, []string{kernelEngineTC}) {
		t.Fatalf("configured order = %v, want %v", resp.ConfiguredOrder, []string{kernelEngineTC})
	}
	if !resp.TrafficStats {
		t.Fatal("traffic_stats = false, want true")
	}
	if resp.ActiveRuleCount != 1 || resp.ActiveRangeCount != 1 {
		t.Fatalf("active counts = rules:%d ranges:%d, want 1/1", resp.ActiveRuleCount, resp.ActiveRangeCount)
	}
	if resp.KernelFallbackRuleCount != 2 || resp.KernelFallbackRangeCount != 1 {
		t.Fatalf("fallback counts = rules:%d ranges:%d, want 2/1", resp.KernelFallbackRuleCount, resp.KernelFallbackRangeCount)
	}
	if resp.TransientFallbackRuleCount != 1 || resp.TransientFallbackRangeCount != 1 {
		t.Fatalf("transient fallback counts = rules:%d ranges:%d, want 1/1", resp.TransientFallbackRuleCount, resp.TransientFallbackRangeCount)
	}
	if !resp.RetryPending {
		t.Fatal("retry_pending = false, want true")
	}
	if resp.TransientFallbackSummary == "" {
		t.Fatal("transient_fallback_summary = empty, want non-empty")
	}
}
