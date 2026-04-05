package app

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
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
	retryAt := time.Unix(1712200000, 0).UTC()
	snapshotAt := retryAt.Add(15 * time.Second)
	netlinkRequestedAt := retryAt.Add(7 * time.Second)
	attachmentHealAt := retryAt.Add(9 * time.Second)
	now := time.Now()
	nextExpiry := now.Add(30 * time.Second)
	clearAt := now.Add(50 * time.Second)
	pm := &ProcessManager{
		cfg: &Config{
			DefaultEngine:     ruleEngineAuto,
			KernelEngineOrder: []string{kernelEngineTC},
			Experimental: map[string]bool{
				experimentalFeatureKernelTraffic:       true,
				experimentalFeatureKernelTCDiag:        true,
				experimentalFeatureKernelTCDiagVerbose: true,
			},
		},
		kernelRules:                         map[int64]bool{101: true},
		kernelRanges:                        map[int64]bool{202: true},
		kernelRetryCount:                    3,
		lastKernelRetryAt:                   retryAt,
		lastKernelRetryReason:               "rules=2 ranges=1 reasons=tc retry=3",
		kernelIncrementalRetryCount:         2,
		kernelIncrementalRetryFallbackCount: 1,
		kernelNetlinkOwnerRetryCooldownUntil: map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState{
			{kind: workerKindRule, id: 301}:  {Until: nextExpiry, Source: "neighbor"},
			{kind: workerKindRange, id: 302}: {Until: clearAt, Source: "fdb"},
			{kind: workerKindRule, id: 303}:  {Until: now.Add(-30 * time.Second), Source: "link"},
		},
		lastKernelIncrementalRetryAt:                   retryAt.Add(5 * time.Second),
		lastKernelIncrementalRetryResult:               "incremental retry recovered rule_owners=1 range_owners=0 entries=2 retained_rule_owners=3 retained_range_owners=1",
		lastKernelIncrementalRetryMatchedRuleOwners:    4,
		lastKernelIncrementalRetryMatchedRangeOwners:   2,
		lastKernelIncrementalRetryAttemptedRuleOwners:  2,
		lastKernelIncrementalRetryAttemptedRangeOwners: 1,
		lastKernelIncrementalRetryRetainedRuleOwners:   3,
		lastKernelIncrementalRetryRetainedRangeOwners:  1,
		lastKernelIncrementalRetryRecoveredRuleOwners:  1,
		lastKernelIncrementalRetryRecoveredRangeOwners: 0,
		lastKernelIncrementalRetryCooldownRuleOwners:   2,
		lastKernelIncrementalRetryCooldownRangeOwners:  1,
		lastKernelIncrementalRetryCooldownSummary:      "neighbor=2,link=1",
		lastKernelIncrementalRetryCooldownScope:        "rule_ids=301,303; range_ids=302",
		lastKernelIncrementalRetryBackoffRuleOwners:    1,
		lastKernelIncrementalRetryBackoffRangeOwners:   1,
		lastKernelIncrementalRetryBackoffSummary:       "neighbor=1,fdb=1",
		lastKernelIncrementalRetryBackoffScope:         "rule_ids=304; range_ids=305",
		lastKernelIncrementalRetryBackoffMaxFailures:   2,
		lastKernelIncrementalRetryBackoffMaxDelay:      12 * time.Second,
		kernelNetlinkRecoverPending:                    true,
		kernelNetlinkRecoverSource:                     "neighbor,fdb",
		kernelNetlinkRecoverSummary:                    "rules=1 ranges=1 reasons=fdb_missing=1,neighbor_missing=1",
		kernelNetlinkRecoverRequestedAt:                netlinkRequestedAt,
		kernelNetlinkRecoverTrigger: func() kernelNetlinkRecoveryTrigger {
			trigger := newKernelNetlinkRecoveryTrigger("neighbor")
			trigger.addInterfaceName("eno2")
			trigger.addLinkFDBInterface("vmbr1")
			trigger.addBackendIP("198.51.100.31")
			trigger.addBackendMAC("02:00:5e:10:00:31")
			return trigger
		}(),
		lastKernelAttachmentIssue:       "tc(active_entries=3)",
		kernelAttachmentHealAt:          attachmentHealAt,
		lastKernelAttachmentHealSummary: "tc(reattach=1 detach=0)",
		lastKernelAttachmentHealError:   "repair tc attachment on ifindex 7: link down",
		kernelStatsSnapshotAt:           snapshotAt,
		kernelStatsLastDuration:         125 * time.Millisecond,
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
	if !resp.TCDiagnostics || !resp.TCDiagnosticsVerbose {
		t.Fatalf("tc diagnostics flags = diag:%t verbose:%t, want true/true", resp.TCDiagnostics, resp.TCDiagnosticsVerbose)
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
	if resp.KernelRetryCount != 3 {
		t.Fatalf("kernel_retry_count = %d, want 3", resp.KernelRetryCount)
	}
	if !resp.LastKernelRetryAt.Equal(retryAt) {
		t.Fatalf("last_kernel_retry_at = %v, want %v", resp.LastKernelRetryAt, retryAt)
	}
	if resp.LastKernelRetryReason != "rules=2 ranges=1 reasons=tc retry=3" {
		t.Fatalf("last_kernel_retry_reason = %q", resp.LastKernelRetryReason)
	}
	if resp.KernelIncrementalRetryCount != 2 {
		t.Fatalf("kernel_incremental_retry_count = %d, want 2", resp.KernelIncrementalRetryCount)
	}
	if resp.KernelIncrementalRetryFallbackCount != 1 {
		t.Fatalf("kernel_incremental_retry_fallback_count = %d, want 1", resp.KernelIncrementalRetryFallbackCount)
	}
	if resp.CooldownRuleOwnerCount != 1 || resp.CooldownRangeOwnerCount != 1 {
		t.Fatalf("cooldown owner counts = rules:%d ranges:%d, want 1/1", resp.CooldownRuleOwnerCount, resp.CooldownRangeOwnerCount)
	}
	if resp.CooldownSummary != "neighbor=1,fdb=1" {
		t.Fatalf("cooldown_summary = %q, want %q", resp.CooldownSummary, "neighbor=1,fdb=1")
	}
	if !resp.CooldownNextExpiryAt.Equal(nextExpiry) {
		t.Fatalf("cooldown_next_expiry_at = %v, want %v", resp.CooldownNextExpiryAt, nextExpiry)
	}
	if !resp.CooldownClearAt.Equal(clearAt) {
		t.Fatalf("cooldown_clear_at = %v, want %v", resp.CooldownClearAt, clearAt)
	}
	if !resp.LastKernelIncrementalRetryAt.Equal(retryAt.Add(5 * time.Second)) {
		t.Fatalf("last_kernel_incremental_retry_at = %v, want %v", resp.LastKernelIncrementalRetryAt, retryAt.Add(5*time.Second))
	}
	if resp.LastKernelIncrementalRetryResult == "" {
		t.Fatal("last_kernel_incremental_retry_result = empty, want non-empty")
	}
	if resp.LastKernelIncrementalRetryMatchedRuleOwners != 4 || resp.LastKernelIncrementalRetryMatchedRangeOwners != 2 {
		t.Fatalf(
			"last incremental matched owners = rules:%d ranges:%d, want 4/2",
			resp.LastKernelIncrementalRetryMatchedRuleOwners,
			resp.LastKernelIncrementalRetryMatchedRangeOwners,
		)
	}
	if resp.LastKernelIncrementalRetryAttemptedRuleOwners != 2 || resp.LastKernelIncrementalRetryAttemptedRangeOwners != 1 {
		t.Fatalf(
			"last incremental attempted owners = rules:%d ranges:%d, want 2/1",
			resp.LastKernelIncrementalRetryAttemptedRuleOwners,
			resp.LastKernelIncrementalRetryAttemptedRangeOwners,
		)
	}
	if resp.LastKernelIncrementalRetryRetainedRuleOwners != 3 || resp.LastKernelIncrementalRetryRetainedRangeOwners != 1 {
		t.Fatalf(
			"last incremental retained owners = rules:%d ranges:%d, want 3/1",
			resp.LastKernelIncrementalRetryRetainedRuleOwners,
			resp.LastKernelIncrementalRetryRetainedRangeOwners,
		)
	}
	if resp.LastKernelIncrementalRetryRecoveredRuleOwners != 1 || resp.LastKernelIncrementalRetryRecoveredRangeOwners != 0 {
		t.Fatalf(
			"last incremental recovered owners = rules:%d ranges:%d, want 1/0",
			resp.LastKernelIncrementalRetryRecoveredRuleOwners,
			resp.LastKernelIncrementalRetryRecoveredRangeOwners,
		)
	}
	if resp.LastKernelIncrementalRetryCooldownRuleOwners != 2 || resp.LastKernelIncrementalRetryCooldownRangeOwners != 1 {
		t.Fatalf(
			"last incremental cooldown owners = rules:%d ranges:%d, want 2/1",
			resp.LastKernelIncrementalRetryCooldownRuleOwners,
			resp.LastKernelIncrementalRetryCooldownRangeOwners,
		)
	}
	if resp.LastKernelIncrementalRetryCooldownSummary != "neighbor=2,link=1" {
		t.Fatalf(
			"last incremental cooldown summary = %q, want %q",
			resp.LastKernelIncrementalRetryCooldownSummary,
			"neighbor=2,link=1",
		)
	}
	if resp.LastKernelIncrementalRetryCooldownScope != "rule_ids=301,303; range_ids=302" {
		t.Fatalf("last incremental cooldown scope = %q", resp.LastKernelIncrementalRetryCooldownScope)
	}
	if resp.LastKernelIncrementalRetryBackoffRuleOwners != 1 || resp.LastKernelIncrementalRetryBackoffRangeOwners != 1 {
		t.Fatalf(
			"last incremental backoff owners = rules:%d ranges:%d, want 1/1",
			resp.LastKernelIncrementalRetryBackoffRuleOwners,
			resp.LastKernelIncrementalRetryBackoffRangeOwners,
		)
	}
	if resp.LastKernelIncrementalRetryBackoffSummary != "neighbor=1,fdb=1" {
		t.Fatalf("last incremental backoff summary = %q", resp.LastKernelIncrementalRetryBackoffSummary)
	}
	if resp.LastKernelIncrementalRetryBackoffScope != "rule_ids=304; range_ids=305" {
		t.Fatalf("last incremental backoff scope = %q", resp.LastKernelIncrementalRetryBackoffScope)
	}
	if resp.LastKernelIncrementalRetryBackoffMaxFailures != 2 {
		t.Fatalf("last incremental backoff max failures = %d, want 2", resp.LastKernelIncrementalRetryBackoffMaxFailures)
	}
	if resp.LastKernelIncrementalRetryBackoffMaxDelayMs != 12000 {
		t.Fatalf("last incremental backoff max delay ms = %d, want 12000", resp.LastKernelIncrementalRetryBackoffMaxDelayMs)
	}
	if !resp.KernelNetlinkRecoverPending {
		t.Fatal("kernel_netlink_recover_pending = false, want true")
	}
	if resp.KernelNetlinkRecoverSource != "neighbor,fdb" {
		t.Fatalf("kernel_netlink_recover_source = %q, want merged source list", resp.KernelNetlinkRecoverSource)
	}
	if resp.KernelNetlinkRecoverSummary != "rules=1 ranges=1 reasons=fdb_missing=1,neighbor_missing=1" {
		t.Fatalf("kernel_netlink_recover_summary = %q", resp.KernelNetlinkRecoverSummary)
	}
	if !resp.KernelNetlinkRecoverRequestedAt.Equal(netlinkRequestedAt) {
		t.Fatalf("kernel_netlink_recover_requested_at = %v, want %v", resp.KernelNetlinkRecoverRequestedAt, netlinkRequestedAt)
	}
	if resp.KernelNetlinkRecoverTriggerSummary != "if=eno2; fdb_if=vmbr1; backend_ip=198.51.100.31; backend_mac=02:00:5e:10:00:31" {
		t.Fatalf("kernel_netlink_recover_trigger_summary = %q", resp.KernelNetlinkRecoverTriggerSummary)
	}
	if resp.LastKernelAttachmentIssue != "tc(active_entries=3)" {
		t.Fatalf("last_kernel_attachment_issue = %q, want propagated issue", resp.LastKernelAttachmentIssue)
	}
	if !resp.LastKernelAttachmentHealAt.Equal(attachmentHealAt) {
		t.Fatalf("last_kernel_attachment_heal_at = %v, want %v", resp.LastKernelAttachmentHealAt, attachmentHealAt)
	}
	if resp.LastKernelAttachmentHealSummary != "tc(reattach=1 detach=0)" {
		t.Fatalf("last_kernel_attachment_heal_summary = %q", resp.LastKernelAttachmentHealSummary)
	}
	if resp.LastKernelAttachmentHealError != "repair tc attachment on ifindex 7: link down" {
		t.Fatalf("last_kernel_attachment_heal_error = %q", resp.LastKernelAttachmentHealError)
	}
	if !resp.LastStatsSnapshotAt.Equal(snapshotAt) {
		t.Fatalf("last_stats_snapshot_at = %v, want %v", resp.LastStatsSnapshotAt, snapshotAt)
	}
	if resp.LastStatsSnapshotMs != 125 {
		t.Fatalf("last_stats_snapshot_ms = %d, want 125", resp.LastStatsSnapshotMs)
	}
	if resp.TransientFallbackSummary == "" {
		t.Fatal("transient_fallback_summary = empty, want non-empty")
	}
}

func TestHandleKernelRuntimePressureFallbackDoesNotSetRetryPending(t *testing.T) {
	pm := &ProcessManager{
		cfg: &Config{
			DefaultEngine:     ruleEngineAuto,
			KernelEngineOrder: []string{kernelEngineTC},
		},
		rulePlans: map[int64]ruleDataplanePlan{
			1: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `kernel dataplane pressure: flows 121000/131072 (92.3%) exceeded 92% high watermark, routing new sessions back to userspace until usage drops below 85%`,
			},
		},
		rangePlans: map[int64]rangeDataplanePlan{},
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
	if resp.TransientFallbackRuleCount != 0 || resp.TransientFallbackRangeCount != 0 {
		t.Fatalf("transient fallback counts = rules:%d ranges:%d, want 0/0 for pressure-only fallback", resp.TransientFallbackRuleCount, resp.TransientFallbackRangeCount)
	}
	if resp.TransientFallbackSummary != "" {
		t.Fatalf("transient_fallback_summary = %q, want empty for pressure-only fallback", resp.TransientFallbackSummary)
	}
	if resp.RetryPending {
		t.Fatal("retry_pending = true, want false for pressure-only fallback")
	}
}
