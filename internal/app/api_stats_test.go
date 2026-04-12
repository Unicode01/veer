package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type stubKernelRuntimeViewRuntime struct {
	available bool
	reason    string
}

func (rt stubKernelRuntimeViewRuntime) Available() (bool, string) {
	return rt.available, rt.reason
}

func (rt stubKernelRuntimeViewRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return map[int64]kernelRuleApplyResult{}, nil
}

func (rt stubKernelRuntimeViewRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (rt stubKernelRuntimeViewRuntime) Maintain() error {
	return nil
}

func (rt stubKernelRuntimeViewRuntime) SnapshotAssignments() map[int64]string {
	return map[int64]string{}
}

func (rt stubKernelRuntimeViewRuntime) Close() error {
	return nil
}

type failingKernelStatsRuntime struct {
	err error
}

func (rt failingKernelStatsRuntime) Available() (bool, string) {
	return true, "ok"
}

func (rt failingKernelStatsRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return map[int64]kernelRuleApplyResult{}, nil
}

func (rt failingKernelStatsRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), rt.err
}

func (rt failingKernelStatsRuntime) Maintain() error {
	return nil
}

func (rt failingKernelStatsRuntime) SnapshotAssignments() map[int64]string {
	return map[int64]string{}
}

func (rt failingKernelStatsRuntime) Close() error {
	return nil
}

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

func TestHandleListRuleStatsSortsByCurrentConnsAndIncludesRemark(t *testing.T) {
	db := openTestDB(t)

	rules := []Rule{
		{InIP: "198.51.100.11", InPort: 11001, OutIP: "203.0.113.11", OutPort: 21001, Protocol: "tcp", Remark: "tcp-rule", Enabled: true},
		{InIP: "198.51.100.12", InPort: 11002, OutIP: "203.0.113.12", OutPort: 21002, Protocol: "udp+icmp", Remark: "udp-icmp-rule", Enabled: true},
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
					ids[0]: {RuleID: ids[0], ActiveConns: 4},
					ids[1]: {RuleID: ids[1], NatTableSize: 7, ICMPNatSize: 3},
				},
			},
		},
		rangeWorkers:     map[int]*WorkerInfo{},
		kernelRuleStats:  map[int64]RuleStatsReport{},
		kernelRangeStats: map[int64]RangeStatsReport{},
	}

	req := httptest.NewRequest("GET", "/api/rules/stats?page=1&page_size=1&sort_key=current_conns&sort_asc=false", nil)
	w := httptest.NewRecorder()

	handleListRuleStats(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp RuleStatsListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp.Items) != 1 {
		t.Fatalf("unexpected items length: %d", len(resp.Items))
	}
	if resp.Items[0].RuleID != ids[1] {
		t.Fatalf("unexpected first rule id: got %d want %d", resp.Items[0].RuleID, ids[1])
	}
	if resp.Items[0].Remark != "udp-icmp-rule" {
		t.Fatalf("unexpected remark: got %q want %q", resp.Items[0].Remark, "udp-icmp-rule")
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

func TestHandleListRangeStatsSortsByCurrentConnsAndIncludesRemark(t *testing.T) {
	db := openTestDB(t)

	ranges := []PortRange{
		{InIP: "198.51.100.21", StartPort: 12001, EndPort: 12001, OutIP: "203.0.113.21", OutStartPort: 22001, Protocol: "tcp", Remark: "tcp-range", Enabled: true},
		{InIP: "198.51.100.22", StartPort: 12002, EndPort: 12002, OutIP: "203.0.113.22", OutStartPort: 22002, Protocol: "icmp", Remark: "icmp-range", Enabled: true},
	}
	var ids []int64
	for i := range ranges {
		item := ranges[i]
		id, err := dbAddRange(db, &item)
		if err != nil {
			t.Fatalf("add range %d: %v", i, err)
		}
		ids = append(ids, id)
	}

	pm := &ProcessManager{
		ruleWorkers: map[int]*WorkerInfo{},
		rangeWorkers: map[int]*WorkerInfo{
			0: {
				rangeStats: map[int64]RangeStatsReport{
					ids[0]: {RangeID: ids[0], ActiveConns: 5},
					ids[1]: {RangeID: ids[1], NatTableSize: 6, ICMPNatSize: 6},
				},
			},
		},
		kernelRuleStats:  map[int64]RuleStatsReport{},
		kernelRangeStats: map[int64]RangeStatsReport{},
	}

	req := httptest.NewRequest("GET", "/api/ranges/stats?page=1&page_size=1&sort_key=current_conns&sort_asc=false", nil)
	w := httptest.NewRecorder()

	handleListRangeStats(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp RangeStatsListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp.Items) != 1 {
		t.Fatalf("unexpected items length: %d", len(resp.Items))
	}
	if resp.Items[0].RangeID != ids[1] {
		t.Fatalf("unexpected first range id: got %d want %d", resp.Items[0].RangeID, ids[1])
	}
	if resp.Items[0].Remark != "icmp-range" {
		t.Fatalf("unexpected remark: got %q want %q", resp.Items[0].Remark, "icmp-range")
	}
}

func TestHandleListEgressNATStatsSortsByCurrentConns(t *testing.T) {
	db := openTestDB(t)

	items := []EgressNAT{
		{ParentInterface: "vmbr1", ChildInterface: "tap100i0", OutInterface: "vmbr0", OutSourceIP: "198.51.100.10", Protocol: "udp", NATType: egressNATTypeFullCone, Enabled: true},
		{ParentInterface: "vmbr2", ChildInterface: "", OutInterface: "vmbr0", OutSourceIP: "198.51.100.11", Protocol: "tcp", NATType: egressNATTypeSymmetric, Enabled: true},
		{ParentInterface: "vmbr3", ChildInterface: "tap300i0", OutInterface: "vmbr9", OutSourceIP: "198.51.100.12", Protocol: "tcp+udp", NATType: egressNATTypeSymmetric, Enabled: true},
	}
	var ids []int64
	for i := range items {
		item := items[i]
		id, err := dbAddEgressNAT(db, &item)
		if err != nil {
			t.Fatalf("add egress nat %d: %v", i, err)
		}
		ids = append(ids, id)
	}

	pm := &ProcessManager{
		kernelEgressNATStats: map[int64]EgressNATStatsReport{
			ids[0]: {EgressNATID: ids[0], TotalConns: 12, NatTableSize: 7, BytesIn: 100},
			ids[1]: {EgressNATID: ids[1], ActiveConns: 5, TotalConns: 8, BytesIn: 200},
			ids[2]: {EgressNATID: ids[2], ActiveConns: 2, TotalConns: 9, NatTableSize: 3, BytesIn: 300},
		},
	}

	req := httptest.NewRequest("GET", "/api/egress-nats/stats?page=1&page_size=1&sort_key=current_conns&sort_asc=false", nil)
	w := httptest.NewRecorder()

	handleListEgressNATStats(w, req, db, pm)
	if w.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp EgressNATStatsListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if resp.Total != 3 {
		t.Fatalf("unexpected total: got %d want 3", resp.Total)
	}
	if resp.Page != 1 || resp.PageSize != 1 {
		t.Fatalf("unexpected page info: page=%d page_size=%d", resp.Page, resp.PageSize)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("unexpected items length: %d", len(resp.Items))
	}
	if resp.Items[0].EgressNATID != ids[0] {
		t.Fatalf("unexpected egress nat id on page 1: got %d want %d", resp.Items[0].EgressNATID, ids[0])
	}
	if resp.Items[0].ParentInterface != "vmbr1" || resp.Items[0].OutInterface != "vmbr0" {
		t.Fatalf("unexpected metadata: %+v", resp.Items[0])
	}
	if resp.Items[0].NATType != egressNATTypeFullCone {
		t.Fatalf("unexpected nat type: got %q want %q", resp.Items[0].NATType, egressNATTypeFullCone)
	}
}

func TestHandleListEgressNATStatsIncludesManagedNetworkAutoEgressNATMetadata(t *testing.T) {
	db := openTestDB(t)

	network := ManagedNetwork{
		Name:            "managed-net",
		BridgeMode:      managedNetworkBridgeModeExisting,
		Bridge:          "vmbr1",
		UplinkInterface: "vmbr0",
		AutoEgressNAT:   true,
		Enabled:         true,
	}
	networkID, err := dbAddManagedNetwork(db, &network)
	if err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	syntheticID := managedNetworkSyntheticID("egress_nat", networkID, network.Bridge)
	pm := &ProcessManager{
		kernelEgressNATStats: map[int64]EgressNATStatsReport{
			syntheticID: {
				EgressNATID:  syntheticID,
				ActiveConns:  3,
				TotalConns:   5,
				NatTableSize: 2,
				BytesIn:      123,
			},
		},
	}

	req := httptest.NewRequest("GET", "/api/egress-nats/stats", nil)
	w := httptest.NewRecorder()

	handleListEgressNATStats(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp EgressNATStatsListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp.Items) != 1 {
		t.Fatalf("unexpected items length: %d", len(resp.Items))
	}
	if resp.Items[0].EgressNATID != syntheticID {
		t.Fatalf("unexpected egress nat id: got %d want %d", resp.Items[0].EgressNATID, syntheticID)
	}
	if resp.Items[0].ParentInterface != network.Bridge {
		t.Fatalf("unexpected parent interface: got %q want %q", resp.Items[0].ParentInterface, network.Bridge)
	}
	if resp.Items[0].OutInterface != network.UplinkInterface {
		t.Fatalf("unexpected out interface: got %q want %q", resp.Items[0].OutInterface, network.UplinkInterface)
	}
	if resp.Items[0].Protocol != "tcp+udp+icmp" {
		t.Fatalf("unexpected protocol: got %q want %q", resp.Items[0].Protocol, "tcp+udp+icmp")
	}
	if resp.Items[0].NATType != egressNATTypeSymmetric {
		t.Fatalf("unexpected nat type: got %q want %q", resp.Items[0].NATType, egressNATTypeSymmetric)
	}
}

func TestHandleListCurrentConnsIncludesEgressNATs(t *testing.T) {
	db := openTestDB(t)

	item := EgressNAT{
		ParentInterface: "vmbr1",
		OutInterface:    "vmbr0",
		OutSourceIP:     "198.51.100.20",
		Protocol:        "udp+icmp",
		Enabled:         true,
	}
	id, err := dbAddEgressNAT(db, &item)
	if err != nil {
		t.Fatalf("add egress nat: %v", err)
	}

	pm := &ProcessManager{
		kernelRuntime: stubKernelStatsRuntime{
			snapshot: kernelRuleStatsSnapshot{
				ByRuleID: map[uint32]kernelRuleStats{
					33: {
						UDPNatEntries:  4,
						ICMPNatEntries: 5,
					},
				},
			},
		},
		kernelEgressNATs: map[int64]bool{
			id: true,
		},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			33: {kind: workerKindEgressNAT, id: id},
		},
	}

	req := httptest.NewRequest("GET", "/api/stats/current-conns", nil)
	w := httptest.NewRecorder()

	handleListCurrentConns(w, req, db, pm)
	if w.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp CurrentConnsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp.EgressNATs) != 1 {
		t.Fatalf("unexpected egress nat conn count rows: %d", len(resp.EgressNATs))
	}
	if resp.EgressNATs[0].EgressNATID != id {
		t.Fatalf("unexpected egress nat id: got %d want %d", resp.EgressNATs[0].EgressNATID, id)
	}
	if resp.EgressNATs[0].CurrentConns != 9 {
		t.Fatalf("unexpected current conns: got %d want 9", resp.EgressNATs[0].CurrentConns)
	}
}

func TestHandleListEgressNATStatsSortsICMPCurrentConnsCorrectly(t *testing.T) {
	db := openTestDB(t)

	items := []EgressNAT{
		{ParentInterface: "vmbr1", OutInterface: "vmbr0", OutSourceIP: "198.51.100.30", Protocol: "icmp", NATType: egressNATTypeSymmetric, Enabled: true},
		{ParentInterface: "vmbr2", OutInterface: "vmbr0", OutSourceIP: "198.51.100.31", Protocol: "udp", NATType: egressNATTypeSymmetric, Enabled: true},
	}
	var ids []int64
	for i := range items {
		item := items[i]
		id, err := dbAddEgressNAT(db, &item)
		if err != nil {
			t.Fatalf("add egress nat %d: %v", i, err)
		}
		ids = append(ids, id)
	}

	pm := &ProcessManager{
		kernelEgressNATStats: map[int64]EgressNATStatsReport{
			ids[0]: {EgressNATID: ids[0], NatTableSize: 5, ICMPNatSize: 5},
			ids[1]: {EgressNATID: ids[1], NatTableSize: 4},
		},
	}

	req := httptest.NewRequest("GET", "/api/egress-nats/stats?page=1&page_size=1&sort_key=current_conns&sort_asc=false", nil)
	w := httptest.NewRecorder()

	handleListEgressNATStats(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp EgressNATStatsListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp.Items) != 1 {
		t.Fatalf("unexpected items length: %d", len(resp.Items))
	}
	if resp.Items[0].EgressNATID != ids[0] {
		t.Fatalf("unexpected first egress nat id: got %d want %d", resp.Items[0].EgressNATID, ids[0])
	}
}

func TestHandleListCurrentConnsIncludesSyntheticManagedNetworkEgressNATs(t *testing.T) {
	db := openTestDB(t)

	network := ManagedNetwork{
		Name:            "managed-net",
		BridgeMode:      managedNetworkBridgeModeExisting,
		Bridge:          "vmbr1",
		UplinkInterface: "vmbr0",
		AutoEgressNAT:   true,
		Enabled:         true,
	}
	networkID, err := dbAddManagedNetwork(db, &network)
	if err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	syntheticID := managedNetworkSyntheticID("egress_nat", networkID, network.Bridge)
	pm := &ProcessManager{
		kernelRuntime: stubKernelStatsRuntime{
			snapshot: kernelRuleStatsSnapshot{
				ByRuleID: map[uint32]kernelRuleStats{
					44: {
						TCPActiveConns: 2,
						UDPNatEntries:  3,
						ICMPNatEntries: 4,
					},
				},
			},
		},
		kernelEgressNATs: map[int64]bool{
			syntheticID: true,
		},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			44: {kind: workerKindEgressNAT, id: syntheticID},
		},
	}

	req := httptest.NewRequest("GET", "/api/stats/current-conns", nil)
	w := httptest.NewRecorder()

	handleListCurrentConns(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp CurrentConnsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp.EgressNATs) != 1 {
		t.Fatalf("unexpected egress nat conn count rows: %d", len(resp.EgressNATs))
	}
	if resp.EgressNATs[0].EgressNATID != syntheticID {
		t.Fatalf("unexpected synthetic egress nat id: got %d want %d", resp.EgressNATs[0].EgressNATID, syntheticID)
	}
	if resp.EgressNATs[0].CurrentConns != 9 {
		t.Fatalf("unexpected current conns: got %d want 9", resp.EgressNATs[0].CurrentConns)
	}
}

func TestHandleListCurrentConnsReturnsKernelSnapshotError(t *testing.T) {
	db := openTestDB(t)
	pm := &ProcessManager{
		kernelRuntime: failingKernelStatsRuntime{err: errors.New("snapshot failed")},
		kernelRules: map[int64]bool{
			1: true,
		},
	}

	req := httptest.NewRequest("GET", "/api/stats/current-conns", nil)
	w := httptest.NewRecorder()

	handleListCurrentConns(w, req, db, pm)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "snapshot failed") {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestHandleListCurrentConnsUsesSharedKernelSnapshotInsteadOfAggregateCache(t *testing.T) {
	db := openTestDB(t)

	rule := Rule{
		InIP:     "198.51.100.51",
		InPort:   15001,
		OutIP:    "203.0.113.51",
		OutPort:  25001,
		Protocol: "udp",
		Enabled:  true,
	}
	ruleID, err := dbAddRule(db, &rule)
	if err != nil {
		t.Fatalf("dbAddRule() error = %v", err)
	}

	pm := &ProcessManager{
		kernelRuntime: stubKernelStatsRuntime{
			snapshot: kernelRuleStatsSnapshot{
				ByRuleID: map[uint32]kernelRuleStats{
					91: {UDPNatEntries: 7},
				},
			},
		},
		kernelRules: map[int64]bool{
			ruleID: true,
		},
		kernelRuleStats: map[int64]RuleStatsReport{
			ruleID: {RuleID: ruleID, NatTableSize: 1},
		},
		kernelStatsAt: time.Now(),
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			91: {kind: workerKindRule, id: ruleID},
		},
	}

	req := httptest.NewRequest("GET", "/api/stats/current-conns", nil)
	w := httptest.NewRecorder()

	handleListCurrentConns(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp CurrentConnsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp.Rules) != 1 {
		t.Fatalf("unexpected rule rows: %d", len(resp.Rules))
	}
	if resp.Rules[0].RuleID != ruleID {
		t.Fatalf("unexpected rule id: got %d want %d", resp.Rules[0].RuleID, ruleID)
	}
	if resp.Rules[0].CurrentConns != 7 {
		t.Fatalf("unexpected current conns: got %d want 7", resp.Rules[0].CurrentConns)
	}
}

func TestHandleListEgressNATStatsSortsSyntheticCurrentConnsCorrectly(t *testing.T) {
	db := openTestDB(t)

	explicit := EgressNAT{
		ParentInterface: "vmbr2",
		OutInterface:    "vmbr0",
		OutSourceIP:     "198.51.100.40",
		Protocol:        "tcp",
		NATType:         egressNATTypeSymmetric,
		Enabled:         true,
	}
	explicitID, err := dbAddEgressNAT(db, &explicit)
	if err != nil {
		t.Fatalf("dbAddEgressNAT() error = %v", err)
	}

	network := ManagedNetwork{
		Name:            "managed-net",
		BridgeMode:      managedNetworkBridgeModeExisting,
		Bridge:          "vmbr1",
		UplinkInterface: "vmbr0",
		AutoEgressNAT:   true,
		Enabled:         true,
	}
	networkID, err := dbAddManagedNetwork(db, &network)
	if err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	syntheticID := managedNetworkSyntheticID("egress_nat", networkID, network.Bridge)
	pm := &ProcessManager{
		kernelEgressNATStats: map[int64]EgressNATStatsReport{
			explicitID:  {EgressNATID: explicitID, ActiveConns: 5},
			syntheticID: {EgressNATID: syntheticID, ActiveConns: 2, NatTableSize: 7, ICMPNatSize: 4},
		},
	}

	req := httptest.NewRequest("GET", "/api/egress-nats/stats?page=1&page_size=1&sort_key=current_conns&sort_asc=false", nil)
	w := httptest.NewRecorder()

	handleListEgressNATStats(w, req, db, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp EgressNATStatsListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp.Items) != 1 {
		t.Fatalf("unexpected items length: %d", len(resp.Items))
	}
	if resp.Items[0].EgressNATID != syntheticID {
		t.Fatalf("unexpected first egress nat id: got %d want %d", resp.Items[0].EgressNATID, syntheticID)
	}
	if resp.Items[0].Protocol != "tcp+udp+icmp" {
		t.Fatalf("unexpected protocol: got %q want %q", resp.Items[0].Protocol, "tcp+udp+icmp")
	}
	if resp.Items[0].ParentInterface != network.Bridge {
		t.Fatalf("unexpected parent interface: got %q want %q", resp.Items[0].ParentInterface, network.Bridge)
	}
}

func TestHandleKernelRuntimeIncludesFallbackSummary(t *testing.T) {
	prevProfile := kernelAdaptiveMapProfileOverride
	prevSet := kernelAdaptiveMapProfileOverrideSet
	kernelAdaptiveMapProfileOverride = kernelAdaptiveMapProfile{
		totalMemoryBytes:   4 << 30,
		flowsBaseLimit:     131072,
		natBaseLimit:       131072,
		egressNATAutoFloor: 131072,
	}
	kernelAdaptiveMapProfileOverrideSet = true
	defer func() {
		kernelAdaptiveMapProfileOverride = prevProfile
		kernelAdaptiveMapProfileOverrideSet = prevSet
	}()

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
	if resp.KernelMapProfile != kernelAdaptiveMapProfileMedium {
		t.Fatalf("kernel_map_profile = %q, want %q", resp.KernelMapProfile, kernelAdaptiveMapProfileMedium)
	}
	if resp.KernelMapTotalMemoryBytes != 4<<30 {
		t.Fatalf("kernel_map_total_memory_bytes = %d, want %d", resp.KernelMapTotalMemoryBytes, uint64(4<<30))
	}
	if resp.KernelRulesMapBaseLimit != kernelRulesMapBaseLimit || resp.KernelFlowsMapBaseLimit != 131072 || resp.KernelNATMapBaseLimit != 131072 || resp.KernelEgressNATAutoFloor != 131072 {
		t.Fatalf(
			"kernel map bases/floor = rules:%d flows:%d nat:%d floor:%d",
			resp.KernelRulesMapBaseLimit,
			resp.KernelFlowsMapBaseLimit,
			resp.KernelNATMapBaseLimit,
			resp.KernelEgressNATAutoFloor,
		)
	}
	if resp.KernelRulesMapCapacityMode != "adaptive" || resp.KernelFlowsMapCapacityMode != "adaptive" || resp.KernelNATMapCapacityMode != "adaptive" {
		t.Fatalf(
			"kernel map modes = rules:%q flows:%q nat:%q",
			resp.KernelRulesMapCapacityMode,
			resp.KernelFlowsMapCapacityMode,
			resp.KernelNATMapCapacityMode,
		)
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
				FallbackReason:  `kernel dataplane pressure: flows 242000/262144 (92.3%) exceeded 92% high watermark, routing new sessions back to userspace until usage drops below 85%`,
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

func TestHandleKernelRuntimeUsesSharedSnapshotCache(t *testing.T) {
	pm := &ProcessManager{
		cfg: &Config{DefaultEngine: ruleEngineAuto},
		kernelRuntime: stubKernelRuntimeViewRuntime{
			available: true,
			reason:    "ok",
		},
		kernelRules: map[int64]bool{
			101: true,
		},
		rulePlans: map[int64]ruleDataplanePlan{
			201: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  "initial fallback",
			},
		},
		kernelRetryCount:      1,
		lastKernelRetryReason: "initial retry",
	}

	req := httptest.NewRequest(http.MethodGet, "/api/kernel/runtime", nil)
	w := httptest.NewRecorder()
	handleKernelRuntime(w, req, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("first status = %d body=%s", w.Code, w.Body.String())
	}
	var first KernelRuntimeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode first response: %v body=%s", err, w.Body.String())
	}
	if first.ActiveRuleCount != 1 || first.KernelFallbackRuleCount != 1 || first.KernelRetryCount != 1 {
		t.Fatalf(
			"first response = active_rules:%d fallback_rules:%d retry_count:%d, want 1/1/1",
			first.ActiveRuleCount,
			first.KernelFallbackRuleCount,
			first.KernelRetryCount,
		)
	}

	pm.mu.Lock()
	pm.kernelRules[102] = true
	pm.rulePlans = map[int64]ruleDataplanePlan{}
	pm.kernelRetryCount = 2
	pm.lastKernelRetryReason = "updated retry"
	pm.mu.Unlock()

	w = httptest.NewRecorder()
	handleKernelRuntime(w, req, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("second status = %d body=%s", w.Code, w.Body.String())
	}
	var cached KernelRuntimeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &cached); err != nil {
		t.Fatalf("decode cached response: %v body=%s", err, w.Body.String())
	}
	if cached.ActiveRuleCount != first.ActiveRuleCount ||
		cached.KernelFallbackRuleCount != first.KernelFallbackRuleCount ||
		cached.KernelRetryCount != first.KernelRetryCount ||
		cached.LastKernelRetryReason != first.LastKernelRetryReason {
		t.Fatalf("cached response changed unexpectedly: %+v (first=%+v)", cached, first)
	}

	freshReq := httptest.NewRequest(http.MethodGet, "/api/kernel/runtime?refresh=1", nil)
	freshReq.Header.Set("Cache-Control", "no-cache")
	w = httptest.NewRecorder()
	handleKernelRuntime(w, freshReq, pm)
	if w.Code != http.StatusOK {
		t.Fatalf("fresh status = %d body=%s", w.Code, w.Body.String())
	}
	var fresh KernelRuntimeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &fresh); err != nil {
		t.Fatalf("decode fresh response: %v body=%s", err, w.Body.String())
	}
	if fresh.ActiveRuleCount != 2 || fresh.KernelFallbackRuleCount != 0 || fresh.KernelRetryCount != 2 {
		t.Fatalf(
			"fresh response = active_rules:%d fallback_rules:%d retry_count:%d, want 2/0/2",
			fresh.ActiveRuleCount,
			fresh.KernelFallbackRuleCount,
			fresh.KernelRetryCount,
		)
	}
	if fresh.LastKernelRetryReason != "updated retry" {
		t.Fatalf("fresh last_kernel_retry_reason = %q, want %q", fresh.LastKernelRetryReason, "updated retry")
	}
}
