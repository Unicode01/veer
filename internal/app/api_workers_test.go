package app

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestHandleListWorkersIncludesEgressNATWorker(t *testing.T) {
	db := openTestDB(t)

	enabled := EgressNAT{
		ParentInterface: "vmbr1",
		ChildInterface:  "tap100i0",
		OutInterface:    "vmbr0",
		OutSourceIP:     "198.51.100.30",
		Protocol:        "tcp+udp",
		NATType:         egressNATTypeFullCone,
		Enabled:         true,
	}
	enabledID, err := dbAddEgressNAT(db, &enabled)
	if err != nil {
		t.Fatalf("add enabled egress nat: %v", err)
	}
	disabled := EgressNAT{
		ParentInterface: "vmbr2",
		ChildInterface:  "tap200i0",
		OutInterface:    "vmbr0",
		OutSourceIP:     "198.51.100.31",
		Protocol:        "udp",
		NATType:         egressNATTypeSymmetric,
		Enabled:         false,
	}
	if _, err := dbAddEgressNAT(db, &disabled); err != nil {
		t.Fatalf("add disabled egress nat: %v", err)
	}

	pm := &ProcessManager{
		binaryHash:             "deadbeefcafebabe",
		ruleWorkers:            map[int]*WorkerInfo{},
		rangeWorkers:           map[int]*WorkerInfo{},
		kernelRules:            map[int64]bool{},
		kernelRanges:           map[int64]bool{},
		kernelEgressNATs:       map[int64]bool{enabledID: true},
		egressNATPlans:         map[int64]ruleDataplanePlan{enabledID: {KernelEligible: true, EffectiveEngine: ruleEngineKernel}},
		kernelEgressNATEngines: map[int64]string{enabledID: kernelEngineTC},
	}

	req := httptest.NewRequest("GET", "/api/workers", nil)
	w := httptest.NewRecorder()

	handleListWorkers(w, req, db, pm)
	if w.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp WorkerListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp.Workers) != 1 {
		t.Fatalf("unexpected worker rows: %d", len(resp.Workers))
	}
	worker := resp.Workers[0]
	if worker.Kind != workerKindEgressNAT {
		t.Fatalf("worker kind = %q, want %q", worker.Kind, workerKindEgressNAT)
	}
	if worker.Status != "running" {
		t.Fatalf("worker status = %q, want running", worker.Status)
	}
	if worker.EgressNATCount != 1 || len(worker.EgressNATs) != 1 {
		t.Fatalf("unexpected egress nat counts: count=%d details=%d", worker.EgressNATCount, len(worker.EgressNATs))
	}
	if worker.EgressNATs[0].ID != enabledID {
		t.Fatalf("unexpected egress nat id: got %d want %d", worker.EgressNATs[0].ID, enabledID)
	}
	if worker.EgressNATs[0].EffectiveKernelEngine != kernelEngineTC {
		t.Fatalf("effective kernel engine = %q, want %q", worker.EgressNATs[0].EffectiveKernelEngine, kernelEngineTC)
	}
	if worker.EgressNATs[0].NATType != egressNATTypeFullCone {
		t.Fatalf("nat type = %q, want %q", worker.EgressNATs[0].NATType, egressNATTypeFullCone)
	}
}

func TestHandleListWorkersIncludesManagedNetworkAutoEgressNATWorker(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "eno1", Kind: "device"},
			{Name: "vmbr1", Kind: "bridge"},
			{Name: "tap100i0", Parent: "vmbr1", Kind: "tap"},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	network := ManagedNetwork{
		Name:            "managed-net",
		BridgeMode:      managedNetworkBridgeModeExisting,
		Bridge:          "vmbr1",
		UplinkInterface: "eno1",
		AutoEgressNAT:   true,
		Enabled:         true,
	}
	networkID, err := dbAddManagedNetwork(db, &network)
	if err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}
	network.ID = networkID

	syntheticID := managedNetworkSyntheticID("egress_nat", network.ID, network.Bridge)
	pm := &ProcessManager{
		binaryHash:             "deadbeefcafebabe",
		ruleWorkers:            map[int]*WorkerInfo{},
		rangeWorkers:           map[int]*WorkerInfo{},
		kernelRules:            map[int64]bool{},
		kernelRanges:           map[int64]bool{},
		kernelEgressNATs:       map[int64]bool{syntheticID: true},
		egressNATPlans:         map[int64]ruleDataplanePlan{syntheticID: {KernelEligible: true, EffectiveEngine: ruleEngineKernel}},
		kernelEgressNATEngines: map[int64]string{syntheticID: kernelEngineTC},
	}

	req := httptest.NewRequest("GET", "/api/workers", nil)
	w := httptest.NewRecorder()

	handleListWorkers(w, req, db, pm)
	if w.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp WorkerListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp.Workers) != 1 {
		t.Fatalf("unexpected worker rows: %d", len(resp.Workers))
	}
	worker := resp.Workers[0]
	if worker.Kind != workerKindEgressNAT {
		t.Fatalf("worker kind = %q, want %q", worker.Kind, workerKindEgressNAT)
	}
	if worker.Status != "running" {
		t.Fatalf("worker status = %q, want running", worker.Status)
	}
	if worker.EgressNATCount != 1 || len(worker.EgressNATs) != 1 {
		t.Fatalf("unexpected egress nat counts: count=%d details=%d", worker.EgressNATCount, len(worker.EgressNATs))
	}
	if worker.EgressNATs[0].ID != syntheticID {
		t.Fatalf("unexpected egress nat id: got %d want %d", worker.EgressNATs[0].ID, syntheticID)
	}
	if worker.EgressNATs[0].ParentInterface != network.Bridge {
		t.Fatalf("parent interface = %q, want %q", worker.EgressNATs[0].ParentInterface, network.Bridge)
	}
	if worker.EgressNATs[0].OutInterface != network.UplinkInterface {
		t.Fatalf("out interface = %q, want %q", worker.EgressNATs[0].OutInterface, network.UplinkInterface)
	}
	if worker.EgressNATs[0].Protocol != "tcp+udp+icmp" {
		t.Fatalf("protocol = %q, want %q", worker.EgressNATs[0].Protocol, "tcp+udp+icmp")
	}
	if worker.EgressNATs[0].NATType != egressNATTypeSymmetric {
		t.Fatalf("nat type = %q, want %q", worker.EgressNATs[0].NATType, egressNATTypeSymmetric)
	}
	if worker.EgressNATs[0].EffectiveKernelEngine != kernelEngineTC {
		t.Fatalf("effective kernel engine = %q, want %q", worker.EgressNATs[0].EffectiveKernelEngine, kernelEngineTC)
	}
}

func TestHandleListWorkersIncludesSharedProxyEnabledSiteCount(t *testing.T) {
	db := openTestDB(t)

	for _, site := range []Site{
		{Domain: "a.example.com", ListenIP: "0.0.0.0", BackendIP: "127.0.0.1", BackendHTTP: 8080, Enabled: true},
		{Domain: "b.example.com", ListenIP: "0.0.0.0", BackendIP: "127.0.0.1", BackendHTTPS: 8443, Enabled: true},
		{Domain: "c.example.com", ListenIP: "0.0.0.0", BackendIP: "127.0.0.1", BackendHTTP: 8081, Enabled: false},
	} {
		if _, err := dbAddSite(db, &site); err != nil {
			t.Fatalf("add site: %v", err)
		}
	}

	pm := &ProcessManager{
		binaryHash:       "proxyhash",
		ruleWorkers:      map[int]*WorkerInfo{},
		rangeWorkers:     map[int]*WorkerInfo{},
		kernelRules:      map[int64]bool{},
		kernelRanges:     map[int64]bool{},
		kernelEgressNATs: map[int64]bool{},
		sharedProxy: &WorkerInfo{
			kind:       workerKindShared,
			running:    true,
			binaryHash: "proxyhash",
		},
	}

	req := httptest.NewRequest("GET", "/api/workers", nil)
	w := httptest.NewRecorder()

	handleListWorkers(w, req, db, pm)
	if w.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp WorkerListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp.Workers) != 1 {
		t.Fatalf("unexpected worker rows: %d", len(resp.Workers))
	}
	worker := resp.Workers[0]
	if worker.Kind != workerKindShared {
		t.Fatalf("worker kind = %q, want %q", worker.Kind, workerKindShared)
	}
	if worker.Status != "running" {
		t.Fatalf("worker status = %q, want running", worker.Status)
	}
	if worker.SiteCount != 2 {
		t.Fatalf("worker site_count = %d, want 2", worker.SiteCount)
	}
}

func TestHandleListWorkersIncludesKernelRulesFromEnabledIDQuery(t *testing.T) {
	db := openTestDB(t)

	enabledRuleID, err := dbAddRule(db, &Rule{
		InIP:     "198.51.100.10",
		InPort:   443,
		OutIP:    "203.0.113.10",
		OutPort:  8443,
		Protocol: "tcp",
		Enabled:  true,
		Remark:   "enabled",
		Tag:      "prod",
	})
	if err != nil {
		t.Fatalf("add enabled rule: %v", err)
	}
	disabledRuleID, err := dbAddRule(db, &Rule{
		InIP:     "198.51.100.11",
		InPort:   443,
		OutIP:    "203.0.113.11",
		OutPort:  8443,
		Protocol: "tcp",
		Enabled:  false,
		Remark:   "disabled",
		Tag:      "prod",
	})
	if err != nil {
		t.Fatalf("add disabled rule: %v", err)
	}

	pm := &ProcessManager{
		binaryHash:        "kernelhash",
		ruleWorkers:       map[int]*WorkerInfo{},
		rangeWorkers:      map[int]*WorkerInfo{},
		kernelRules:       map[int64]bool{enabledRuleID: true, disabledRuleID: true},
		kernelRanges:      map[int64]bool{},
		kernelEgressNATs:  map[int64]bool{},
		rulePlans:         map[int64]ruleDataplanePlan{enabledRuleID: {KernelEligible: true, EffectiveEngine: ruleEngineKernel}},
		kernelRuleEngines: map[int64]string{enabledRuleID: kernelEngineTC},
	}

	req := httptest.NewRequest("GET", "/api/workers", nil)
	w := httptest.NewRecorder()

	handleListWorkers(w, req, db, pm)
	if w.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var resp WorkerListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(resp.Workers) != 1 {
		t.Fatalf("unexpected worker rows: %d", len(resp.Workers))
	}
	worker := resp.Workers[0]
	if worker.Kind != "kernel" {
		t.Fatalf("worker kind = %q, want kernel", worker.Kind)
	}
	if worker.RuleCount != 1 || len(worker.Rules) != 1 {
		t.Fatalf("unexpected kernel rule counts: count=%d details=%d", worker.RuleCount, len(worker.Rules))
	}
	if worker.Rules[0].ID != enabledRuleID {
		t.Fatalf("worker rule id = %d, want %d", worker.Rules[0].ID, enabledRuleID)
	}
	if worker.Rules[0].Status != "running" {
		t.Fatalf("worker rule status = %q, want running", worker.Rules[0].Status)
	}
}
