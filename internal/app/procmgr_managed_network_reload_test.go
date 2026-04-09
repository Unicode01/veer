package app

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type orderedManagedNetworkRuntime struct {
	reconcileCalls     int
	lastItems          []ManagedNetwork
	repairDone         <-chan struct{}
	calledBeforeRepair bool
	mu                 sync.Mutex
}

func (rt *orderedManagedNetworkRuntime) Reconcile(items []ManagedNetwork, reservations []ManagedNetworkReservation) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.reconcileCalls++
	rt.lastItems = append([]ManagedNetwork(nil), items...)
	select {
	case <-rt.repairDone:
	default:
		rt.calledBeforeRepair = true
	}
	return nil
}

func (rt *orderedManagedNetworkRuntime) SnapshotStatus() map[int64]managedNetworkRuntimeStatus {
	return nil
}

func (rt *orderedManagedNetworkRuntime) Close() error {
	return nil
}

func TestReloadManagedNetworkRuntimeOnlyRetainsKernelRulesWhileRefreshingManagedAutoEgressNAT(t *testing.T) {
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

	rule := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.10",
		InPort:       10001,
		OutInterface: "eno2",
		OutIP:        "198.51.100.10",
		OutPort:      20001,
		Protocol:     "tcp",
		Enabled:      true,
	}
	ruleID, err := dbAddRule(db, &rule)
	if err != nil {
		t.Fatalf("dbAddRule() error = %v", err)
	}
	rule.ID = ruleID
	rule.kernelLogKind = workerKindRule
	rule.kernelLogOwnerID = ruleID

	network := ManagedNetwork{
		Name:            "managed",
		BridgeMode:      managedNetworkBridgeModeCreate,
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

	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule.ID: kernelEngineTC,
		},
		retainedRules: map[int64][]Rule{
			rule.ID: {rule},
		},
	}

	pm := &ProcessManager{
		db:                 db,
		cfg:                &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 1},
		ruleWorkers:        make(map[int]*WorkerInfo),
		rangeWorkers:       make(map[int]*WorkerInfo),
		rulePlans:          map[int64]ruleDataplanePlan{rule.ID: {KernelEligible: true, EffectiveEngine: ruleEngineKernel}},
		rangePlans:         map[int64]rangeDataplanePlan{},
		egressNATPlans:     map[int64]ruleDataplanePlan{},
		kernelRuntime:      rt,
		kernelRules:        map[int64]bool{rule.ID: true},
		kernelRanges:       map[int64]bool{},
		kernelEgressNATs:   map[int64]bool{},
		kernelRuleEngines:  map[int64]string{rule.ID: kernelEngineTC},
		kernelRangeEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule.ID): {kind: workerKindRule, id: rule.ID},
		},
	}

	if err := pm.reloadManagedNetworkRuntimeOnly(); err != nil {
		t.Fatalf("reloadManagedNetworkRuntimeOnly() error = %v", err)
	}
	if len(rt.incrementalCalls) != 1 {
		t.Fatalf("incrementalCalls = %d, want 1", len(rt.incrementalCalls))
	}

	call := rt.incrementalCalls[0]
	retainedRules := call.retainedByEngine[kernelEngineTC]
	if len(retainedRules) != 1 || retainedRules[0].ID != rule.ID {
		t.Fatalf("retained rules = %+v, want retained kernel rule %d", retainedRules, rule.ID)
	}
	if len(call.newRules) == 0 {
		t.Fatal("newRules = 0, want managed auto egress nat rules to be applied")
	}
	for _, item := range call.newRules {
		if !isKernelEgressNATRule(item) {
			t.Fatalf("new rule = %+v, want kernel egress nat rule", item)
		}
		if item.InInterface != "tap100i0" || item.OutInterface != "eno1" {
			t.Fatalf("new rule interfaces = in:%s out:%s, want tap100i0 -> eno1", item.InInterface, item.OutInterface)
		}
	}

	syntheticID := managedNetworkSyntheticID("egress_nat", network.ID, network.Bridge)
	if !pm.kernelRules[rule.ID] {
		t.Fatalf("kernelRules = %#v, want retained rule %d", pm.kernelRules, rule.ID)
	}
	if !pm.kernelEgressNATs[syntheticID] {
		t.Fatalf("kernelEgressNATs = %#v, want managed auto egress nat %d active", pm.kernelEgressNATs, syntheticID)
	}
	if _, ok := pm.dynamicEgressNATParents["vmbr1"]; !ok {
		t.Fatalf("dynamicEgressNATParents = %#v, want vmbr1", pm.dynamicEgressNATParents)
	}
	if until, ok := pm.managedRuntimeReloadSuppressUntil["vmbr1"]; !ok || until.IsZero() {
		t.Fatalf("managedRuntimeReloadSuppressUntil[vmbr1] = %v, want active suppression", until)
	}
	if until, ok := pm.managedRuntimeReloadSuppressUntil["tap100i0"]; !ok || until.IsZero() {
		t.Fatalf("managedRuntimeReloadSuppressUntil[tap100i0] = %v, want active suppression", until)
	}
}

func TestSummarizeManagedNetworkRuntimeReload(t *testing.T) {
	t.Parallel()

	managedNetworks := []ManagedNetwork{
		{
			ID:             1,
			Name:           "managed-a",
			Bridge:         "vmbr1",
			IPv4Enabled:    true,
			IPv4CIDR:       "10.0.0.254/24",
			IPv4PoolStart:  "10.0.0.10",
			IPv4PoolEnd:    "10.0.0.20",
			IPv4DNSServers: "1.1.1.1",
			AutoEgressNAT:  true,
			Enabled:        true,
		},
		{
			ID:      2,
			Name:    "managed-b",
			Bridge:  "vmbr2",
			Enabled: true,
		},
		{
			ID:      3,
			Name:    "managed-disabled",
			Bridge:  "vmbr9",
			Enabled: false,
		},
	}
	reservations := []ManagedNetworkReservation{
		{ManagedNetworkID: 1, MACAddress: "bc:24:11:31:53:db", IPv4Address: "10.0.0.11"},
	}
	effectiveIPv6Assignments := []IPv6Assignment{
		{
			ID:              10,
			ParentInterface: "vmbr0",
			TargetInterface: "tap100i0",
			ParentPrefix:    "2001:db8:100::/64",
			AssignedPrefix:  "2001:db8:100::2/128",
			Enabled:         true,
		},
		{
			ID:              11,
			ParentInterface: "vmbr0",
			TargetInterface: "tap200i0",
			ParentPrefix:    "2001:db8:200::/56",
			AssignedPrefix:  "2001:db8:200:1::/64",
			Enabled:         true,
		},
		{
			ID:              12,
			ParentInterface: "",
			TargetInterface: "tap300i0",
			ParentPrefix:    "2001:db8:300::/64",
			AssignedPrefix:  "2001:db8:300::2/128",
			Enabled:         true,
		},
		{
			ID:              13,
			ParentInterface: "vmbr0",
			TargetInterface: "tap400i0",
			ParentPrefix:    "2001:db8:400::/64",
			AssignedPrefix:  "2001:db8:400::2/128",
			Enabled:         false,
		},
	}
	autoEgressNATs := []EgressNAT{
		{ID: -1, ParentInterface: "vmbr1", Enabled: true},
		{ID: -2, ParentInterface: "vmbr2", Enabled: true},
		{ID: -3, ParentInterface: "vmbr9", Enabled: false},
	}

	if got := summarizeManagedNetworkRuntimeReload(managedNetworks, reservations, effectiveIPv6Assignments, autoEgressNATs); got != "networks=2 bridges=vmbr1,vmbr2 dhcpv4=vmbr1 ipv6_routes=2 proxy_ndp=1 ra=tap100i0,tap200i0 dhcpv6=tap100i0 auto_egress_nat=2(vmbr1,vmbr2)" {
		t.Fatalf("summarizeManagedNetworkRuntimeReload() = %q", got)
	}
}

func TestCollectManagedNetworkRuntimeTouchedInterfaces(t *testing.T) {
	t.Parallel()

	got := collectManagedNetworkRuntimeTouchedInterfaces(
		[]ManagedNetwork{{
			ID:                  1,
			Bridge:              "vmbr1",
			UplinkInterface:     "eno1",
			IPv6ParentInterface: "eno2",
			Enabled:             true,
		}},
		[]IPv6Assignment{{
			ID:              10,
			ParentInterface: "eno2",
			TargetInterface: "tap100i0",
			Enabled:         true,
		}},
		managedNetworkRuntimeCompilation{
			Previews: map[int64]managedNetworkRuntimePreview{
				1: {ChildInterfaces: []string{"tap100i0", "tap100i1"}},
			},
		},
	)
	if len(got) != 5 {
		t.Fatalf("len(collectManagedNetworkRuntimeTouchedInterfaces()) = %d, want 5 (%v)", len(got), got)
	}
	if got[0] != "vmbr1" || got[1] != "eno1" || got[2] != "eno2" || got[3] != "tap100i0" || got[4] != "tap100i1" {
		t.Fatalf("collectManagedNetworkRuntimeTouchedInterfaces() = %v, want [vmbr1 eno1 eno2 tap100i0 tap100i1]", got)
	}
}

func waitForManagedNetworkReloadCondition(t *testing.T, timeout time.Duration, fn func() bool, description string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func TestManagedRuntimeReloadLoopAppliesQueuedReload(t *testing.T) {
	db := openTestDB(t)

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:          "lab",
		BridgeMode:    managedNetworkBridgeModeCreate,
		Bridge:        "vmbr1",
		IPv4Enabled:   true,
		IPv4CIDR:      "192.0.2.1/24",
		IPv4PoolEnd:   "192.0.2.20",
		IPv4PoolStart: "192.0.2.10",
		Enabled:       true,
	}); err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	fakeManagedRuntime := &fakeManagedNetworkRuntime{}
	fakeIPv6Runtime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		db:                       db,
		cfg:                      &Config{DefaultEngine: ruleEngineAuto},
		managedNetworkRuntime:    fakeManagedRuntime,
		ipv6Runtime:              fakeIPv6Runtime,
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedRuntimeReloadDone: make(chan struct{}),
		redistributeWake:         make(chan struct{}, 1),
	}

	go pm.managedRuntimeReloadLoop()
	t.Cleanup(func() {
		pm.beginShutdown()
		if !waitForStopChannel(pm.managedRuntimeReloadDone, time.Second) {
			t.Fatal("managedRuntimeReloadDone did not close during cleanup")
		}
	})

	pm.requestManagedNetworkRuntimeReloadWithSource(0, "link_change", "tap100i0", "vmbr1")

	waitForManagedNetworkReloadCondition(t, 2*time.Second, func() bool {
		status := pm.snapshotManagedNetworkRuntimeReloadStatus()
		return status.LastResult == "success" && fakeManagedRuntime.reconcileCalls == 1 && fakeIPv6Runtime.reconcileCalls == 1
	}, "managed runtime reload success")

	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if status.Pending {
		t.Fatal("Pending = true, want false after queued reload is applied")
	}
	if status.LastRequestSource != "link_change" {
		t.Fatalf("LastRequestSource = %q, want link_change", status.LastRequestSource)
	}
	if status.LastRequestSummary != "tap100i0,vmbr1" {
		t.Fatalf("LastRequestSummary = %q, want tap100i0,vmbr1", status.LastRequestSummary)
	}
	if status.LastStartedAt.IsZero() || status.LastCompletedAt.IsZero() {
		t.Fatalf("reload timestamps = started:%v completed:%v, want both recorded", status.LastStartedAt, status.LastCompletedAt)
	}
	if !strings.Contains(status.LastAppliedSummary, "networks=1") || !strings.Contains(status.LastAppliedSummary, "bridges=vmbr1") || !strings.Contains(status.LastAppliedSummary, "dhcpv4=vmbr1") {
		t.Fatalf("LastAppliedSummary = %q, want managed runtime summary", status.LastAppliedSummary)
	}
	if pm.redistributePending {
		t.Fatal("redistributePending = true, want false after successful targeted reload")
	}
	if fakeManagedRuntime.reconcileCalls != 1 || len(fakeManagedRuntime.lastItems) != 1 {
		t.Fatalf("managed runtime reconcile = calls:%d items:%d, want 1/1", fakeManagedRuntime.reconcileCalls, len(fakeManagedRuntime.lastItems))
	}
	if fakeIPv6Runtime.reconcileCalls != 1 {
		t.Fatalf("ipv6 runtime reconcileCalls = %d, want 1", fakeIPv6Runtime.reconcileCalls)
	}
}

func TestManagedRuntimeReloadLoopMarksPartialWhenManagedRuntimeReconcileFails(t *testing.T) {
	db := openTestDB(t)

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:          "lab",
		BridgeMode:    managedNetworkBridgeModeCreate,
		Bridge:        "vmbr1",
		IPv4Enabled:   true,
		IPv4CIDR:      "192.0.2.1/24",
		IPv4PoolEnd:   "192.0.2.20",
		IPv4PoolStart: "192.0.2.10",
		Enabled:       true,
	}); err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	fakeManagedRuntime := &fakeManagedNetworkRuntime{reconcileErr: errors.New("apply failed")}
	fakeIPv6Runtime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		db:                       db,
		cfg:                      &Config{DefaultEngine: ruleEngineAuto},
		managedNetworkRuntime:    fakeManagedRuntime,
		ipv6Runtime:              fakeIPv6Runtime,
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedRuntimeReloadDone: make(chan struct{}),
		redistributeWake:         make(chan struct{}, 1),
	}

	go pm.managedRuntimeReloadLoop()
	t.Cleanup(func() {
		pm.beginShutdown()
		if !waitForStopChannel(pm.managedRuntimeReloadDone, time.Second) {
			t.Fatal("managedRuntimeReloadDone did not close during cleanup")
		}
	})

	pm.requestManagedNetworkRuntimeReload(0, "vmbr1")

	waitForManagedNetworkReloadCondition(t, 2*time.Second, func() bool {
		status := pm.snapshotManagedNetworkRuntimeReloadStatus()
		return status.LastResult == "partial" && fakeManagedRuntime.reconcileCalls == 1 && fakeIPv6Runtime.reconcileCalls == 1
	}, "managed runtime reload partial result")

	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if status.LastError != "managed network runtime reconcile: apply failed" {
		t.Fatalf("LastError = %q, want managed network runtime reconcile failure", status.LastError)
	}
	if status.LastAppliedSummary == "" {
		t.Fatal("LastAppliedSummary = empty, want targeted reload summary")
	}
	if pm.redistributePending {
		t.Fatal("redistributePending = true, want no full redistribute for partial targeted reload")
	}
}

func TestManagedRuntimeReloadLoopMarksPartialWhenInterfaceInventoryUnavailable(t *testing.T) {
	db := openTestDB(t)

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:          "lab",
		BridgeMode:    managedNetworkBridgeModeCreate,
		Bridge:        "vmbr1",
		IPv4Enabled:   true,
		IPv4CIDR:      "192.0.2.1/24",
		IPv4PoolEnd:   "192.0.2.20",
		IPv4PoolStart: "192.0.2.10",
		Enabled:       true,
	}); err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return nil, errors.New("inventory failed")
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	fakeManagedRuntime := &fakeManagedNetworkRuntime{}
	fakeIPv6Runtime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		db:                       db,
		cfg:                      &Config{DefaultEngine: ruleEngineAuto},
		managedNetworkRuntime:    fakeManagedRuntime,
		ipv6Runtime:              fakeIPv6Runtime,
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedRuntimeReloadDone: make(chan struct{}),
		redistributeWake:         make(chan struct{}, 1),
	}

	go pm.managedRuntimeReloadLoop()
	t.Cleanup(func() {
		pm.beginShutdown()
		if !waitForStopChannel(pm.managedRuntimeReloadDone, time.Second) {
			t.Fatal("managedRuntimeReloadDone did not close during cleanup")
		}
	})

	pm.requestManagedNetworkRuntimeReload(0, "vmbr1")

	waitForManagedNetworkReloadCondition(t, 2*time.Second, func() bool {
		status := pm.snapshotManagedNetworkRuntimeReloadStatus()
		return status.LastResult == "partial" && fakeManagedRuntime.reconcileCalls == 1 && fakeIPv6Runtime.reconcileCalls == 1
	}, "managed runtime reload partial inventory result")

	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if status.LastError != "managed network interface inventory: inventory failed" {
		t.Fatalf("LastError = %q, want interface inventory failure", status.LastError)
	}
	if status.LastAppliedSummary == "" {
		t.Fatal("LastAppliedSummary = empty, want targeted reload summary")
	}
	if pm.redistributePending {
		t.Fatal("redistributePending = true, want no full redistribute for partial targeted reload")
	}
}

func TestManagedRuntimeReloadLoopFallbackQueuesRedistribute(t *testing.T) {
	pm := &ProcessManager{
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedRuntimeReloadDone: make(chan struct{}),
		redistributeWake:         make(chan struct{}, 1),
	}

	go pm.managedRuntimeReloadLoop()
	t.Cleanup(func() {
		pm.beginShutdown()
		if !waitForStopChannel(pm.managedRuntimeReloadDone, time.Second) {
			t.Fatal("managedRuntimeReloadDone did not close during cleanup")
		}
	})

	pm.requestManagedNetworkRuntimeReloadWithSource(0, "link_change", "vmbr1")

	waitForManagedNetworkReloadCondition(t, 2*time.Second, func() bool {
		status := pm.snapshotManagedNetworkRuntimeReloadStatus()
		pm.mu.Lock()
		redistributePending := pm.redistributePending
		pm.mu.Unlock()
		return status.LastResult == "fallback" && redistributePending
	}, "managed runtime reload fallback")

	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if status.LastRequestSource != "link_change" {
		t.Fatalf("LastRequestSource = %q, want link_change", status.LastRequestSource)
	}
	if status.LastAppliedSummary != "" {
		t.Fatalf("LastAppliedSummary = %q, want empty on fallback", status.LastAppliedSummary)
	}
	if !strings.Contains(status.LastError, "requires database access") {
		t.Fatalf("LastError = %q, want database access failure", status.LastError)
	}
	if status.LastStartedAt.IsZero() || status.LastCompletedAt.IsZero() {
		t.Fatalf("reload timestamps = started:%v completed:%v, want both recorded", status.LastStartedAt, status.LastCompletedAt)
	}
}

func TestManagedRuntimeReloadLoopStopsPromptlyDuringPendingDelay(t *testing.T) {
	pm := &ProcessManager{
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedRuntimeReloadDone: make(chan struct{}),
	}

	go pm.managedRuntimeReloadLoop()

	pm.requestManagedNetworkRuntimeReload(10*time.Minute, "vmbr1")
	pm.beginShutdown()

	if !waitForStopChannel(pm.managedRuntimeReloadDone, 500*time.Millisecond) {
		t.Fatal("managedRuntimeReloadLoop did not stop promptly during shutdown")
	}

	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if !status.LastStartedAt.IsZero() || !status.LastCompletedAt.IsZero() {
		t.Fatalf("reload timestamps = started:%v completed:%v, want zero because delayed reload should not execute during shutdown", status.LastStartedAt, status.LastCompletedAt)
	}
}

func TestManagedRuntimeReloadLoopLinkChangeAutoRepairsBeforeReload(t *testing.T) {
	db := openTestDB(t)

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:          "lab",
		BridgeMode:    managedNetworkBridgeModeCreate,
		Bridge:        "vmbr1",
		IPv4Enabled:   true,
		IPv4CIDR:      "192.0.2.1/24",
		IPv4PoolEnd:   "192.0.2.20",
		IPv4PoolStart: "192.0.2.10",
		Enabled:       true,
	}); err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	oldRepair := repairManagedNetworkHostStateForTests
	repairDone := make(chan struct{})
	repairCalls := 0
	repairManagedNetworkHostStateForTests = func(items []ManagedNetwork) (managedNetworkRepairResult, error) {
		repairCalls++
		close(repairDone)
		return managedNetworkRepairResult{Bridges: []string{"vmbr1"}}, nil
	}
	defer func() {
		repairManagedNetworkHostStateForTests = oldRepair
	}()

	fakeManagedRuntime := &orderedManagedNetworkRuntime{repairDone: repairDone}
	fakeIPv6Runtime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		db:                       db,
		cfg:                      &Config{DefaultEngine: ruleEngineAuto},
		managedNetworkRuntime:    fakeManagedRuntime,
		ipv6Runtime:              fakeIPv6Runtime,
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedRuntimeReloadDone: make(chan struct{}),
		redistributeWake:         make(chan struct{}, 1),
	}

	go pm.managedRuntimeReloadLoop()
	t.Cleanup(func() {
		pm.beginShutdown()
		if !waitForStopChannel(pm.managedRuntimeReloadDone, time.Second) {
			t.Fatal("managedRuntimeReloadDone did not close during cleanup")
		}
	})

	pm.requestManagedNetworkRuntimeReloadWithSource(0, "link_change", "vmbr1")

	waitForManagedNetworkReloadCondition(t, 2*time.Second, func() bool {
		status := pm.snapshotManagedNetworkRuntimeReloadStatus()
		return status.LastResult == "success" && fakeManagedRuntime.reconcileCalls == 1
	}, "managed runtime reload success after auto repair")

	if repairCalls != 1 {
		t.Fatalf("repairCalls = %d, want 1", repairCalls)
	}
	if fakeManagedRuntime.calledBeforeRepair {
		t.Fatal("managed runtime reload reconciled before auto repair completed")
	}
}

func TestManagedRuntimeReloadLoopLinkChangeMarksPartialWhenAutoRepairFails(t *testing.T) {
	db := openTestDB(t)

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:          "lab",
		BridgeMode:    managedNetworkBridgeModeCreate,
		Bridge:        "vmbr1",
		IPv4Enabled:   true,
		IPv4CIDR:      "192.0.2.1/24",
		IPv4PoolEnd:   "192.0.2.20",
		IPv4PoolStart: "192.0.2.10",
		Enabled:       true,
	}); err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	oldRepair := repairManagedNetworkHostStateForTests
	repairCalls := 0
	repairManagedNetworkHostStateForTests = func(items []ManagedNetwork) (managedNetworkRepairResult, error) {
		repairCalls++
		return managedNetworkRepairResult{}, errors.New("repair failed")
	}
	defer func() {
		repairManagedNetworkHostStateForTests = oldRepair
	}()

	fakeManagedRuntime := &fakeManagedNetworkRuntime{}
	fakeIPv6Runtime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		db:                       db,
		cfg:                      &Config{DefaultEngine: ruleEngineAuto},
		managedNetworkRuntime:    fakeManagedRuntime,
		ipv6Runtime:              fakeIPv6Runtime,
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedRuntimeReloadDone: make(chan struct{}),
		redistributeWake:         make(chan struct{}, 1),
	}

	go pm.managedRuntimeReloadLoop()
	t.Cleanup(func() {
		pm.beginShutdown()
		if !waitForStopChannel(pm.managedRuntimeReloadDone, time.Second) {
			t.Fatal("managedRuntimeReloadDone did not close during cleanup")
		}
	})

	pm.requestManagedNetworkRuntimeReloadWithSource(0, "link_change", "vmbr1")

	waitForManagedNetworkReloadCondition(t, 2*time.Second, func() bool {
		status := pm.snapshotManagedNetworkRuntimeReloadStatus()
		return status.LastResult == "partial" && fakeManagedRuntime.reconcileCalls == 1 && fakeIPv6Runtime.reconcileCalls == 1
	}, "managed runtime reload partial result after auto repair failure")

	if repairCalls != 1 {
		t.Fatalf("repairCalls = %d, want 1", repairCalls)
	}
	status := pm.snapshotManagedNetworkRuntimeReloadStatus()
	if status.LastError != "managed network auto repair: repair failed" {
		t.Fatalf("LastError = %q, want managed network auto repair failure", status.LastError)
	}
	if pm.redistributePending {
		t.Fatal("redistributePending = true, want no full redistribute for partial targeted reload")
	}
}

func TestManagedRuntimeReloadLoopLinkChangeCanDisableAutoRepair(t *testing.T) {
	db := openTestDB(t)

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:          "lab",
		BridgeMode:    managedNetworkBridgeModeCreate,
		Bridge:        "vmbr1",
		IPv4Enabled:   true,
		IPv4CIDR:      "192.0.2.1/24",
		IPv4PoolEnd:   "192.0.2.20",
		IPv4PoolStart: "192.0.2.10",
		Enabled:       true,
	}); err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	oldRepair := repairManagedNetworkHostStateForTests
	repairCalls := 0
	repairManagedNetworkHostStateForTests = func(items []ManagedNetwork) (managedNetworkRepairResult, error) {
		repairCalls++
		return managedNetworkRepairResult{Bridges: []string{"vmbr1"}}, nil
	}
	defer func() {
		repairManagedNetworkHostStateForTests = oldRepair
	}()

	autoRepairDisabled := false
	fakeManagedRuntime := &fakeManagedNetworkRuntime{}
	fakeIPv6Runtime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		db:                       db,
		cfg:                      &Config{DefaultEngine: ruleEngineAuto, ManagedNetworkAutoRepair: &autoRepairDisabled},
		managedNetworkRuntime:    fakeManagedRuntime,
		ipv6Runtime:              fakeIPv6Runtime,
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedRuntimeReloadDone: make(chan struct{}),
		redistributeWake:         make(chan struct{}, 1),
	}

	go pm.managedRuntimeReloadLoop()
	t.Cleanup(func() {
		pm.beginShutdown()
		if !waitForStopChannel(pm.managedRuntimeReloadDone, time.Second) {
			t.Fatal("managedRuntimeReloadDone did not close during cleanup")
		}
	})

	pm.requestManagedNetworkRuntimeReloadWithSource(0, "link_change", "vmbr1")

	waitForManagedNetworkReloadCondition(t, 2*time.Second, func() bool {
		status := pm.snapshotManagedNetworkRuntimeReloadStatus()
		return status.LastResult == "success" && fakeManagedRuntime.reconcileCalls == 1
	}, "managed runtime reload success with auto repair disabled")

	if repairCalls != 0 {
		t.Fatalf("repairCalls = %d, want 0 when auto repair is disabled", repairCalls)
	}
}

func TestManagedRuntimeReloadLoopManualReloadSkipsAutoRepair(t *testing.T) {
	db := openTestDB(t)

	if _, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:          "lab",
		BridgeMode:    managedNetworkBridgeModeCreate,
		Bridge:        "vmbr1",
		IPv4Enabled:   true,
		IPv4CIDR:      "192.0.2.1/24",
		IPv4PoolEnd:   "192.0.2.20",
		IPv4PoolStart: "192.0.2.10",
		Enabled:       true,
	}); err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}

	oldRepair := repairManagedNetworkHostStateForTests
	repairCalls := 0
	repairManagedNetworkHostStateForTests = func(items []ManagedNetwork) (managedNetworkRepairResult, error) {
		repairCalls++
		return managedNetworkRepairResult{Bridges: []string{"vmbr1"}}, nil
	}
	defer func() {
		repairManagedNetworkHostStateForTests = oldRepair
	}()

	fakeManagedRuntime := &fakeManagedNetworkRuntime{}
	fakeIPv6Runtime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		db:                       db,
		cfg:                      &Config{DefaultEngine: ruleEngineAuto},
		managedNetworkRuntime:    fakeManagedRuntime,
		ipv6Runtime:              fakeIPv6Runtime,
		shutdownCh:               make(chan struct{}),
		managedRuntimeReloadWake: make(chan struct{}, 1),
		managedRuntimeReloadDone: make(chan struct{}),
		redistributeWake:         make(chan struct{}, 1),
	}

	go pm.managedRuntimeReloadLoop()
	t.Cleanup(func() {
		pm.beginShutdown()
		if !waitForStopChannel(pm.managedRuntimeReloadDone, time.Second) {
			t.Fatal("managedRuntimeReloadDone did not close during cleanup")
		}
	})

	pm.requestManagedNetworkRuntimeReload(0, "vmbr1")

	waitForManagedNetworkReloadCondition(t, 2*time.Second, func() bool {
		status := pm.snapshotManagedNetworkRuntimeReloadStatus()
		return status.LastResult == "success" && fakeManagedRuntime.reconcileCalls == 1
	}, "manual managed runtime reload success")

	if repairCalls != 0 {
		t.Fatalf("repairCalls = %d, want 0 for manual reload", repairCalls)
	}
}
