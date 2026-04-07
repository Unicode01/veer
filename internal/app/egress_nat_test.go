package app

import "testing"

func TestNormalizeAndValidateEgressNAT(t *testing.T) {
	knownIfaces := map[string]struct{}{
		"vmbr0":    {},
		"tap100i0": {},
		"eno1":     {},
	}
	ifaceByName := map[string]InterfaceInfo{
		"vmbr0":    {Name: "vmbr0"},
		"tap100i0": {Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
		"eno1":     {Name: "eno1"},
	}
	hostAddrs := hostInterfaceAddrs{
		"eno1": {
			"198.51.100.10": {},
		},
	}

	item, msg := normalizeAndValidateEgressNAT(EgressNAT{
		ParentInterface: "vmbr0",
		ChildInterface:  "tap100i0",
		OutInterface:    "eno1",
		OutSourceIP:     "198.51.100.10",
		Protocol:        "udp",
	}, false, knownIfaces, ifaceByName, hostAddrs)
	if msg != "" {
		t.Fatalf("normalizeAndValidateEgressNAT() error = %q, want empty", msg)
	}
	if item.OutSourceIP != "198.51.100.10" {
		t.Fatalf("OutSourceIP = %q, want %q", item.OutSourceIP, "198.51.100.10")
	}
	if item.Protocol != "udp" {
		t.Fatalf("Protocol = %q, want %q", item.Protocol, "udp")
	}
	if item.NATType != egressNATTypeSymmetric {
		t.Fatalf("NATType = %q, want %q", item.NATType, egressNATTypeSymmetric)
	}
}

func TestNormalizeAndValidateEgressNATAllowsParentScope(t *testing.T) {
	knownIfaces := map[string]struct{}{
		"vmbr0":    {},
		"tap100i0": {},
		"eno1":     {},
	}
	ifaceByName := map[string]InterfaceInfo{
		"vmbr0":    {Name: "vmbr0"},
		"tap100i0": {Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
		"eno1":     {Name: "eno1", Parent: "vmbr0", Kind: "device"},
	}

	item, msg := normalizeAndValidateEgressNAT(EgressNAT{
		ParentInterface: "vmbr0",
		ChildInterface:  "*",
		OutInterface:    "eno1",
	}, false, knownIfaces, ifaceByName, hostInterfaceAddrs{})
	if msg != "" {
		t.Fatalf("normalizeAndValidateEgressNAT() error = %q, want empty", msg)
	}
	if item.ChildInterface != "" {
		t.Fatalf("ChildInterface = %q, want empty for parent scope", item.ChildInterface)
	}
	if item.Protocol != "tcp+udp" {
		t.Fatalf("Protocol = %q, want default %q", item.Protocol, "tcp+udp")
	}
	if item.NATType != egressNATTypeSymmetric {
		t.Fatalf("NATType = %q, want default %q", item.NATType, egressNATTypeSymmetric)
	}
}

func TestNormalizeAndValidateEgressNATAllowsParentScopeWithoutCurrentChildren(t *testing.T) {
	knownIfaces := map[string]struct{}{
		"vmbr0": {},
		"eno1":  {},
	}
	ifaceByName := map[string]InterfaceInfo{
		"vmbr0": {Name: "vmbr0"},
		"eno1":  {Name: "eno1"},
	}

	item, msg := normalizeAndValidateEgressNAT(EgressNAT{
		ParentInterface: "vmbr0",
		OutInterface:    "eno1",
	}, false, knownIfaces, ifaceByName, hostInterfaceAddrs{})
	if msg != "" {
		t.Fatalf("normalizeAndValidateEgressNAT() error = %q, want empty", msg)
	}
	if item.ChildInterface != "" {
		t.Fatalf("ChildInterface = %q, want empty for parent scope", item.ChildInterface)
	}
}

func TestNormalizeAndValidateEgressNATNormalizesSingleTargetParent(t *testing.T) {
	knownIfaces := map[string]struct{}{
		"vmbr0":    {},
		"tap100i0": {},
		"eno1":     {},
	}
	ifaceByName := map[string]InterfaceInfo{
		"vmbr0":    {Name: "vmbr0", Kind: "bridge"},
		"tap100i0": {Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
		"eno1":     {Name: "eno1", Kind: "device"},
	}

	item, msg := normalizeAndValidateEgressNAT(EgressNAT{
		ParentInterface: "tap100i0",
		OutInterface:    "eno1",
	}, false, knownIfaces, ifaceByName, hostInterfaceAddrs{})
	if msg != "" {
		t.Fatalf("normalizeAndValidateEgressNAT() error = %q, want empty", msg)
	}
	if item.ParentInterface != "vmbr0" {
		t.Fatalf("ParentInterface = %q, want %q", item.ParentInterface, "vmbr0")
	}
	if item.ChildInterface != "tap100i0" {
		t.Fatalf("ChildInterface = %q, want %q for normalized single-target parent", item.ChildInterface, "tap100i0")
	}
}

func TestNormalizeAndValidateEgressNATAllowsStandalonePhysicalSingleTarget(t *testing.T) {
	knownIfaces := map[string]struct{}{
		"enp1s0": {},
		"eno1":   {},
	}
	ifaceByName := map[string]InterfaceInfo{
		"enp1s0": {Name: "enp1s0", Kind: "device"},
		"eno1":   {Name: "eno1", Kind: "device"},
	}

	item, msg := normalizeAndValidateEgressNAT(EgressNAT{
		ParentInterface: "enp1s0",
		OutInterface:    "eno1",
	}, false, knownIfaces, ifaceByName, hostInterfaceAddrs{})
	if msg != "" {
		t.Fatalf("normalizeAndValidateEgressNAT() error = %q, want empty", msg)
	}
	if item.ParentInterface != "enp1s0" {
		t.Fatalf("ParentInterface = %q, want %q", item.ParentInterface, "enp1s0")
	}
	if item.ChildInterface != "" {
		t.Fatalf("ChildInterface = %q, want empty for standalone physical single-target parent", item.ChildInterface)
	}
}

func TestNormalizeAndValidateEgressNATRejectsSingleTargetOutInterfaceSameAsParent(t *testing.T) {
	knownIfaces := map[string]struct{}{
		"vmbr0":    {},
		"tap100i0": {},
	}
	ifaceByName := map[string]InterfaceInfo{
		"vmbr0":    {Name: "vmbr0", Kind: "bridge"},
		"tap100i0": {Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
	}

	_, msg := normalizeAndValidateEgressNAT(EgressNAT{
		ParentInterface: "tap100i0",
		OutInterface:    "tap100i0",
	}, false, knownIfaces, ifaceByName, hostInterfaceAddrs{})
	if msg != "parent_interface must be different from out_interface when selecting a single target interface" {
		t.Fatalf("normalizeAndValidateEgressNAT() error = %q", msg)
	}
}

func TestNormalizeAndValidateEgressNATRejectsWrongParent(t *testing.T) {
	knownIfaces := map[string]struct{}{
		"vmbr0":    {},
		"vmbr1":    {},
		"tap100i0": {},
		"eno1":     {},
	}
	ifaceByName := map[string]InterfaceInfo{
		"vmbr0":    {Name: "vmbr0"},
		"vmbr1":    {Name: "vmbr1"},
		"tap100i0": {Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
		"eno1":     {Name: "eno1"},
	}

	_, msg := normalizeAndValidateEgressNAT(EgressNAT{
		ParentInterface: "vmbr1",
		ChildInterface:  "tap100i0",
		OutInterface:    "eno1",
	}, false, knownIfaces, ifaceByName, hostInterfaceAddrs{})
	if msg != "child_interface is not attached to the selected parent_interface" {
		t.Fatalf("normalizeAndValidateEgressNAT() error = %q", msg)
	}
}

func TestNormalizeAndValidateEgressNATRejectsUnsupportedProtocol(t *testing.T) {
	knownIfaces := map[string]struct{}{
		"vmbr0": {},
		"eno1":  {},
	}
	ifaceByName := map[string]InterfaceInfo{
		"vmbr0": {Name: "vmbr0"},
		"eno1":  {Name: "eno1"},
	}

	_, msg := normalizeAndValidateEgressNAT(EgressNAT{
		ParentInterface: "vmbr0",
		OutInterface:    "eno1",
		Protocol:        "gre",
	}, false, knownIfaces, ifaceByName, hostInterfaceAddrs{})
	if msg != "protocol must include one or more of tcp, udp, icmp" {
		t.Fatalf("normalizeAndValidateEgressNAT() error = %q", msg)
	}
}

func TestNormalizeAndValidateEgressNATRejectsUnsupportedNATType(t *testing.T) {
	knownIfaces := map[string]struct{}{
		"vmbr0": {},
		"eno1":  {},
	}
	ifaceByName := map[string]InterfaceInfo{
		"vmbr0": {Name: "vmbr0"},
		"eno1":  {Name: "eno1"},
	}

	_, msg := normalizeAndValidateEgressNAT(EgressNAT{
		ParentInterface: "vmbr0",
		OutInterface:    "eno1",
		NATType:         "port_restricted",
	}, false, knownIfaces, ifaceByName, hostInterfaceAddrs{})
	if msg != "nat_type must be symmetric or full_cone" {
		t.Fatalf("normalizeAndValidateEgressNAT() error = %q", msg)
	}
}

func TestNormalizeEgressNATProtocolCanonicalizesCombinations(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{input: "", want: "tcp+udp"},
		{input: "icmp", want: "icmp"},
		{input: " udp + tcp ", want: "tcp+udp"},
		{input: "icmp,tcp", want: "tcp+icmp"},
		{input: "udp/tcp/icmp", want: "tcp+udp+icmp"},
		{input: "tcp|udp|tcp", want: "tcp+udp"},
	}

	for _, tc := range cases {
		if got := normalizeEgressNATProtocol(tc.input); got != tc.want {
			t.Fatalf("normalizeEgressNATProtocol(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestResolveEgressNATTargetInterfacesParentScopeFiltersPhysicalUplink(t *testing.T) {
	targets, err := resolveEgressNATTargetInterfaces(EgressNAT{
		ParentInterface: "vmbr0",
		OutInterface:    "eno1",
	}, []InterfaceInfo{
		{Name: "vmbr0", Kind: "bridge"},
		{Name: "eno1", Parent: "vmbr0", Kind: "device"},
		{Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
		{Name: "fwln100i0", Parent: "vmbr0", Kind: "veth"},
	})
	if err != nil {
		t.Fatalf("resolveEgressNATTargetInterfaces() error = %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("len(targets) = %d, want 2", len(targets))
	}
	if targets[0].Name != "fwln100i0" || targets[1].Name != "tap100i0" {
		t.Fatalf("targets = %#v", targets)
	}
}

func TestResolveEgressNATTargetInterfacesSingleTargetParentReturnsSelf(t *testing.T) {
	targets, err := resolveEgressNATTargetInterfaces(EgressNAT{
		ParentInterface: "tap100i0",
		OutInterface:    "vmbr0",
	}, []InterfaceInfo{
		{Name: "vmbr0", Kind: "bridge"},
		{Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
	})
	if err != nil {
		t.Fatalf("resolveEgressNATTargetInterfaces() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Name != "tap100i0" {
		t.Fatalf("targets[0].Name = %q, want %q", targets[0].Name, "tap100i0")
	}
}

func TestResolveEgressNATTargetInterfacesStandalonePhysicalReturnsSelf(t *testing.T) {
	targets, err := resolveEgressNATTargetInterfaces(EgressNAT{
		ParentInterface: "enp1s0",
		OutInterface:    "eno1",
	}, []InterfaceInfo{
		{Name: "enp1s0", Kind: "device"},
		{Name: "eno1", Kind: "device"},
	})
	if err != nil {
		t.Fatalf("resolveEgressNATTargetInterfaces() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Name != "enp1s0" {
		t.Fatalf("targets[0].Name = %q, want %q", targets[0].Name, "enp1s0")
	}
}

func TestCollectDynamicEgressNATParents(t *testing.T) {
	got := collectDynamicEgressNATParents([]EgressNAT{
		{ID: 1, ParentInterface: " vmbr0 ", Enabled: true},
		{ID: 2, ParentInterface: "vmbr0", ChildInterface: "tap100i0", Enabled: true},
		{ID: 3, ParentInterface: "vmbr1", Enabled: false},
		{ID: 4, ParentInterface: "vmbr2", Enabled: true},
	})

	if len(got) != 2 {
		t.Fatalf("len(collectDynamicEgressNATParents()) = %d, want 2", len(got))
	}
	if _, ok := got["vmbr0"]; !ok {
		t.Fatal("collectDynamicEgressNATParents() missing vmbr0")
	}
	if _, ok := got["vmbr2"]; !ok {
		t.Fatal("collectDynamicEgressNATParents() missing vmbr2")
	}
	if _, ok := got["vmbr1"]; ok {
		t.Fatal("collectDynamicEgressNATParents() unexpectedly included disabled parent")
	}
}

func TestCollectDynamicEgressNATParentsIncludesNormalizedSingleTargetParent(t *testing.T) {
	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "vmbr0", Kind: "bridge"},
			{Name: "vmbr1", Kind: "bridge"},
			{Name: "tap100i0", Parent: "vmbr1", Kind: "tuntap"},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	got := collectDynamicEgressNATParents([]EgressNAT{
		{ID: 1, ParentInterface: "vmbr0", Enabled: true},
		{ID: 2, ParentInterface: "tap100i0", Enabled: true},
	})

	if len(got) != 2 {
		t.Fatalf("len(collectDynamicEgressNATParents()) = %d, want 2", len(got))
	}
	if _, ok := got["vmbr0"]; !ok {
		t.Fatal("collectDynamicEgressNATParents() missing vmbr0")
	}
	if _, ok := got["vmbr1"]; !ok {
		t.Fatal("collectDynamicEgressNATParents() missing normalized single-target parent vmbr1")
	}
}

func TestValidateProjectedEgressNATsDetectsParentScopeOverlap(t *testing.T) {
	ifaceByName := map[string]InterfaceInfo{
		"vmbr0":    {Name: "vmbr0"},
		"tap100i0": {Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
	}
	issues := validateProjectedEgressNATs([]EgressNAT{
		{ID: 1, ParentInterface: "vmbr0", ChildInterface: "", OutInterface: "eno1", Enabled: true},
		{ID: 2, ParentInterface: "vmbr0", ChildInterface: "tap100i0", OutInterface: "eno2", Enabled: true},
	}, ifaceByName, "update", 2)
	if len(issues) != 1 {
		t.Fatalf("len(issues) = %d, want 1", len(issues))
	}
	if issues[0].Message != "egress nat scope conflicts with egress nat #1" {
		t.Fatalf("issues[0].Message = %q", issues[0].Message)
	}
}

func TestValidateProjectedEgressNATsDetectsSingleTargetOverlapWithParentScope(t *testing.T) {
	ifaceByName := map[string]InterfaceInfo{
		"vmbr0":    {Name: "vmbr0", Kind: "bridge"},
		"tap100i0": {Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
	}
	issues := validateProjectedEgressNATs([]EgressNAT{
		{ID: 1, ParentInterface: "vmbr0", ChildInterface: "", OutInterface: "eno1", Protocol: "tcp", Enabled: true},
		{ID: 2, ParentInterface: "tap100i0", ChildInterface: "", OutInterface: "eno2", Protocol: "tcp", Enabled: true},
	}, ifaceByName, "update", 2)
	if len(issues) != 1 {
		t.Fatalf("len(issues) = %d, want 1", len(issues))
	}
	if issues[0].Message != "egress nat scope conflicts with egress nat #1" {
		t.Fatalf("issues[0].Message = %q", issues[0].Message)
	}
}

func TestValidateProjectedEgressNATsKeepsStoredChildScopeWhenChildIsCurrentlyMissing(t *testing.T) {
	ifaceByName := map[string]InterfaceInfo{
		"vmbr0": {Name: "vmbr0", Kind: "bridge"},
	}
	issues := validateProjectedEgressNATs([]EgressNAT{
		{ID: 1, ParentInterface: "vmbr0", ChildInterface: "", OutInterface: "eno1", Protocol: "tcp", Enabled: true},
		{ID: 2, ParentInterface: "vmbr0", ChildInterface: "tap100i0", OutInterface: "eno2", Protocol: "tcp", Enabled: true},
	}, ifaceByName, "update", 2)
	if len(issues) != 1 {
		t.Fatalf("len(issues) = %d, want 1", len(issues))
	}
	if issues[0].Message != "egress nat scope conflicts with egress nat #1" {
		t.Fatalf("issues[0].Message = %q", issues[0].Message)
	}
}

func TestValidateProjectedEgressNATsAllowsDisjointProtocolsOnSameScope(t *testing.T) {
	ifaceByName := map[string]InterfaceInfo{
		"vmbr0":    {Name: "vmbr0"},
		"tap100i0": {Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
	}
	issues := validateProjectedEgressNATs([]EgressNAT{
		{ID: 1, ParentInterface: "vmbr0", ChildInterface: "tap100i0", OutInterface: "eno1", Protocol: "tcp", Enabled: true},
		{ID: 2, ParentInterface: "vmbr0", ChildInterface: "tap100i0", OutInterface: "eno2", Protocol: "udp", Enabled: true},
	}, ifaceByName, "update", 2)
	if len(issues) != 0 {
		t.Fatalf("validateProjectedEgressNATs() issues = %#v, want none", issues)
	}
}

func TestBuildEgressNATKernelCandidates(t *testing.T) {
	planner := newRuleDataplanePlanner(stubKernelSupportRuntime{
		available: true,
		supported: true,
	}, ruleEngineKernel)
	usedIDs := map[int64]struct{}{1: {}}
	nextID := int64(2)

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "vmbr0", Kind: "bridge"},
			{Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
			{Name: "eno1", Parent: "vmbr0", Kind: "device", Addrs: []string{"198.51.100.10"}},
			{Name: "lo", Kind: "device", Addrs: []string{"127.0.0.1"}},
			{Name: "vmbr1", Kind: "bridge", Addrs: []string{"10.0.0.1"}},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	candidates, plans := buildEgressNATKernelCandidates([]EgressNAT{{
		ID:              7,
		ParentInterface: "vmbr0",
		OutInterface:    "eno1",
		OutSourceIP:     "198.51.100.10",
		Protocol:        "tcp+udp+icmp",
		Enabled:         true,
	}}, planner, 0, 0, usedIDs, &nextID)

	if got := plans[7].EffectiveEngine; got != ruleEngineKernel {
		t.Fatalf("plans[7].EffectiveEngine = %q, want %q", got, ruleEngineKernel)
	}
	if !plans[7].KernelEligible {
		t.Fatal("plans[7].KernelEligible = false, want true")
	}
	if len(candidates) != 3 {
		t.Fatalf("len(candidates) = %d, want 3", len(candidates))
	}

	natProtocols := map[string]struct{}{}
	for _, candidate := range candidates {
		if candidate.owner.kind != workerKindEgressNAT {
			t.Fatalf("owner kind = %q, want %q", candidate.owner.kind, workerKindEgressNAT)
		}
		if !isKernelEgressNATRule(candidate.rule) {
			t.Fatalf("unexpected candidate mode for %#v", candidate.rule)
		}
		if candidate.rule.kernelNATType != egressNATTypeSymmetric {
			t.Fatalf("candidate.rule.kernelNATType = %q, want %q", candidate.rule.kernelNATType, egressNATTypeSymmetric)
		}
		natProtocols[candidate.rule.Protocol] = struct{}{}
	}
	if len(natProtocols) != 3 {
		t.Fatalf("len(natProtocols) = %d, want 3", len(natProtocols))
	}
}

func TestBuildEgressNATKernelCandidatesSingleProtocol(t *testing.T) {
	planner := newRuleDataplanePlanner(stubKernelSupportRuntime{
		available: true,
		supported: true,
	}, ruleEngineKernel)
	usedIDs := map[int64]struct{}{1: {}}
	nextID := int64(2)

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "vmbr0", Kind: "bridge"},
			{Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
			{Name: "eno1", Parent: "vmbr0", Kind: "device", Addrs: []string{"198.51.100.10"}},
			{Name: "vmbr1", Kind: "bridge", Addrs: []string{"10.0.0.1"}},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	candidates, plans := buildEgressNATKernelCandidates([]EgressNAT{{
		ID:              7,
		ParentInterface: "vmbr0",
		OutInterface:    "eno1",
		OutSourceIP:     "198.51.100.10",
		Protocol:        "icmp",
		Enabled:         true,
	}}, planner, 0, 0, usedIDs, &nextID)

	if got := plans[7].EffectiveEngine; got != ruleEngineKernel {
		t.Fatalf("plans[7].EffectiveEngine = %q, want %q", got, ruleEngineKernel)
	}
	if len(candidates) != 1 {
		t.Fatalf("len(candidates) = %d, want 1", len(candidates))
	}
	for _, candidate := range candidates {
		if candidate.rule.Protocol != "icmp" {
			t.Fatalf("candidate rule protocol = %q, want icmp", candidate.rule.Protocol)
		}
	}
}

func TestBuildKernelEgressNATLocalIPv4Set(t *testing.T) {
	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "lo", Kind: "device", Addrs: []string{"127.0.0.1", "::1"}},
			{Name: "vmbr0", Kind: "bridge", Addrs: []string{"10.0.0.254"}},
			{Name: "vmbr1", Kind: "bridge", Addrs: []string{"10.0.0.254", "198.51.100.10"}},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	set, err := buildKernelEgressNATLocalIPv4Set([]Rule{{
		ID:         1,
		Protocol:   "tcp",
		kernelMode: kernelModeEgressNAT,
	}})
	if err != nil {
		t.Fatalf("buildKernelEgressNATLocalIPv4Set() error = %v", err)
	}
	if len(set) != 2 {
		t.Fatalf("len(local IPv4 set) = %d, want 2", len(set))
	}

	first, err := parseEgressNATIPv4Uint32("10.0.0.254")
	if err != nil {
		t.Fatalf("parseEgressNATIPv4Uint32(10.0.0.254): %v", err)
	}
	second, err := parseEgressNATIPv4Uint32("198.51.100.10")
	if err != nil {
		t.Fatalf("parseEgressNATIPv4Uint32(198.51.100.10): %v", err)
	}
	if _, ok := set[first]; !ok {
		t.Fatal("local IPv4 set missing 10.0.0.254")
	}
	if _, ok := set[second]; !ok {
		t.Fatal("local IPv4 set missing 198.51.100.10")
	}
}

func TestBuildEgressNATStatusReportsKernelOnlyError(t *testing.T) {
	pm := &ProcessManager{
		egressNATPlans: map[int64]ruleDataplanePlan{
			7: {
				PreferredEngine: ruleEngineKernel,
				EffectiveEngine: ruleEngineUserspace,
				KernelEligible:  true,
				FallbackReason:  "parent_interface has no eligible child interfaces for egress nat takeover",
			},
		},
		kernelEgressNATs:       map[int64]bool{},
		kernelEgressNATEngines: map[int64]string{},
	}

	item := EgressNAT{
		ID:              7,
		ParentInterface: "vmbr0",
		OutInterface:    "eno1",
		Enabled:         true,
	}
	status := pm.buildEgressNATStatus(item, pm.egressNATRuntimeStatus(item.ID, item.Enabled))

	if status.Status != "error" {
		t.Fatalf("Status = %q, want error", status.Status)
	}
	if status.EffectiveEngine != ruleEngineKernel {
		t.Fatalf("EffectiveEngine = %q, want %q", status.EffectiveEngine, ruleEngineKernel)
	}
	if status.FallbackReason == "" {
		t.Fatal("FallbackReason = empty, want unavailable reason")
	}
}

func TestEgressNATProtocolPersistsInDB(t *testing.T) {
	db := openTestDB(t)

	item := EgressNAT{
		ParentInterface: "vmbr0",
		ChildInterface:  "tap100i0",
		OutInterface:    "eno1",
		OutSourceIP:     "198.51.100.10",
		Protocol:        "udp+icmp",
		Enabled:         true,
	}
	id, err := dbAddEgressNAT(db, &item)
	if err != nil {
		t.Fatalf("dbAddEgressNAT() error = %v", err)
	}

	got, err := dbGetEgressNAT(db, id)
	if err != nil {
		t.Fatalf("dbGetEgressNAT() error = %v", err)
	}
	if got.Protocol != "udp+icmp" {
		t.Fatalf("Protocol after add = %q, want %q", got.Protocol, "udp+icmp")
	}

	got.Protocol = "tcp+udp+icmp"
	if err := dbUpdateEgressNAT(db, got); err != nil {
		t.Fatalf("dbUpdateEgressNAT() error = %v", err)
	}

	updated, err := dbGetEgressNAT(db, id)
	if err != nil {
		t.Fatalf("dbGetEgressNAT() after update error = %v", err)
	}
	if updated.Protocol != "tcp+udp+icmp" {
		t.Fatalf("Protocol after update = %q, want %q", updated.Protocol, "tcp+udp+icmp")
	}
}

func TestEgressNATNATTypePersistsInDB(t *testing.T) {
	db := openTestDB(t)

	item := EgressNAT{
		ParentInterface: "vmbr0",
		ChildInterface:  "tap100i0",
		OutInterface:    "eno1",
		OutSourceIP:     "198.51.100.10",
		Protocol:        "tcp+udp",
		NATType:         egressNATTypeFullCone,
		Enabled:         true,
	}
	id, err := dbAddEgressNAT(db, &item)
	if err != nil {
		t.Fatalf("dbAddEgressNAT() error = %v", err)
	}

	got, err := dbGetEgressNAT(db, id)
	if err != nil {
		t.Fatalf("dbGetEgressNAT() error = %v", err)
	}
	if got.NATType != egressNATTypeFullCone {
		t.Fatalf("NATType after add = %q, want %q", got.NATType, egressNATTypeFullCone)
	}

	got.NATType = egressNATTypeSymmetric
	if err := dbUpdateEgressNAT(db, got); err != nil {
		t.Fatalf("dbUpdateEgressNAT() error = %v", err)
	}

	updated, err := dbGetEgressNAT(db, id)
	if err != nil {
		t.Fatalf("dbGetEgressNAT() after update error = %v", err)
	}
	if updated.NATType != egressNATTypeSymmetric {
		t.Fatalf("NATType after update = %q, want %q", updated.NATType, egressNATTypeSymmetric)
	}
}
