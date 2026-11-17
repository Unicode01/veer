//go:build linux

package app

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestKernelTCHotRestartPreservedMapNames(t *testing.T) {
	t.Parallel()

	present := func(names ...string) func(string) bool {
		set := make(map[string]bool, len(names))
		for _, name := range names {
			set[name] = true
		}
		return func(name string) bool { return set[name] }
	}
	tests := []struct {
		name      string
		present   func(string) bool
		flags     uint32
		skipStats bool
		want      []string
	}{
		{
			name:    "ipv4 only",
			present: present(kernelFlowsMapName, kernelNatPortsMapName, kernelStatsMapName),
			want:    []string{kernelFlowsMapName, kernelNatPortsMapName, kernelStatsMapName},
		},
		{
			name: "draining ipv4 old bank without stats",
			present: present(kernelFlowsMapName, kernelNatPortsMapName, kernelFlowsMapNameV6, kernelNatPortsMapNameV6,
				kernelTCFlowsOldMapNameV4, kernelTCNatPortsOldMapNameV4, kernelTCFlowsOldMapNameV6, kernelTCNatPortsOldMapNameV6),
			flags:     tcFlowMigrationFlagV4Old,
			skipStats: true,
			want: []string{kernelFlowsMapName, kernelNatPortsMapName, kernelFlowsMapNameV6, kernelNatPortsMapNameV6,
				kernelTCFlowsOldMapNameV4, kernelTCNatPortsOldMapNameV4},
		},
		{
			name:    "flag without old maps",
			present: present(kernelFlowsMapName, kernelNatPortsMapName),
			flags:   tcFlowMigrationFlagV6Old,
			want:    []string{kernelFlowsMapName, kernelNatPortsMapName, kernelStatsMapName},
		},
	}
	for _, tt := range tests {
		got := kernelTCHotRestartPreservedMapNames(tt.present, tt.flags, tt.skipStats)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: kernelTCHotRestartPreservedMapNames() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestKernelXDPHotRestartPreservedMapNames(t *testing.T) {
	t.Parallel()

	all := func(string) bool { return true }
	noOldV6NAT := func(name string) bool { return name != kernelTCNatPortsOldMapNameV6 }
	if got, want := kernelXDPHotRestartPreservedMapNames(all, 0, false, false), []string{kernelFlowsMapName, kernelFlowsMapNameV6, kernelStatsMapName}; !reflect.DeepEqual(got, want) {
		t.Fatalf("without NAT entries = %v, want %v", got, want)
	}
	got := kernelXDPHotRestartPreservedMapNames(noOldV6NAT, xdpFlowMigrationFlagV4Old|xdpFlowMigrationFlagV6Old, true, false)
	want := []string{
		kernelFlowsMapName, kernelFlowsMapNameV6, kernelNatPortsMapName, kernelNatPortsMapNameV6,
		kernelXDPFlowsOldMapNameV4, kernelTCNatPortsOldMapNameV4, kernelXDPFlowsOldMapNameV6, kernelStatsMapName,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("draining with NAT entries = %v, want %v", got, want)
	}
}

func TestResolveHotRestartLiveMapsTellsOldNATBanksApart(t *testing.T) {
	t.Parallel()

	resolved, err := resolveHotRestartLiveMaps([]hotRestartLiveMap{
		{id: 1, name: kernelFlowsMapName, keySize: 16},
		{id: 2, name: kernelNatPortsMapNameV4, keySize: 8},
		{id: 3, name: kernelNatPortsMapNameV6, keySize: 20},
		{id: 4, name: "nat_ports_old_v", keySize: 20},
		{id: 5, name: "nat_ports_old_v", keySize: 8},
		{id: 6, name: "unrelated_map", keySize: 4},
	})
	if err != nil {
		t.Fatalf("resolveHotRestartLiveMaps() error = %v", err)
	}
	got := make(map[string]ebpf.MapID, len(resolved))
	for name, item := range resolved {
		got[name] = item.id
	}
	want := map[string]ebpf.MapID{
		kernelFlowsMapName:           1,
		kernelNatPortsMapNameV4:      2,
		kernelNatPortsMapNameV6:      3,
		kernelTCNatPortsOldMapNameV4: 5,
		kernelTCNatPortsOldMapNameV6: 4,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved ids = %v, want %v", got, want)
	}
}

// After a hot restart the successor's old banks are the predecessor's active
// banks and keep their names; the newer map is the active one.
func TestResolveHotRestartLiveMapsAfterHandoff(t *testing.T) {
	t.Parallel()

	resolved, err := resolveHotRestartLiveMaps([]hotRestartLiveMap{
		{id: 10, name: kernelFlowsMapName, keySize: 16},
		{id: 31, name: kernelFlowsMapName, keySize: 16},
		{id: 11, name: kernelNatPortsMapNameV4, keySize: 8},
		{id: 32, name: kernelNatPortsMapNameV4, keySize: 8},
		{id: 33, name: kernelNatPortsMapNameV6, keySize: 20},
		{id: 34, name: "nat_ports_old_v", keySize: 20},
		{id: 35, name: kernelFlowsMapNameV6, keySize: 40},
		{id: 36, name: kernelTCFlowsOldMapNameV6, keySize: 40},
		{id: 12, name: kernelStatsMapName, keySize: 4},
	})
	if err != nil {
		t.Fatalf("resolveHotRestartLiveMaps() error = %v", err)
	}
	got := make(map[string]ebpf.MapID, len(resolved))
	for name, item := range resolved {
		got[name] = item.id
	}
	want := map[string]ebpf.MapID{
		kernelFlowsMapName:           31,
		kernelTCFlowsOldMapNameV4:    10,
		kernelNatPortsMapNameV4:      32,
		kernelTCNatPortsOldMapNameV4: 11,
		kernelNatPortsMapNameV6:      33,
		kernelTCNatPortsOldMapNameV6: 34,
		kernelFlowsMapNameV6:         35,
		kernelTCFlowsOldMapNameV6:    36,
		kernelStatsMapName:           12,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved ids = %v, want %v", got, want)
	}
}

func TestResolveHotRestartLiveMapsRejectsAmbiguousMaps(t *testing.T) {
	t.Parallel()

	if _, err := resolveHotRestartLiveMaps([]hotRestartLiveMap{
		{id: 1, name: kernelFlowsMapName},
		{id: 2, name: kernelFlowsMapName},
		{id: 3, name: kernelFlowsMapName},
	}); err == nil || !strings.Contains(err.Error(), "3 maps for the flows_v4 bank pair") {
		t.Fatalf("three flows_v4 maps error = %v", err)
	}
	if _, err := resolveHotRestartLiveMaps([]hotRestartLiveMap{
		{id: 1, name: kernelStatsMapName},
		{id: 2, name: kernelStatsMapName},
	}); err == nil || !strings.Contains(err.Error(), `2 maps named "stats_v4"`) {
		t.Fatalf("duplicate stats_v4 error = %v", err)
	}
	if _, err := resolveHotRestartLiveMaps([]hotRestartLiveMap{
		{id: 1, name: kernelNatPortsMapNameV4, keySize: 8},
		{id: 2, name: "nat_ports_old_v", keySize: 20},
	}); err == nil || !strings.Contains(err.Error(), "matches 0 active banks") {
		t.Fatalf("old NAT bank matching no active bank error = %v", err)
	}
	if _, err := resolveHotRestartLiveMaps([]hotRestartLiveMap{
		{id: 1, name: kernelNatPortsMapNameV4, keySize: 8},
		{id: 2, name: kernelNatPortsMapNameV6, keySize: 8},
		{id: 3, name: "nat_ports_old_v", keySize: 8},
	}); err == nil || !strings.Contains(err.Error(), "matches 2 active banks") {
		t.Fatalf("old NAT bank matching both active banks error = %v", err)
	}
	// Without IPv6 maps the IPv4 old bank is still found.
	resolved, err := resolveHotRestartLiveMaps([]hotRestartLiveMap{
		{id: 1, name: kernelNatPortsMapNameV4, keySize: 8},
		{id: 2, name: "nat_ports_old_v", keySize: 8},
	})
	if err != nil || resolved[kernelTCNatPortsOldMapNameV4].id != 2 {
		t.Fatalf("IPv4-only resolution = %v, %v; want nat_ports_old_v4 = map 2", resolved, err)
	}
}

func TestParseFDInfoProgramID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		text   string
		want   ebpf.ProgramID
		wantOK bool
	}{
		{"program", "pos:\t0\nflags:\t02000002\nprog_type:\t3\nprog_jited:\t1\nprog_id:\t812\n", 812, true},
		{"link", "link_type:\ttcx\nlink_id:\t9\nprog_tag:\tabc\nprog_id:\t77\nifindex:\t3\n", 77, true},
		{"map", "map_type:\t1\nkey_size:\t16\nvalue_size:\t104\nmap_id:\t40\n", 0, false},
		{"garbage", "prog_id:\tnope\n", 0, false},
	}
	for _, tt := range tests {
		got, ok := parseFDInfoProgramID(tt.text)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("%s: parseFDInfoProgramID() = %d, %t; want %d, %t", tt.name, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestKernelRuntimeMetadataRecordsCompatToken(t *testing.T) {
	t.Parallel()

	tc := (&linuxKernelRuleRuntime{enableTrafficStats: true}).runtimeMetadata()
	if tc.Engine != kernelEngineTC || tc.CompatToken != kernelTCHotRestartCompatToken(true) {
		t.Fatalf("tc runtime metadata = %+v, want engine tc and the traffic-stats token", tc)
	}
	if err := validateKernelHotRestartMetadataWithOptions(tc, kernelTCHotRestartValidationOptions("any", true)); err != nil {
		t.Fatalf("tc runtime metadata against the same setting: %v", err)
	}
	assertKernelHotRestartIncompatible(t, validateKernelHotRestartMetadataWithOptions(tc, kernelTCHotRestartValidationOptions("any", false)))

	xdp := (&xdpKernelRuleRuntime{}).runtimeMetadata()
	if xdp.Engine != kernelEngineXDP || xdp.CompatToken != kernelXDPHotRestartCompatToken(false) {
		t.Fatalf("xdp runtime metadata = %+v, want engine xdp and the base token", xdp)
	}
}

func TestHotRestartCheckTrafficStatsReadsConfigWithoutTouchingIt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"experimental_features":{"kernel_traffic_stats":true}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	enabled, found, err := hotRestartCheckTrafficStats(path)
	if err != nil || !found || !enabled {
		t.Fatalf("hotRestartCheckTrafficStats() = %t, %t, %v; want true, true, nil", enabled, found, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("config mode after the check = %v, %v; want 0644 unchanged", info.Mode().Perm(), err)
	}
	if _, found, err := hotRestartCheckTrafficStats(filepath.Join(dir, "missing.json")); found || err != nil {
		t.Fatalf("missing config = found %t, %v; want not found, nil", found, err)
	}
	if err := os.WriteFile(path, []byte(`{`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hotRestartCheckTrafficStats(path); err == nil {
		t.Fatal("broken config error = nil, want parse error")
	}
}

func TestHotRestartEngineCheckWithoutStateIsNothingPinned(t *testing.T) {
	t.Setenv(forwardBPFStateDirEnv, t.TempDir())
	t.Setenv(forwardRuntimeStateDirEnv, t.TempDir())

	report := hotRestartEngineCheck{engine: kernelEngineTC}.run(nil)
	if report.Source != hotRestartSourceNone || report.Verdict != hotRestartVerdictNone {
		t.Fatalf("report = %+v, want source none and verdict none", report)
	}
}

func TestHotRestartEngineCheckRunningWithoutAttachmentsIsNothingPinned(t *testing.T) {
	t.Setenv(forwardBPFStateDirEnv, t.TempDir())
	t.Setenv(forwardRuntimeStateDirEnv, t.TempDir())
	if err := writeKernelRuntimeMetadata(kernelEngineTC, (&linuxKernelRuleRuntime{}).runtimeMetadata()); err != nil {
		t.Fatalf("writeKernelRuntimeMetadata() error = %v", err)
	}

	discover := func(int) (*hotRestartLiveMaps, error) {
		t.Fatal("discover called for a daemon without attachments")
		return nil, nil
	}
	report := hotRestartEngineCheck{engine: kernelEngineTC}.run(discover)
	if report.Source != hotRestartSourceRunning || report.PID != os.Getpid() || report.Verdict != hotRestartVerdictNone {
		t.Fatalf("report = %+v, want running pid %d with verdict none", report, os.Getpid())
	}
}

// hotRestartCheckTestSpec is a tc object whose flow maps hold values of
// flowValueSize bytes.
func hotRestartCheckTestSpec(flowValueSize uint32) *ebpf.CollectionSpec {
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{}}
	for _, name := range []string{kernelFlowsMapName, kernelTCFlowsOldMapNameV4} {
		spec.Maps[name] = &ebpf.MapSpec{Name: name, Type: ebpf.Hash, KeySize: 16, ValueSize: flowValueSize, MaxEntries: 4096}
	}
	for _, name := range []string{kernelNatPortsMapName, kernelTCNatPortsOldMapNameV4} {
		spec.Maps[name] = &ebpf.MapSpec{Name: name, Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 4096}
	}
	spec.Maps[kernelStatsMapName] = &ebpf.MapSpec{Name: kernelStatsMapName, Type: ebpf.Hash, KeySize: 4, ValueSize: 32, MaxEntries: 4096}
	return spec
}

// newHotRestartCheckTestMaps creates the maps a tc runtime without IPv6 or a
// draining migration preserves, smaller than the object asks for.
func newHotRestartCheckTestMaps(t *testing.T, flowValueSize uint32) map[string]*ebpf.Map {
	t.Helper()
	maps := make(map[string]*ebpf.Map)
	for name, spec := range hotRestartCheckTestSpec(flowValueSize).Maps {
		spec = spec.Copy()
		spec.MaxEntries = 64
		maps[name] = newKernelHotRestartTestMap(t, spec)
	}
	return maps
}

func TestCompareKernelHotRestartMapReplacementsReportsEveryMap(t *testing.T) {
	maps := newHotRestartCheckTestMaps(t, 48)
	replacements := map[string]*ebpf.Map{
		kernelFlowsMapName:    maps[kernelFlowsMapName],
		kernelNatPortsMapName: maps[kernelNatPortsMapName],
		kernelStatsMapName:    maps[kernelStatsMapName],
	}
	spec := hotRestartCheckTestSpec(104)

	comparisons, err := compareKernelHotRestartMapReplacements(spec, replacements, kernelTCHotRestartFlexibleCapacityMaps(), kernelTCMapLayoutRules)
	if err != nil {
		t.Fatalf("compareKernelHotRestartMapReplacements() error = %v", err)
	}
	if len(comparisons) != 3 {
		t.Fatalf("comparisons = %+v, want one per preserved map", comparisons)
	}
	flows, nat, stats := comparisons[0], comparisons[1], comparisons[2]
	if flows.name != kernelFlowsMapName || flows.copied || kernelHotRestartIncompatibilityReason(flows.err) != "value_size=48 but current object expects 104" {
		t.Fatalf("flows comparison = %+v (%v), want a value_size incompatibility: 48 bytes is no listed prefix", flows, flows.err)
	}
	if flows.actual == nil || flows.actual.ValueSize != 48 || flows.desired == nil || flows.desired.ValueSize != 104 {
		t.Fatalf("flows layouts = %+v / %+v, want 48 / 104 byte values", flows.actual, flows.desired)
	}
	if nat.name != kernelNatPortsMapName || nat.err != nil {
		t.Fatalf("nat comparison = %+v, want compatible: a smaller NAT bank is adopted", nat)
	}
	if stats.name != kernelStatsMapName || kernelHotRestartIncompatibilityReason(stats.err) != "max_entries=64 but current object expects at least 4096" {
		t.Fatalf("stats comparison = %+v (%v), want the stats capacity rule", stats, stats.err)
	}

	err = validateKernelHotRestartMapReplacements(spec, replacements, kernelTCHotRestartFlexibleCapacityMaps())
	assertKernelHotRestartIncompatible(t, err)
	if got, want := err.Error(), `map "flows_v4" incompatible: value_size=48 but current object expects 104`; got != want {
		t.Fatalf("validateKernelHotRestartMapReplacements() = %q, want the first incompatible map %q", got, want)
	}
}

func TestPlanLayoutCopiesMovesListedPrefixesOutOfReplacements(t *testing.T) {
	maps := newHotRestartCheckTestMaps(t, 64)
	spec := hotRestartCheckTestSpec(104)
	state := &kernelHotRestartMapState{replacements: map[string]*ebpf.Map{
		kernelTCFlowsOldMapNameV4:    maps[kernelFlowsMapName],
		kernelTCNatPortsOldMapNameV4: maps[kernelNatPortsMapName],
	}}

	if err := state.planLayoutCopies(spec, kernelTCHotRestartFlexibleCapacityMaps(), kernelTCMapLayoutRules); err != nil {
		t.Fatalf("planLayoutCopies() error = %v", err)
	}
	if state.replacements[kernelTCFlowsOldMapNameV4] != nil || state.replacements[kernelTCNatPortsOldMapNameV4] == nil {
		t.Fatalf("replacements = %v, want the NAT bank adopted and the flow bank moved out", state.replacements)
	}
	if len(state.layoutCopies) != 1 {
		t.Fatalf("layoutCopies = %+v, want the flow bank", state.layoutCopies)
	}
	c := state.layoutCopies[0]
	if c.name != kernelTCFlowsOldMapNameV4 || c.source != maps[kernelFlowsMapName] || c.fromValueSize != 64 || c.toValueSize != 104 {
		t.Fatalf("layout copy = %+v, want flows_old_v4 from the 64-byte map into 104-byte values", c)
	}
	sources := state.capacitySources(state.replacements)
	if sources[kernelTCFlowsOldMapNameV4] != maps[kernelFlowsMapName] || sources[kernelTCNatPortsOldMapNameV4] != maps[kernelNatPortsMapName] {
		t.Fatalf("capacitySources() = %v, want both preserved maps", sources)
	}

	// Without a rule, the same map set is cold.
	state = &kernelHotRestartMapState{replacements: map[string]*ebpf.Map{kernelTCFlowsOldMapNameV4: maps[kernelFlowsMapName]}}
	err := state.planLayoutCopies(spec, kernelTCHotRestartFlexibleCapacityMaps(), nil)
	assertKernelHotRestartIncompatible(t, err)
	if len(state.layoutCopies) != 0 || state.replacements[kernelTCFlowsOldMapNameV4] == nil {
		t.Fatalf("state = %+v after a failed plan, want it unchanged", state)
	}
}

func TestKernelMapHasEntriesIgnoresValueLayout(t *testing.T) {
	m := newKernelHotRestartTestMap(t, &ebpf.MapSpec{Name: "has_entries", Type: ebpf.Hash, KeySize: 12, ValueSize: 104, MaxEntries: 4})
	if used, err := kernelMapHasEntries(m); err != nil || used {
		t.Fatalf("empty map = %t, %v; want false, nil", used, err)
	}
	if err := m.Put(make([]byte, 12), make([]byte, 104)); err != nil {
		t.Fatal(err)
	}
	if used, err := kernelMapHasEntries(m); err != nil || !used {
		t.Fatalf("map with one entry = %t, %v; want true, nil", used, err)
	}
}

// runLiveHotRestartCheck runs the tc check against a fake running daemon
// whose programs use maps.
func runLiveHotRestartCheck(t *testing.T, spec *ebpf.CollectionSpec, maps map[string]*ebpf.Map, recordedToken string) hotRestartEngineReport {
	t.Helper()
	t.Setenv(forwardBPFStateDirEnv, t.TempDir())
	t.Setenv(forwardRuntimeStateDirEnv, t.TempDir())
	meta := kernelHotRestartMetadata{
		FormatVersion: kernelHotRestartMetadataFormatVersion,
		Engine:        kernelEngineTC,
		TCAttachments: []kernelHotRestartTCAttachment{{LinkIndex: 1, Parent: 1, Priority: 1, Handle: 1}},
	}
	if recordedToken != "" {
		meta = kernelHotRestartMetadataWithABI(meta, recordedToken)
	}
	if err := writeKernelRuntimeMetadata(kernelEngineTC, meta); err != nil {
		t.Fatalf("writeKernelRuntimeMetadata() error = %v", err)
	}
	live := &hotRestartLiveMaps{byEngine: map[string][]hotRestartLiveMap{}}
	for name, m := range maps {
		live.byEngine[kernelEngineTC] = append(live.byEngine[kernelEngineTC], hotRestartLiveMap{name: bpfObjName(name), keySize: m.KeySize(), m: m})
	}
	check := hotRestartEngineCheck{
		engine: kernelEngineTC,
		spec:   spec,
		opts:   kernelTCHotRestartValidationOptions("new-object", false),
	}
	return check.run(func(pid int) (*hotRestartLiveMaps, error) {
		if pid != os.Getpid() {
			t.Fatalf("discover pid = %d, want the metadata owner %d", pid, os.Getpid())
		}
		return live, nil
	})
}

func hotRestartReportMap(report hotRestartEngineReport, name string) (hotRestartMapReport, bool) {
	for _, item := range report.Maps {
		if item.Name == name {
			return item, true
		}
	}
	return hotRestartMapReport{}, false
}

func TestHotRestartEngineCheckLiveSameLayoutIsHot(t *testing.T) {
	maps := newHotRestartCheckTestMaps(t, 104)
	report := runLiveHotRestartCheck(t, hotRestartCheckTestSpec(104), maps, kernelTCHotRestartCompatToken(false))

	if report.Source != hotRestartSourceRunning || report.Verdict != hotRestartVerdictHot {
		t.Fatalf("report = %+v, want a hot verdict from the running daemon", report)
	}
	// Without a draining migration the successor adopts the active banks as
	// its old banks.
	flows, ok := hotRestartReportMap(report, kernelTCFlowsOldMapNameV4)
	if !ok || flows.From != kernelFlowsMapName || !flows.Compatible || flows.Preserved == nil || flows.Preserved.MaxEntries != 64 {
		t.Fatalf("flows report = %+v, want flows_v4 adopted as flows_old_v4 at its preserved size", flows)
	}
	if stats, ok := hotRestartReportMap(report, kernelStatsMapName); !ok || !stats.Compatible || stats.From != "" {
		t.Fatalf("stats report = %+v, want a compatible stats map: capacity does not decide", stats)
	}
	if len(report.Maps) != 3 {
		t.Fatalf("maps = %+v, want flows, NAT and stats", report.Maps)
	}
}

func TestHotRestartEngineCheckLiveListedValueGrowthIsCopied(t *testing.T) {
	maps := newHotRestartCheckTestMaps(t, 64)
	report := runLiveHotRestartCheck(t, hotRestartCheckTestSpec(104), maps, kernelTCHotRestartCompatToken(false))

	if report.Verdict != hotRestartVerdictHot {
		t.Fatalf("report = %+v, want hot: the 64-byte flow values are a listed prefix", report)
	}
	flows, ok := hotRestartReportMap(report, kernelTCFlowsOldMapNameV4)
	if !ok || !flows.Compatible || !flows.Copied || flows.From != kernelFlowsMapName || flows.Preserved.ValueSize != 64 || flows.Current.ValueSize != 104 {
		t.Fatalf("flows report = %+v, want flows_v4 copied into the 104-byte flows_old_v4", flows)
	}
	if nat, ok := hotRestartReportMap(report, kernelTCNatPortsOldMapNameV4); !ok || !nat.Compatible || nat.Copied {
		t.Fatalf("nat report = %+v, want adopted", nat)
	}
}

func TestHotRestartEngineCheckLiveUnlistedValueGrowthIsCold(t *testing.T) {
	maps := newHotRestartCheckTestMaps(t, 48)
	report := runLiveHotRestartCheck(t, hotRestartCheckTestSpec(104), maps, "")

	if report.Verdict != hotRestartVerdictCold || !strings.Contains(report.Reason, kernelTCFlowsOldMapNameV4+" cannot be adopted") {
		t.Fatalf("report = %+v, want cold because the flow bank cannot be adopted", report)
	}
	flows, ok := hotRestartReportMap(report, kernelTCFlowsOldMapNameV4)
	if !ok || flows.Compatible || flows.Copied || flows.Reason != "value_size=48 but current object expects 104" {
		t.Fatalf("flows report = %+v, want the value_size reason", flows)
	}
	if nat, ok := hotRestartReportMap(report, kernelTCNatPortsOldMapNameV4); !ok || !nat.Compatible {
		t.Fatalf("nat report = %+v, want compatible", nat)
	}
	if len(report.Notes) == 0 || !strings.Contains(report.Notes[0], "does not record its compat token") {
		t.Fatalf("notes = %v, want the note about the missing compat token", report.Notes)
	}
}

func TestHotRestartEngineCheckLiveTrafficStatsToggleIsCold(t *testing.T) {
	maps := newHotRestartCheckTestMaps(t, 104)
	report := runLiveHotRestartCheck(t, hotRestartCheckTestSpec(104), maps, kernelTCHotRestartCompatToken(true))

	want := "metadata compat token=" + kernelTCHotRestartCompatToken(true) + " but current runtime expects " + kernelTCHotRestartCompatToken(false)
	if report.Verdict != hotRestartVerdictCold || report.Reason != want {
		t.Fatalf("report = %+v, want cold with reason %q", report, want)
	}
}

func TestHotRestartEngineCheckReadsPinnedHandoff(t *testing.T) {
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	t.Setenv(forwardBPFStateDirEnv, bpfRoot)
	t.Setenv(forwardRuntimeStateDirEnv, t.TempDir())
	maps := newHotRestartCheckTestMaps(t, 48)
	if err := pinKernelHotRestartMaps(kernelEngineTC, map[string]*ebpf.Map{
		kernelFlowsMapName:    maps[kernelFlowsMapName],
		kernelNatPortsMapName: maps[kernelNatPortsMapName],
		kernelStatsMapName:    maps[kernelStatsMapName],
	}); err != nil {
		t.Fatalf("pinKernelHotRestartMaps() error = %v", err)
	}
	meta := kernelHotRestartMetadataWithABI(kernelHotRestartTCMetadata(nil, "old-object"), kernelTCHotRestartCompatToken(false))
	if err := writeKernelHotRestartMetadata(kernelEngineTC, meta); err != nil {
		t.Fatalf("writeKernelHotRestartMetadata() error = %v", err)
	}
	check := hotRestartEngineCheck{engine: kernelEngineTC, opts: kernelTCHotRestartValidationOptions("new-object", false)}

	check.spec = hotRestartCheckTestSpec(48)
	if report := check.run(nil); report.Source != hotRestartSourcePinned || report.Verdict != hotRestartVerdictHot {
		t.Fatalf("same layout report = %+v, want a hot verdict from the pinned handoff", report)
	}
	check.spec = hotRestartCheckTestSpec(104)
	if report := check.run(nil); report.Verdict != hotRestartVerdictCold {
		t.Fatalf("grown flow value report = %+v, want cold", report)
	}
	if !kernelHotRestartStateExists(kernelEngineTC) {
		t.Fatal("the check removed the pinned handoff, want it left in place")
	}
}
