//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func assertKernelHotRestartIncompatible(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected hot restart incompatibility error, got nil")
	}
	if !isKernelHotRestartIncompatible(err) {
		t.Fatalf("expected hot restart incompatibility error, got %T: %v", err, err)
	}
}

func TestKernelHotRestartSkipStatsRequested(t *testing.T) {
	marker := filepath.Join(t.TempDir(), ".hot-restart-kernel")
	t.Setenv(forwardHotRestartMarkerEnv, marker)

	skipMarker := marker + ".skip-stats"
	if got := kernelHotRestartSkipStatsMarkerPath(); got != skipMarker {
		t.Fatalf("kernelHotRestartSkipStatsMarkerPath() = %q, want %q", got, skipMarker)
	}
	if kernelHotRestartSkipStatsRequested() {
		t.Fatal("kernelHotRestartSkipStatsRequested() = true, want false without marker file")
	}

	if err := os.WriteFile(skipMarker, []byte("1"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", skipMarker, err)
	}
	if !kernelHotRestartSkipStatsRequested() {
		t.Fatal("kernelHotRestartSkipStatsRequested() = false, want true with marker file")
	}
}

func TestValidateKernelHotRestartMapCompatibility(t *testing.T) {
	t.Parallel()

	base := kernelHotRestartMapDescriptor{
		Type:       ebpf.Hash,
		KeySize:    16,
		ValueSize:  32,
		MaxEntries: 1024,
		Flags:      0,
	}

	t.Run("exact match", func(t *testing.T) {
		if err := validateKernelHotRestartMapCompatibility("flows", base, base, false); err != nil {
			t.Fatalf("validateKernelHotRestartMapCompatibility() error = %v, want nil", err)
		}
	})

	t.Run("smaller capacity allowed for preserved flow map", func(t *testing.T) {
		actual := base
		actual.MaxEntries = 512
		if err := validateKernelHotRestartMapCompatibility("flows", actual, base, true); err != nil {
			t.Fatalf("validateKernelHotRestartMapCompatibility() error = %v, want nil", err)
		}
	})

	t.Run("smaller capacity rejected when not allowed", func(t *testing.T) {
		actual := base
		actual.MaxEntries = 512
		if err := validateKernelHotRestartMapCompatibility("stats", actual, base, false); err == nil {
			t.Fatal("validateKernelHotRestartMapCompatibility() error = nil, want max_entries mismatch")
		}
	})

	t.Run("value size mismatch rejected", func(t *testing.T) {
		actual := base
		actual.ValueSize = 40
		if err := validateKernelHotRestartMapCompatibility("flows_v6", actual, base, true); err == nil {
			t.Fatal("validateKernelHotRestartMapCompatibility() error = nil, want value_size mismatch")
		}
	})
}

func TestValidateKernelHotRestartMetadata(t *testing.T) {
	t.Parallel()

	const (
		engine     = kernelEngineTC
		objectHash = "abc123"
	)

	base := kernelHotRestartMetadata{
		FormatVersion: kernelHotRestartMetadataFormatVersion,
		Engine:        engine,
		ObjectHash:    objectHash,
	}

	t.Run("matching metadata", func(t *testing.T) {
		if err := validateKernelHotRestartMetadata(base, engine, objectHash); err != nil {
			t.Fatalf("validateKernelHotRestartMetadata() error = %v, want nil", err)
		}
	})

	t.Run("missing format version is rejected", func(t *testing.T) {
		meta := base
		meta.FormatVersion = 0
		if err := validateKernelHotRestartMetadata(meta, engine, objectHash); err == nil {
			t.Fatal("validateKernelHotRestartMetadata() error = nil, want format mismatch")
		} else {
			assertKernelHotRestartIncompatible(t, err)
		}
	})

	t.Run("missing object hash is rejected", func(t *testing.T) {
		meta := base
		meta.ObjectHash = ""
		if err := validateKernelHotRestartMetadata(meta, engine, objectHash); err == nil {
			t.Fatal("validateKernelHotRestartMetadata() error = nil, want object hash mismatch")
		} else {
			assertKernelHotRestartIncompatible(t, err)
		}
	})

	t.Run("different object hash is rejected", func(t *testing.T) {
		meta := base
		meta.ObjectHash = "def456"
		if err := validateKernelHotRestartMetadata(meta, engine, objectHash); err == nil {
			t.Fatal("validateKernelHotRestartMetadata() error = nil, want object hash mismatch")
		} else {
			assertKernelHotRestartIncompatible(t, err)
		}
	})

	t.Run("abi compatibility accepts matching compat token", func(t *testing.T) {
		meta := base
		meta.FormatVersion = kernelHotRestartMetadataFormatVersionABI
		meta.CompatMode = kernelHotRestartCompatModeABI
		meta.CompatToken = kernelTCHotRestartCompatToken(false)
		meta.ObjectHash = "old-object"
		if err := validateKernelHotRestartMetadataWithOptions(meta, kernelTCHotRestartValidationOptions(objectHash, false)); err != nil {
			t.Fatalf("validateKernelHotRestartMetadataWithOptions() error = %v, want nil", err)
		}
	})

	t.Run("abi compatibility rejects different compat token", func(t *testing.T) {
		meta := base
		meta.FormatVersion = kernelHotRestartMetadataFormatVersionABI
		meta.CompatMode = kernelHotRestartCompatModeABI
		meta.CompatToken = "tc:base:v999"
		if err := validateKernelHotRestartMetadataWithOptions(meta, kernelTCHotRestartValidationOptions(objectHash, false)); err == nil {
			t.Fatal("validateKernelHotRestartMetadataWithOptions() error = nil, want compat token mismatch")
		} else {
			assertKernelHotRestartIncompatible(t, err)
		}
	})
}

func TestKernelHotRestartIncompatibilityReason(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf(
		"validate tc hot restart metadata: %w",
		newKernelHotRestartIncompatibleError("metadata object hash=old but current runtime expects new"),
	)
	assertKernelHotRestartIncompatible(t, err)
	if got := kernelHotRestartIncompatibilityReason(err); got != "metadata object hash=old but current runtime expects new" {
		t.Fatalf("kernelHotRestartIncompatibilityReason() = %q, want %q", got, "metadata object hash=old but current runtime expects new")
	}
}

func TestValidateKernelHotRestartMapReplacementsClassifiesIncompatibility(t *testing.T) {
	t.Parallel()

	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{}}
	err := validateKernelHotRestartMapReplacements(spec, map[string]*ebpf.Map{
		"flows": nil,
	}, nil)
	assertKernelHotRestartIncompatible(t, err)
	if got := kernelHotRestartIncompatibilityReason(err); got != `map "flows" is preserved but missing from current object` {
		t.Fatalf("kernelHotRestartIncompatibilityReason() = %q, want %q", got, `map "flows" is preserved but missing from current object`)
	}
}

func TestValidateKernelHotRestartMapCompatibilityClassifiesIncompatibility(t *testing.T) {
	t.Parallel()

	err := validateKernelHotRestartMapCompatibility(
		"flows",
		kernelHotRestartMapDescriptor{
			Type:       ebpf.Hash,
			KeySize:    16,
			ValueSize:  32,
			MaxEntries: 64,
		},
		kernelHotRestartMapDescriptor{
			Type:       ebpf.Hash,
			KeySize:    16,
			ValueSize:  48,
			MaxEntries: 64,
		},
		true,
	)
	assertKernelHotRestartIncompatible(t, err)
}

func TestKernelCollectionSpecWithReplacementMapCapacitiesUsesExactMapSizes(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			kernelFlowsMapName: {
				Name:       kernelFlowsMapName,
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  8,
				MaxEntries: 128,
			},
			kernelStatsMapName: {
				Name:       kernelStatsMapName,
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  8,
				MaxEntries: 256,
			},
		},
	}
	replacement := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 64,
	})

	loadSpec, err := kernelCollectionSpecWithReplacementMapCapacities(spec, map[string]*ebpf.Map{
		kernelFlowsMapName: replacement,
	})
	if err != nil {
		t.Fatalf("kernelCollectionSpecWithReplacementMapCapacities() error = %v", err)
	}
	if loadSpec == spec {
		t.Fatal("kernelCollectionSpecWithReplacementMapCapacities() reused the original spec, want a copy")
	}
	if got := spec.Maps[kernelFlowsMapName].MaxEntries; got != 128 {
		t.Fatalf("original spec flows max_entries = %d, want 128", got)
	}
	if got := loadSpec.Maps[kernelFlowsMapName].MaxEntries; got != 64 {
		t.Fatalf("load spec flows max_entries = %d, want 64", got)
	}
	if got := loadSpec.Maps[kernelStatsMapName].MaxEntries; got != 256 {
		t.Fatalf("load spec stats max_entries = %d, want 256", got)
	}
}

func TestIsKernelHotRestartIncompatibleUsesErrorChain(t *testing.T) {
	t.Parallel()

	base := newKernelHotRestartIncompatibleError("metadata format mismatch")
	err := fmt.Errorf("outer wrapper: %w", base)
	if !errors.Is(err, base) {
		t.Fatalf("errors.Is(%v, %v) = false, want true", err, base)
	}
	assertKernelHotRestartIncompatible(t, err)
}

func TestLoadTCKernelHotRestartStatePromotesActiveMapsToOldBank(t *testing.T) {
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	runtimeRoot := t.TempDir()
	t.Setenv(forwardBPFStateDirEnv, bpfRoot)
	t.Setenv(forwardRuntimeStateDirEnv, runtimeRoot)
	clearKernelHotRestartState(kernelEngineTC)
	t.Cleanup(func() { clearKernelHotRestartState(kernelEngineTC) })

	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 64,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  4,
		MaxEntries: 64,
	})
	stats := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelStatsMapName,
		Type:       ebpf.PerCPUHash,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(kernelStatsValueV4{})),
		MaxEntries: 128,
	})
	if err := pinKernelHotRestartMaps(kernelEngineTC, map[string]*ebpf.Map{
		kernelFlowsMapName:    flows,
		kernelNatPortsMapName: nat,
		kernelStatsMapName:    stats,
	}); err != nil {
		t.Fatalf("pinKernelHotRestartMaps() error = %v", err)
	}
	meta := kernelHotRestartMetadataWithABI(kernelHotRestartTCMetadata(nil, "old-object"), kernelTCHotRestartCompatToken(false))
	if err := writeKernelHotRestartMetadata(kernelEngineTC, meta); err != nil {
		t.Fatalf("writeKernelHotRestartMetadata() error = %v", err)
	}

	desired := kernelMapCapacities{Rules: 128, Flows: 128, NATPorts: 128}
	state, err := loadTCKernelHotRestartState(desired, kernelTCHotRestartValidationOptions("new-object", false))
	if err != nil {
		t.Fatalf("loadTCKernelHotRestartState() error = %v", err)
	}
	if state == nil {
		t.Fatal("loadTCKernelHotRestartState() = nil, want promoted old-bank state")
	}
	defer state.close()

	if state.tcFlowMigrationFlags != tcFlowMigrationFlagV4Old {
		t.Fatalf("tcFlowMigrationFlags = %#x, want %#x", state.tcFlowMigrationFlags, tcFlowMigrationFlagV4Old)
	}
	if state.replacements[kernelTCFlowsOldMapNameV4] == nil || state.replacements[kernelTCNatPortsOldMapNameV4] == nil {
		t.Fatalf("replacements = %v, want promoted old-bank flow/nat maps", state.replacementMapNames())
	}
	if state.replacements[kernelFlowsMapName] != nil || state.replacements[kernelNatPortsMapName] != nil {
		t.Fatalf("replacements = %v, want fresh active maps after promotion", state.replacementMapNames())
	}
	if state.replacements[kernelStatsMapName] == nil {
		t.Fatalf("replacements = %v, want preserved stats map", state.replacementMapNames())
	}
	if state.actualCapacities != desired {
		t.Fatalf("actualCapacities = %+v, want %+v", state.actualCapacities, desired)
	}
}

func TestLoadTCKernelHotRestartStateKeepsExistingTCBanks(t *testing.T) {
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	runtimeRoot := t.TempDir()
	t.Setenv(forwardBPFStateDirEnv, bpfRoot)
	t.Setenv(forwardRuntimeStateDirEnv, runtimeRoot)
	clearKernelHotRestartState(kernelEngineTC)
	t.Cleanup(func() { clearKernelHotRestartState(kernelEngineTC) })

	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 64,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  4,
		MaxEntries: 64,
	})
	flowsOld := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelTCFlowsOldMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 32,
	})
	natOld := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelTCNatPortsOldMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  4,
		MaxEntries: 32,
	})
	stats := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelStatsMapName,
		Type:       ebpf.PerCPUHash,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(kernelStatsValueV4{})),
		MaxEntries: 256,
	})
	if err := pinKernelHotRestartMaps(kernelEngineTC, map[string]*ebpf.Map{
		kernelFlowsMapName:           flows,
		kernelNatPortsMapName:        nat,
		kernelTCFlowsOldMapNameV4:    flowsOld,
		kernelTCNatPortsOldMapNameV4: natOld,
		kernelStatsMapName:           stats,
	}); err != nil {
		t.Fatalf("pinKernelHotRestartMaps() error = %v", err)
	}
	meta := kernelHotRestartMetadataWithABI(kernelHotRestartTCMetadata(nil, "old-object"), kernelTCHotRestartCompatToken(false))
	if err := writeKernelHotRestartMetadata(kernelEngineTC, meta); err != nil {
		t.Fatalf("writeKernelHotRestartMetadata() error = %v", err)
	}

	desired := kernelMapCapacities{Rules: 128, Flows: 128, NATPorts: 128}
	state, err := loadTCKernelHotRestartState(desired, kernelTCHotRestartValidationOptions("new-object", false))
	if err != nil {
		t.Fatalf("loadTCKernelHotRestartState() error = %v", err)
	}
	if state == nil {
		t.Fatal("loadTCKernelHotRestartState() = nil, want preserved dual-bank state")
	}
	defer state.close()

	if state.tcFlowMigrationFlags != tcFlowMigrationFlagV4Old {
		t.Fatalf("tcFlowMigrationFlags = %#x, want %#x", state.tcFlowMigrationFlags, tcFlowMigrationFlagV4Old)
	}
	for _, name := range []string{
		kernelFlowsMapName,
		kernelNatPortsMapName,
		kernelTCFlowsOldMapNameV4,
		kernelTCNatPortsOldMapNameV4,
		kernelStatsMapName,
	} {
		if state.replacements[name] == nil {
			t.Fatalf("replacements = %v, want map %q", state.replacementMapNames(), name)
		}
	}
	if state.actualCapacities.Flows != 64 {
		t.Fatalf("actualCapacities.Flows = %d, want 64", state.actualCapacities.Flows)
	}
	if state.actualCapacities.NATPorts != 64 {
		t.Fatalf("actualCapacities.NATPorts = %d, want 64", state.actualCapacities.NATPorts)
	}
}

func TestTCOldFlowMigrationFlagsFromRuntimeMapRefsTracksOldBankOccupancy(t *testing.T) {
	flowsOld := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelTCFlowsOldMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 8,
	})

	flags, err := tcOldFlowMigrationFlagsFromRuntimeMapRefs(kernelRuntimeMapRefs{flowsOldV4: flowsOld})
	if err != nil {
		t.Fatalf("tcOldFlowMigrationFlagsFromRuntimeMapRefs(empty) error = %v", err)
	}
	if flags != 0 {
		t.Fatalf("flags(empty) = %#x, want 0", flags)
	}

	key := tcFlowKeyV4{IfIndex: 1, SrcAddr: 0x0a000001, DstAddr: 0x0a000002, SrcPort: 12345, DstPort: 80, Proto: unix.IPPROTO_TCP}
	value := tcFlowValueV4{RuleID: 7, NATAddr: 0x0a000003, NATPort: 20001}
	if err := flowsOld.Put(key, value); err != nil {
		t.Fatalf("flowsOld.Put() error = %v", err)
	}

	flags, err = tcOldFlowMigrationFlagsFromRuntimeMapRefs(kernelRuntimeMapRefs{flowsOldV4: flowsOld})
	if err != nil {
		t.Fatalf("tcOldFlowMigrationFlagsFromRuntimeMapRefs(populated) error = %v", err)
	}
	if flags != tcFlowMigrationFlagV4Old {
		t.Fatalf("flags(populated) = %#x, want %#x", flags, tcFlowMigrationFlagV4Old)
	}
}

func TestConfigureTCFlowMigrationStateWritesArrayValue(t *testing.T) {
	flowState := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelTCFlowMigrationStateMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})

	want := uint32(tcFlowMigrationFlagV4Old | tcFlowMigrationFlagV6Old)
	if err := configureTCFlowMigrationState(kernelCollectionPieces{flowMigrationState: flowState}, want); err != nil {
		t.Fatalf("configureTCFlowMigrationState() error = %v", err)
	}

	var got uint32
	if err := flowState.Lookup(uint32(0), &got); err != nil {
		t.Fatalf("flowState.Lookup() error = %v", err)
	}
	if got != want {
		t.Fatalf("flow migration state = %#x, want %#x", got, want)
	}
}

func TestTCEffectiveOldFlowMigrationFlagsFromRuntimeMapRefsUsesMigrationState(t *testing.T) {
	flowState := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelTCFlowMigrationStateMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})

	want := uint32(tcFlowMigrationFlagV4Old)
	if err := flowState.Put(uint32(0), want); err != nil {
		t.Fatalf("flowState.Put() error = %v", err)
	}

	flags, err := tcEffectiveOldFlowMigrationFlagsFromRuntimeMapRefs(kernelRuntimeMapRefs{tcFlowMigrationState: flowState})
	if err != nil {
		t.Fatalf("tcEffectiveOldFlowMigrationFlagsFromRuntimeMapRefs() error = %v", err)
	}
	if flags != want {
		t.Fatalf("flags = %#x, want %#x", flags, want)
	}
}

func TestKernelRuntimeMapCapacityUsesTCMigrationState(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 64,
	})
	flowsOld := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelTCFlowsOldMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 32,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  4,
		MaxEntries: 40,
	})
	natOld := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelTCNatPortsOldMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  4,
		MaxEntries: 20,
	})
	flowState := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelTCFlowMigrationStateMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})

	refs := kernelRuntimeMapRefs{
		flowsV4:              flows,
		flowsOldV4:           flowsOld,
		natV4:                nat,
		natOldV4:             natOld,
		tcFlowMigrationState: flowState,
	}

	if got := kernelRuntimeFlowMapCapacity(refs); got != 64 {
		t.Fatalf("kernelRuntimeFlowMapCapacity(inactive old bank) = %d, want 64", got)
	}
	if got := kernelRuntimeNATMapCapacity(refs); got != 40 {
		t.Fatalf("kernelRuntimeNATMapCapacity(inactive old bank) = %d, want 40", got)
	}

	var view KernelEngineRuntimeView
	applyKernelRuntimeMapBreakdown(&view, refs, kernelRuntimeMapCountSnapshot{}, true)
	if view.FlowsMapCapacityV4 != 64 || view.FlowsMapOldCapacityV4 != 0 || view.NATMapCapacityV4 != 40 || view.NATMapOldCapacityV4 != 0 {
		t.Fatalf("inactive old-bank breakdown = %+v, want flow_v4=64 flow_old_v4=0 nat_v4=40 nat_old_v4=0", view)
	}

	if err := flowState.Put(uint32(0), uint32(tcFlowMigrationFlagV4Old)); err != nil {
		t.Fatalf("flowState.Put(active) error = %v", err)
	}
	if got := kernelRuntimeFlowMapCapacity(refs); got != 96 {
		t.Fatalf("kernelRuntimeFlowMapCapacity(active old bank) = %d, want 96", got)
	}
	if got := kernelRuntimeNATMapCapacity(refs); got != 60 {
		t.Fatalf("kernelRuntimeNATMapCapacity(active old bank) = %d, want 60", got)
	}

	view = KernelEngineRuntimeView{}
	applyKernelRuntimeMapBreakdown(&view, refs, kernelRuntimeMapCountSnapshot{}, true)
	if view.FlowsMapCapacityV4 != 64 || view.FlowsMapOldCapacityV4 != 32 || view.NATMapCapacityV4 != 40 || view.NATMapOldCapacityV4 != 20 {
		t.Fatalf("active old-bank breakdown = %+v, want flow_v4=64 flow_old_v4=32 nat_v4=40 nat_old_v4=20", view)
	}
}

func TestLoadXDPKernelHotRestartStatePromotesActiveMapsToOldBank(t *testing.T) {
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	runtimeRoot := t.TempDir()
	t.Setenv(forwardBPFStateDirEnv, bpfRoot)
	t.Setenv(forwardRuntimeStateDirEnv, runtimeRoot)
	clearKernelHotRestartState(kernelEngineXDP)
	t.Cleanup(func() { clearKernelHotRestartState(kernelEngineXDP) })

	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(xdpFlowValueV4{})),
		MaxEntries: 64,
	})
	stats := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelStatsMapName,
		Type:       ebpf.PerCPUHash,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(kernelStatsValueV4{})),
		MaxEntries: 128,
	})
	if err := pinKernelHotRestartMaps(kernelEngineXDP, map[string]*ebpf.Map{
		kernelFlowsMapName: flows,
		kernelStatsMapName: stats,
	}); err != nil {
		t.Fatalf("pinKernelHotRestartMaps() error = %v", err)
	}
	meta := kernelHotRestartMetadataWithABI(kernelHotRestartXDPMetadata(nil, "old-object"), kernelXDPHotRestartCompatToken(false))
	if err := writeKernelHotRestartMetadata(kernelEngineXDP, meta); err != nil {
		t.Fatalf("writeKernelHotRestartMetadata() error = %v", err)
	}

	desired := kernelMapCapacities{Rules: 128, Flows: 128}
	state, err := loadXDPKernelHotRestartState(desired, kernelXDPHotRestartValidationOptions("new-object", false))
	if err != nil {
		t.Fatalf("loadXDPKernelHotRestartState() error = %v", err)
	}
	if state == nil {
		t.Fatal("loadXDPKernelHotRestartState() = nil, want promoted old-bank state")
	}
	defer state.close()

	if state.xdpFlowMigrationFlags != xdpFlowMigrationFlagV4Old {
		t.Fatalf("xdpFlowMigrationFlags = %#x, want %#x", state.xdpFlowMigrationFlags, xdpFlowMigrationFlagV4Old)
	}
	if state.replacements[kernelXDPFlowsOldMapNameV4] == nil {
		t.Fatalf("replacements = %v, want promoted old-bank flow map", state.replacementMapNames())
	}
	if state.replacements[kernelFlowsMapName] != nil {
		t.Fatalf("replacements = %v, want fresh active flow map after promotion", state.replacementMapNames())
	}
	if state.replacements[kernelStatsMapName] == nil {
		t.Fatalf("replacements = %v, want preserved stats map", state.replacementMapNames())
	}
	if state.actualCapacities != desired {
		t.Fatalf("actualCapacities = %+v, want %+v", state.actualCapacities, desired)
	}
}

func TestLoadXDPKernelHotRestartStatePromotesActiveIPv6NATMapsToOldBank(t *testing.T) {
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	runtimeRoot := t.TempDir()
	t.Setenv(forwardBPFStateDirEnv, bpfRoot)
	t.Setenv(forwardRuntimeStateDirEnv, runtimeRoot)
	clearKernelHotRestartState(kernelEngineXDP)
	t.Cleanup(func() { clearKernelHotRestartState(kernelEngineXDP) })

	flowsV6 := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapNameV6,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV6{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV6{})),
		MaxEntries: 64,
	})
	natV6 := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapNameV6,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV6{})),
		ValueSize:  4,
		MaxEntries: 32,
	})
	stats := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelStatsMapName,
		Type:       ebpf.PerCPUHash,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(kernelStatsValueV4{})),
		MaxEntries: 128,
	})
	if err := pinKernelHotRestartMaps(kernelEngineXDP, map[string]*ebpf.Map{
		kernelFlowsMapNameV6:    flowsV6,
		kernelNatPortsMapNameV6: natV6,
		kernelStatsMapName:      stats,
	}); err != nil {
		t.Fatalf("pinKernelHotRestartMaps() error = %v", err)
	}
	meta := kernelHotRestartMetadataWithABI(kernelHotRestartXDPMetadata(nil, "old-object"), kernelXDPHotRestartCompatToken(false))
	if err := writeKernelHotRestartMetadata(kernelEngineXDP, meta); err != nil {
		t.Fatalf("writeKernelHotRestartMetadata() error = %v", err)
	}

	desired := kernelMapCapacities{Rules: 128, Flows: 128, NATPorts: 128}
	state, err := loadXDPKernelHotRestartState(desired, kernelXDPHotRestartValidationOptions("new-object", false))
	if err != nil {
		t.Fatalf("loadXDPKernelHotRestartState() error = %v", err)
	}
	if state == nil {
		t.Fatal("loadXDPKernelHotRestartState() = nil, want promoted IPv6 old-bank state")
	}
	defer state.close()

	if state.xdpFlowMigrationFlags != xdpFlowMigrationFlagV6Old {
		t.Fatalf("xdpFlowMigrationFlags = %#x, want %#x", state.xdpFlowMigrationFlags, xdpFlowMigrationFlagV6Old)
	}
	if state.replacements[kernelXDPFlowsOldMapNameV6] == nil || state.replacements[kernelTCNatPortsOldMapNameV6] == nil {
		t.Fatalf("replacements = %v, want promoted IPv6 old-bank flow/nat maps", state.replacementMapNames())
	}
	if state.replacements[kernelFlowsMapNameV6] != nil || state.replacements[kernelNatPortsMapNameV6] != nil {
		t.Fatalf("replacements = %v, want fresh active IPv6 flow/nat maps after promotion", state.replacementMapNames())
	}
}

func TestLoadXDPKernelHotRestartStateKeepsExistingXDPBanks(t *testing.T) {
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	runtimeRoot := t.TempDir()
	t.Setenv(forwardBPFStateDirEnv, bpfRoot)
	t.Setenv(forwardRuntimeStateDirEnv, runtimeRoot)
	clearKernelHotRestartState(kernelEngineXDP)
	t.Cleanup(func() { clearKernelHotRestartState(kernelEngineXDP) })

	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(xdpFlowValueV4{})),
		MaxEntries: 64,
	})
	flowsOld := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelXDPFlowsOldMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(xdpFlowValueV4{})),
		MaxEntries: 32,
	})
	stats := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelStatsMapName,
		Type:       ebpf.PerCPUHash,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(kernelStatsValueV4{})),
		MaxEntries: 256,
	})
	if err := pinKernelHotRestartMaps(kernelEngineXDP, map[string]*ebpf.Map{
		kernelFlowsMapName:         flows,
		kernelXDPFlowsOldMapNameV4: flowsOld,
		kernelStatsMapName:         stats,
	}); err != nil {
		t.Fatalf("pinKernelHotRestartMaps() error = %v", err)
	}
	meta := kernelHotRestartMetadataWithABI(kernelHotRestartXDPMetadata(nil, "old-object"), kernelXDPHotRestartCompatToken(false))
	if err := writeKernelHotRestartMetadata(kernelEngineXDP, meta); err != nil {
		t.Fatalf("writeKernelHotRestartMetadata() error = %v", err)
	}

	desired := kernelMapCapacities{Rules: 128, Flows: 128}
	state, err := loadXDPKernelHotRestartState(desired, kernelXDPHotRestartValidationOptions("new-object", false))
	if err != nil {
		t.Fatalf("loadXDPKernelHotRestartState() error = %v", err)
	}
	if state == nil {
		t.Fatal("loadXDPKernelHotRestartState() = nil, want preserved dual-bank state")
	}
	defer state.close()

	if state.xdpFlowMigrationFlags != xdpFlowMigrationFlagV4Old {
		t.Fatalf("xdpFlowMigrationFlags = %#x, want %#x", state.xdpFlowMigrationFlags, xdpFlowMigrationFlagV4Old)
	}
	for _, name := range []string{
		kernelFlowsMapName,
		kernelXDPFlowsOldMapNameV4,
		kernelStatsMapName,
	} {
		if state.replacements[name] == nil {
			t.Fatalf("replacements = %v, want map %q", state.replacementMapNames(), name)
		}
	}
	if state.actualCapacities.Flows != 64 {
		t.Fatalf("actualCapacities.Flows = %d, want 64", state.actualCapacities.Flows)
	}
}

func TestLoadXDPKernelHotRestartStateRejectsOrphanOldNATBank(t *testing.T) {
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	runtimeRoot := t.TempDir()
	t.Setenv(forwardBPFStateDirEnv, bpfRoot)
	t.Setenv(forwardRuntimeStateDirEnv, runtimeRoot)
	clearKernelHotRestartState(kernelEngineXDP)
	t.Cleanup(func() { clearKernelHotRestartState(kernelEngineXDP) })

	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(xdpFlowValueV4{})),
		MaxEntries: 64,
	})
	natOld := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelTCNatPortsOldMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  4,
		MaxEntries: 32,
	})
	if err := pinKernelHotRestartMaps(kernelEngineXDP, map[string]*ebpf.Map{
		kernelFlowsMapName:           flows,
		kernelTCNatPortsOldMapNameV4: natOld,
	}); err != nil {
		t.Fatalf("pinKernelHotRestartMaps() error = %v", err)
	}
	meta := kernelHotRestartMetadataWithABI(kernelHotRestartXDPMetadata(nil, "old-object"), kernelXDPHotRestartCompatToken(false))
	if err := writeKernelHotRestartMetadata(kernelEngineXDP, meta); err != nil {
		t.Fatalf("writeKernelHotRestartMetadata() error = %v", err)
	}

	desired := kernelMapCapacities{Rules: 128, Flows: 128}
	_, err := loadXDPKernelHotRestartState(desired, kernelXDPHotRestartValidationOptions("new-object", false))
	assertKernelHotRestartIncompatible(t, err)
}

func TestXDPOldFlowMigrationFlagsFromRuntimeMapRefsTracksOldBankOccupancy(t *testing.T) {
	flowsOld := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelXDPFlowsOldMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(xdpFlowValueV4{})),
		MaxEntries: 8,
	})

	flags, err := xdpOldFlowMigrationFlagsFromRuntimeMapRefs(kernelRuntimeMapRefs{flowsOldV4: flowsOld})
	if err != nil {
		t.Fatalf("xdpOldFlowMigrationFlagsFromRuntimeMapRefs(empty) error = %v", err)
	}
	if flags != 0 {
		t.Fatalf("flags(empty) = %#x, want 0", flags)
	}

	key := tcFlowKeyV4{IfIndex: 1, SrcAddr: 0x0a000001, DstAddr: 0x0a000002, SrcPort: 12345, DstPort: 80, Proto: unix.IPPROTO_TCP}
	value := xdpFlowValueV4{RuleID: 7, NATAddr: 0x0a000003, NATPort: 20001}
	if err := flowsOld.Put(key, value); err != nil {
		t.Fatalf("flowsOld.Put() error = %v", err)
	}

	flags, err = xdpOldFlowMigrationFlagsFromRuntimeMapRefs(kernelRuntimeMapRefs{flowsOldV4: flowsOld})
	if err != nil {
		t.Fatalf("xdpOldFlowMigrationFlagsFromRuntimeMapRefs(populated) error = %v", err)
	}
	if flags != xdpFlowMigrationFlagV4Old {
		t.Fatalf("flags(populated) = %#x, want %#x", flags, xdpFlowMigrationFlagV4Old)
	}
}

func TestXDPOldFlowMigrationFlagsFromCollectionTracksOldBankOccupancy(t *testing.T) {
	flowsOld := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelXDPFlowsOldMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(xdpFlowValueV4{})),
		MaxEntries: 8,
	})

	flags, err := xdpOldFlowMigrationFlagsFromCollection(&ebpf.Collection{
		Maps: map[string]*ebpf.Map{
			kernelXDPFlowsOldMapNameV4: flowsOld,
		},
	})
	if err != nil {
		t.Fatalf("xdpOldFlowMigrationFlagsFromCollection(empty) error = %v", err)
	}
	if flags != 0 {
		t.Fatalf("flags(empty) = %#x, want 0", flags)
	}

	key := tcFlowKeyV4{IfIndex: 1, SrcAddr: 0x0a000001, DstAddr: 0x0a000002, SrcPort: 12345, DstPort: 80, Proto: unix.IPPROTO_TCP}
	value := xdpFlowValueV4{RuleID: 7, NATAddr: 0x0a000003, NATPort: 20001}
	if err := flowsOld.Put(key, value); err != nil {
		t.Fatalf("flowsOld.Put() error = %v", err)
	}

	flags, err = xdpOldFlowMigrationFlagsFromCollection(&ebpf.Collection{
		Maps: map[string]*ebpf.Map{
			kernelXDPFlowsOldMapNameV4: flowsOld,
		},
	})
	if err != nil {
		t.Fatalf("xdpOldFlowMigrationFlagsFromCollection(populated) error = %v", err)
	}
	if flags != xdpFlowMigrationFlagV4Old {
		t.Fatalf("flags(populated) = %#x, want %#x", flags, xdpFlowMigrationFlagV4Old)
	}
}

func TestConfigureXDPFlowMigrationStateWritesArrayValue(t *testing.T) {
	flowState := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelXDPFlowMigrationStateMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})

	want := uint32(xdpFlowMigrationFlagV4Old | xdpFlowMigrationFlagV6Old)
	if err := configureXDPFlowMigrationState(xdpCollectionPieces{flowMigrationState: flowState}, want); err != nil {
		t.Fatalf("configureXDPFlowMigrationState() error = %v", err)
	}

	var got uint32
	if err := flowState.Lookup(uint32(0), &got); err != nil {
		t.Fatalf("flowState.Lookup() error = %v", err)
	}
	if got != want {
		t.Fatalf("flow migration state = %#x, want %#x", got, want)
	}
}

func TestXDPEffectiveOldFlowMigrationFlagsFromRuntimeMapRefsUsesMigrationState(t *testing.T) {
	flowState := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelXDPFlowMigrationStateMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})

	want := uint32(xdpFlowMigrationFlagV4Old)
	if err := flowState.Put(uint32(0), want); err != nil {
		t.Fatalf("flowState.Put() error = %v", err)
	}

	flags, err := xdpEffectiveOldFlowMigrationFlagsFromRuntimeMapRefs(kernelRuntimeMapRefs{xdpFlowMigrationState: flowState})
	if err != nil {
		t.Fatalf("xdpEffectiveOldFlowMigrationFlagsFromRuntimeMapRefs() error = %v", err)
	}
	if flags != want {
		t.Fatalf("flags = %#x, want %#x", flags, want)
	}
}

func TestKernelRuntimeFlowMapCapacityUsesXDPMigrationState(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(xdpFlowValueV4{})),
		MaxEntries: 64,
	})
	flowsOld := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelXDPFlowsOldMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(xdpFlowValueV4{})),
		MaxEntries: 32,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  4,
		MaxEntries: 40,
	})
	natOld := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelTCNatPortsOldMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  4,
		MaxEntries: 20,
	})
	flowState := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelXDPFlowMigrationStateMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})

	refs := kernelRuntimeMapRefs{
		flowsV4:               flows,
		flowsOldV4:            flowsOld,
		natV4:                 nat,
		natOldV4:              natOld,
		xdpFlowMigrationState: flowState,
	}

	if got := kernelRuntimeFlowMapCapacity(refs); got != 64 {
		t.Fatalf("kernelRuntimeFlowMapCapacity(inactive xdp old bank) = %d, want 64", got)
	}
	if err := flowState.Put(uint32(0), uint32(xdpFlowMigrationFlagV4Old)); err != nil {
		t.Fatalf("flowState.Put(active) error = %v", err)
	}
	if got := kernelRuntimeFlowMapCapacity(refs); got != 96 {
		t.Fatalf("kernelRuntimeFlowMapCapacity(active xdp old bank) = %d, want 96", got)
	}
	if got := kernelRuntimeNATMapCapacity(refs); got != 60 {
		t.Fatalf("kernelRuntimeNATMapCapacity(active xdp old bank) = %d, want 60", got)
	}

	var view KernelEngineRuntimeView
	applyKernelRuntimeMapBreakdown(&view, refs, kernelRuntimeMapCountSnapshot{}, true)
	if view.FlowsMapCapacityV4 != 64 || view.FlowsMapOldCapacityV4 != 32 || view.NATMapCapacityV4 != 40 || view.NATMapOldCapacityV4 != 20 {
		t.Fatalf("active xdp old-bank breakdown = %+v, want flow_v4=64 flow_old_v4=32 nat_v4=40 nat_old_v4=20", view)
	}
}

func requireKernelHotRestartBPFStateRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root for bpffs pinning")
	}
	root, err := os.MkdirTemp("/sys/fs/bpf", "forward-hot-restart-test-")
	if err != nil {
		t.Skipf("bpffs temp dir unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func newKernelHotRestartTestMap(t *testing.T, spec *ebpf.MapSpec) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(spec)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("eBPF map creation unavailable: %v", err)
		}
		t.Fatalf("ebpf.NewMap(%q) error = %v", spec.Name, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}
