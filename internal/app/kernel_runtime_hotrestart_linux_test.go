//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
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

func TestIsKernelHotRestartIncompatibleUsesErrorChain(t *testing.T) {
	t.Parallel()

	base := newKernelHotRestartIncompatibleError("metadata format mismatch")
	err := fmt.Errorf("outer wrapper: %w", base)
	if !errors.Is(err, base) {
		t.Fatalf("errors.Is(%v, %v) = false, want true", err, base)
	}
	assertKernelHotRestartIncompatible(t, err)
}
