//go:build linux

package app

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Linux usage:
//   1. Prepare embedded eBPF objects first:
//      bash release.sh
//   2. Run the load smoke test as root:
//      FORWARD_RUN_KERNEL_LOAD_SMOKE=1 go test ./internal/app -run TestLoadEmbeddedKernelCollectionsSmoke -count=1 -v

const kernelLoadSmokeEnableEnv = "FORWARD_RUN_KERNEL_LOAD_SMOKE"

func TestLoadEmbeddedKernelCollectionsSmoke(t *testing.T) {
	if os.Getenv(kernelLoadSmokeEnableEnv) != "1" {
		t.Skipf("set %s=1 to run embedded kernel collection load smoke", kernelLoadSmokeEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	repoRoot := findRepoRoot(t)
	requireEmbeddedEBPFObjects(t, repoRoot)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Logf("memlock auto-raise unavailable: %v (%s)", err, kernelMemlockStatus())
	}

	cases := []struct {
		name               string
		enableTrafficStats bool
		load               func(bool) (*ebpf.CollectionSpec, error)
		validate           func(*ebpf.CollectionSpec) error
	}{
		{
			name:               "tc",
			enableTrafficStats: false,
			load:               loadEmbeddedKernelCollectionSpec,
			validate:           validateKernelCollectionSpec,
		},
		{
			name:               "tc-stats",
			enableTrafficStats: true,
			load:               loadEmbeddedKernelCollectionSpec,
			validate:           validateKernelCollectionSpec,
		},
		{
			name:               "xdp",
			enableTrafficStats: false,
			load:               loadEmbeddedXDPCollectionSpec,
			validate:           validateXDPCollectionSpec,
		},
		{
			name:               "xdp-stats",
			enableTrafficStats: true,
			load:               loadEmbeddedXDPCollectionSpec,
			validate:           validateXDPCollectionSpec,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			spec, err := tc.load(tc.enableTrafficStats)
			if err != nil {
				t.Fatalf("load embedded collection spec: %v", err)
			}
			if err := tc.validate(spec); err != nil {
				t.Fatalf("validate embedded collection spec: %v", err)
			}

			smokeSpec := spec.Copy()
			if _, err := applyKernelMapCapacitiesWithOccupancy(smokeSpec, 64, 128, 64, 64, kernelRuntimeMapCountSnapshot{}, true, false, false); err != nil {
				t.Fatalf("shrink smoke-test map capacities: %v", err)
			}

			coll, err := ebpf.NewCollectionWithOptions(smokeSpec, kernelCollectionOptions(nil))
			if err != nil {
				t.Fatalf("load embedded %s collection into kernel: %v", tc.name, err)
			}
			coll.Close()
		})
	}
}
