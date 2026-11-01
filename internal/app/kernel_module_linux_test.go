//go:build linux && veer_kfuncs

package app

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeKernelModule struct {
	present                bool
	id                     kernelModuleIdentity
	loads, unloads, probes int
	probeErr               error
	busy                   int
}

func (f *fakeKernelModule) system() kernelModuleSystem {
	return kernelModuleSystem{
		identity: func() (kernelModuleIdentity, error) {
			if !f.present {
				return kernelModuleIdentity{}, os.ErrNotExist
			}
			return f.id, nil
		},
		load: func() error { f.present = true; f.loads++; return nil },
		unload: func() error {
			f.unloads++
			if f.busy > 0 {
				f.busy--
				return unix.EBUSY
			}
			f.present = false
			return nil
		},
		probe: func() error { f.probes++; return f.probeErr },
	}
}
func TestOptionalKernelModuleLifecycle(t *testing.T) {
	t.Run("owned normal stop and idempotence", func(t *testing.T) {
		f := fakeKernelModule{id: kernelModuleIdentity{"boot", 1}, busy: 1}
		close, err := manageOptionalKernelModule(t.TempDir(), f.system(), func() bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		if f.loads != 1 || f.probes != 1 {
			t.Fatalf("load/probe: %+v", f)
		}
		close()
		close()
		if f.present || f.unloads != 2 {
			t.Fatalf("cleanup: %+v", f)
		}
	})
	t.Run("hot restart successor and crash recovery ownership", func(t *testing.T) {
		dir := t.TempDir()
		f := fakeKernelModule{id: kernelModuleIdentity{"boot", 2}}
		close, err := manageOptionalKernelModule(dir, f.system(), func() bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		close()
		if !f.present || f.unloads != 0 {
			t.Fatal("hot restart unloaded module")
		}
		successor, err := manageOptionalKernelModule(dir, f.system(), func() bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		successor()
		if f.present || f.loads != 1 || f.unloads != 1 {
			t.Fatalf("successor: %+v", f)
		}
	})
	t.Run("simultaneous daemon leases", func(t *testing.T) {
		dir := t.TempDir()
		f := fakeKernelModule{id: kernelModuleIdentity{"boot", 3}}
		first, err := manageOptionalKernelModule(dir, f.system(), func() bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		second, err := manageOptionalKernelModule(dir, f.system(), func() bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		first()
		if !f.present || f.unloads != 0 {
			t.Fatal("active successor lost module")
		}
		second()
		if f.present || f.unloads != 1 {
			t.Fatalf("final lease: %+v", f)
		}
	})
	t.Run("externally loaded module", func(t *testing.T) {
		f := fakeKernelModule{present: true, id: kernelModuleIdentity{"boot", 4}}
		close, err := manageOptionalKernelModule(t.TempDir(), f.system(), func() bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		close()
		if !f.present || f.loads != 0 || f.unloads != 0 {
			t.Fatal("claimed an external module")
		}
	})
	t.Run("replaced module incarnation", func(t *testing.T) {
		f := fakeKernelModule{id: kernelModuleIdentity{"boot", 5}}
		close, err := manageOptionalKernelModule(t.TempDir(), f.system(), func() bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		f.id.Instance++
		close()
		if !f.present || f.unloads != 0 {
			t.Fatal("unloaded replacement")
		}
	})
	t.Run("failed ABI probe remains unavailable and cleans owned module", func(t *testing.T) {
		f := fakeKernelModule{id: kernelModuleIdentity{"boot", 6}, probeErr: errors.New("bad ABI")}
		close, err := manageOptionalKernelModule(t.TempDir(), f.system(), func() bool { return false })
		if err == nil {
			t.Fatal("accepted bad ABI")
		}
		close()
		if f.present || f.unloads != 1 {
			t.Fatalf("failed probe cleanup: %+v", f)
		}
	})
	t.Run("lock symlink is rejected", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "other")
		if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "lock")); err != nil {
			t.Fatal(err)
		}
		f := fakeKernelModule{}
		close, err := manageOptionalKernelModule(dir, f.system(), func() bool { return false })
		close()
		if err == nil || f.loads != 0 {
			t.Fatal("accepted symlink lock")
		}
	})
}

func TestOptionalKernelModuleActualAPI(t *testing.T) {
	if os.Getenv("VEER_RUN_KFUNCS_TESTS") != "1" {
		t.Skip("set VEER_RUN_KFUNCS_TESTS=1 with the matching module loaded")
	}
	if err := probeOptionalKernelModule(); err != nil {
		t.Fatal(err)
	}
	id, err := realKernelModuleIdentity()
	if err != nil || id.Instance == 0 {
		t.Fatalf("module identity: %+v %v", id, err)
	}
	if status := optionalKernelModuleFeatureStatus(); !status.Available {
		t.Fatalf("capability unavailable: %+v", status)
	}
	if status := optionalKernelModuleIngressFeatureStatus(); !status.Available {
		t.Fatalf("ingress capability unavailable: %+v", status)
	}
}
