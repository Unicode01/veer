//go:build linux && veer_kfuncs

package app

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

//go:embed ebpf/veer-kfuncs-probe-bpf.o
var kernelModuleProbeBytes []byte

//go:embed ebpf/veer-kfuncs-ingress-probe-bpf.o
var kernelModuleIngressProbeBytes []byte

const optionalKernelModuleName = "veer_kfuncs"
const optionalKernelModuleCompiled = true

func probeOptionalKernelModule() error {
	return probeKernelModuleHandoff(kernelModuleProbeBytes)
}

func probeKernelModuleHandoff(object []byte) error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	defer coll.Close()
	result, _, err := coll.Programs["veer_kfuncs_probe"].Test(make([]byte, 64))
	if err != nil {
		return err
	}
	if result != 1 {
		return fmt.Errorf("unsupported veer_kfuncs ABI %d", result)
	}
	return nil
}

var optionalKernelModuleProbe struct {
	sync.Mutex
	identity kernelModuleIdentity
	cached   bool
	status   PluginHostFeatureStatus
	ingress  PluginHostFeatureStatus
}

func optionalKernelModuleFeatureStatus() PluginHostFeatureStatus {
	optionalKernelModuleProbe.Lock()
	defer optionalKernelModuleProbe.Unlock()
	identity, err := realKernelModuleIdentity()
	if err != nil {
		return PluginHostFeatureStatus{Reason: "optional kernel module unavailable: " + err.Error()}
	}
	if !optionalKernelModuleProbe.cached || optionalKernelModuleProbe.identity != identity {
		err = probeOptionalKernelModule()
		optionalKernelModuleProbe.identity = identity
		optionalKernelModuleProbe.cached = true
		optionalKernelModuleProbe.status = PluginHostFeatureStatus{Available: err == nil}
		if err != nil {
			optionalKernelModuleProbe.status.Reason = "optional kernel module unavailable: " + err.Error()
		}
		optionalKernelModuleProbe.ingress = optionalKernelModuleProbe.status
		if err == nil {
			if err := probeKernelModuleHandoff(kernelModuleIngressProbeBytes); err != nil {
				optionalKernelModuleProbe.ingress = PluginHostFeatureStatus{Reason: "optional kernel ingress handoff unavailable: " + err.Error()}
			}
		}
	}
	return optionalKernelModuleProbe.status
}

func optionalKernelModuleIngressFeatureStatus() PluginHostFeatureStatus {
	if status := optionalKernelModuleFeatureStatus(); !status.Available {
		return status
	}
	optionalKernelModuleProbe.Lock()
	defer optionalKernelModuleProbe.Unlock()
	return optionalKernelModuleProbe.ingress
}

type kernelModuleIdentity struct {
	Boot     string `json:"boot"`
	Instance uint64 `json:"instance"`
}

type kernelModuleSystem struct {
	identity func() (kernelModuleIdentity, error)
	load     func() error
	unload   func() error
	probe    func() error
}

func realKernelModuleIdentity() (kernelModuleIdentity, error) {
	instance, err := os.ReadFile("/sys/module/" + optionalKernelModuleName + "/parameters/instance")
	if err != nil {
		return kernelModuleIdentity{}, err
	}
	nonce, err := strconv.ParseUint(strings.TrimSpace(string(instance)), 10, 64)
	if err != nil {
		return kernelModuleIdentity{}, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return kernelModuleIdentity{}, err
	}
	return kernelModuleIdentity{Boot: string(boot), Instance: nonce}, nil
}

func loadOptionalKernelModule() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var name unix.Utsname
	if err = unix.Uname(&name); err != nil {
		return err
	}
	release := unix.ByteSliceToString(name.Release[:])
	path := filepath.Join(filepath.Dir(exe), "kernel", release, optionalKernelModuleName+".ko")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open optional module: %w", err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0022 != 0 {
		return fmt.Errorf("optional module must be a root-owned regular file without group/world write permission")
	}
	if err = unix.FinitModule(fd, "", 0); err != nil {
		return fmt.Errorf("load optional module: %w", err)
	}
	return nil
}

func startOptionalKernelModule() (func(), error) {
	return manageOptionalKernelModule("/run/veer-kfuncs", kernelModuleSystem{
		identity: realKernelModuleIdentity, load: loadOptionalKernelModule,
		unload: func() error { return unix.DeleteModule(optionalKernelModuleName, unix.O_NONBLOCK) },
		probe:  probeOptionalKernelModule,
	}, kernelHotRestartRequested)
}

// Each daemon holds a shared lease. Only the last daemon may unload a module
// installed by Veer. A boot+random module-load identity marker survives daemon crashes,
// but never claims a module installed independently. BPF references are the
// final kernel-enforced lifetime protection; unload is NEVER forced.
func manageOptionalKernelModule(dir string, system kernelModuleSystem, preserve func() bool) (func(), error) {
	noop := func() {}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return noop, err
	}
	startupLock, err := lockKernelModuleInitialization(dir)
	if err != nil {
		return noop, err
	}
	defer startupLock.Close()
	fd, err := unix.Open(filepath.Join(dir, "lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return noop, err
	}
	lock := os.NewFile(uintptr(fd), "kernel module lease")
	if err = unix.Flock(fd, unix.LOCK_SH); err != nil {
		lock.Close()
		return noop, err
	}
	marker := filepath.Join(dir, "owner.json")
	_, err = system.identity()
	if errors.Is(err, os.ErrNotExist) {
		if err = system.load(); err == nil {
			var id kernelModuleIdentity
			id, err = system.identity()
			if err == nil {
				data, _ := json.Marshal(id)
				err = os.WriteFile(marker, data, 0600)
			}
		}
	}

	if err == nil {
		err = system.probe()
	}
	// Keep a lease even when the ABI probe fails. This prevents another Veer
	// daemon from unloading an inherited module during an upgrade decision.
	if flockErr := unix.Flock(fd, unix.LOCK_SH); flockErr != nil {
		lock.Close()
		return noop, flockErr
	}
	var once sync.Once
	close := func() {
		once.Do(func() {
			defer lock.Close()
			initializationLock, lockErr := lockKernelModuleInitialization(dir)
			if lockErr != nil {
				return
			}
			defer initializationLock.Close()
			if preserve() {
				return
			}
			// flock conversion is deliberately nonblocking: a successor may have
			// acquired a lease, in which case it owns the eventual cleanup.
			if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
				return
			}
			data, readErr := os.ReadFile(marker)
			var owner kernelModuleIdentity
			if readErr != nil || json.Unmarshal(data, &owner) != nil {
				return
			}
			current, identityErr := system.identity()
			if identityErr != nil || owner != current {
				return
			}
			// Closing BPF FDs can release module references after an RCU grace
			// period. Retry a bounded interval without ever forcing detach.
			var unloadErr error
			for attempt := 0; attempt < 30; attempt++ {
				unloadErr = system.unload()
				if unloadErr == nil || (!errors.Is(unloadErr, unix.EBUSY) && !errors.Is(unloadErr, unix.EWOULDBLOCK)) {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if unloadErr == nil {
				_ = os.Remove(marker)
			} else {
				log.Printf("optional kernel module retained (live BPF/session references or unload denied): %v", unloadErr)
			}
		})
	}
	if err == nil {
		log.Printf("optional kernel module: handoff ABI v1 ready")
	}
	return close, err
}

// Startup and final cleanup serialize briefly on a separate mutex. The shared
// daemon lease must never serve as the startup mutex: an unavailable module
// would otherwise block a second daemon for the first daemon's whole lifetime.
func lockKernelModuleInitialization(dir string) (*os.File, error) {
	fd, err := unix.Open(filepath.Join(dir, "init.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "kernel module initialization")
	if err = unix.Flock(fd, unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
