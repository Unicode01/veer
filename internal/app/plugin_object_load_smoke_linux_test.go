//go:build linux

package app

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Bundled plugins' XDP objects, relative to the repository root, and the
// section of the program the plugin hooks into the dispatcher.
// scripts/verify-kernel-load-matrix.py copies these files into its guests.
var bundledXDPPluginObjects = []struct {
	plugin, object, section string
}{
	{"firewall", "plugins/firewall/firewall.o", "xdp/veer/firewall"},
}

// TestLoadBundledPluginObjectsSmoke loads each bundled XDP plugin object the
// way the XDP plugin runtime does (loadKernelXDPPluginObject): the verified
// spec, the dispatcher's program chain in place of the object's own, the
// runtime's collection options. Then one frame runs through the program: with
// its maps still empty a plugin must hand the packet on, and the dispatcher's
// continue slot passes it. A verifier rejection fails here first, instead of
// when a user binds the plugin. scripts/verify-kernel-load-matrix.py runs it
// on every pinned distribution kernel.
//
//	FORWARD_RUN_KERNEL_LOAD_SMOKE=1 go test ./internal/app -run TestLoadBundledPluginObjectsSmoke -count=1 -v
func TestLoadBundledPluginObjectsSmoke(t *testing.T) {
	if os.Getenv(kernelLoadSmokeEnableEnv) != "1" {
		t.Skipf("set %s=1 to run the bundled plugin object load smoke", kernelLoadSmokeEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	root := findRepoRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Logf("memlock auto-raise unavailable: %v (%s)", err, kernelMemlockStatus())
	}
	dispatcher, err := loadKernelXDPPluginDispatcher()
	if err != nil {
		t.Fatalf("load xdp plugin dispatcher: %+v", err)
	}
	defer dispatcher.Close()
	pieces, err := kernelXDPPluginCollectionPieces(dispatcher)
	if err != nil {
		t.Fatal(err)
	}

	for _, object := range bundledXDPPluginObjects {
		object := object
		t.Run(object.plugin, func(t *testing.T) {
			path := filepath.Join(root, filepath.FromSlash(object.object))
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s is not built (scripts/build-plugin-ebpf.sh): %v", object.object, err)
			}
			spec, err := loadVerifiedPluginObjectCollectionSpec(path, fmt.Sprintf("%x", sha256.Sum256(data)))
			if err != nil {
				t.Fatalf("load spec: %v", err)
			}
			chain := spec.Maps[kernelXDPPluginProgramChainMapName]
			if chain == nil || chain.Type != ebpf.ProgramArray || chain.MaxEntries < kernelXDPPluginProgramChainMaxEntries {
				t.Fatalf("object does not declare %s as a program array of at least %d entries", kernelXDPPluginProgramChainMapName, kernelXDPPluginProgramChainMaxEntries)
			}
			programName := ""
			for name, program := range spec.Programs {
				if program.SectionName == object.section {
					programName = name
				}
			}
			if programName == "" || spec.Programs[programName].Type != ebpf.XDP {
				t.Fatalf("object has no XDP program in section %s", object.section)
			}
			coll, err := ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(map[string]*ebpf.Map{
				kernelXDPPluginProgramChainMapName: pieces.progChain,
			}))
			if err != nil {
				logKernelVerifierDetails(err)
				t.Fatalf("load %s into kernel %s: %+v", object.object, kernelRelease(), err)
			}
			defer coll.Close()

			ret, err := coll.Programs[programName].Run(&ebpf.RunOptions{Data: bundledPluginSmokeFrame()})
			if err != nil {
				t.Fatalf("run %s: %v", programName, err)
			}
			if ret != 2 { // XDP_PASS
				t.Fatalf("%s returned %d for a frame with empty maps, want XDP_PASS", programName, ret)
			}
		})
	}
}

// bundledPluginSmokeFrame is an Ethernet/IPv4/TCP SYN to port 22.
func bundledPluginSmokeFrame() []byte {
	frame := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(frame[12:], 0x0800)
	ip := frame[14:]
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:], 40)
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{198, 51, 100, 1})
	tcp := frame[34:]
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 22)
	tcp[12], tcp[13] = 5<<4, 0x02
	return frame
}
