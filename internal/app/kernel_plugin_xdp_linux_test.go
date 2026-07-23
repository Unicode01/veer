//go:build linux

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const kernelXDPPluginTestEnv = "VEER_RUN_XDP_PLUGIN_TESTS"

func BenchmarkKernelXDPPluginChain(b *testing.B) {
	if os.Getenv("VEER_RUN_XDP_PLUGIN_BENCH") != "1" {
		b.Skip("set VEER_RUN_XDP_PLUGIN_BENCH=1 to run the privileged XDP plugin benchmark")
	}
	if os.Geteuid() != 0 {
		b.Skip("root privileges are required")
	}
	dispatcher, err := loadKernelXDPPluginDispatcher()
	if err != nil {
		b.Fatal(err)
	}
	defer dispatcher.Close()
	pieces, err := kernelXDPPluginCollectionPieces(dispatcher)
	if err != nil {
		b.Fatal(err)
	}
	plain, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "xdp_plain_pass",
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 2),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		b.Fatal(err)
	}
	defer plain.Close()
	noopObject := compileKernelXDPNoopBenchmarkObject(b)
	noopSpec, err := ebpf.LoadCollectionSpec(noopObject)
	if err != nil {
		b.Fatal(err)
	}
	noopCollection, err := ebpf.NewCollectionWithOptions(noopSpec, kernelCollectionOptions(map[string]*ebpf.Map{
		kernelXDPPluginProgramChainMapName: pieces.progChain,
	}))
	if err != nil {
		b.Fatal(err)
	}
	defer noopCollection.Close()
	continuing := noopCollection.Programs["xdp_chain_noop"]
	if continuing == nil {
		b.Fatal("xdp benchmark no-op program is missing")
	}
	packet := make([]byte, 64)
	packet[12], packet[13] = 0x08, 0x00

	run := func(b *testing.B, program *ebpf.Program) {
		b.Helper()
		b.ReportAllocs()
		b.ResetTimer()
		result, err := program.Run(&ebpf.RunOptions{Data: packet, Repeat: uint32(b.N)})
		if err != nil {
			b.Fatal(err)
		}
		if result != 2 {
			b.Fatalf("xdp benchmark result = %d, want XDP_PASS", result)
		}
	}
	b.Run("plain_pass", func(b *testing.B) { run(b, plain) })
	for _, count := range []int{0, 1, 2, 4, 8} {
		count := count
		b.Run(fmt.Sprintf("dispatcher_%d_plugins", count), func(b *testing.B) {
			if err := clearKernelXDPPluginBank(pieces, 0); err != nil {
				b.Fatal(err)
			}
			for i := 0; i < count; i++ {
				if err := pieces.progChain.Put(uint32(kernelXDPPluginBank0Base+i), uint32(continuing.FD())); err != nil {
					b.Fatal(err)
				}
			}
			mask := uint32(0)
			if count > 0 {
				mask = (uint32(1) << uint32(count)) - 1
			}
			if err := pieces.config.Put(uint32(0), kernelXDPPluginConfig{Count: uint32(count), ActiveBank: 0, GlobalMask: mask}); err != nil {
				b.Fatal(err)
			}
			run(b, pieces.dispatcher)
		})
	}
}

func compileKernelXDPNoopBenchmarkObject(b *testing.B) string {
	b.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		b.Skipf("clang unavailable: %v", err)
	}
	dir := b.TempDir()
	sourcePath := filepath.Join(dir, "xdp_noop.c")
	objectPath := filepath.Join(dir, "xdp_noop.o")
	source := `
#define SEC(name) __attribute__((section(name), used))
typedef unsigned int __u32;
struct xdp_md;
struct bpf_map_def { __u32 type, key_size, value_size, max_entries, map_flags; };
struct bpf_map_def SEC("maps") xdp_prog_chain = {3, sizeof(__u32), sizeof(__u32), 24, 0};
static void (*bpf_tail_call)(void *, void *, __u32) = (void *)12;
SEC("xdp/noop") int xdp_chain_noop(struct xdp_md *ctx) {
  bpf_tail_call(ctx, &xdp_prog_chain, 7);
  return 0;
}
char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		b.Fatal(err)
	}
	cmd := exec.Command(clang, "-O2", "-target", "bpf", "-D__TARGET_ARCH_"+testBPFTargetArch(), "-c", sourcePath, "-o", objectPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		b.Skipf("compile xdp benchmark object: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return objectPath
}

func TestNormalizeKernelXDPPluginStage(t *testing.T) {
	for _, test := range []struct {
		stage    string
		priority int
		wantErr  bool
	}{
		{stage: "pre_forward", priority: 100},
		{stage: "forward", priority: pluginPipelineCorePriority - 1},
		{stage: "forward", priority: pluginPipelineCorePriority, wantErr: true},
		{stage: "post_lookup", priority: 10, wantErr: true},
		{stage: "reply", priority: 10, wantErr: true},
	} {
		stage, err := normalizeKernelXDPPluginStage(test.stage, test.priority)
		if test.wantErr {
			if err == nil {
				t.Fatalf("normalizeKernelXDPPluginStage(%q,%d) = %q, want error", test.stage, test.priority, stage)
			}
			continue
		}
		if err != nil || stage != kernelPluginPipelineStagePreForward {
			t.Fatalf("normalizeKernelXDPPluginStage(%q,%d) = %q,%v", test.stage, test.priority, stage, err)
		}
	}
}

func TestEmbeddedKernelXDPPluginDispatcherSpec(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedPluginXDPDispatcherObject))
	if err != nil {
		t.Fatalf("load embedded xdp plugin dispatcher: %v", err)
	}
	if err := validateKernelXDPPluginDispatcherSpec(spec); err != nil {
		t.Fatalf("validate embedded xdp plugin dispatcher: %v", err)
	}
}

func TestKernelXDPPluginCanPreserveDesiredRequiresSameHookTopology(t *testing.T) {
	base := []kernelXDPPluginDesiredPlugin{{
		plugin: LoadedPlugin{PluginManifest: PluginManifest{ID: "firewall"}},
		hooks: []kernelXDPPluginHookPlan{{
			PluginID: "firewall", HookID: "ingress", ObjectID: "filter", Stage: "pre_forward", Mode: "drop",
			Priority: 10, Interfaces: []string{"eth0"}, InterfaceIndexes: []uint32{2},
		}},
	}}
	unchanged := cloneKernelXDPPluginDesired(base)
	unchanged[0].hooks[0].ObjectSHA256 = strings.Repeat("a", 64)
	if !kernelXDPPluginCanPreserveDesired(base, unchanged) {
		t.Fatal("object-only update should be allowed to preserve the previous chain on failure")
	}
	if kernelXDPPluginCanPreserveDesired(base, nil) {
		t.Fatal("plugin removal must not preserve the previous chain")
	}
	changedScope := cloneKernelXDPPluginDesired(base)
	changedScope[0].hooks[0].Interfaces = []string{"eth1"}
	changedScope[0].hooks[0].InterfaceIndexes = []uint32{3}
	if kernelXDPPluginCanPreserveDesired(base, changedScope) {
		t.Fatal("interface scope change must not preserve the previous chain")
	}
	changedMode := cloneKernelXDPPluginDesired(base)
	changedMode[0].hooks[0].Mode = "observe"
	if kernelXDPPluginCanPreserveDesired(base, changedMode) {
		t.Fatal("mode change must not preserve the previous chain")
	}
}

func TestKernelXDPPluginPipelineChainHotUpdateAndConflict(t *testing.T) {
	if os.Getenv(kernelXDPPluginTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged XDP plugin pipeline test", kernelXDPPluginTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	stateRoot := t.TempDir()
	t.Setenv(veerRuntimeStateDirEnv, stateRoot)
	pluginDir := t.TempDir()
	objectPath := compileKernelXDPPluginTestObject(t, pluginDir)

	suffix := fmt.Sprintf("%04x", uint16(time.Now().UnixNano()))
	targetName := "vxp" + suffix
	peerName := "vyp" + suffix
	if len(targetName) > linuxInterfaceNameMaxBytes || len(peerName) > linuxInterfaceNameMaxBytes {
		t.Fatalf("test interface names are too long: %s %s", targetName, peerName)
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: targetName}, PeerName: peerName}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("create xdp test veth: %v", err)
	}
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(targetName); err == nil {
			_ = netlink.LinkDel(link)
		}
	})
	target, err := netlink.LinkByName(targetName)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(target); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		t.Fatal(err)
	}

	plugin := kernelXDPPluginTestPlugin(t, pluginDir, objectPath, targetName)
	enabled := true
	cfg := &Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		Experimental: map[string]bool{
			experimentalFeatureXDPGeneric: true,
		},
	}
	runtime := newKernelXDPPluginPipelineRuntime(cfg)
	t.Cleanup(func() { _ = runtime.Close() })
	catalog := PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}}

	snapshot := runtime.Reconcile(catalog)
	state := snapshot.Plugins[plugin.ID]
	if state.Error != "" || !state.Attached || state.AttachmentCount != 2 {
		t.Fatalf("initial xdp plugin state = %+v", state)
	}
	if !xdpAttachmentExists(runtime.attachments[0], runtime.programID) {
		t.Fatal("xdp plugin dispatcher is not attached after reconcile")
	}

	frame := kernelXDPPluginTestFrame(target.Attrs().HardwareAddr, peer.Attrs().HardwareAddr, 1)
	if err := sendAndReceiveKernelXDPPluginTestFrame(peer.Attrs().Index, target.Attrs().Index, frame); err != nil {
		t.Fatalf("first xdp plugin packet did not pass: %v", err)
	}
	_, secondBeforeUpdate := waitKernelXDPPluginCountersAtLeast(t, runtime, plugin.ID, 1, 1)

	firstProgramID := runtime.programID
	secondDispatcher, err := loadKernelXDPPluginDispatcher()
	if err != nil {
		t.Fatalf("load conflicting dispatcher: %v", err)
	}
	defer secondDispatcher.Close()
	secondPieces, err := kernelXDPPluginCollectionPieces(secondDispatcher)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attachKernelXDPPluginDispatcher(target.Attrs().Index, secondPieces.dispatcher, true); err == nil || !strings.Contains(err.Error(), "already has xdp program") {
		t.Fatalf("conflicting dispatcher attach error = %v", err)
	}
	if !xdpAttachmentExists(runtime.attachments[0], firstProgramID) {
		t.Fatal("conflict probe replaced the active xdp plugin dispatcher")
	}

	plugin.Hooks = plugin.Hooks[:1]
	catalog.Plugins[1] = plugin
	snapshot = runtime.Reconcile(catalog)
	state = snapshot.Plugins[plugin.ID]
	if state.Error != "" || !state.Attached || state.AttachmentCount != 1 {
		t.Fatalf("updated xdp plugin state = %+v", state)
	}
	if runtime.programID != firstProgramID {
		t.Fatalf("dispatcher program id changed across chain-only update: %d -> %d", firstProgramID, runtime.programID)
	}
	firstBeforeSend := kernelXDPPluginCounter(t, runtime, plugin.ID, 0)
	secondAfterUpdate := kernelXDPPluginCounter(t, runtime, plugin.ID, 1)
	if secondAfterUpdate < secondBeforeUpdate {
		t.Fatalf("preserved second counter regressed during hot update: %d -> %d", secondBeforeUpdate, secondAfterUpdate)
	}
	frame = kernelXDPPluginTestFrame(target.Attrs().HardwareAddr, peer.Attrs().HardwareAddr, 2)
	if err := sendAndReceiveKernelXDPPluginTestFrame(peer.Attrs().Index, target.Attrs().Index, frame); err != nil {
		t.Fatalf("updated xdp plugin packet did not pass: %v", err)
	}
	waitKernelXDPPluginCounterAdvance(t, runtime, plugin.ID, firstBeforeSend, secondAfterUpdate)

	oldIfIndex := target.Attrs().Index
	if err := netlink.LinkDel(target); err != nil {
		t.Fatalf("delete xdp test veth: %v", err)
	}
	if err := runtime.Maintain(); err == nil {
		t.Fatal("xdp plugin runtime reported healthy after its interface disappeared")
	}
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: targetName}, PeerName: peerName}); err != nil {
		t.Fatalf("recreate xdp test veth: %v", err)
	}
	target, err = netlink.LinkByName(targetName)
	if err != nil {
		t.Fatal(err)
	}
	peer, err = netlink.LinkByName(peerName)
	if err != nil {
		t.Fatal(err)
	}
	if target.Attrs().Index == oldIfIndex {
		t.Fatalf("recreated interface reused ifindex %d; test cannot prove identity recovery", oldIfIndex)
	}
	if err := netlink.LinkSetUp(target); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		t.Fatal(err)
	}
	snapshot = runtime.Reconcile(catalog)
	state = snapshot.Plugins[plugin.ID]
	if state.Error != "" || !state.Attached || state.AttachmentCount != 1 {
		t.Fatalf("xdp plugin state after interface recreation = %+v", state)
	}
	if len(runtime.attachments) != 1 || runtime.attachments[0].ifindex != target.Attrs().Index || !xdpAttachmentExists(runtime.attachments[0], runtime.programID) {
		t.Fatalf("xdp plugin attachment did not move to recreated interface: %+v", runtime.attachments)
	}
	firstBeforeSend = kernelXDPPluginCounter(t, runtime, plugin.ID, 0)
	secondAfterUpdate = kernelXDPPluginCounter(t, runtime, plugin.ID, 1)
	frame = kernelXDPPluginTestFrame(target.Attrs().HardwareAddr, peer.Attrs().HardwareAddr, 3)
	if err := sendAndReceiveKernelXDPPluginTestFrame(peer.Attrs().Index, target.Attrs().Index, frame); err != nil {
		t.Fatalf("recreated-interface xdp plugin packet did not pass: %v", err)
	}
	waitKernelXDPPluginCounterAdvance(t, runtime, plugin.ID, firstBeforeSend, secondAfterUpdate)

	if err := runtime.Close(); err != nil {
		t.Fatalf("close xdp plugin runtime: %v", err)
	}
	target, err = netlink.LinkByName(targetName)
	if err != nil {
		t.Fatal(err)
	}
	if target.Attrs().Xdp != nil && target.Attrs().Xdp.Attached {
		t.Fatalf("xdp dispatcher remained attached after close: %+v", target.Attrs().Xdp)
	}
}

func TestKernelXDPPluginPipelineRecoversOrphanAfterSIGKILL(t *testing.T) {
	if os.Getenv(kernelXDPPluginTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged XDP plugin recovery test", kernelXDPPluginTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	stateRoot := t.TempDir()
	t.Setenv(veerRuntimeStateDirEnv, stateRoot)
	pluginDir := t.TempDir()
	objectPath := compileKernelXDPPluginTestObject(t, pluginDir)
	suffix := fmt.Sprintf("%04x", uint16(time.Now().UnixNano()))
	targetName := "vxr" + suffix
	peerName := "vyr" + suffix
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: targetName}, PeerName: peerName}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("create xdp recovery veth: %v", err)
	}
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(targetName); err == nil {
			_ = netlink.LinkDel(link)
		}
	})
	target, _ := netlink.LinkByName(targetName)
	peer, _ := netlink.LinkByName(peerName)
	if target == nil || peer == nil {
		t.Fatal("recovery veth pair was not created")
	}
	if err := netlink.LinkSetUp(target); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		t.Fatal(err)
	}

	readyPath := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestKernelXDPPluginCrashHelper$", "-test.v")
	cmd.Env = append(os.Environ(),
		"VEER_XDP_PLUGIN_CRASH_HELPER=1",
		"VEER_XDP_PLUGIN_TEST_ROOT="+pluginDir,
		"VEER_XDP_PLUGIN_TEST_OBJECT="+objectPath,
		"VEER_XDP_PLUGIN_TEST_INTERFACE="+targetName,
		"VEER_XDP_PLUGIN_TEST_READY="+readyPath,
		veerRuntimeStateDirEnv+"="+stateRoot,
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			t.Fatal("xdp plugin crash helper did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	target, err := netlink.LinkByName(targetName)
	if err != nil || target.Attrs().Xdp == nil || !target.Attrs().Xdp.Attached {
		t.Fatalf("helper xdp attachment = %+v err=%v", target, err)
	}
	orphanProgramID := target.Attrs().Xdp.ProgId
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = cmd.Process.Wait()
	target, err = netlink.LinkByName(targetName)
	if err != nil || target.Attrs().Xdp == nil || !target.Attrs().Xdp.Attached || target.Attrs().Xdp.ProgId != orphanProgramID {
		t.Fatalf("xdp attachment did not survive SIGKILL: xdp=%+v err=%v", target.Attrs().Xdp, err)
	}

	plugin := kernelXDPPluginTestPlugin(t, pluginDir, objectPath, targetName)
	enabled := true
	cfg := &Config{PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled, Experimental: map[string]bool{experimentalFeatureXDPGeneric: true}}
	runtime := newKernelXDPPluginPipelineRuntime(cfg)
	snapshot := runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
	if state := snapshot.Plugins[plugin.ID]; state.Error != "" || !state.Attached {
		_ = runtime.Close()
		t.Fatalf("recovered xdp plugin state = %+v", state)
	}
	if runtime.programID == 0 || !xdpAttachmentExists(runtime.attachments[0], runtime.programID) {
		_ = runtime.Close()
		t.Fatal("replacement xdp plugin dispatcher is not attached")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOrderedKernelRuntimeChainsXDPIntoTCPlugin(t *testing.T) {
	if os.Getenv(kernelXDPPluginTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged XDP-to-TC plugin test", kernelXDPPluginTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	t.Setenv(veerRuntimeStateDirEnv, t.TempDir())
	pluginDir := t.TempDir()
	xdpObject := compileKernelXDPPluginTestObject(t, pluginDir)
	tcObject := compileKernelTCPluginTestObject(t, pluginDir)
	suffix := fmt.Sprintf("%04x", uint16(time.Now().UnixNano()))
	targetName := "vxc" + suffix
	peerName := "vyc" + suffix
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: targetName}, PeerName: peerName}); err != nil {
		t.Skipf("create xdp-to-tc test veth: %v", err)
	}
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(targetName); err == nil {
			_ = netlink.LinkDel(link)
		}
	})
	target, _ := netlink.LinkByName(targetName)
	peer, _ := netlink.LinkByName(peerName)
	if target == nil || peer == nil {
		t.Fatal("xdp-to-tc veth pair was not created")
	}
	if err := netlink.LinkSetUp(target); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		t.Fatal(err)
	}

	plugin := kernelXDPAndTCPluginTestPlugin(t, pluginDir, xdpObject, tcObject, targetName)
	enabled := true
	cfg := &Config{PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled, Experimental: map[string]bool{experimentalFeatureXDPGeneric: true}}
	runtime, ok := newOrderedKernelRuleRuntime([]string{kernelEngineXDP, kernelEngineTC}, cfg).(*orderedKernelRuleRuntime)
	if !ok {
		t.Fatal("ordered kernel runtime was not created")
	}
	t.Cleanup(func() { _ = runtime.Close() })
	catalog := PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}}
	if results, err := runtime.ReconcileWithPluginCatalog(nil, catalog); err != nil || len(results) != 0 {
		t.Fatalf("reconcile xdp-to-tc plugin chain: results=%+v err=%v", results, err)
	}
	snapshot := runtime.PluginSnapshot()
	state := snapshot.Plugins[plugin.ID]
	if state.Error != "" || !state.Attached || state.AttachmentCount != 2 {
		t.Fatalf("combined xdp-to-tc plugin state = %+v", state)
	}
	engines := map[string]bool{}
	for _, attachment := range state.Attachments {
		engines[attachment.Engine] = true
	}
	if !engines[kernelEngineXDP] || !engines[kernelEngineTC] {
		t.Fatalf("combined xdp-to-tc attachments = %+v", state.Attachments)
	}

	frame := kernelXDPPluginTestFrame(target.Attrs().HardwareAddr, peer.Attrs().HardwareAddr, 4)
	if err := sendAndReceiveKernelXDPPluginTestFrame(peer.Attrs().Index, target.Attrs().Index, frame); err != nil {
		t.Fatalf("xdp-to-tc packet did not pass: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		xdpCount := orderedKernelPluginCounter(t, runtime, plugin.ID, "xdp_chain", "counters")
		tcCount := orderedKernelPluginCounter(t, runtime, plugin.ID, "tc_chain", "tc_counters")
		if xdpCount > 0 && tcCount > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("xdp-to-tc counters = xdp:%d tc:%d", xdpCount, tcCount)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	target, err := netlink.LinkByName(targetName)
	if err != nil {
		t.Fatal(err)
	}
	if target.Attrs().Xdp != nil && target.Attrs().Xdp.Attached {
		t.Fatalf("xdp program remained after combined runtime close: %+v", target.Attrs().Xdp)
	}
	filters, err := netlink.FilterList(target, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatal(err)
	}
	for _, filter := range filters {
		if bpf, ok := filter.(*netlink.BpfFilter); ok && strings.HasPrefix(bpf.Name, "veer") {
			t.Fatalf("Veer TC filter remained after combined runtime close: %+v", bpf)
		}
	}
}

func TestKernelXDPPluginCrashHelper(t *testing.T) {
	if os.Getenv("VEER_XDP_PLUGIN_CRASH_HELPER") != "1" {
		t.Skip("helper process only")
	}
	root := os.Getenv("VEER_XDP_PLUGIN_TEST_ROOT")
	objectPath := os.Getenv("VEER_XDP_PLUGIN_TEST_OBJECT")
	interfaceName := os.Getenv("VEER_XDP_PLUGIN_TEST_INTERFACE")
	readyPath := os.Getenv("VEER_XDP_PLUGIN_TEST_READY")
	plugin := kernelXDPPluginTestPlugin(t, root, objectPath, interfaceName)
	enabled := true
	cfg := &Config{PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled, Experimental: map[string]bool{experimentalFeatureXDPGeneric: true}}
	runtime := newKernelXDPPluginPipelineRuntime(cfg)
	snapshot := runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
	if state := snapshot.Plugins[plugin.ID]; state.Error != "" || !state.Attached {
		t.Fatalf("helper xdp plugin state = %+v", state)
	}
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {}
}

func compileKernelXDPPluginTestObject(t *testing.T, dir string) string {
	t.Helper()
	sourcePath := filepath.Join(dir, "xdp_chain.bpf.c")
	objectPath := filepath.Join(dir, "xdp_chain.o")
	source := `
#define SEC(name) __attribute__((section(name), used))
typedef unsigned int __u32;
typedef unsigned long long __u64;
struct xdp_md;
struct bpf_map_def { __u32 type, key_size, value_size, max_entries, map_flags; };
struct bpf_map_def SEC("maps") xdp_prog_chain = {3, sizeof(__u32), sizeof(__u32), 24, 0};
struct bpf_map_def SEC("maps") counters = {2, sizeof(__u32), sizeof(__u64), 2, 0};
static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static void (*bpf_tail_call)(void *, void *, __u32) = (void *)12;
static __inline int observe(struct xdp_md *ctx, __u32 key) {
  __u64 *value = bpf_map_lookup_elem(&counters, &key);
  if (value) __sync_fetch_and_add(value, 1);
  bpf_tail_call(ctx, &xdp_prog_chain, 7);
  return 0;
}
SEC("xdp/first") int xdp_first(struct xdp_md *ctx) { return observe(ctx, 0); }
SEC("xdp/second") int xdp_second(struct xdp_md *ctx) { return observe(ctx, 1); }
char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	compileBPFObjectFromSource(t, sourcePath, objectPath)
	return objectPath
}

func compileKernelTCPluginTestObject(t *testing.T, dir string) string {
	t.Helper()
	sourcePath := filepath.Join(dir, "tc_chain.bpf.c")
	objectPath := filepath.Join(dir, "tc_chain.o")
	source := `
#define SEC(name) __attribute__((section(name), used))
typedef unsigned int __u32;
typedef unsigned long long __u64;
struct __sk_buff;
struct bpf_map_def { __u32 type, key_size, value_size, max_entries, map_flags; };
struct bpf_map_def SEC("maps") tc_prog_chain_v4 = {3, sizeof(__u32), sizeof(__u32), 111, 0};
struct bpf_map_def SEC("maps") tc_counters = {2, sizeof(__u32), sizeof(__u64), 1, 0};
static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static void (*bpf_tail_call)(void *, void *, __u32) = (void *)12;
SEC("tc/first") int tc_first(struct __sk_buff *skb) {
  __u32 key = 0;
  __u64 *value = bpf_map_lookup_elem(&tc_counters, &key);
  if (value) __sync_fetch_and_add(value, 1);
  bpf_tail_call(skb, &tc_prog_chain_v4, 8);
  return 2;
}
char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	compileBPFObjectFromSource(t, sourcePath, objectPath)
	return objectPath
}

func kernelXDPPluginTestPlugin(t *testing.T, root, objectPath, interfaceName string) LoadedPlugin {
	t.Helper()
	data, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "xdp_chain_test",
			Name:      "XDP Chain Test",
			Version:   "1.0.0",
			Kind:      "pipeline",
			Stability: pluginStabilityLab,
		},
		Objects: []PluginObject{{
			ID:             "chain",
			Path:           filepath.Base(objectPath),
			ResolvedSHA256: fmt.Sprintf("%x", sum[:]),
			Status:         pluginObjectStatusVerified,
			Programs: []PluginObjectProgram{
				{ID: "xdp_first", Section: "xdp/first", Type: kernelEngineXDP},
				{ID: "xdp_second", Section: "xdp/second", Type: kernelEngineXDP},
			},
			StateMaps: []PluginObjectStateMap{{Name: "counters", Policy: pluginObjectMapPreserve, SchemaVersion: 1}},
		}},
		Hooks: []PluginHook{
			{ID: "first", Engine: kernelEngineXDP, Attach: "ingress", Stage: "pre_forward", Priority: 10, Program: "chain:xdp_first", Mode: "observe", Interfaces: []string{interfaceName}},
			{ID: "second", Engine: kernelEngineXDP, Attach: "ingress", Stage: "pre_forward", Priority: 20, Program: "chain:xdp_second", Mode: "observe", Interfaces: []string{interfaceName}},
		},
		Status:  pluginStatusActive,
		rootDir: root,
	}
}

func kernelXDPAndTCPluginTestPlugin(t *testing.T, root, xdpObjectPath, tcObjectPath, interfaceName string) LoadedPlugin {
	t.Helper()
	plugin := kernelXDPPluginTestPlugin(t, root, xdpObjectPath, interfaceName)
	plugin.ID = "xdp_tc_chain_test"
	plugin.Name = "XDP TC Chain Test"
	plugin.Objects[0].ID = "xdp_chain"
	for i := range plugin.Hooks {
		plugin.Hooks[i].Program = strings.Replace(plugin.Hooks[i].Program, "chain:", "xdp_chain:", 1)
	}
	plugin.Hooks = plugin.Hooks[:1]
	data, err := os.ReadFile(tcObjectPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	plugin.Objects = append(plugin.Objects, PluginObject{
		ID:             "tc_chain",
		Path:           filepath.Base(tcObjectPath),
		ResolvedSHA256: fmt.Sprintf("%x", sum[:]),
		Status:         pluginObjectStatusVerified,
		Programs:       []PluginObjectProgram{{ID: "tc_first", Section: "tc/first", Type: kernelEngineTC}},
		StateMaps:      []PluginObjectStateMap{{Name: "tc_counters", Policy: pluginObjectMapPreserve, SchemaVersion: 1}},
	})
	plugin.Hooks = append(plugin.Hooks, PluginHook{
		ID: "tc_first", Engine: kernelEngineTC, Attach: "ingress", Stage: "pre_forward", Priority: 20,
		Program: "tc_chain:tc_first", Mode: "observe", Interfaces: []string{interfaceName},
	})
	return plugin
}

func kernelXDPPluginTestFrame(dst, src []byte, marker byte) []byte {
	frame := make([]byte, 64)
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	frame[12] = 0x08
	frame[13] = 0x00
	frame[14] = marker
	return frame
}

func sendAndReceiveKernelXDPPluginTestFrame(sendIfIndex, receiveIfIndex int, frame []byte) error {
	receiveFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htonsUnix(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(receiveFD)
	if err := unix.Bind(receiveFD, &unix.SockaddrLinklayer{Protocol: htonsUnix(unix.ETH_P_ALL), Ifindex: receiveIfIndex}); err != nil {
		return err
	}
	if err := unix.SetsockoptTimeval(receiveFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
		return err
	}
	sendFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htonsUnix(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(sendFD)
	var addr [8]byte
	copy(addr[:], frame[:6])
	if err := unix.Sendto(sendFD, frame, 0, &unix.SockaddrLinklayer{Protocol: htonsUnix(unix.ETH_P_ALL), Ifindex: sendIfIndex, Halen: 6, Addr: addr}); err != nil {
		return err
	}
	buffer := make([]byte, 2048)
	for {
		n, _, err := unix.Recvfrom(receiveFD, buffer, 0)
		if err != nil {
			return err
		}
		if n >= len(frame) && buffer[14] == frame[14] {
			return nil
		}
	}
}

func waitKernelXDPPluginCountersAtLeast(t *testing.T, runtime *kernelXDPPluginPipelineRuntime, pluginID string, first, second uint64) (uint64, uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		gotFirst := kernelXDPPluginCounter(t, runtime, pluginID, 0)
		gotSecond := kernelXDPPluginCounter(t, runtime, pluginID, 1)
		if gotFirst >= first && gotSecond >= second {
			return gotFirst, gotSecond
		}
		if time.Now().After(deadline) {
			t.Fatalf("xdp plugin counters = %d,%d, want at least %d,%d", gotFirst, gotSecond, first, second)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitKernelXDPPluginCounterAdvance(t *testing.T, runtime *kernelXDPPluginPipelineRuntime, pluginID string, firstBefore, secondWant uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		first := kernelXDPPluginCounter(t, runtime, pluginID, 0)
		second := kernelXDPPluginCounter(t, runtime, pluginID, 1)
		if first > firstBefore && second == secondWant {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("xdp plugin counters after update = %d,%d, want first > %d and second = %d", first, second, firstBefore, secondWant)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func kernelXDPPluginCounter(t *testing.T, runtime *kernelXDPPluginPipelineRuntime, pluginID string, key uint32) uint64 {
	t.Helper()
	keyBytes := make([]byte, 4)
	binary.NativeEndian.PutUint32(keyBytes, key)
	value, err := runtime.GetPluginMapValue(pluginID, "chain", "counters", keyBytes)
	if err != nil {
		t.Fatalf("read xdp plugin counter %d: %v", key, err)
	}
	if len(value) < 8 {
		t.Fatalf("xdp plugin counter %d returned %d bytes", key, len(value))
	}
	return binary.NativeEndian.Uint64(value[:8])
}

func orderedKernelPluginCounter(t *testing.T, runtime *orderedKernelRuleRuntime, pluginID, objectID, mapName string) uint64 {
	t.Helper()
	key := make([]byte, 4)
	value, err := runtime.GetPluginMapValue(pluginID, objectID, mapName, key)
	if err != nil {
		t.Fatalf("read ordered plugin counter %s/%s: %v", objectID, mapName, err)
	}
	if len(value) < 8 {
		t.Fatalf("ordered plugin counter %s/%s returned %d bytes", objectID, mapName, len(value))
	}
	return binary.NativeEndian.Uint64(value[:8])
}
