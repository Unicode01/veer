//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestKernelSupportsXDPPluginReplace(t *testing.T) {
	for release, want := range map[string]bool{
		"5.6.19":        false,
		"5.7.0":         true,
		"5.15.0-91-gen": true,
		"6.8.12-4-pve":  true,
		"7.0.14-8-pve":  true,
		"4.19.0":        false,
		"":              false,
		"garbage":       false,
	} {
		if got := kernelSupportsXDPPluginReplace(release); got != want {
			t.Errorf("kernelSupportsXDPPluginReplace(%q) = %v, want %v", release, got, want)
		}
	}
}

func TestBuildKernelXDPPluginDesiredSkipsMissingInterfaces(t *testing.T) {
	root := t.TempDir()
	objectPath := filepath.Join(root, "xdp_chain.o")
	if err := os.WriteFile(objectPath, []byte("placeholder object"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pluginControlNetLinkByName("lo"); err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	const missing = "veermiss0"
	if _, err := pluginControlNetLinkByName(missing); err == nil {
		t.Skipf("interface %s unexpectedly exists", missing)
	}

	plugin := kernelXDPPluginTestPlugin(t, root, objectPath, "lo")
	plugin.Hooks[0].Interfaces = []string{"lo", missing}
	plugin.Hooks[1].Interfaces = []string{missing}
	item, state := buildKernelXDPPluginDesiredPlugin(plugin)
	if state.Error != "" {
		t.Fatalf("state.Error = %q, want the live interface to keep its hook", state.Error)
	}
	if len(item.hooks) != 1 || item.hooks[0].HookID != "first" {
		t.Fatalf("hooks = %+v, want only hook first", item.hooks)
	}
	if got := item.hooks[0].Interfaces; len(got) != 1 || got[0] != "lo" {
		t.Fatalf("hook first interfaces = %v, want [lo]", got)
	}
	warnings := strings.Join(item.warnings, "; ")
	if !strings.Contains(warnings, "hook first interface \""+missing+"\"") || !strings.Contains(warnings, "hook second interface \""+missing+"\"") {
		t.Fatalf("warnings = %q, want both missing bindings reported", warnings)
	}

	plugin.Hooks[0].Interfaces = []string{missing}
	item, state = buildKernelXDPPluginDesiredPlugin(plugin)
	if len(item.hooks) != 0 || state.Error == "" {
		t.Fatalf("all-missing plugin = hooks %+v state %+v, want an error and no hook", item.hooks, state)
	}
}

func TestSyncKernelPluginConfigsWriteBankBeforeHeader(t *testing.T) {
	xdpConfig := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelXDPPluginConfigMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  16,
		MaxEntries: kernelXDPPluginConfigEntries,
	})
	want := kernelXDPPluginConfig{Count: 3, ActiveBank: 1, GlobalMask: 0, Generation: 9}
	if err := syncKernelXDPPluginConfig(xdpConfig, want); err != nil {
		t.Fatal(err)
	}
	for key, expected := range map[uint32]kernelXDPPluginConfig{0: want, 1: {}, 2: want} {
		var got kernelXDPPluginConfig
		if err := xdpConfig.Lookup(key, &got); err != nil {
			t.Fatal(err)
		}
		if got != expected {
			t.Fatalf("xdp config key %d = %+v, want %+v", key, got, expected)
		}
	}

	tcConfig := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelTCPluginConfigMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(kernelTCPluginConfigV4{})),
		MaxEntries: kernelTCPluginConfigEntries,
	})
	tcWant := kernelTCPluginConfigV4{PreForwardCount: 2, ActiveBank: 0, PreForwardGlobalMask: 1, ForwardCoreEnable: 1}
	if err := syncKernelPluginConfigV4(tcConfig, tcWant); err != nil {
		t.Fatal(err)
	}
	for key, expected := range map[uint32]kernelTCPluginConfigV4{0: tcWant, 1: tcWant, 2: {}} {
		var got kernelTCPluginConfigV4
		if err := tcConfig.Lookup(key, &got); err != nil {
			t.Fatal(err)
		}
		if got != expected {
			t.Fatalf("tc config key %d = %+v, want %+v", key, got, expected)
		}
	}
}

func TestPinKernelHotRestartTailCallsKeepsChainAfterLastFD(t *testing.T) {
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	t.Setenv(veerBPFStateDirEnv, bpfRoot)
	t.Setenv(veerRuntimeStateDirEnv, t.TempDir())
	clearKernelHotRestartState(kernelEngineTC)
	t.Cleanup(func() { clearKernelHotRestartState(kernelEngineTC) })

	chain, err := ebpf.NewMap(&ebpf.MapSpec{Name: "tc_prog_chain_v4", Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 4})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("eBPF map creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "veer_tail_pin",
		Type:         ebpf.SchedCLS,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		License:      "GPL",
	})
	if err != nil {
		_ = chain.Close()
		t.Skipf("eBPF program load unavailable: %v", err)
	}
	if err := chain.Put(uint32(2), uint32(prog.FD())); err != nil {
		t.Fatal(err)
	}
	if err := pinKernelHotRestartTailCalls(kernelEngineTC, kernelTCProgramChainMapName, chain); err != nil {
		t.Fatal(err)
	}
	// Drop every fd the "predecessor" held. Only the pin keeps a user reference.
	_ = prog.Close()
	_ = chain.Close()
	// The kernel clears an unreferenced prog array from a work item; give it
	// time to run before checking that the pin prevented it.
	time.Sleep(100 * time.Millisecond)

	path := filepath.Join(kernelHotRestartEngineDir(kernelEngineTC), "tail-calls", kernelTCProgramChainMapName)
	pinned, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		t.Fatalf("load pinned tail-call map: %v", err)
	}
	defer pinned.Close()
	var programID uint32
	if err := pinned.Lookup(uint32(2), &programID); err != nil || programID == 0 {
		t.Fatalf("pinned tail-call slot 2 = %d err=%v, want the program to stay installed", programID, err)
	}

	clearKernelHotRestartState(kernelEngineTC)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("tail-call pin still present after clearing hot restart state: %v", err)
	}
}

func TestKernelXDPPluginPipelineHotRestartHandsOffInPlace(t *testing.T) {
	if os.Getenv(kernelXDPPluginTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged XDP plugin hot restart test", kernelXDPPluginTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if release := kernelRelease(); !kernelSupportsXDPPluginReplace(release) {
		t.Skipf("kernel %s lacks XDP_FLAGS_REPLACE", release)
	}
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	stateRoot := t.TempDir()
	t.Setenv(veerBPFStateDirEnv, bpfRoot)
	t.Setenv(veerRuntimeStateDirEnv, stateRoot)
	t.Cleanup(func() { clearKernelHotRestartState(kernelXDPPluginRuntimeEngine) })
	pluginDir := t.TempDir()
	objectPath := compileKernelXDPPluginTestObject(t, pluginDir)

	suffix := fmt.Sprintf("%04x", uint16(time.Now().UnixNano()))
	targetName := "vxh" + suffix
	peerName := "vyh" + suffix
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: targetName}, PeerName: peerName}); err != nil {
		t.Skipf("create xdp handoff veth: %v", err)
	}
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(targetName); err == nil {
			_ = netlink.LinkDel(link)
		}
	})
	target, _ := netlink.LinkByName(targetName)
	peer, _ := netlink.LinkByName(peerName)
	if target == nil || peer == nil {
		t.Fatal("handoff veth pair was not created")
	}
	for _, link := range []netlink.Link{target, peer} {
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
	}

	control := t.TempDir()
	readyPath := filepath.Join(control, "ready")
	closePath := filepath.Join(control, "close")
	markerPath := filepath.Join(control, "hot-restart")
	if err := os.WriteFile(markerPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestKernelXDPPluginHandoffHelper$", "-test.v")
	cmd.Env = append(os.Environ(),
		"VEER_XDP_PLUGIN_HANDOFF_HELPER=1",
		"VEER_XDP_PLUGIN_TEST_ROOT="+pluginDir,
		"VEER_XDP_PLUGIN_TEST_OBJECT="+objectPath,
		"VEER_XDP_PLUGIN_TEST_INTERFACE="+targetName,
		"VEER_XDP_PLUGIN_TEST_READY="+readyPath,
		"VEER_XDP_PLUGIN_TEST_CLOSE="+closePath,
		veerRuntimeStateDirEnv+"="+stateRoot,
		veerBPFStateDirEnv+"="+bpfRoot,
		veerHotRestartMarkerEnv+"="+markerPath,
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	// Kill is a no-op once Wait has reaped the helper.
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	waitForKernelXDPPluginTestFile(t, readyPath, exited)
	target, err := netlink.LinkByName(targetName)
	if err != nil || target.Attrs().Xdp == nil || !target.Attrs().Xdp.Attached {
		t.Fatalf("predecessor xdp attachment = %+v err=%v", target, err)
	}
	predecessorID := target.Attrs().Xdp.ProgId

	if err := os.WriteFile(closePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("handoff helper exited with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handoff helper did not exit")
	}

	// The predecessor is gone, but its dispatcher stays attached with a full chain.
	target, err = netlink.LinkByName(targetName)
	if err != nil || target.Attrs().Xdp == nil || target.Attrs().Xdp.ProgId != predecessorID {
		t.Fatalf("dispatcher after predecessor exit = %+v err=%v, want program %d still attached", target.Attrs().Xdp, err, predecessorID)
	}
	time.Sleep(100 * time.Millisecond)
	chainPath := kernelHotRestartPinPath(kernelXDPPluginRuntimeEngine, kernelXDPPluginProgramChainMapName)
	chain, err := ebpf.LoadPinnedMap(chainPath, nil)
	if err != nil {
		t.Fatalf("load predecessor plugin chain: %v", err)
	}
	var continueID uint32
	lookupErr := chain.Lookup(uint32(kernelXDPPluginContinueSlot), &continueID)
	_ = chain.Close()
	if lookupErr != nil || continueID == 0 {
		t.Fatalf("predecessor continuation slot = %d err=%v, want the chain to survive the exit", continueID, lookupErr)
	}
	frame := kernelXDPPluginTestFrame(target.Attrs().HardwareAddr, peer.Attrs().HardwareAddr, 3)
	if err := sendAndReceiveKernelXDPPluginTestFrame(peer.Attrs().Index, target.Attrs().Index, frame); err != nil {
		t.Fatalf("packet during handoff did not pass: %v", err)
	}

	if err := os.Remove(markerPath); err != nil {
		t.Fatal(err)
	}
	plugin := kernelXDPPluginTestPlugin(t, pluginDir, objectPath, targetName)
	enabled := true
	cfg := &Config{PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled, Experimental: map[string]bool{experimentalFeatureXDPGeneric: true}}
	runtime := newKernelXDPPluginPipelineRuntime(cfg)
	t.Cleanup(func() { _ = runtime.Close() })
	snapshot := runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
	if state := snapshot.Plugins[plugin.ID]; state.Error != "" || !state.Attached {
		t.Fatalf("successor xdp plugin state = %+v", state)
	}
	target, err = netlink.LinkByName(targetName)
	if err != nil || target.Attrs().Xdp == nil || target.Attrs().Xdp.ProgId != runtime.programID || runtime.programID == predecessorID {
		t.Fatalf("dispatcher after takeover = %+v err=%v, want successor program %d", target.Attrs().Xdp, err, runtime.programID)
	}
	if _, err := os.Stat(chainPath); !os.IsNotExist(err) {
		t.Fatalf("predecessor chain pin still present after takeover: %v", err)
	}
	if err := sendAndReceiveKernelXDPPluginTestFrame(peer.Attrs().Index, target.Attrs().Index, kernelXDPPluginTestFrame(target.Attrs().HardwareAddr, peer.Attrs().HardwareAddr, 4)); err != nil {
		t.Fatalf("packet after takeover did not pass: %v", err)
	}
	waitKernelXDPPluginCountersAtLeast(t, runtime, plugin.ID, 1, 1)
}

func TestKernelXDPPluginHandoffHelper(t *testing.T) {
	if os.Getenv("VEER_XDP_PLUGIN_HANDOFF_HELPER") != "1" {
		t.Skip("helper process only")
	}
	plugin := kernelXDPPluginTestPlugin(t, os.Getenv("VEER_XDP_PLUGIN_TEST_ROOT"), os.Getenv("VEER_XDP_PLUGIN_TEST_OBJECT"), os.Getenv("VEER_XDP_PLUGIN_TEST_INTERFACE"))
	enabled := true
	cfg := &Config{PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled, Experimental: map[string]bool{experimentalFeatureXDPGeneric: true}}
	runtime := newKernelXDPPluginPipelineRuntime(cfg)
	snapshot := runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
	if state := snapshot.Plugins[plugin.ID]; state.Error != "" || !state.Attached {
		t.Fatalf("helper xdp plugin state = %+v", state)
	}
	if err := os.WriteFile(os.Getenv("VEER_XDP_PLUGIN_TEST_READY"), []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	closePath := os.Getenv("VEER_XDP_PLUGIN_TEST_CLOSE")
	for {
		if _, err := os.Stat(closePath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if !runtime.handedOff {
		t.Fatal("helper did not hand off its dispatcher")
	}
}

func waitForKernelXDPPluginTestFile(t *testing.T, path string, exited <-chan error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case err := <-exited:
			t.Fatalf("helper exited before %s appeared: %v", filepath.Base(path), err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper did not create %s", filepath.Base(path))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
