//go:build linux

package app

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const kernelXDPPluginTCFallbackDropMarker = 0xdd

func TestKernelXDPPluginTCFallbackCandidates(t *testing.T) {
	tc := &ebpf.Program{}
	program := func(hook string, tcProg *ebpf.Program, ifindexes ...uint32) loadedKernelXDPPluginProgram {
		return loadedKernelXDPPluginProgram{plan: kernelXDPPluginHookPlan{HookID: hook, InterfaceIndexes: ifindexes}, tcProg: tcProg}
	}
	hooks := func(items []loadedKernelXDPPluginProgram) string {
		names := make([]string, 0, len(items))
		for _, item := range items {
			names = append(names, item.plan.HookID)
		}
		return strings.Join(names, ",")
	}
	got := kernelXDPPluginTCFallbackCandidates([]loadedKernelXDPPluginProgram{
		program("a", tc, 2, 3, 5),
		program("b", nil, 3, 5),
		program("c", tc, 2, 4, 5),
	})
	// 2: every hook has a fallback. 3: the chain ends in a hook without one,
	// so nothing can follow the dispatcher to TC. 5: a and b stay in the
	// dispatcher, c runs at TC.
	if len(got) != 3 || got[2].inXDP != 0 || hooks(got[2].tc) != "a,c" || got[4].inXDP != 0 || hooks(got[4].tc) != "c" || got[5].inXDP != 2 || hooks(got[5].tc) != "c" {
		t.Fatalf("candidates = %+v", got)
	}
	if _, ok := got[3]; ok {
		t.Fatalf("interface 3 ends in a hook without a fallback but is a candidate: %+v", got[3])
	}
	many := make([]loadedKernelXDPPluginProgram, 0, kernelXDPPluginTCFallbackMaxPerInterface+1)
	for i := 0; i <= kernelXDPPluginTCFallbackMaxPerInterface; i++ {
		many = append(many, program(fmt.Sprintf("h%d", i), tc, 7))
	}
	if got := kernelXDPPluginTCFallbackCandidates(many)[7]; got.inXDP != 1 || len(got.tc) != kernelXDPPluginTCFallbackMaxPerInterface || got.tc[0].plan.HookID != "h1" {
		t.Fatalf("over the position limit: inXDP %d, tc %s; want the first hook kept in the dispatcher", got.inXDP, hooks(got.tc))
	}
}

func TestKernelXDPPluginTCFallbackKeys(t *testing.T) {
	for _, tcx := range []bool{false, true} {
		for position := 0; position < kernelXDPPluginTCFallbackMaxPerInterface; position++ {
			key := kernelXDPPluginTCFallbackKey(9, position, tcx)
			if key.priority >= kernelReplyFilterPrio {
				t.Fatalf("position %d priority %d is not ahead of the core (%d)", position, key.priority, kernelReplyFilterPrio)
			}
			items := kernelXDPPluginTCFallbackMetadata([]kernelXDPPluginTCFallback{{key: key}})
			back, ok := kernelXDPPluginTCFallbackKeyFromMetadata(items[0])
			if !ok || back != key {
				t.Fatalf("metadata round trip of %+v = %+v %v", key, back, ok)
			}
		}
	}
	foreign := kernelHotRestartTCAttachment{LinkIndex: 9, Parent: netlink.HANDLE_MIN_INGRESS, Priority: kernelReplyFilterPrio, Handle: 1}
	if _, ok := kernelXDPPluginTCFallbackKeyFromMetadata(foreign); ok {
		t.Fatal("a core filter position was accepted as a tc fallback")
	}
}

func TestKernelXDPPluginTCFallbackRunsAheadOfCore(t *testing.T) {
	requireKernelXDPPluginTCFallbackPrivileges(t)
	modes := []string{"cls_bpf"}
	if kernelTCXSupported() {
		modes = append([]string{"tcx"}, modes...)
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			tcx := mode == "tcx"
			t.Setenv(veerRuntimeStateDirEnv, t.TempDir())
			pluginDir := t.TempDir()
			objectPath := compileKernelXDPPluginTCFallbackTestObject(t, pluginDir)
			target, peer := newKernelXDPPluginTCFallbackTestVeth(t, "vtf")
			core := attachKernelXDPPluginTCFallbackTestCore(t, target.Attrs().Index, tcx)

			plugin := kernelXDPPluginTCFallbackTestPlugin(t, pluginDir, objectPath, target.Attrs().Name)
			runtime := newKernelXDPPluginPipelineRuntime(kernelXDPPluginTCFallbackTestConfig(tcx))
			t.Cleanup(func() { _ = runtime.Close() })
			catalog := PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}}

			snapshot := runtime.Reconcile(catalog)
			state := snapshot.Plugins[plugin.ID]
			if state.Error != "" || !state.Attached || state.AttachmentCount != 1 || state.Attachments[0].XDPMode != kernelXDPPluginTCFallbackMode {
				t.Fatalf("plugin state = %+v, want one attachment running its tc fallback", state)
			}
			if len(runtime.attachments) != 0 || len(runtime.tcFallbacks) != 1 || runtime.tcFallbacks[0].key.tcx != tcx {
				t.Fatalf("attachments = %+v, tc fallbacks = %+v", runtime.attachments, runtime.tcFallbacks)
			}
			assertKernelXDPPluginTCFallbackFirst(t, target.Attrs().Index, runtime.tcFallbacks[0])
			firstPosition := runtime.tcFallbacks[0]

			counters := kernelXDPPluginTCFallbackTestCounters(t, runtime, plugin.ID)
			sendKernelXDPPluginTCFallbackTestFrame(t, target, peer, 1)
			waitKernelXDPPluginTCFallbackCounter(t, counters, 1, 1)
			waitKernelXDPPluginTCFallbackCounter(t, core, 0, 1)
			if xdp := readKernelXDPPluginTCFallbackCounter(t, counters, 0); xdp != 0 {
				t.Fatalf("xdp program ran %d times on an interface without native xdp", xdp)
			}
			coreBefore := readKernelXDPPluginTCFallbackCounter(t, core, 0)
			sendKernelXDPPluginTCFallbackTestFrame(t, target, peer, kernelXDPPluginTCFallbackDropMarker)
			waitKernelXDPPluginTCFallbackCounter(t, counters, 1, 2)
			time.Sleep(50 * time.Millisecond)
			if after := readKernelXDPPluginTCFallbackCounter(t, core, 0); after != coreBefore {
				t.Fatalf("core saw %d packets after the tc fallback dropped one", after-coreBefore)
			}

			// An unchanged catalog keeps the position as it is.
			runtime.Reconcile(catalog)
			if len(runtime.tcFallbacks) != 1 || !sameKernelXDPPluginTCFallbackPosition(runtime.tcFallbacks[0], firstPosition) {
				t.Fatalf("tc fallback after a no-op reconcile = %+v, want %+v", runtime.tcFallbacks, firstPosition)
			}

			// A hook without a fallback on the same interface moves it to
			// generic XDP, which runs every hook; the tc position goes away.
			mixed := plugin
			mixed.Hooks = append(append([]PluginHook(nil), plugin.Hooks...), PluginHook{
				ID: "plain", Engine: kernelEngineXDP, Attach: "ingress", Stage: "pre_forward", Priority: 20,
				Program: "fb:xdp_plain", Mode: "observe", Interfaces: []string{target.Attrs().Name},
			})
			catalog.Plugins[1] = mixed
			snapshot = runtime.Reconcile(catalog)
			state = snapshot.Plugins[plugin.ID]
			if state.Error != "" || len(runtime.attachments) != 1 || runtime.attachments[0].flags != xdpGenericFlagsForTest() || len(runtime.tcFallbacks) != 0 {
				t.Fatalf("mixed hooks: state = %+v attachments = %+v tc fallbacks = %+v", state, runtime.attachments, runtime.tcFallbacks)
			}
			assertKernelXDPPluginTCFallbackGone(t, firstPosition)

			// The same hook ahead of fw splits the chain: the dispatcher runs
			// plain in generic mode and leaves fw to its tc fallback, which
			// runs once, ahead of the core.
			split := mixed
			split.Hooks = append([]PluginHook(nil), mixed.Hooks...)
			split.Hooks[1].Priority = 5
			catalog.Plugins[1] = split
			snapshot = runtime.Reconcile(catalog)
			state = snapshot.Plugins[plugin.ID]
			if state.Error != "" || len(runtime.attachments) != 1 || runtime.attachments[0].flags != xdpGenericFlagsForTest() || len(runtime.tcFallbacks) != 1 {
				t.Fatalf("split chain: state = %+v attachments = %+v tc fallbacks = %+v", state, runtime.attachments, runtime.tcFallbacks)
			}
			modes := map[string]string{}
			for _, attachment := range state.Attachments {
				modes[attachment.HookID] = attachment.XDPMode
			}
			if modes["fw"] != kernelXDPPluginTCFallbackMode || modes["plain"] != "generic" {
				t.Fatalf("split chain modes = %v, want fw at tc and plain generic", modes)
			}
			assertKernelXDPPluginTCFallbackFirst(t, target.Attrs().Index, runtime.tcFallbacks[0])
			counters = kernelXDPPluginTCFallbackTestCounters(t, runtime, plugin.ID)
			xdpBefore := readKernelXDPPluginTCFallbackCounter(t, counters, 0)
			tcBefore := readKernelXDPPluginTCFallbackCounter(t, counters, 1)
			plainBefore := readKernelXDPPluginTCFallbackCounter(t, counters, 2)
			coreBefore = readKernelXDPPluginTCFallbackCounter(t, core, 0)
			sendKernelXDPPluginTCFallbackTestFrame(t, target, peer, 3)
			waitKernelXDPPluginTCFallbackCounter(t, counters, 2, plainBefore+1)
			waitKernelXDPPluginTCFallbackCounter(t, counters, 1, tcBefore+1)
			waitKernelXDPPluginTCFallbackCounter(t, core, 0, coreBefore+1)
			sendKernelXDPPluginTCFallbackTestFrame(t, target, peer, kernelXDPPluginTCFallbackDropMarker)
			waitKernelXDPPluginTCFallbackCounter(t, counters, 2, plainBefore+2)
			waitKernelXDPPluginTCFallbackCounter(t, counters, 1, tcBefore+2)
			time.Sleep(50 * time.Millisecond)
			if got := readKernelXDPPluginTCFallbackCounter(t, core, 0); got != coreBefore+1 {
				t.Fatalf("core saw %d packets, want 1: the tc fallback drops the marked one", got-coreBefore)
			}
			if got := readKernelXDPPluginTCFallbackCounter(t, counters, 0); got != xdpBefore {
				t.Fatalf("the dispatcher ran fw's xdp program %d times beside its tc fallback", got-xdpBefore)
			}

			catalog.Plugins[1] = plugin
			snapshot = runtime.Reconcile(catalog)
			if state := snapshot.Plugins[plugin.ID]; state.Error != "" || len(runtime.attachments) != 0 || len(runtime.tcFallbacks) != 1 {
				t.Fatalf("back to the fallback: state = %+v attachments = %+v", state, runtime.attachments)
			}
			if xdpAttachmentExists(xdpAttachment{ifindex: target.Attrs().Index, flags: xdpGenericFlagsForTest()}, 0) {
				t.Fatal("generic dispatcher is still attached after the interface went back to its tc fallback")
			}
			position := runtime.tcFallbacks[0]
			assertKernelXDPPluginTCFallbackFirst(t, target.Attrs().Index, position)

			if err := runtime.Close(); err != nil {
				t.Fatal(err)
			}
			assertKernelXDPPluginTCFallbackGone(t, position)
		})
	}
}

func TestKernelXDPPluginTCFallbackHotRestartHandsOffInPlace(t *testing.T) {
	requireKernelXDPPluginTCFallbackPrivileges(t)
	modes := []string{"cls_bpf"}
	if kernelTCXSupported() {
		modes = append([]string{"tcx"}, modes...)
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			tcx := mode == "tcx"
			bpfRoot := requireKernelHotRestartBPFStateRoot(t)
			stateRoot := t.TempDir()
			t.Setenv(veerBPFStateDirEnv, bpfRoot)
			t.Setenv(veerRuntimeStateDirEnv, stateRoot)
			t.Cleanup(func() { clearKernelHotRestartState(kernelXDPPluginRuntimeEngine) })
			pluginDir := t.TempDir()
			objectPath := compileKernelXDPPluginTCFallbackTestObject(t, pluginDir)
			target, peer := newKernelXDPPluginTCFallbackTestVeth(t, "vth")
			core := attachKernelXDPPluginTCFallbackTestCore(t, target.Attrs().Index, tcx)

			control := t.TempDir()
			readyPath := filepath.Join(control, "ready")
			closePath := filepath.Join(control, "close")
			markerPath := filepath.Join(control, "hot-restart")
			if err := os.WriteFile(markerPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			legacy := "0"
			if !tcx {
				legacy = "1"
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestKernelXDPPluginTCFallbackHandoffHelper$", "-test.v")
			cmd.Env = append(os.Environ(),
				"VEER_XDP_TC_FALLBACK_HANDOFF_HELPER=1",
				"VEER_XDP_PLUGIN_TEST_ROOT="+pluginDir,
				"VEER_XDP_PLUGIN_TEST_OBJECT="+objectPath,
				"VEER_XDP_PLUGIN_TEST_INTERFACE="+target.Attrs().Name,
				"VEER_XDP_PLUGIN_TEST_READY="+readyPath,
				"VEER_XDP_PLUGIN_TEST_CLOSE="+closePath,
				"VEER_XDP_TC_FALLBACK_TEST_LEGACY="+legacy,
				veerRuntimeStateDirEnv+"="+stateRoot,
				veerBPFStateDirEnv+"="+bpfRoot,
				veerHotRestartMarkerEnv+"="+markerPath,
			)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			waitForKernelXDPPluginTestFile(t, readyPath, exited)
			data, err := os.ReadFile(readyPath)
			if err != nil {
				t.Fatal(err)
			}
			fields := strings.Fields(string(data))
			if len(fields) != 2 {
				t.Fatalf("helper ready file = %q", data)
			}
			predecessorLink, _ := strconv.ParseUint(fields[0], 10, 32)
			predecessorProg, _ := strconv.ParseUint(fields[1], 10, 32)

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

			// The predecessor is gone; its tc fallback still runs ahead of the core.
			key := kernelXDPPluginTCFallbackKey(target.Attrs().Index, 0, tcx)
			if got := kernelXDPPluginTCFallbackTestProgramID(t, key, link.ID(predecessorLink)); got != uint32(predecessorProg) {
				t.Fatalf("tc fallback after predecessor exit runs program %d, want %d", got, predecessorProg)
			}
			coreBefore := readKernelXDPPluginTCFallbackCounter(t, core, 0)
			sendKernelXDPPluginTCFallbackTestFrame(t, target, peer, kernelXDPPluginTCFallbackDropMarker)
			time.Sleep(50 * time.Millisecond)
			if after := readKernelXDPPluginTCFallbackCounter(t, core, 0); after != coreBefore {
				t.Fatal("a packet reached the core while only the predecessor's tc fallback ran")
			}

			if err := os.Remove(markerPath); err != nil {
				t.Fatal(err)
			}
			plugin := kernelXDPPluginTCFallbackTestPlugin(t, pluginDir, objectPath, target.Attrs().Name)
			runtime := newKernelXDPPluginPipelineRuntime(kernelXDPPluginTCFallbackTestConfig(tcx))
			t.Cleanup(func() { _ = runtime.Close() })
			snapshot := runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
			if state := snapshot.Plugins[plugin.ID]; state.Error != "" || !state.Attached || len(runtime.tcFallbacks) != 1 {
				t.Fatalf("successor state = %+v tc fallbacks = %+v", state, runtime.tcFallbacks)
			}
			position := runtime.tcFallbacks[0]
			if tcx && position.slot.linkID != link.ID(predecessorLink) {
				t.Fatalf("successor tcx link %d, want the predecessor's link %d taken over", position.slot.linkID, predecessorLink)
			}
			if got := kernelXDPPluginTCFallbackTestProgramID(t, key, position.linkID()); got == uint32(predecessorProg) || got == 0 {
				t.Fatalf("tc fallback program after takeover = %d, want the successor's program", got)
			}
			if _, err := os.Stat(kernelXDPPluginTCFallbackPinPath(key)); !os.IsNotExist(err) {
				t.Fatalf("tc fallback pin still present after takeover: %v", err)
			}
			assertKernelXDPPluginTCFallbackFirst(t, target.Attrs().Index, position)
			counters := kernelXDPPluginTCFallbackTestCounters(t, runtime, plugin.ID)
			sendKernelXDPPluginTCFallbackTestFrame(t, target, peer, 2)
			waitKernelXDPPluginTCFallbackCounter(t, counters, 1, 1)
		})
	}
}

func TestKernelXDPPluginTCFallbackHandoffHelper(t *testing.T) {
	if os.Getenv("VEER_XDP_TC_FALLBACK_HANDOFF_HELPER") != "1" {
		t.Skip("helper process only")
	}
	tcx := os.Getenv("VEER_XDP_TC_FALLBACK_TEST_LEGACY") != "1"
	plugin := kernelXDPPluginTCFallbackTestPlugin(t, os.Getenv("VEER_XDP_PLUGIN_TEST_ROOT"), os.Getenv("VEER_XDP_PLUGIN_TEST_OBJECT"), os.Getenv("VEER_XDP_PLUGIN_TEST_INTERFACE"))
	runtime := newKernelXDPPluginPipelineRuntime(kernelXDPPluginTCFallbackTestConfig(tcx))
	snapshot := runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
	if state := snapshot.Plugins[plugin.ID]; state.Error != "" || !state.Attached || len(runtime.tcFallbacks) != 1 {
		t.Fatalf("helper state = %+v tc fallbacks = %+v", state, runtime.tcFallbacks)
	}
	position := runtime.tcFallbacks[0]
	progID := kernelXDPPluginTCFallbackTestProgramID(t, position.key, position.linkID())
	ready := fmt.Sprintf("%d %d\n", position.linkID(), progID)
	if err := os.WriteFile(os.Getenv("VEER_XDP_PLUGIN_TEST_READY"), []byte(ready), 0o600); err != nil {
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
		t.Fatal("helper did not hand off its tc fallback")
	}
}

func (p kernelXDPPluginTCFallback) linkID() link.ID {
	if p.slot == nil {
		return 0
	}
	return p.slot.linkID
}

func sameKernelXDPPluginTCFallbackPosition(left, right kernelXDPPluginTCFallback) bool {
	return left.key == right.key && left.linkID() == right.linkID()
}

func requireKernelXDPPluginTCFallbackPrivileges(t *testing.T) {
	t.Helper()
	if os.Getenv(kernelXDPPluginTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged XDP plugin tc fallback test", kernelXDPPluginTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
}

func kernelXDPPluginTCFallbackTestConfig(tcx bool) *Config {
	enabled := true
	cfg := &Config{PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled}
	if !tcx {
		cfg.Experimental = map[string]bool{experimentalFeatureKernelTCLegacyAttach: true}
	}
	return cfg
}

func xdpGenericFlagsForTest() int {
	return xdpPluginAttachOrder(true)[1]
}

// newKernelXDPPluginTCFallbackTestVeth gives the target a 9000-byte MTU,
// which veth's native XDP refuses for programs without frags support.
func newKernelXDPPluginTCFallbackTestVeth(t *testing.T, prefix string) (netlink.Link, netlink.Link) {
	t.Helper()
	suffix := fmt.Sprintf("%04x", uint16(time.Now().UnixNano()))
	targetName := prefix + suffix
	peerName := prefix + "p" + suffix
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: targetName, MTU: 9000}, PeerName: peerName}); err != nil {
		t.Skipf("create tc fallback veth: %v", err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName(targetName); err == nil {
			_ = netlink.LinkDel(l)
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
	if err := netlink.LinkSetMTU(peer, 9000); err != nil {
		t.Fatal(err)
	}
	// No IPv6 on the pair: router solicitations and MLD reports would reach
	// the counters next to the test frames.
	for _, name := range []string{targetName, peerName} {
		_ = os.WriteFile(filepath.Join("/proc/sys/net/ipv6/conf", name, "disable_ipv6"), []byte("1"), 0o644)
	}
	for _, l := range []netlink.Link{target, peer} {
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
	}
	if target, err = netlink.LinkByName(targetName); err != nil {
		t.Fatal(err)
	}
	if peer, err = netlink.LinkByName(peerName); err != nil {
		t.Fatal(err)
	}
	return target, peer
}

// attachKernelXDPPluginTCFallbackTestCore stands in for the Veer core: a tc
// program that counts what reaches it and passes it on, attached the way the
// core attaches (tcx at the tail, or cls_bpf at the core's priority).
func attachKernelXDPPluginTCFallbackTestCore(t *testing.T, ifindex int, tcx bool) *ebpf.Map {
	t.Helper()
	counter, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = counter.Close() })
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.SchedCLS,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R1, 0),
			asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),
			asm.LoadMapPtr(asm.R1, counter.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "out"),
			asm.Mov.Imm(asm.R1, 1),
			asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
			asm.Mov.Imm(asm.R0, -1).WithSymbol("out"),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	if tcx {
		l, err := link.AttachTCX(link.TCXOptions{Interface: ifindex, Program: prog, Attach: ebpf.AttachTCXIngress})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		return counter
	}
	if err := ensureClsactQdisc(ifindex); err != nil {
		t.Fatal(err)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Priority:  kernelForwardFilterPrio,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         "test_core",
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.FilterDel(filter) })
	return counter
}

func compileKernelXDPPluginTCFallbackTestObject(t *testing.T, dir string) string {
	t.Helper()
	sourcePath := filepath.Join(dir, "xdp_fallback.bpf.c")
	objectPath := filepath.Join(dir, "xdp_fallback.o")
	source := `
#define SEC(name) __attribute__((section(name), used))
typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;
struct xdp_md;
struct __sk_buff;
struct bpf_map_def { __u32 type, key_size, value_size, max_entries, map_flags; };
struct bpf_map_def SEC("maps") xdp_prog_chain = {3, sizeof(__u32), sizeof(__u32), 24, 0};
struct bpf_map_def SEC("maps") counters = {2, sizeof(__u32), sizeof(__u64), 3, 0};
static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static void (*bpf_tail_call)(void *, void *, __u32) = (void *)12;
static long (*bpf_skb_load_bytes)(const void *, __u32, void *, __u32) = (void *)26;
static __inline void count(__u32 key) {
  __u64 *value = bpf_map_lookup_elem(&counters, &key);
  if (value) __sync_fetch_and_add(value, 1);
}
SEC("xdp/fw") int xdp_fw(struct xdp_md *ctx) { count(0); bpf_tail_call(ctx, &xdp_prog_chain, 7); return 2; }
SEC("xdp/plain") int xdp_plain(struct xdp_md *ctx) { count(2); bpf_tail_call(ctx, &xdp_prog_chain, 7); return 2; }
SEC("tc/fw") int tc_fw(struct __sk_buff *skb) {
  __u8 marker = 0;
  count(1);
  if (bpf_skb_load_bytes(skb, 14, &marker, 1) == 0 && marker == 0xdd) return 2;
  return -1;
}
char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	compileBPFObjectFromSource(t, sourcePath, objectPath)
	return objectPath
}

func kernelXDPPluginTCFallbackTestPlugin(t *testing.T, root, objectPath, interfaceName string) LoadedPlugin {
	t.Helper()
	data, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return LoadedPlugin{
		PluginManifest: PluginManifest{ID: "xdp_tc_fallback_test", Name: "XDP TC Fallback Test", Version: "1.0.0", Kind: "pipeline", Stability: pluginStabilityLab},
		Objects: []PluginObject{{
			ID:             "fb",
			Path:           filepath.Base(objectPath),
			ResolvedSHA256: fmt.Sprintf("%x", sum[:]),
			Status:         pluginObjectStatusVerified,
			Programs: []PluginObjectProgram{
				{ID: "xdp_fw", Section: "xdp/fw", Type: kernelEngineXDP},
				{ID: "xdp_plain", Section: "xdp/plain", Type: kernelEngineXDP},
				{ID: "tc_fw", Section: "tc/fw", Type: kernelEngineTC},
			},
			StateMaps: []PluginObjectStateMap{{Name: "counters", Policy: pluginObjectMapPreserve, SchemaVersion: 1}},
		}},
		Hooks: []PluginHook{{
			ID: "fw", Engine: kernelEngineXDP, Attach: "ingress", Stage: "pre_forward", Priority: 10,
			Program: "fb:xdp_fw", TCFallback: "fb:tc_fw", Mode: "drop", Interfaces: []string{interfaceName},
		}},
		Status:  pluginStatusActive,
		rootDir: root,
	}
}

func kernelXDPPluginTCFallbackTestCounters(t *testing.T, runtime *kernelXDPPluginPipelineRuntime, pluginID string) *ebpf.Map {
	t.Helper()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for _, ref := range runtime.loaded {
		if ref.PluginID == pluginID && ref.coll != nil && ref.coll.Maps["counters"] != nil {
			return ref.coll.Maps["counters"]
		}
	}
	t.Fatalf("plugin %s counters map is not loaded", pluginID)
	return nil
}

func readKernelXDPPluginTCFallbackCounter(t *testing.T, m *ebpf.Map, key uint32) uint64 {
	t.Helper()
	var value uint64
	if err := m.Lookup(key, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func waitKernelXDPPluginTCFallbackCounter(t *testing.T, m *ebpf.Map, key uint32, want uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := readKernelXDPPluginTCFallbackCounter(t, m, key)
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("counter %d = %d, want at least %d", key, got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sendKernelXDPPluginTCFallbackTestFrame(t *testing.T, target, peer netlink.Link, marker byte) {
	t.Helper()
	frame := kernelXDPPluginTestFrame(target.Attrs().HardwareAddr, peer.Attrs().HardwareAddr, marker)
	// Packet taps run before TC ingress, so the receiver sees dropped frames too.
	if err := sendAndReceiveKernelXDPPluginTestFrame(peer.Attrs().Index, target.Attrs().Index, frame); err != nil {
		t.Fatalf("send frame %#x: %v", marker, err)
	}
}

func assertKernelXDPPluginTCFallbackFirst(t *testing.T, ifindex int, position kernelXDPPluginTCFallback) {
	t.Helper()
	if position.key.tcx {
		result, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: ebpf.AttachTCXIngress})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Programs) < 2 {
			t.Fatalf("tcx ingress runs %d programs, want the fallback and the core", len(result.Programs))
		}
		if id, ok := result.Programs[0].LinkID(); !ok || id != position.slot.linkID {
			t.Fatalf("first tcx program belongs to link %d, want the fallback's link %d", id, position.slot.linkID)
		}
		return
	}
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		t.Fatal(err)
	}
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatal(err)
	}
	lowest := uint16(0xffff)
	found := false
	for _, filter := range filters {
		attrs := filter.Attrs()
		if attrs.Priority < lowest {
			lowest = attrs.Priority
		}
		if attrs.Priority == position.key.priority && attrs.Handle == position.key.handle {
			found = true
		}
	}
	if !found || lowest != position.key.priority || position.key.priority >= kernelReplyFilterPrio {
		t.Fatalf("cls_bpf filters = %+v, want the fallback at priority %d first", filters, position.key.priority)
	}
}

func assertKernelXDPPluginTCFallbackGone(t *testing.T, position kernelXDPPluginTCFallback) {
	t.Helper()
	ifindex := position.key.linkIndex
	if position.key.tcx {
		result, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: ebpf.AttachTCXIngress})
		if err != nil {
			t.Fatal(err)
		}
		for _, prog := range result.Programs {
			if id, ok := prog.LinkID(); ok && id == position.linkID() {
				t.Fatalf("tcx link %d is still attached", id)
			}
		}
		return
	}
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		t.Fatal(err)
	}
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatal(err)
	}
	for _, filter := range filters {
		if attrs := filter.Attrs(); attrs.Priority == position.key.priority && attrs.Handle == position.key.handle {
			t.Fatalf("cls_bpf filter %d/%x is still attached", attrs.Priority, attrs.Handle)
		}
	}
}

// kernelXDPPluginTCFallbackTestProgramID is the program the kernel runs at
// key: through the tcx link linkID, or in the cls_bpf filter.
func kernelXDPPluginTCFallbackTestProgramID(t *testing.T, key kernelAttachmentKey, linkID link.ID) uint32 {
	t.Helper()
	if key.tcx {
		result, err := link.QueryPrograms(link.QueryOptions{Target: key.linkIndex, Attach: ebpf.AttachTCXIngress})
		if err != nil {
			t.Fatal(err)
		}
		for _, prog := range result.Programs {
			if id, ok := prog.LinkID(); ok && id == linkID {
				return uint32(prog.ID)
			}
		}
		return 0
	}
	l, err := netlink.LinkByIndex(key.linkIndex)
	if err != nil {
		t.Fatal(err)
	}
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatal(err)
	}
	for _, filter := range filters {
		bpf, ok := filter.(*netlink.BpfFilter)
		if ok && bpf.Priority == key.priority && bpf.Handle == key.handle {
			return uint32(bpf.Id)
		}
	}
	return 0
}
