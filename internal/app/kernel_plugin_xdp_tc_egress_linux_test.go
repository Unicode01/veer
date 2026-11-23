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
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// tc_egress of an xdp hook: the host attaches it at the head of TC egress of
// every bound interface, whatever runs the hook at ingress (its tc_fallback
// here, on a veth whose MTU native XDP refuses, or the dispatcher in driver
// mode), takes it down with the hook or the binding's tc_egress: false, and
// hands it to a successor in place on a hot restart.

func compileKernelXDPPluginTCEgressTestObject(t *testing.T, dir string) string {
	t.Helper()
	sourcePath := filepath.Join(dir, "xdp_egress.bpf.c")
	objectPath := filepath.Join(dir, "xdp_egress.o")
	source := `
#define SEC(name) __attribute__((section(name), used))
typedef unsigned int __u32;
typedef unsigned long long __u64;
struct xdp_md;
struct __sk_buff;
struct bpf_map_def { __u32 type, key_size, value_size, max_entries, map_flags; };
struct bpf_map_def SEC("maps") xdp_prog_chain = {3, sizeof(__u32), sizeof(__u32), 24, 0};
struct bpf_map_def SEC("maps") counters = {2, sizeof(__u32), sizeof(__u64), 3, 0};
static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static void (*bpf_tail_call)(void *, void *, __u32) = (void *)12;
static __inline void count(__u32 key) {
  __u64 *value = bpf_map_lookup_elem(&counters, &key);
  if (value) __sync_fetch_and_add(value, 1);
}
SEC("xdp/fw") int xdp_fw(struct xdp_md *ctx) { count(0); bpf_tail_call(ctx, &xdp_prog_chain, 7); return 2; }
SEC("tc/fw") int tc_fw(struct __sk_buff *skb) { count(1); return -1; }
SEC("tc/eg") int tc_eg(struct __sk_buff *skb) { count(2); return -1; }
char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	compileBPFObjectFromSource(t, sourcePath, objectPath)
	return objectPath
}

func kernelXDPPluginTCEgressTestPlugin(t *testing.T, root, objectPath, interfaceName string) LoadedPlugin {
	t.Helper()
	data, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return LoadedPlugin{
		PluginManifest: PluginManifest{ID: "xdp_tc_egress_test", Name: "XDP TC Egress Test", Version: "1.0.0", Kind: "pipeline", Stability: pluginStabilityLab},
		Objects: []PluginObject{{
			ID:             "eg",
			Path:           filepath.Base(objectPath),
			ResolvedSHA256: fmt.Sprintf("%x", sum[:]),
			Status:         pluginObjectStatusVerified,
			Programs: []PluginObjectProgram{
				{ID: "xdp_fw", Section: "xdp/fw", Type: kernelEngineXDP},
				{ID: "tc_fw", Section: "tc/fw", Type: kernelEngineTC},
				{ID: "tc_eg", Section: "tc/eg", Type: kernelEngineTC},
			},
			StateMaps: []PluginObjectStateMap{{Name: "counters", Policy: pluginObjectMapPreserve, SchemaVersion: 1}},
		}},
		Hooks: []PluginHook{{
			ID: "fw", Engine: kernelEngineXDP, Attach: "ingress", Stage: "pre_forward", Priority: 10,
			Program: "eg:xdp_fw", TCFallback: "eg:tc_fw", TCEgress: "eg:tc_eg", Mode: "drop", Interfaces: []string{interfaceName},
		}},
		Status:  pluginStatusActive,
		rootDir: root,
	}
}

func kernelXDPPluginTCEgressPositions(rt *kernelXDPPluginPipelineRuntime) []kernelXDPPluginTCFallback {
	var out []kernelXDPPluginTCFallback
	for _, position := range rt.tcFallbacks {
		if position.egress() {
			out = append(out, position)
		}
	}
	return out
}

// assertKernelXDPPluginTCEgressFirst checks that position runs first at TC
// egress of its interface, ahead of other programs there.
func assertKernelXDPPluginTCEgressFirst(t *testing.T, position kernelXDPPluginTCFallback) {
	t.Helper()
	ifindex := position.key.linkIndex
	if position.key.tcx {
		result, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: ebpf.AttachTCXEgress})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Programs) == 0 {
			t.Fatal("tcx egress runs no program")
		}
		if id, ok := result.Programs[0].LinkID(); !ok || id != position.slot.linkID {
			t.Fatalf("first tcx egress program belongs to link %d, want the egress program's link %d", id, position.slot.linkID)
		}
		return
	}
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		t.Fatal(err)
	}
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_EGRESS)
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
	if !found || lowest != position.key.priority {
		t.Fatalf("cls_bpf egress filters = %+v, want the egress program at priority %d first", filters, position.key.priority)
	}
}

// kernelXDPPluginTCEgressTestProgramID is the program running at an egress
// position: through the tcx link linkID, or in the cls_bpf filter.
func kernelXDPPluginTCEgressTestProgramID(t *testing.T, key kernelAttachmentKey, linkID link.ID) uint32 {
	t.Helper()
	if key.tcx {
		result, err := link.QueryPrograms(link.QueryOptions{Target: key.linkIndex, Attach: ebpf.AttachTCXEgress})
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
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_EGRESS)
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

func assertKernelXDPPluginTCEgressGone(t *testing.T, position kernelXDPPluginTCFallback) {
	t.Helper()
	if got := kernelXDPPluginTCEgressTestProgramID(t, position.key, position.linkID()); got != 0 {
		t.Fatalf("egress position %+v still runs program %d", position.key, got)
	}
}

func TestKernelXDPPluginTCEgressKeys(t *testing.T) {
	for _, tcx := range []bool{false, true} {
		for position := 0; position < kernelXDPPluginTCFallbackMaxPerInterface; position++ {
			key := kernelXDPPluginTCPositionKey(9, position, tcx, true)
			ingress := kernelXDPPluginTCFallbackKey(9, position, tcx)
			if key == ingress || kernelXDPPluginTCFallbackPinPath(key) == kernelXDPPluginTCFallbackPinPath(ingress) {
				t.Fatalf("egress position %d shares its key or pin with the ingress one", position)
			}
			items := kernelXDPPluginTCFallbackMetadata([]kernelXDPPluginTCFallback{{key: key}})
			back, ok := kernelXDPPluginTCFallbackKeyFromMetadata(items[0])
			if !ok || back != key {
				t.Fatalf("metadata round trip of %+v = %+v %v", key, back, ok)
			}
		}
	}
	// Egress positions never count as the interface running its hooks at TC.
	positions := []kernelXDPPluginTCFallback{{key: kernelXDPPluginTCPositionKey(4, 0, true, true), pluginID: "p", hookID: "h"}}
	if len(kernelXDPPluginTCFallbackInterfaces(positions)) != 0 || len(kernelXDPPluginTCFallbackHookSet(positions)) != 0 ||
		len(kernelXDPPluginTCFallbackExclusions([]xdpAttachment{{ifindex: 4}}, positions)) != 0 {
		t.Fatal("an egress position was taken for a tc fallback")
	}
	if kernelXDPPluginTCEgressCount(positions) != 1 {
		t.Fatal("egress position not counted")
	}
}

func TestKernelXDPPluginTCEgressAttachesOnBoundInterfaces(t *testing.T) {
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
			objectPath := compileKernelXDPPluginTCEgressTestObject(t, pluginDir)
			target, peer := newKernelXDPPluginTCFallbackTestVeth(t, "vte")

			plugin := kernelXDPPluginTCEgressTestPlugin(t, pluginDir, objectPath, target.Attrs().Name)
			runtime := newKernelXDPPluginPipelineRuntime(kernelXDPPluginTCFallbackTestConfig(tcx))
			t.Cleanup(func() { _ = runtime.Close() })
			catalog := PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}}

			snapshot := runtime.Reconcile(catalog)
			state := snapshot.Plugins[plugin.ID]
			if state.Error != "" || state.AttachmentCount != 2 {
				t.Fatalf("plugin state = %+v, want the ingress and the egress attachment", state)
			}
			var egressState *PluginAttachmentState
			for i := range state.Attachments {
				if state.Attachments[i].Attach == "egress" {
					egressState = &state.Attachments[i]
				}
			}
			if egressState == nil || egressState.Program != "eg:tc_eg" || egressState.XDPMode != kernelXDPPluginTCFallbackMode || egressState.Interface != target.Attrs().Name {
				t.Fatalf("egress attachment = %+v", egressState)
			}
			egress := kernelXDPPluginTCEgressPositions(runtime)
			if len(egress) != 1 || egress[0].key.tcx != tcx || len(runtime.tcFallbacks) != 2 {
				t.Fatalf("positions = %+v", runtime.tcFallbacks)
			}
			assertKernelXDPPluginTCEgressFirst(t, egress[0])
			first := egress[0]

			counters := kernelXDPPluginTCFallbackTestCounters(t, runtime, plugin.ID)
			// Out of target: its egress program counts; into it: the fallback.
			sendKernelXDPPluginTCFallbackTestFrame(t, peer, target, 1)
			waitKernelXDPPluginTCFallbackCounter(t, counters, 2, 1)
			sendKernelXDPPluginTCFallbackTestFrame(t, target, peer, 1)
			waitKernelXDPPluginTCFallbackCounter(t, counters, 1, 1)

			runtime.Reconcile(catalog)
			if egress := kernelXDPPluginTCEgressPositions(runtime); len(egress) != 1 || !sameKernelXDPPluginTCFallbackPosition(egress[0], first) {
				t.Fatalf("egress position after a no-op reconcile = %+v, want %+v", egress, first)
			}
			if !runtime.attachmentsHealthyLocked(runtime.desired) {
				t.Fatal("runtime with its egress position reports unhealthy")
			}

			// A binding with tc_egress: false takes the egress program off;
			// the hook stays.
			off := plugin
			off.Hooks = []PluginHook{plugin.Hooks[0]}
			off.Hooks[0].TCEgress = ""
			catalog.Plugins[1] = off
			snapshot = runtime.Reconcile(catalog)
			if state := snapshot.Plugins[plugin.ID]; state.Error != "" || state.AttachmentCount != 1 || len(kernelXDPPluginTCEgressPositions(runtime)) != 0 {
				t.Fatalf("without tc_egress: state %+v, positions %+v", state, runtime.tcFallbacks)
			}
			assertKernelXDPPluginTCEgressGone(t, first)

			catalog.Plugins[1] = plugin
			runtime.Reconcile(catalog)
			egress = kernelXDPPluginTCEgressPositions(runtime)
			if len(egress) != 1 {
				t.Fatalf("egress positions after turning it back on = %+v", runtime.tcFallbacks)
			}
			if err := runtime.Close(); err != nil {
				t.Fatal(err)
			}
			assertKernelXDPPluginTCEgressGone(t, egress[0])
		})
	}
}

// With native XDP the dispatcher runs the hook; the egress program still
// goes on TC egress.
func TestKernelXDPPluginTCEgressBesideNativeXDP(t *testing.T) {
	requireKernelXDPPluginTCFallbackPrivileges(t)
	t.Setenv(veerRuntimeStateDirEnv, t.TempDir())
	pluginDir := t.TempDir()
	objectPath := compileKernelXDPPluginTCEgressTestObject(t, pluginDir)
	target, peer := newKernelXDPPluginTCFallbackTestVeth(t, "vtn")
	for _, l := range []netlink.Link{target, peer} {
		if err := netlink.LinkSetMTU(l, 1500); err != nil {
			t.Fatal(err)
		}
	}
	plugin := kernelXDPPluginTCEgressTestPlugin(t, pluginDir, objectPath, target.Attrs().Name)
	runtime := newKernelXDPPluginPipelineRuntime(kernelXDPPluginTCFallbackTestConfig(kernelTCXSupported()))
	t.Cleanup(func() { _ = runtime.Close() })
	snapshot := runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
	state := snapshot.Plugins[plugin.ID]
	modes := map[string]string{}
	for _, a := range state.Attachments {
		modes[a.Attach] = a.XDPMode
	}
	if state.Error != "" || modes["ingress"] != "driver" || modes["egress"] != kernelXDPPluginTCFallbackMode {
		t.Fatalf("state = %+v, want the dispatcher in driver mode and the egress program at TC", state)
	}
	counters := kernelXDPPluginTCFallbackTestCounters(t, runtime, plugin.ID)
	sendKernelXDPPluginTCFallbackTestFrame(t, peer, target, 1)
	waitKernelXDPPluginTCFallbackCounter(t, counters, 2, 1)
}

func TestKernelXDPPluginTCEgressHotRestartHandsOffInPlace(t *testing.T) {
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
			objectPath := compileKernelXDPPluginTCEgressTestObject(t, pluginDir)
			target, peer := newKernelXDPPluginTCFallbackTestVeth(t, "vtr")

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
			cmd := exec.Command(os.Args[0], "-test.run=^TestKernelXDPPluginTCEgressHandoffHelper$", "-test.v")
			cmd.Env = append(os.Environ(),
				"VEER_XDP_TC_EGRESS_HANDOFF_HELPER=1",
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

			// The predecessor is gone; its egress program still runs.
			key := kernelXDPPluginTCPositionKey(target.Attrs().Index, 0, tcx, true)
			if got := kernelXDPPluginTCEgressTestProgramID(t, key, link.ID(predecessorLink)); got != uint32(predecessorProg) {
				t.Fatalf("egress program after predecessor exit = %d, want %d", got, predecessorProg)
			}

			if err := os.Remove(markerPath); err != nil {
				t.Fatal(err)
			}
			plugin := kernelXDPPluginTCEgressTestPlugin(t, pluginDir, objectPath, target.Attrs().Name)
			runtime := newKernelXDPPluginPipelineRuntime(kernelXDPPluginTCFallbackTestConfig(tcx))
			t.Cleanup(func() { _ = runtime.Close() })
			snapshot := runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
			egress := kernelXDPPluginTCEgressPositions(runtime)
			if state := snapshot.Plugins[plugin.ID]; state.Error != "" || len(egress) != 1 {
				t.Fatalf("successor state = %+v positions = %+v", state, runtime.tcFallbacks)
			}
			if tcx && egress[0].slot.linkID != link.ID(predecessorLink) {
				t.Fatalf("successor egress link %d, want the predecessor's link %d taken over", egress[0].slot.linkID, predecessorLink)
			}
			if got := kernelXDPPluginTCEgressTestProgramID(t, key, egress[0].linkID()); got == uint32(predecessorProg) || got == 0 {
				t.Fatalf("egress program after takeover = %d, want the successor's", got)
			}
			if _, err := os.Stat(kernelXDPPluginTCFallbackPinPath(key)); !os.IsNotExist(err) {
				t.Fatalf("egress pin still present after takeover: %v", err)
			}
			assertKernelXDPPluginTCEgressFirst(t, egress[0])
			counters := kernelXDPPluginTCFallbackTestCounters(t, runtime, plugin.ID)
			sendKernelXDPPluginTCFallbackTestFrame(t, peer, target, 2)
			waitKernelXDPPluginTCFallbackCounter(t, counters, 2, 1)
		})
	}
}

func TestKernelXDPPluginTCEgressHandoffHelper(t *testing.T) {
	if os.Getenv("VEER_XDP_TC_EGRESS_HANDOFF_HELPER") != "1" {
		t.Skip("helper process only")
	}
	tcx := os.Getenv("VEER_XDP_TC_FALLBACK_TEST_LEGACY") != "1"
	plugin := kernelXDPPluginTCEgressTestPlugin(t, os.Getenv("VEER_XDP_PLUGIN_TEST_ROOT"), os.Getenv("VEER_XDP_PLUGIN_TEST_OBJECT"), os.Getenv("VEER_XDP_PLUGIN_TEST_INTERFACE"))
	runtime := newKernelXDPPluginPipelineRuntime(kernelXDPPluginTCFallbackTestConfig(tcx))
	snapshot := runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
	egress := kernelXDPPluginTCEgressPositions(runtime)
	if state := snapshot.Plugins[plugin.ID]; state.Error != "" || len(egress) != 1 {
		t.Fatalf("helper state = %+v positions = %+v", state, runtime.tcFallbacks)
	}
	progID := kernelXDPPluginTCEgressTestProgramID(t, egress[0].key, egress[0].linkID())
	if err := os.WriteFile(os.Getenv("VEER_XDP_PLUGIN_TEST_READY"), []byte(fmt.Sprintf("%d %d\n", egress[0].linkID(), progID)), 0o600); err != nil {
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
		t.Fatal("helper did not hand off")
	}
}
