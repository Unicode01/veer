//go:build linux

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

const kernelNetfilterPluginTestEnv = "VEER_RUN_NETFILTER_PLUGIN_TEST"
const kernelNetfilterPluginPerfTestEnv = "VEER_RUN_NETFILTER_PLUGIN_PERF"

func TestKernelNetfilterPluginPipelineIntegration(t *testing.T) {
	if os.Getenv(kernelNetfilterPluginTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged Netfilter plugin pipeline test", kernelNetfilterPluginTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	for _, command := range []string{"clang", "ip", "ping"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is unavailable: %v", command, err)
		}
	}

	namespace := fmt.Sprintf("veer-nf-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	mustRunKernelNetfilterTestCommand(t, "ip", "netns", "add", namespace)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", namespace).Run()
	})
	mustRunKernelNetfilterTestCommand(t, "ip", "-n", namespace, "link", "set", "lo", "up")
	if _, err := exec.LookPath("nft"); err == nil {
		mustRunKernelNetfilterTestCommand(t, "ip", "netns", "exec", namespace, "nft", "add", "table", "inet", "veer_nf_test")
		mustRunKernelNetfilterTestCommand(t, "ip", "netns", "exec", namespace, "nft", "add", "chain", "inet", "veer_nf_test", "output", "{ type filter hook output priority 0; policy accept; }")
	}

	pluginRoot := t.TempDir()
	objectPath := compileKernelNetfilterPluginTestObject(t, pluginRoot)
	plugin := kernelNetfilterPluginTestPlugin(t, pluginRoot, objectPath, namespace)
	enabled := true
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
	})
	runtime, ok := newPluginDataplaneRuntime(cfg).(*linuxPluginDataplaneRuntime)
	if !ok {
		t.Fatalf("newPluginDataplaneRuntime() = %T, want *linuxPluginDataplaneRuntime", runtime)
	}
	defer runtime.Close()

	reconcile := func(current LoadedPlugin, wantAttached int) PluginRuntimeState {
		t.Helper()
		snapshot := runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), current}})
		state, ok := snapshot.stateFor(current.ID)
		if !ok || state.Error != "" || !state.Attached || state.AttachmentCount != wantAttached {
			t.Fatalf("netfilter plugin state = %+v/%t, want %d healthy attachments", state, ok, wantAttached)
		}
		return state
	}

	state := reconcile(plugin, 2)
	for _, attachment := range state.Attachments {
		if attachment.Engine != pluginEngineNetfilter || attachment.Namespace != namespace || attachment.NetfilterHook != "output" || attachment.Phase != "filter" {
			t.Fatalf("unexpected netfilter attachment = %+v", attachment)
		}
	}
	if err := runKernelNetfilterTestPing(namespace, "-4", "127.0.0.1"); err != nil {
		t.Fatalf("IPv4 observe link blocked traffic: %v", err)
	}
	if err := runKernelNetfilterTestPing(namespace, "-6", "::1"); err != nil {
		t.Fatalf("IPv6 observe link blocked traffic: %v", err)
	}

	drop := plugin
	drop.Hooks = clonePluginHooks(plugin.Hooks)
	drop.Hooks[0].Program = "chain:nf_drop"
	drop.Hooks[0].Mode = "drop"
	reconcile(drop, 2)
	if err := runKernelNetfilterTestPing(namespace, "-4", "127.0.0.1"); err == nil {
		t.Fatal("IPv4 drop link allowed loopback traffic")
	}
	if err := runKernelNetfilterTestPing(namespace, "-6", "::1"); err == nil {
		t.Fatal("IPv6 drop link allowed loopback traffic")
	}

	broken := drop
	broken.Objects = append([]PluginObject(nil), drop.Objects...)
	broken.Objects[0].ResolvedSHA256 = strings.Repeat("0", 64)
	failed := runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), broken}})
	failedState, ok := failed.stateFor(drop.ID)
	if !ok || !failedState.Attached || failedState.Error == "" || !strings.Contains(failedState.Reason, "previous links preserved") {
		t.Fatalf("failed hot update state = %+v/%t", failedState, ok)
	}
	if err := runKernelNetfilterTestPing(namespace, "-4", "127.0.0.1"); err == nil {
		t.Fatal("failed hot update did not preserve the previous IPv4 drop link")
	}

	reconcile(plugin, 2)
	if err := runKernelNetfilterTestPing(namespace, "-4", "127.0.0.1"); err != nil {
		t.Fatalf("IPv4 traffic did not recover after hot update: %v", err)
	}
	if err := runKernelNetfilterTestPing(namespace, "-6", "::1"); err != nil {
		t.Fatalf("IPv6 traffic did not recover after hot update: %v", err)
	}

	scoped := plugin
	scoped.Hooks = clonePluginHooks(plugin.Hooks)
	scoped.Hooks[0].Program = "chain:nf_scoped_drop"
	scoped.Hooks[0].Mode = "drop"
	reconcile(scoped, 2)
	loopbackIndex := kernelNetfilterTestInterfaceIndex(t, namespace, "lo")
	putKernelNetfilterTestRuntimeMapValue(t, runtime, scoped.ID, "chain", "scope_ifindex", pluginMapTestUint32(0), pluginMapTestUint32(loopbackIndex))
	if err := runKernelNetfilterTestPing(namespace, "-4", "127.0.0.1"); err == nil {
		t.Fatal("IPv4 interface-scoped drop program allowed matching loopback traffic")
	}
	if err := runKernelNetfilterTestPing(namespace, "-6", "::1"); err == nil {
		t.Fatal("IPv6 interface-scoped drop program allowed matching loopback traffic")
	}
	putKernelNetfilterTestRuntimeMapValue(t, runtime, scoped.ID, "chain", "scope_ifindex", pluginMapTestUint32(0), pluginMapTestUint32(0))
	if err := runKernelNetfilterTestPing(namespace, "-4", "127.0.0.1"); err != nil {
		t.Fatalf("IPv4 interface-scoped program did not accept an unmatched interface: %v", err)
	}
	if err := runKernelNetfilterTestPing(namespace, "-6", "::1"); err != nil {
		t.Fatalf("IPv6 interface-scoped program did not accept an unmatched interface: %v", err)
	}

	runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin()}})
	if len(runtime.netfilter.attachments) != 0 || len(runtime.netfilter.loaded) != 0 {
		t.Fatalf("runtime resources remain after plugin removal: attachments=%d loaded=%d", len(runtime.netfilter.attachments), len(runtime.netfilter.loaded))
	}
	if err := runKernelNetfilterTestPing(namespace, "-4", "127.0.0.1"); err != nil {
		t.Fatalf("IPv4 traffic remained intercepted after plugin removal: %v", err)
	}
	if err := runKernelNetfilterTestPing(namespace, "-6", "::1"); err != nil {
		t.Fatalf("IPv6 traffic remained intercepted after plugin removal: %v", err)
	}
}

func TestKernelNetfilterPluginPriorityIntegration(t *testing.T) {
	requireKernelNetfilterPluginIntegration(t)

	namespace := fmt.Sprintf("veer-nf-order-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	mustRunKernelNetfilterTestCommand(t, "ip", "netns", "add", namespace)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "delete", namespace).Run() })
	mustRunKernelNetfilterTestCommand(t, "ip", "-n", namespace, "link", "set", "lo", "up")

	pluginRoot := t.TempDir()
	objectPath := compileKernelNetfilterPluginTestObject(t, pluginRoot)
	base := kernelNetfilterPluginTestPlugin(t, pluginRoot, objectPath, namespace)
	base.Hooks[0].Family = "ipv4"

	counter := cloneKernelNetfilterTestPlugin(base, "nf_counter", "count", "chain:nf_count", "observe")
	dropper := cloneKernelNetfilterTestPlugin(base, "nf_dropper", "drop", "chain:nf_drop", "drop")
	enabled := true
	cfg := pluginsEnabledTestConfig(&Config{PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled})
	runtime, ok := newPluginDataplaneRuntime(cfg).(*linuxPluginDataplaneRuntime)
	if !ok {
		t.Fatalf("newPluginDataplaneRuntime() = %T, want *linuxPluginDataplaneRuntime", runtime)
	}
	defer runtime.Close()

	assertOrder := func(name string, counterPriority, dropPriority int, counterBefore []string, wantCounter bool) {
		t.Helper()
		currentCounter := counter
		currentCounter.Hooks = clonePluginHooks(counter.Hooks)
		currentCounter.Hooks[0].Priority = counterPriority
		currentCounter.Hooks[0].Before = append([]string(nil), counterBefore...)
		currentCounter.Hooks[0].After = nil
		currentDropper := dropper
		currentDropper.Hooks = clonePluginHooks(dropper.Hooks)
		currentDropper.Hooks[0].Priority = dropPriority

		snapshot := runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), currentCounter, currentDropper}})
		for _, pluginID := range []string{currentCounter.ID, currentDropper.ID} {
			state, present := snapshot.stateFor(pluginID)
			if !present || state.Error != "" || !state.Attached || state.AttachmentCount != 1 {
				t.Fatalf("%s state for %s = %+v/%t", name, pluginID, state, present)
			}
		}
		putKernelNetfilterTestRuntimeMapValue(t, runtime, currentCounter.ID, "chain", "visit_count", pluginMapTestUint32(0), pluginMapTestUint64(0))
		if err := runKernelNetfilterTestPing(namespace, "-4", "127.0.0.1"); err == nil {
			t.Fatalf("%s: drop program allowed IPv4 traffic", name)
		}
		value, err := runtime.GetPluginMapValue(currentCounter.ID, "chain", "visit_count", pluginMapTestUint32(0))
		if err != nil {
			t.Fatalf("%s: read counter map: %v", name, err)
		}
		visited := !bytes.Equal(value, pluginMapTestUint64(0))
		if visited != wantCounter {
			t.Fatalf("%s: counter visited = %t, want %t (raw=%x)", name, visited, wantCounter, value)
		}
	}

	assertOrder("priority-drop-first", 20, 10, nil, false)
	assertOrder("priority-counter-first", 10, 20, nil, true)
	assertOrder("explicit-before-overrides-priority", 100, 0, []string{"nf_dropper/drop"}, true)
}

func TestKernelNetfilterPluginNamespaceRecreateIntegration(t *testing.T) {
	requireKernelNetfilterPluginIntegration(t)

	namespace := fmt.Sprintf("veer-nf-recreate-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	mustRunKernelNetfilterTestCommand(t, "ip", "netns", "add", namespace)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "delete", namespace).Run() })
	mustRunKernelNetfilterTestCommand(t, "ip", "-n", namespace, "link", "set", "lo", "up")

	pluginRoot := t.TempDir()
	objectPath := compileKernelNetfilterPluginTestObject(t, pluginRoot)
	plugin := kernelNetfilterPluginTestPlugin(t, pluginRoot, objectPath, namespace)
	plugin.Hooks[0].Family = "ipv4"
	enabled := true
	cfg := pluginsEnabledTestConfig(&Config{PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled})
	runtime, ok := newPluginDataplaneRuntime(cfg).(*linuxPluginDataplaneRuntime)
	if !ok {
		t.Fatalf("newPluginDataplaneRuntime() = %T, want *linuxPluginDataplaneRuntime", runtime)
	}
	defer runtime.Close()
	catalog := PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}}

	state, present := runtime.Reconcile(catalog).stateFor(plugin.ID)
	if !present || state.Error != "" || state.AttachmentCount != 1 {
		t.Fatalf("initial state = %+v/%t", state, present)
	}
	if !runtime.PluginDataplaneHealthy() {
		t.Fatal("initial plugin dataplane is unhealthy")
	}
	oldAttachments := append([]*loadedKernelNetfilterPluginAttachment(nil), runtime.netfilter.attachments...)
	oldIdentity := oldAttachments[0].namespaceIdentity

	mustRunKernelNetfilterTestCommand(t, "ip", "netns", "delete", namespace)
	mustRunKernelNetfilterTestCommand(t, "ip", "netns", "add", namespace)
	mustRunKernelNetfilterTestCommand(t, "ip", "-n", namespace, "link", "set", "lo", "up")
	if runtime.PluginDataplaneHealthy() {
		t.Fatal("namespace identity drift was not detected")
	}

	state, present = runtime.Reconcile(catalog).stateFor(plugin.ID)
	if !present || state.Error != "" || !state.Attached || state.AttachmentCount != 1 {
		t.Fatalf("recreated namespace state = %+v/%t", state, present)
	}
	if pluginControlNamespaceIdentityEqual(oldIdentity, runtime.netfilter.attachments[0].namespaceIdentity) {
		t.Fatalf("namespace identity was not refreshed: %+v", oldIdentity)
	}
	if oldAttachments[0].link != nil {
		t.Fatal("old namespace link remains tracked after recovery")
	}
	if err := runKernelNetfilterTestPing(namespace, "-4", "127.0.0.1"); err != nil {
		t.Fatalf("traffic failed after namespace recreation: %v", err)
	}
	if !runtime.PluginDataplaneHealthy() {
		t.Fatal("plugin dataplane remained unhealthy after recovery")
	}
}

func TestKernelNetfilterPluginInitialMissingNamespaceRecoversIntegration(t *testing.T) {
	requireKernelNetfilterPluginIntegration(t)

	namespace := fmt.Sprintf("veer-nf-late-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	pluginRoot := t.TempDir()
	objectPath := compileKernelNetfilterPluginTestObject(t, pluginRoot)
	plugin := kernelNetfilterPluginTestPlugin(t, pluginRoot, objectPath, namespace)
	plugin.Hooks[0].Family = "ipv4"
	enabled := true
	runtime, ok := newPluginDataplaneRuntime(pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
	})).(*linuxPluginDataplaneRuntime)
	if !ok {
		t.Fatalf("newPluginDataplaneRuntime() = %T, want *linuxPluginDataplaneRuntime", runtime)
	}
	defer runtime.Close()
	catalog := PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}}

	state, present := runtime.Reconcile(catalog).stateFor(plugin.ID)
	if !present || state.Error == "" || state.Attached {
		t.Fatalf("missing namespace state = %+v/%t, want unattached error", state, present)
	}
	if runtime.PluginDataplaneHealthy() {
		t.Fatal("initial attach failure was not retained for health-based retry")
	}

	mustRunKernelNetfilterTestCommand(t, "ip", "netns", "add", namespace)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "delete", namespace).Run() })
	mustRunKernelNetfilterTestCommand(t, "ip", "-n", namespace, "link", "set", "lo", "up")
	state, present = runtime.Reconcile(catalog).stateFor(plugin.ID)
	if !present || state.Error != "" || !state.Attached || state.AttachmentCount != 1 {
		t.Fatalf("recovered namespace state = %+v/%t", state, present)
	}
	if !runtime.PluginDataplaneHealthy() {
		t.Fatal("plugin dataplane remained unhealthy after the namespace appeared")
	}
}

func TestPreviousKernelNetfilterPluginObjectUsesIDHashAndStateContract(t *testing.T) {
	stateMaps := []PluginObjectStateMap{{Name: "rules", Policy: pluginObjectMapPreserve, SchemaVersion: 1}}
	refs := []loadedPluginObjectRef{{
		PluginID:     "firewall",
		ObjectID:     "filter",
		ObjectPath:   "/old/filter.o",
		ObjectSHA256: strings.Repeat("a", 64),
		StateMaps:    append([]PluginObjectStateMap(nil), stateMaps...),
		coll:         &ebpf.Collection{},
	}}
	plan := kernelNetfilterPluginHookPlan{
		PluginID:        "firewall",
		ObjectID:        "filter",
		ObjectPath:      "/new/filter.o",
		ObjectSHA256:    strings.Repeat("A", 64),
		ObjectStateMaps: append([]PluginObjectStateMap(nil), stateMaps...),
	}

	previous, unchanged := previousKernelNetfilterPluginObject(refs, plan)
	if previous != &refs[0] || !unchanged {
		t.Fatalf("previous object = %p/%t, want matching object with unchanged contract", previous, unchanged)
	}
	plan.ObjectStateMaps[0].SchemaVersion = 2
	previous, unchanged = previousKernelNetfilterPluginObject(refs, plan)
	if previous != &refs[0] || unchanged {
		t.Fatalf("changed state contract = %p/%t, want previous object requiring migration", previous, unchanged)
	}
	plan.ObjectStateMaps = append([]PluginObjectStateMap(nil), stateMaps...)
	plan.ObjectSHA256 = ""
	previous, unchanged = previousKernelNetfilterPluginObject(refs, plan)
	if previous != &refs[0] || unchanged {
		t.Fatalf("missing verified hash = %p/%t, want previous object without unchanged fast path", previous, unchanged)
	}
	plan.ObjectID = "other"
	if previous, _ := previousKernelNetfilterPluginObject(refs, plan); previous != nil {
		t.Fatalf("different object ID matched previous object: %p", previous)
	}
}

func TestKernelNetfilterPluginRuntimeNoHooksNoResources(t *testing.T) {
	enabled := true
	runtime := newKernelNetfilterPluginPipelineRuntime(pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
	}))
	defer runtime.Close()
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{ID: "control_only", Name: "Control Only", Version: "1.0.0", Kind: "control", Stability: pluginStabilityStable},
		Status:         pluginStatusActive,
	}
	runtime.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
	if len(runtime.attachments) != 0 || len(runtime.loaded) != 0 || len(runtime.desired) != 0 {
		t.Fatalf("no-hook runtime allocated resources: attachments=%d loaded=%d desired=%d", len(runtime.attachments), len(runtime.loaded), len(runtime.desired))
	}
}

func TestKernelNetfilterPluginPriorityBandsDoNotOverlap(t *testing.T) {
	phases := []string{"early", "raw", "mangle", "dstnat", "filter", "security", "srcnat", "late"}
	type priorityBand struct {
		phase string
		start int32
		end   int32
	}
	var bands []priorityBand
	for _, phase := range phases {
		bands = append(bands,
			priorityBand{phase: phase + "/final", start: kernelNetfilterPluginPriority(phase, 0, 0), end: kernelNetfilterPluginPriority(phase, pluginNetfilterPipelineHookLimit-1, 0)},
			priorityBand{phase: phase + "/staging", start: kernelNetfilterPluginPriority(phase, 0, pluginNetfilterPipelineHookLimit), end: kernelNetfilterPluginPriority(phase, pluginNetfilterPipelineHookLimit-1, pluginNetfilterPipelineHookLimit)},
		)
	}
	for i := range bands {
		if bands[i].start > bands[i].end {
			t.Fatalf("invalid priority band %+v", bands[i])
		}
		for j := i + 1; j < len(bands); j++ {
			if bands[i].start <= bands[j].end && bands[j].start <= bands[i].end {
				t.Fatalf("priority bands overlap: %+v and %+v", bands[i], bands[j])
			}
		}
	}
}

func TestKernelNetfilterPluginPerformance(t *testing.T) {
	if os.Getenv(kernelNetfilterPluginPerfTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged Netfilter plugin performance test", kernelNetfilterPluginPerfTestEnv)
	}
	requireKernelNetfilterPluginIntegration(t)
	if _, err := exec.LookPath("iperf3"); err != nil {
		t.Skipf("iperf3 is unavailable: %v", err)
	}

	namespace := fmt.Sprintf("veer-nf-perf-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	mustRunKernelNetfilterTestCommand(t, "ip", "netns", "add", namespace)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "delete", namespace).Run() })
	mustRunKernelNetfilterTestCommand(t, "ip", "-n", namespace, "link", "set", "lo", "up")

	pluginRoot := t.TempDir()
	objectPath := compileKernelNetfilterPluginTestObject(t, pluginRoot)
	base := kernelNetfilterPluginTestPlugin(t, pluginRoot, objectPath, namespace)
	base.Hooks[0].Family = "ipv4"
	enabled := true
	runtime, ok := newPluginDataplaneRuntime(pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
	})).(*linuxPluginDataplaneRuntime)
	if !ok {
		t.Fatalf("newPluginDataplaneRuntime() = %T, want *linuxPluginDataplaneRuntime", runtime)
	}
	defer runtime.Close()

	applyHooks := func(count int) {
		t.Helper()
		plugins := []LoadedPlugin{builtinVeerPlugin()}
		for index := 0; index < count; index++ {
			pluginID := fmt.Sprintf("nf_perf_%02d", index)
			plugin := cloneKernelNetfilterTestPlugin(base, pluginID, "observe", "chain:nf_observe", "observe")
			plugin.Hooks[0].Priority = index
			plugins = append(plugins, plugin)
		}
		snapshot := runtime.Reconcile(PluginCatalog{Plugins: plugins})
		for _, plugin := range plugins[1:] {
			state, present := snapshot.stateFor(plugin.ID)
			if !present || state.Error != "" || !state.Attached || state.AttachmentCount != 1 {
				t.Fatalf("%d-hook state for %s = %+v/%t", count, plugin.ID, state, present)
			}
		}
	}
	measure := func(label string) kernelNetfilterIPerfResult {
		t.Helper()
		var samples []kernelNetfilterIPerfResult
		for sample := 0; sample < 2; sample++ {
			samples = append(samples, runKernelNetfilterIPerf(t, namespace))
		}
		result := medianKernelNetfilterIPerfResult(samples)
		t.Logf("%s: %.2f Gbps, client CPU %.2f%%, server CPU %.2f%%", label, result.BitsPerSecond/1e9, result.ClientCPU, result.ServerCPU)
		return result
	}

	applyHooks(0)
	baselineBefore := measure("baseline-before")
	results := make(map[int]kernelNetfilterIPerfResult)
	for _, hooks := range []int{1, 4, 8} {
		applyHooks(hooks)
		results[hooks] = measure(fmt.Sprintf("%d-hooks", hooks))
	}
	applyHooks(0)
	baselineAfter := measure("baseline-after")
	baseline := (baselineBefore.BitsPerSecond + baselineAfter.BitsPerSecond) / 2
	if baseline <= 0 || results[8].BitsPerSecond < baseline*0.5 {
		t.Fatalf("8-hook throughput %.2f Gbps is below 50%% of %.2f Gbps baseline", results[8].BitsPerSecond/1e9, baseline/1e9)
	}
}

type kernelNetfilterIPerfResult struct {
	BitsPerSecond float64
	ClientCPU     float64
	ServerCPU     float64
}

func runKernelNetfilterIPerf(t *testing.T, namespace string) kernelNetfilterIPerfResult {
	t.Helper()
	server := exec.Command("ip", "netns", "exec", namespace, "iperf3", "-s", "-1", "-B", "127.0.0.1")
	var serverOutput bytes.Buffer
	server.Stdout = &serverOutput
	server.Stderr = &serverOutput
	if err := server.Start(); err != nil {
		t.Fatalf("start iperf3 server: %v", err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Wait() }()
	t.Cleanup(func() {
		if server.Process != nil {
			_ = server.Process.Kill()
		}
	})
	time.Sleep(200 * time.Millisecond)

	client := exec.Command("ip", "netns", "exec", namespace, "iperf3", "-c", "127.0.0.1", "-t", "2", "-O", "1", "-J")
	output, err := client.CombinedOutput()
	if err != nil {
		_ = server.Process.Kill()
		<-serverDone
		t.Fatalf("run iperf3 client: %v: %s; server: %s", err, strings.TrimSpace(string(output)), strings.TrimSpace(serverOutput.String()))
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("iperf3 server: %v: %s", err, strings.TrimSpace(serverOutput.String()))
	}
	var report struct {
		Error string `json:"error"`
		End   struct {
			SumReceived struct {
				BitsPerSecond float64 `json:"bits_per_second"`
			} `json:"sum_received"`
			CPU struct {
				HostTotal   float64 `json:"host_total"`
				RemoteTotal float64 `json:"remote_total"`
			} `json:"cpu_utilization_percent"`
		} `json:"end"`
	}
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatalf("decode iperf3 JSON: %v: %s", err, strings.TrimSpace(string(output)))
	}
	if report.Error != "" || report.End.SumReceived.BitsPerSecond <= 0 {
		t.Fatalf("invalid iperf3 report: error=%q throughput=%f", report.Error, report.End.SumReceived.BitsPerSecond)
	}
	return kernelNetfilterIPerfResult{
		BitsPerSecond: report.End.SumReceived.BitsPerSecond,
		ClientCPU:     report.End.CPU.HostTotal,
		ServerCPU:     report.End.CPU.RemoteTotal,
	}
}

func medianKernelNetfilterIPerfResult(values []kernelNetfilterIPerfResult) kernelNetfilterIPerfResult {
	if len(values) == 0 {
		return kernelNetfilterIPerfResult{}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].BitsPerSecond < values[j].BitsPerSecond })
	if len(values)%2 == 1 {
		return values[len(values)/2]
	}
	left, right := values[len(values)/2-1], values[len(values)/2]
	return kernelNetfilterIPerfResult{
		BitsPerSecond: (left.BitsPerSecond + right.BitsPerSecond) / 2,
		ClientCPU:     (left.ClientCPU + right.ClientCPU) / 2,
		ServerCPU:     (left.ServerCPU + right.ServerCPU) / 2,
	}
}

func compileKernelNetfilterPluginTestObject(t *testing.T, dir string) string {
	t.Helper()
	sourcePath := filepath.Join(dir, "netfilter_chain.bpf.c")
	objectPath := filepath.Join(dir, "netfilter_chain.o")
	source := `
#define SEC(name) __attribute__((section(name), used))
typedef unsigned int __u32;
typedef unsigned long long __u64;
struct net_device {
  int ifindex;
} __attribute__((preserve_access_index));
struct nf_hook_state {
  const struct net_device *in;
  const struct net_device *out;
} __attribute__((preserve_access_index));
struct bpf_nf_ctx {
  const struct nf_hook_state *state;
  void *skb;
};
struct bpf_map_def { __u32 type, key_size, value_size, max_entries, map_flags; };
struct bpf_map_def SEC("maps") scope_ifindex = {2, sizeof(__u32), sizeof(__u32), 1, 0};
struct bpf_map_def SEC("maps") visit_count = {2, sizeof(__u32), sizeof(__u64), 1, 0};
static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
SEC("netfilter/observe") int nf_observe(struct bpf_nf_ctx *ctx) { return 1; }
SEC("netfilter/drop") int nf_drop(struct bpf_nf_ctx *ctx) { return 0; }
SEC("netfilter/count") int nf_count(struct bpf_nf_ctx *ctx) {
  __u32 key = 0;
  __u64 *count = bpf_map_lookup_elem(&visit_count, &key);
  if (count)
    __sync_fetch_and_add(count, 1);
  return 1;
}
SEC("netfilter/scoped_drop") int nf_scoped_drop(struct bpf_nf_ctx *ctx) {
  __u32 key = 0;
  __u32 *scope = bpf_map_lookup_elem(&scope_ifindex, &key);
  if (!scope || *scope == 0 || !ctx || !ctx->state || !ctx->state->out)
    return 1;
  return (__u32)ctx->state->out->ifindex == *scope ? 0 : 1;
}
char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	compileKernelNetfilterPluginTestBPFObject(t, sourcePath, objectPath)
	return objectPath
}

func compileKernelNetfilterPluginTestBPFObject(t *testing.T, sourcePath, objectPath string) {
	t.Helper()
	command := exec.Command(
		"clang",
		"-O2",
		"-g",
		"-target", "bpf",
		"-D__TARGET_ARCH_"+testBPFTargetArch(),
		"-c", sourcePath,
		"-o", objectPath,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("compile Netfilter test bpf object: %v: %s", err, strings.TrimSpace(string(output)))
	}
}

func kernelNetfilterPluginTestPlugin(t *testing.T, root, objectPath, namespace string) LoadedPlugin {
	t.Helper()
	data, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	hook := PluginHook{
		ID:            "loopback-filter",
		Engine:        pluginEngineNetfilter,
		Family:        "inet",
		NetfilterHook: "output",
		Phase:         "filter",
		Namespace:     namespace,
		Program:       "chain:nf_observe",
		Mode:          "observe",
	}
	if err := normalizePluginHook(&hook); err != nil {
		t.Fatalf("normalize netfilter test hook: %v", err)
	}
	return LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "netfilter_chain_test",
			Name:      "Netfilter Chain Test",
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
				{ID: "nf_observe", Section: "netfilter/observe", Type: pluginEngineNetfilter},
				{ID: "nf_drop", Section: "netfilter/drop", Type: pluginEngineNetfilter},
				{ID: "nf_count", Section: "netfilter/count", Type: pluginEngineNetfilter},
				{ID: "nf_scoped_drop", Section: "netfilter/scoped_drop", Type: pluginEngineNetfilter},
			},
			StateMaps: []PluginObjectStateMap{
				{Name: "scope_ifindex", Policy: pluginObjectMapPreserve, SchemaVersion: 1},
				{Name: "visit_count", Policy: pluginObjectMapPreserve, SchemaVersion: 1},
			},
		}},
		Hooks:   []PluginHook{hook},
		Status:  pluginStatusActive,
		rootDir: root,
	}
}

func cloneKernelNetfilterTestPlugin(base LoadedPlugin, pluginID, hookID, program, mode string) LoadedPlugin {
	out := base
	out.PluginManifest.ID = pluginID
	out.PluginManifest.Name = pluginID
	out.Hooks = clonePluginHooks(base.Hooks)
	out.Hooks[0].ID = hookID
	out.Hooks[0].Program = program
	out.Hooks[0].Mode = mode
	return out
}

func kernelNetfilterTestInterfaceIndex(t *testing.T, namespace, name string) uint32 {
	t.Helper()
	var ifindex uint32
	if err := linuxPluginRunInNamespace(namespace, func() error {
		link, err := pluginControlNetLinkByName(name)
		if err != nil {
			return err
		}
		if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
			return fmt.Errorf("interface %s has no valid ifindex", name)
		}
		ifindex = uint32(link.Attrs().Index)
		return nil
	}); err != nil {
		t.Fatalf("resolve %s/%s: %v", namespace, name, err)
	}
	return ifindex
}

func putKernelNetfilterTestRuntimeMapValue(t *testing.T, runtime *linuxPluginDataplaneRuntime, pluginID, objectID, mapName string, key, value []byte) {
	t.Helper()
	if err := runtime.PutPluginMapValue(pluginID, objectID, mapName, key, value); err != nil {
		t.Fatalf("update map %s/%s/%s: %v", pluginID, objectID, mapName, err)
	}
}

func requireKernelNetfilterPluginIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(kernelNetfilterPluginTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged Netfilter plugin pipeline test", kernelNetfilterPluginTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	for _, command := range []string{"clang", "ip", "ping"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is unavailable: %v", command, err)
		}
	}
}

func mustRunKernelNetfilterTestCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	command := exec.Command(name, args...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
}

func runKernelNetfilterTestPing(namespace, family, destination string) error {
	command := exec.Command("ip", "netns", "exec", namespace, "ping", family, "-c", "1", "-W", "1", destination)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
