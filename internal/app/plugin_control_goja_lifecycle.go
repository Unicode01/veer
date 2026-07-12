package app

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type pluginControlUpgradeGate struct {
	mu        sync.Mutex
	cond      *sync.Cond
	active    int
	upgrading bool
}

type pluginControlUpgradeLease struct {
	gate      *pluginControlUpgradeGate
	exclusive bool
	once      sync.Once
}

type pluginControlWorkerUpgrade struct {
	key       pluginControlWorkerKey
	old       *pluginControlVM
	candidate *pluginControlVM
}

func newPluginControlUpgradeGate() *pluginControlUpgradeGate {
	gate := &pluginControlUpgradeGate{}
	gate.cond = sync.NewCond(&gate.mu)
	return gate
}

func (gate *pluginControlUpgradeGate) enter(inherited bool, deadline time.Time) (*pluginControlUpgradeLease, error) {
	if gate == nil {
		return nil, nil
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if !inherited {
		for gate.upgrading {
			if !gate.waitLocked(deadline) {
				return nil, fmt.Errorf("plugin control upgrade gate timed out")
			}
		}
	}
	gate.active++
	return &pluginControlUpgradeLease{gate: gate}, nil
}

func (gate *pluginControlUpgradeGate) begin(deadline time.Time) (*pluginControlUpgradeLease, error) {
	if gate == nil {
		return nil, nil
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	for gate.upgrading {
		if !gate.waitLocked(deadline) {
			return nil, fmt.Errorf("plugin control upgrade gate timed out")
		}
	}
	gate.upgrading = true
	for gate.active > 0 {
		if gate.waitLocked(deadline) {
			continue
		}
		gate.upgrading = false
		gate.cond.Broadcast()
		return nil, fmt.Errorf("plugin control upgrade timed out while draining %d request(s)", gate.active)
	}
	return &pluginControlUpgradeLease{gate: gate, exclusive: true}, nil
}

func (gate *pluginControlUpgradeGate) waitLocked(deadline time.Time) bool {
	if deadline.IsZero() {
		gate.cond.Wait()
		return true
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	timedOut := false
	timer := time.AfterFunc(remaining, func() {
		gate.mu.Lock()
		timedOut = true
		gate.cond.Broadcast()
		gate.mu.Unlock()
	})
	gate.cond.Wait()
	if timer.Stop() {
		return true
	}
	return !timedOut
}

func (lease *pluginControlUpgradeLease) release() {
	if lease == nil || lease.gate == nil {
		return
	}
	lease.once.Do(func() {
		gate := lease.gate
		gate.mu.Lock()
		if lease.exclusive {
			gate.upgrading = false
		} else if gate.active > 0 {
			gate.active--
		}
		gate.cond.Broadcast()
		gate.mu.Unlock()
	})
}

func (rt *gojaPluginControlRuntime) pluginControlUpgradeGate(pluginID string) (*pluginControlUpgradeGate, error) {
	if rt == nil {
		return nil, errPluginRuntimeTargetNotLoaded
	}
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	if pluginID == "" {
		return nil, fmt.Errorf("plugin id is required")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return nil, errPluginRuntimeTargetNotLoaded
	}
	if rt.upgradeGates == nil {
		rt.upgradeGates = make(map[string]*pluginControlUpgradeGate)
	}
	gate := rt.upgradeGates[pluginID]
	if gate == nil {
		gate = newPluginControlUpgradeGate()
		rt.upgradeGates[pluginID] = gate
	}
	return gate, nil
}

func (rt *gojaPluginControlRuntime) acquirePluginControlUpgradeLease(pluginID string, deadline time.Time, inherited bool) (*pluginControlUpgradeLease, error) {
	gate, err := rt.pluginControlUpgradeGate(pluginID)
	if err != nil {
		return nil, err
	}
	return gate.enter(inherited, deadline)
}

func (vm *pluginControlVM) acquirePluginControlRequestLease(event pluginControlEvent, deadline time.Time) (*pluginControlUpgradeLease, error) {
	if vm == nil || event.bypassUpgradeGate {
		return nil, nil
	}
	if vm.rt == nil {
		return nil, errPluginRuntimeTargetNotLoaded
	}
	return vm.rt.acquirePluginControlUpgradeLease(vm.pluginID, deadline, event.inheritUpgradeGate)
}

func (vm *pluginControlVM) trackPluginControlUpgradeLease(lease *pluginControlUpgradeLease, state *pluginControlRequestState) error {
	if vm == nil || lease == nil {
		return nil
	}
	vm.pendingMu.Lock()
	defer vm.pendingMu.Unlock()
	if !vm.accepting {
		return errPluginRuntimeTargetNotLoaded
	}
	if vm.upgradeLeases == nil {
		vm.upgradeLeases = make(map[*pluginControlUpgradeLease]*pluginControlRequestState)
	}
	vm.upgradeLeases[lease] = state
	return nil
}

func (rt *gojaPluginControlRuntime) installPluginControlCandidate(plugin LoadedPlugin, candidate *pluginControlVM) (*pluginControlVM, error) {
	gate, err := rt.pluginControlUpgradeGate(plugin.ID)
	if err != nil {
		candidate.stopVM()
		return nil, err
	}
	exclusive, err := gate.begin(time.Now().Add(pluginControlExecutionLockTimeout))
	if err != nil {
		candidate.stopVM()
		return nil, err
	}
	defer exclusive.release()

	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		candidate.stopVM()
		return nil, errPluginRuntimeTargetNotLoaded
	}
	old := rt.controlVMs[plugin.ID]
	if old != nil && old.key == candidate.key {
		rt.mu.Unlock()
		candidate.stopVM()
		return old, nil
	}
	oldWorkers := rt.pluginControlWorkerUpgradesLocked(plugin.ID)
	rt.mu.Unlock()

	oldHasSnapshot := false
	if old != nil {
		oldHasSnapshot, err = probePluginControlUpgradeHook(old, old.plugin, "snapshot", "control", "")
		if err != nil {
			candidate.stopVM()
			return nil, err
		}
	}
	newHasRestore, err := probePluginControlUpgradeHook(candidate, plugin, "restore", "control", "")
	if err != nil {
		candidate.stopVM()
		return nil, err
	}
	if oldHasSnapshot && !newHasRestore {
		candidate.stopVM()
		return nil, fmt.Errorf("plugin %s exports onUpgradeSnapshot but the candidate does not export onUpgradeRestore", plugin.ID)
	}
	if !oldHasSnapshot && !newHasRestore {
		return rt.commitColdPluginControlReplacement(plugin, old, oldWorkers, candidate)
	}

	timers := rt.pluginControlUpgradeTimerMetadata(plugin.ID)
	if len(timers) > 0 && !pluginControlHasPermission(plugin, "timer") {
		candidate.stopVM()
		return nil, fmt.Errorf("plugin %s cannot inherit %d timer(s) without the timer permission", plugin.ID, len(timers))
	}
	if len(oldWorkers) > 0 && !pluginControlHasPermission(plugin, "worker") {
		candidate.stopVM()
		return nil, fmt.Errorf("plugin %s cannot inherit %d worker(s) without the worker permission", plugin.ID, len(oldWorkers))
	}
	socketInfos := make([]pluginControlSocketInfo, 0)
	if old != nil && rt.socketRegistry != nil {
		socketInfos = rt.socketRegistry.List(plugin.ID, old.key)
	}
	sockets := pluginControlUpgradeSocketMetadata(socketInfos)
	fromVersion := ""
	if old != nil {
		fromVersion = old.plugin.Version
	}
	controlState, err := snapshotPluginControlUpgradeState(old, oldHasSnapshot, fromVersion, plugin.Version, "control", "", timers, sockets)
	if err != nil {
		candidate.stopVM()
		return nil, err
	}
	if err := restorePluginControlUpgradeState(candidate, plugin, fromVersion, "control", "", controlState, timers, sockets); err != nil {
		candidate.stopVM()
		return nil, err
	}

	preparedWorkers := make([]pluginControlWorkerUpgrade, 0, len(oldWorkers))
	for _, worker := range oldWorkers {
		prepared, prepareErr := rt.preparePluginControlWorkerUpgrade(plugin, worker, oldHasSnapshot, fromVersion, timers, sockets)
		if prepareErr != nil {
			stopPreparedPluginControlWorkers(preparedWorkers)
			candidate.stopVM()
			return nil, prepareErr
		}
		preparedWorkers = append(preparedWorkers, prepared)
	}

	rt.mu.Lock()
	if rt.closed || rt.controlVMs[plugin.ID] != old {
		rt.mu.Unlock()
		stopPreparedPluginControlWorkers(preparedWorkers)
		candidate.stopVM()
		return nil, fmt.Errorf("plugin %s control runtime changed during upgrade", plugin.ID)
	}
	if old != nil && rt.socketRegistry != nil {
		if _, err := rt.socketRegistry.TransferPluginGeneration(plugin, old.key, candidate.key); err != nil {
			rt.mu.Unlock()
			stopPreparedPluginControlWorkers(preparedWorkers)
			candidate.stopVM()
			return nil, fmt.Errorf("plugin %s socket handoff failed: %w", plugin.ID, err)
		}
	}
	rt.controlVMs[plugin.ID] = candidate
	if rt.plugins == nil {
		rt.plugins = make(map[string]LoadedPlugin)
	}
	rt.plugins[plugin.ID] = plugin
	for _, worker := range preparedWorkers {
		rt.pluginWorkers[worker.key] = worker.candidate
	}
	rt.mu.Unlock()

	if old != nil {
		old.stopVM()
	}
	for _, worker := range preparedWorkers {
		worker.old.stopVM()
	}
	return candidate, nil
}

func (rt *gojaPluginControlRuntime) commitColdPluginControlReplacement(plugin LoadedPlugin, old *pluginControlVM, oldWorkers []pluginControlWorkerUpgrade, candidate *pluginControlVM) (*pluginControlVM, error) {
	rt.mu.Lock()
	if rt.closed || rt.controlVMs[plugin.ID] != old {
		rt.mu.Unlock()
		candidate.stopVM()
		return nil, fmt.Errorf("plugin %s control runtime changed during replacement", plugin.ID)
	}
	if old != nil {
		rt.clearPluginTimersLocked(plugin.ID)
	}
	for _, worker := range oldWorkers {
		delete(rt.pluginWorkers, worker.key)
	}
	rt.controlVMs[plugin.ID] = candidate
	if rt.plugins == nil {
		rt.plugins = make(map[string]LoadedPlugin)
	}
	rt.plugins[plugin.ID] = plugin
	rt.mu.Unlock()
	if old != nil && rt.socketRegistry != nil {
		rt.socketRegistry.ClosePluginGeneration(plugin.ID, old.key)
	}
	if old != nil {
		old.stopVM()
	}
	for _, worker := range oldWorkers {
		worker.old.stopVM()
	}
	return candidate, nil
}

func (rt *gojaPluginControlRuntime) pluginControlWorkerUpgradesLocked(pluginID string) []pluginControlWorkerUpgrade {
	out := make([]pluginControlWorkerUpgrade, 0)
	for key, vm := range rt.pluginWorkers {
		if key.pluginID == pluginID {
			out = append(out, pluginControlWorkerUpgrade{key: key, old: vm})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key.name < out[j].key.name })
	return out
}

func (rt *gojaPluginControlRuntime) preparePluginControlWorkerUpgrade(plugin LoadedPlugin, worker pluginControlWorkerUpgrade, oldHasSnapshot bool, fromVersion string, timers []map[string]any, sockets []map[string]any) (pluginControlWorkerUpgrade, error) {
	key, err := pluginControlVMKey(plugin, "worker", worker.key.name)
	if err != nil {
		return worker, err
	}
	candidate := newPluginControlVMForPlugin(rt, plugin, key, "worker", worker.key.name)
	registration, err := candidate.run(plugin, pluginControlEvent{Kind: "register", bypassUpgradeGate: true}, true)
	if err != nil {
		candidate.stopVM()
		return worker, fmt.Errorf("plugin worker %s registration failed: %w", worker.key.name, err)
	}
	validated := plugin
	applyPluginRuntimeSurface(&validated, registration.surface)
	if validated.Status != pluginStatusActive {
		candidate.stopVM()
		return worker, fmt.Errorf("plugin worker %s surface validation failed: %s", worker.key.name, strings.TrimSpace(validated.Error))
	}
	candidate.plugin = validated
	hasRestore, err := probePluginControlUpgradeHook(candidate, validated, "restore", "worker", worker.key.name)
	if err != nil {
		candidate.stopVM()
		return worker, err
	}
	if !hasRestore {
		candidate.stopVM()
		return worker, fmt.Errorf("plugin worker %s does not export onUpgradeRestore", worker.key.name)
	}
	state, err := snapshotPluginControlUpgradeState(worker.old, oldHasSnapshot, fromVersion, plugin.Version, "worker", worker.key.name, timers, sockets)
	if err != nil {
		candidate.stopVM()
		return worker, err
	}
	if err := restorePluginControlUpgradeState(candidate, validated, fromVersion, "worker", worker.key.name, state, timers, sockets); err != nil {
		candidate.stopVM()
		return worker, err
	}
	worker.candidate = candidate
	return worker, nil
}

func probePluginControlUpgradeHook(vm *pluginControlVM, plugin LoadedPlugin, phase string, scope string, workerName string) (bool, error) {
	if vm == nil {
		return false, nil
	}
	result, err := vm.run(plugin, pluginControlEvent{
		Kind: "upgrade_probe",
		Upgrade: &pluginControlUpgradeEvent{
			Phase:      phase,
			Scope:      scope,
			WorkerName: workerName,
		},
		bypassUpgradeGate: true,
	}, true)
	if err != nil {
		return false, fmt.Errorf("plugin %s %s upgrade hook validation failed: %w", plugin.ID, scope, err)
	}
	return result.handled, nil
}

func snapshotPluginControlUpgradeState(vm *pluginControlVM, enabled bool, fromVersion string, toVersion string, scope string, workerName string, timers []map[string]any, sockets []map[string]any) (any, error) {
	if vm == nil || !enabled {
		return nil, nil
	}
	result, err := vm.run(vm.plugin, pluginControlEvent{
		Kind: "upgrade_snapshot",
		Upgrade: &pluginControlUpgradeEvent{
			Phase:       "snapshot",
			Scope:       scope,
			WorkerName:  workerName,
			FromVersion: fromVersion,
			ToVersion:   toVersion,
			Timers:      timers,
			Sockets:     sockets,
		},
		bypassUpgradeGate: true,
	}, false)
	if err != nil {
		return nil, fmt.Errorf("plugin %s %s upgrade snapshot failed: %w", vm.pluginID, scope, err)
	}
	return result.value, nil
}

func restorePluginControlUpgradeState(vm *pluginControlVM, plugin LoadedPlugin, fromVersion string, scope string, workerName string, state any, timers []map[string]any, sockets []map[string]any) error {
	_, err := vm.run(plugin, pluginControlEvent{
		Kind: "upgrade_restore",
		Upgrade: &pluginControlUpgradeEvent{
			Phase:       "restore",
			Scope:       scope,
			WorkerName:  workerName,
			FromVersion: fromVersion,
			ToVersion:   plugin.Version,
			State:       state,
			Timers:      timers,
			Sockets:     sockets,
		},
		bypassUpgradeGate: true,
	}, false)
	if err != nil {
		return fmt.Errorf("plugin %s %s upgrade restore failed: %w", plugin.ID, scope, err)
	}
	return nil
}

func (rt *gojaPluginControlRuntime) pluginControlUpgradeTimerMetadata(pluginID string) []map[string]any {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]map[string]any, 0)
	for key, state := range rt.timers {
		if key.pluginID != pluginID {
			continue
		}
		remaining := time.Until(state.spec.NextFire)
		if remaining < 0 {
			remaining = 0
		}
		out = append(out, map[string]any{
			"name":         key.name,
			"kind":         state.spec.Kind,
			"delay_ms":     state.spec.Delay.Milliseconds(),
			"remaining_ms": remaining.Milliseconds(),
			"next_fire":    state.spec.NextFire.UTC().Format(time.RFC3339Nano),
			"payload":      pluginControlDecodeJSON(state.spec.Payload),
		})
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]["name"]) < fmt.Sprint(out[j]["name"]) })
	return out
}

func pluginControlUpgradeSocketMetadata(infos []pluginControlSocketInfo) []map[string]any {
	out := make([]map[string]any, 0, len(infos))
	for _, info := range infos {
		out = append(out, pluginControlSocketInfoObject(info))
	}
	return out
}

func stopPreparedPluginControlWorkers(workers []pluginControlWorkerUpgrade) {
	for _, worker := range workers {
		if worker.candidate != nil {
			worker.candidate.stopVM()
		}
	}
}

func cloneLoadedPluginMap(values map[string]LoadedPlugin) map[string]LoadedPlugin {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]LoadedPlugin, len(values))
	for id, plugin := range values {
		out[id] = plugin
	}
	return out
}

func clonePluginRuntimeSurfaces(values map[string]PluginRuntimeSurface) map[string]PluginRuntimeSurface {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]PluginRuntimeSurface, len(values))
	for id, surface := range values {
		out[id] = clonePluginRuntimeSurface(surface)
	}
	return out
}

func preservePreviousPluginControlRuntime(
	pluginID string,
	previousPlugins map[string]LoadedPlugin,
	previousSurfaces map[string]PluginRuntimeSurface,
	registered map[string]LoadedPlugin,
	surfaces map[string]PluginRuntimeSurface,
) bool {
	previous, ok := previousPlugins[pluginID]
	if !ok {
		return false
	}
	registered[pluginID] = previous
	if surface, found := previousSurfaces[pluginID]; found {
		surfaces[pluginID] = clonePluginRuntimeSurface(surface)
		return true
	}
	surfaces[pluginID] = PluginRuntimeSurface{
		Capabilities:      append([]string(nil), previous.Capabilities...),
		VirtualInterfaces: append([]PluginVirtualInterface(nil), previous.VirtualInterfaces...),
		Objects:           append([]PluginObject(nil), previous.Objects...),
		Hooks:             append([]PluginHook(nil), previous.Hooks...),
		Resources:         append([]PluginResource(nil), previous.Resources...),
		Actions:           append([]PluginAction(nil), previous.Actions...),
		UI:                clonePluginUI(previous.UI),
	}
	return true
}

func clonePluginUI(value *PluginUI) *PluginUI {
	if value == nil {
		return nil
	}
	out := *value
	return &out
}

func preservedPluginControlRuntimeState(reason string, err error) PluginRuntimeState {
	message := ""
	if err != nil {
		message = err.Error()
	}
	return PluginRuntimeState{
		Mode:       pluginRuntimeModeControl,
		Attachable: false,
		Attached:   false,
		Reason:     reason,
		Error:      message,
	}
}

func pluginControlEventKey(event pluginControlEvent) string {
	switch event.Kind {
	case "resource_apply":
		if event.Resource != nil {
			return event.Kind + ":" + event.Resource.ID
		}
	case "action":
		if event.Action != nil {
			return event.Kind + ":" + event.Action.ID
		}
	case "timer":
		if event.Timer != nil {
			return event.Kind + ":" + event.Timer.Name
		}
	case "worker":
		if event.Worker != nil {
			return event.Kind + ":" + event.Worker.Name + ":" + event.Worker.Handler
		}
	}
	if strings.TrimSpace(event.Kind) == "" {
		return "reconcile"
	}
	return event.Kind
}

func (rt *gojaPluginControlRuntime) interruptPluginControlIfRunning(pluginID string, reason string) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	vm := rt.controlVMs[pluginID]
	rt.mu.Unlock()
	if vm != nil {
		vm.interruptIfRunning(reason)
	}
}

func (h *pluginControlHost) beginSynchronousPluginCall(targetPluginID string, operation string) func() {
	if h.runtime == nil || targetPluginID == h.plugin.ID {
		return func() {}
	}
	if err := h.runtime.beginSynchronousPluginCall(h.plugin.ID, targetPluginID); err != nil {
		h.throwf("plugins: %s %s/%s: %v", operation, targetPluginID, h.plugin.ID, err)
	}
	return func() {
		h.runtime.endSynchronousPluginCall(h.plugin.ID, targetPluginID)
	}
}

func (rt *gojaPluginControlRuntime) beginSynchronousPluginCall(sourcePluginID string, targetPluginID string) error {
	if rt == nil {
		return fmt.Errorf("plugin control runtime is unavailable")
	}
	sourcePluginID = strings.TrimSpace(strings.ToLower(sourcePluginID))
	targetPluginID = strings.TrimSpace(strings.ToLower(targetPluginID))
	if sourcePluginID == "" || targetPluginID == "" {
		return fmt.Errorf("plugin call source and target are required")
	}
	if sourcePluginID == targetPluginID {
		return fmt.Errorf("synchronous self-call is not supported")
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return errPluginRuntimeTargetNotLoaded
	}
	if path, found := pluginSyncCallPath(rt.syncCalls, targetPluginID, sourcePluginID); found {
		cycle := append([]string{sourcePluginID}, path...)
		return fmt.Errorf("synchronous plugin call cycle rejected: %s", strings.Join(cycle, " -> "))
	}
	if rt.syncCalls == nil {
		rt.syncCalls = make(map[string]map[string]int)
	}
	if rt.syncCalls[sourcePluginID] == nil {
		rt.syncCalls[sourcePluginID] = make(map[string]int)
	}
	rt.syncCalls[sourcePluginID][targetPluginID]++
	return nil
}

func (rt *gojaPluginControlRuntime) endSynchronousPluginCall(sourcePluginID string, targetPluginID string) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	targets := rt.syncCalls[sourcePluginID]
	if targets == nil {
		return
	}
	if targets[targetPluginID] <= 1 {
		delete(targets, targetPluginID)
	} else {
		targets[targetPluginID]--
	}
	if len(targets) == 0 {
		delete(rt.syncCalls, sourcePluginID)
	}
}

func pluginSyncCallPath(graph map[string]map[string]int, from string, target string) ([]string, bool) {
	visited := make(map[string]bool)
	var visit func(string) ([]string, bool)
	visit = func(current string) ([]string, bool) {
		if current == target {
			return []string{current}, true
		}
		if visited[current] {
			return nil, false
		}
		visited[current] = true
		next := make([]string, 0, len(graph[current]))
		for candidate, count := range graph[current] {
			if count > 0 {
				next = append(next, candidate)
			}
		}
		sort.Strings(next)
		for _, candidate := range next {
			if path, found := visit(candidate); found {
				return append([]string{current}, path...), true
			}
		}
		return nil, false
	}
	return visit(from)
}
