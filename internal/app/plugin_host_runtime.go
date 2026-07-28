package app

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	pluginHostRestartMinBackoff = 250 * time.Millisecond
	pluginHostRestartMaxBackoff = 30 * time.Second
)

func (vm *pluginControlVM) isolationEnabled() bool {
	return vm != nil && vm.rt != nil && vm.rt.cfg != nil && vm.rt.cfg.PluginsIsolationEnabled()
}

func (vm *pluginControlVM) initRemote(plugin LoadedPlugin) (*pluginControlHost, error) {
	source, err := readPluginControlScript(plugin)
	if err != nil {
		return nil, err
	}
	host, err := vm.newControlHost(plugin, false)
	if err != nil {
		return nil, err
	}
	client, err := startPluginHostClient(vm.rt.cfg, plugin, vm.mode, vm.workerName, source, host)
	if err != nil {
		return nil, err
	}
	host.registrationPhase = false
	vm.setCurrentHost(client)
	host.remoteEventInvoker = func(event pluginControlEvent, optionalHandler bool) (PluginRuntimeSurface, any, bool, error) {
		return vm.runRemoteEvent(host, event, optionalHandler, true)
	}
	return host, nil
}

func (vm *pluginControlVM) runRemoteWithTimeout(host *pluginControlHost, req pluginControlRequest) pluginControlResult {
	var result pluginControlResult
	host.executionDeadline = time.Now().Add(vm.rt.handlerTimeout())
	if req.state != nil && !req.state.deadline.IsZero() && req.state.deadline.Before(host.executionDeadline) {
		host.executionDeadline = req.state.deadline
	}
	vm.setExecuting(true)
	defer func() {
		host.executionDeadline = time.Time{}
		vm.setExecuting(false)
	}()
	result.surface, result.value, result.handled, result.err = vm.runRemoteEvent(host, req.event, req.optionalHandler, false)
	return result
}

func (vm *pluginControlVM) runRemoteEvent(host *pluginControlHost, event pluginControlEvent, optionalHandler, nested bool) (PluginRuntimeSurface, any, bool, error) {
	client := vm.currentPluginHost()
	if client == nil {
		return host.surface, nil, false, errPluginRuntimeTargetNotLoaded
	}
	deadline := host.executionDeadline
	if deadline.IsZero() {
		deadline = time.Now().Add(vm.rt.handlerTimeout())
	}
	return host.runRemoteEvent(event, optionalHandler, func(request pluginHostEventRequest) (pluginHostEventResponse, error) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return pluginHostEventResponse{}, fmt.Errorf("isolated plugin handler deadline exceeded")
		}
		if timeout := vm.rt.handlerTimeout(); remaining > timeout {
			remaining = timeout
		}
		request.TimeoutMS = max(1, remaining.Milliseconds())
		return client.runEvent(request, host, deadline, nested)
	})
}

func pluginHostFatalError(err error) bool {
	return errors.Is(err, errPluginHostProcessExited)
}

func (vm *pluginControlVM) setCurrentHost(client *pluginHostClient) {
	vm.currentMu.Lock()
	previous := vm.currentHost
	vm.currentHost = client
	vm.currentMu.Unlock()
	if previous != nil && previous != client {
		previous.Close()
	}
}

func (vm *pluginControlVM) currentPluginHost() *pluginHostClient {
	vm.currentMu.Lock()
	defer vm.currentMu.Unlock()
	return vm.currentHost
}

func (vm *pluginControlVM) clearCurrentHost() {
	vm.setCurrentHost(nil)
}

func (vm *pluginControlVM) pluginHostRestartAllowed(now time.Time) error {
	vm.currentMu.Lock()
	defer vm.currentMu.Unlock()
	if vm.hostRestartAfter.IsZero() || !now.Before(vm.hostRestartAfter) {
		return nil
	}
	return fmt.Errorf(
		"isolated plugin host restart backoff active for %s (until %s)",
		time.Until(vm.hostRestartAfter).Round(time.Millisecond),
		vm.hostRestartAfter.UTC().Format(time.RFC3339Nano),
	)
}

func (vm *pluginControlVM) notePluginHostStarted() {
	vm.currentMu.Lock()
	if vm.hostEverStarted {
		vm.hostRestartCount++
	} else {
		vm.hostEverStarted = true
	}
	vm.currentMu.Unlock()
}

func (vm *pluginControlVM) notePluginHostFailure(err error) {
	if err == nil {
		return
	}
	vm.currentMu.Lock()
	vm.hostFailureCount++
	shift := min(vm.hostFailureCount-1, 16)
	delay := pluginHostRestartMinBackoff * time.Duration(1<<shift)
	if delay > pluginHostRestartMaxBackoff {
		delay = pluginHostRestartMaxBackoff
	}
	vm.hostRestartAfter = time.Now().Add(delay)
	vm.hostLastError = boundedPluginHostError(err.Error())
	vm.currentMu.Unlock()
}

func (vm *pluginControlVM) notePluginHostSuccess() {
	vm.currentMu.Lock()
	vm.hostFailureCount = 0
	vm.hostRestartAfter = time.Time{}
	vm.currentMu.Unlock()
}

func (rt *gojaPluginControlRuntime) pluginHostIsolationSnapshot(pluginID string) PluginControlIsolationState {
	state := PluginControlIsolationState{
		Enabled:           rt != nil && rt.cfg != nil && rt.cfg.PluginsIsolationEnabled(),
		Platform:          pluginHostPlatformLabel(),
		ResourceLimitMode: pluginHostResourceLimitMode(),
	}
	if rt == nil {
		return state
	}
	rt.mu.Lock()
	vms := make([]*pluginControlVM, 0)
	for _, vm := range rt.controlVMs {
		if vm.pluginID == pluginID {
			vms = append(vms, vm)
		}
	}
	for _, vm := range rt.pluginWorkers {
		if vm.pluginID == pluginID {
			vms = append(vms, vm)
		}
	}
	rt.mu.Unlock()
	degraded := make(map[string]struct{})
	sandboxModes := make(map[string]struct{})
	sandboxLevel := ""
	if state.ResourceLimitMode == "process_only" {
		degraded["hard memory, CPU, and process limits are unavailable on this platform"] = struct{}{}
	}
	for _, vm := range vms {
		vm.currentMu.Lock()
		client := vm.currentHost
		state.RestartCount += vm.hostRestartCount
		if vm.hostRestartAfter.After(parsePluginHostRuntimeTime(state.RestartBackoffUntil)) {
			state.RestartBackoffUntil = vm.hostRestartAfter.UTC().Format(time.RFC3339Nano)
		}
		if vm.hostLastError != "" {
			state.LastError = vm.hostLastError
		}
		vm.currentMu.Unlock()
		if client == nil || !client.Running() {
			continue
		}
		state.ProcessCount++
		if pid := client.PID(); pid > 0 {
			state.PIDs = append(state.PIDs, pid)
		}
		state.RSSBytes += client.RSS()
		sandbox := client.SandboxState()
		if sandbox.Mode != "" {
			sandboxModes[sandbox.Mode] = struct{}{}
		}
		if sandboxLevel == "" || pluginHostSandboxLevelRank(sandbox.Level) < pluginHostSandboxLevelRank(sandboxLevel) {
			sandboxLevel = sandbox.Level
		}
		for _, reason := range sandbox.Degraded {
			if reason = strings.TrimSpace(reason); reason != "" {
				degraded["sandbox: "+reason] = struct{}{}
			}
		}
		if reason := strings.TrimSpace(client.ResourceError()); reason != "" {
			degraded[reason] = struct{}{}
		}
	}
	if len(sandboxModes) > 0 {
		modes := make([]string, 0, len(sandboxModes))
		for mode := range sandboxModes {
			modes = append(modes, mode)
		}
		sort.Strings(modes)
		state.SandboxMode = strings.Join(modes, ",")
		state.SandboxLevel = sandboxLevel
	}
	sort.Ints(state.PIDs)
	if len(degraded) > 0 {
		reasons := make([]string, 0, len(degraded))
		for reason := range degraded {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		state.ResourceLimitDegraded = strings.Join(reasons, "; ")
		state.SandboxDegraded = state.ResourceLimitDegraded
	}
	return state
}

func pluginHostSandboxLevelRank(level string) int {
	switch level {
	case pluginSandboxLevelFull:
		return 3
	case pluginSandboxLevelPartial:
		return 2
	case pluginSandboxLevelMinimal:
		return 1
	case pluginSandboxLevelNone:
		return 0
	default:
		return -1
	}
}

func validatePluginHostSandboxAdmission(state PluginHostSandboxState, minimum string) error {
	minimum = strings.ToLower(strings.TrimSpace(minimum))
	if minimum == "" {
		minimum = pluginSandboxLevelFull
	}
	if !validPluginSandboxLevel(minimum) {
		return fmt.Errorf("invalid minimum plugin sandbox level %q", minimum)
	}
	actual := strings.ToLower(strings.TrimSpace(state.Level))
	if !validPluginSandboxLevel(actual) || actual == pluginSandboxLevelNone {
		return fmt.Errorf("plugin host reported invalid sandbox level %q", state.Level)
	}
	if pluginHostSandboxLevelRank(actual) < pluginHostSandboxLevelRank(minimum) {
		reason := strings.Join(state.Degraded, "; ")
		if reason != "" {
			return fmt.Errorf("plugin host sandbox level %s is below required %s: %s", actual, minimum, reason)
		}
		return fmt.Errorf("plugin host sandbox level %s is below required %s", actual, minimum)
	}
	return nil
}

func parsePluginHostRuntimeTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}
