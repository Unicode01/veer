package app

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	pluginHostRestartMinBackoff = 250 * time.Millisecond
	pluginHostRestartMaxBackoff = 30 * time.Second
)

// errPluginHostProcessExited marks a handler failure that left the plugin's
// instance unusable (its worker exited or it panicked): the next message
// starts a fresh instance, after the restart backoff.
var errPluginHostProcessExited = errors.New("plugin process exited")

func pluginHostProcessError(err error) error {
	if err == nil {
		return errPluginHostProcessExited
	}
	if errors.Is(err, errPluginHostProcessExited) {
		return err
	}
	return fmt.Errorf("%w: %v", errPluginHostProcessExited, err)
}

func pluginHostFatalError(err error) bool {
	return errors.Is(err, errPluginHostProcessExited)
}

func boundedPluginHostError(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return "plugin host request failed"
	}
	if len(message) <= pluginHostMaxErrorBytes {
		return message
	}
	return message[:pluginHostMaxErrorBytes] + "...<truncated>"
}

func pluginHostPlatformLabel() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

func (vm *pluginControlVM) pluginHostRestartAllowed(now time.Time) error {
	vm.currentMu.Lock()
	defer vm.currentMu.Unlock()
	if vm.hostRestartAfter.IsZero() || !now.Before(vm.hostRestartAfter) {
		return nil
	}
	return fmt.Errorf(
		"plugin restart backoff active for %s (until %s)",
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

// pluginHostIsolationSnapshot reports the worker processes that run a
// plugin's instances and how often those instances were restarted. A
// shared worker's memory counts for every plugin it runs.
func (rt *pluginControlManager) pluginHostIsolationSnapshot(pluginID string) PluginControlIsolationState {
	state := PluginControlIsolationState{Enabled: true, Platform: pluginHostPlatformLabel()}
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
	pool := rt.nativePool
	rt.mu.Unlock()
	for _, vm := range vms {
		vm.currentMu.Lock()
		state.RestartCount += vm.hostRestartCount
		if vm.hostRestartAfter.After(parsePluginHostRuntimeTime(state.RestartBackoffUntil)) {
			state.RestartBackoffUntil = vm.hostRestartAfter.UTC().Format(time.RFC3339Nano)
		}
		if vm.hostLastError != "" {
			state.LastError = vm.hostLastError
		}
		vm.currentMu.Unlock()
	}
	if pool != nil {
		for _, worker := range pool.snapshot() {
			if !slices.Contains(worker.Plugins, pluginID) {
				continue
			}
			state.ProcessCount++
			if worker.PID > 0 {
				state.PIDs = append(state.PIDs, worker.PID)
			}
			state.RSSBytes += worker.RSSBytes
		}
	}
	sort.Ints(state.PIDs)
	return state
}

func parsePluginHostRuntimeTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}
