package app

import (
	"errors"
	"fmt"
	"time"
)

// Plugins are native: their control code is a library run by a plugin
// worker. The host's own tests also use small JavaScript plugins to drive
// the host API; they register an engine for those here. Such a script calls
// the host through callPluginHostMethod, the dispatch native plugins use.
// Production builds register no engine, so a control script is refused.
var pluginControlScriptEngine func(host *pluginControlHost, plugin LoadedPlugin, source string, deadline time.Time) (pluginControlScript, error)

// pluginControlScript is one loaded control script.
type pluginControlScript interface {
	// run calls the handler a request names; a handler may call the host,
	// which may run a nested handler of the same script.
	run(request pluginHostEventRequest, deadline time.Time) (pluginHostEventResponse, error)
	// interrupt stops the running handler.
	interrupt(reason string)
	close()
}

var errPluginControlScriptUnsupported = errors.New("control scripts are not supported: control must name a native library")

func (vm *pluginControlVM) initScript(plugin LoadedPlugin) (*pluginControlHost, error) {
	engine := pluginControlScriptEngine
	if engine == nil {
		return nil, fmt.Errorf("plugin %s: %w", plugin.ID, errPluginControlScriptUnsupported)
	}
	source, err := readPluginControlScript(plugin)
	if err != nil {
		return nil, err
	}
	host, err := vm.newControlHost(plugin)
	if err != nil {
		return nil, err
	}
	script, err := engine(host, plugin, source, time.Now().Add(pluginControlTimeout))
	host.registrationPhase = false
	if err != nil {
		return nil, fmt.Errorf("run control script %s: %w", plugin.Control.Main, err)
	}
	vm.setScript(script)
	host.remoteEventInvoker = func(event pluginControlEvent, optionalHandler bool) (PluginRuntimeSurface, any, bool, error) {
		return vm.runScriptEvent(host, event, optionalHandler)
	}
	return host, nil
}

func (vm *pluginControlVM) setScript(script pluginControlScript) {
	vm.currentMu.Lock()
	previous := vm.script
	vm.script = script
	vm.currentMu.Unlock()
	if previous != nil && previous != script {
		previous.close()
	}
}

func (vm *pluginControlVM) currentScript() pluginControlScript {
	vm.currentMu.Lock()
	defer vm.currentMu.Unlock()
	return vm.script
}

func (vm *pluginControlVM) runScriptWithTimeout(host *pluginControlHost, req pluginControlRequest) pluginControlResult {
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
	result.surface, result.value, result.handled, result.err = vm.runScriptEvent(host, req.event, req.optionalHandler)
	return result
}

func (vm *pluginControlVM) runScriptEvent(host *pluginControlHost, event pluginControlEvent, optionalHandler bool) (PluginRuntimeSurface, any, bool, error) {
	script := vm.currentScript()
	if script == nil {
		return host.surface, nil, false, errPluginRuntimeTargetNotLoaded
	}
	deadline := host.executionDeadline
	if deadline.IsZero() {
		deadline = time.Now().Add(vm.rt.handlerTimeout())
	}
	return host.runRemoteEvent(event, optionalHandler, func(request pluginHostEventRequest) (pluginHostEventResponse, error) {
		if time.Until(deadline) <= 0 {
			return pluginHostEventResponse{}, fmt.Errorf("plugin handler deadline exceeded")
		}
		return script.run(request, deadline)
	})
}
