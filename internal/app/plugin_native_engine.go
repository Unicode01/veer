package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// initNative prepares the control host for a native plugin. Registration
// comes from the manifest and runs here, in the host; the plugin's library
// is only loaded when its first handler runs.
func (vm *pluginControlVM) initNative(plugin LoadedPlugin) (*pluginControlHost, error) {
	host, err := vm.newControlHost(plugin)
	if err != nil {
		return nil, err
	}
	host.registrationPhase = true
	defer func() { host.registrationPhase = false }()
	calls, err := pluginNativeRegisterCalls(plugin, currentPluginHostFeatureAvailability().Available)
	if err != nil {
		return nil, fmt.Errorf("native plugin registration: %w", err)
	}
	for _, call := range calls {
		if _, _, err := host.callPluginHostMethod(call.method, call.args); err != nil {
			return nil, fmt.Errorf("native plugin registration %s: %w", call.method, err)
		}
	}
	// A plugin's own runtime_apply resource changes made inside a handler are
	// applied after that handler returns: a native instance never runs two
	// handlers at once.
	host.remoteEventInvoker = func(event pluginControlEvent, _ bool) (PluginRuntimeSurface, any, bool, error) {
		vm.nativeDeferred = append(vm.nativeDeferred, event)
		return host.surface, nil, true, nil
	}
	return host, nil
}

func (vm *pluginControlVM) runNativeWithTimeout(host *pluginControlHost, req pluginControlRequest) pluginControlResult {
	if req.event.Kind == "register" {
		return pluginControlResult{surface: host.surface}
	}
	deadline := time.Now().Add(vm.rt.handlerTimeout())
	if req.state != nil && !req.state.deadline.IsZero() && req.state.deadline.Before(deadline) {
		deadline = req.state.deadline
	}
	host.executionDeadline = deadline
	vm.setExecuting(true)
	defer func() {
		host.executionDeadline = time.Time{}
		vm.setExecuting(false)
	}()

	var result pluginControlResult
	result.surface, result.value, result.handled, result.err = vm.runNativeEvent(host, req.plugin, req.event, req.optionalHandler, deadline)
	for len(vm.nativeDeferred) > 0 && !pluginHostFatalError(result.err) {
		deferred := vm.nativeDeferred[0]
		vm.nativeDeferred = vm.nativeDeferred[1:]
		_, _, _, err := vm.runNativeEvent(host, req.plugin, deferred, false, deadline)
		vm.finishDeferredNativeEvent(req.plugin, deferred, err)
		if pluginHostFatalError(err) && result.err == nil {
			result.err = err
		}
	}
	vm.nativeDeferred = nil
	return result
}

func (vm *pluginControlVM) finishDeferredNativeEvent(plugin LoadedPlugin, event pluginControlEvent, err error) {
	if event.Kind != "resource_apply" || event.Resource == nil || vm.rt == nil || vm.rt.db == nil {
		if err != nil {
			log.Printf("plugin %s deferred %s failed: %v", plugin.ID, event.Kind, err)
		}
		return
	}
	if err == nil {
		_ = markPluginRuntimeAppliedToCurrentRevision(vm.rt.db, plugin.ID, "resource", event.Resource.ID)
		return
	}
	log.Printf("plugin %s apply of its own resource %s failed: %v", plugin.ID, event.Resource.ID, err)
	_ = markPluginRuntimeError(vm.rt.db, plugin.ID, "resource", event.Resource.ID, err)
}

func (vm *pluginControlVM) runNativeEvent(host *pluginControlHost, plugin LoadedPlugin, event pluginControlEvent, optionalHandler bool, deadline time.Time) (PluginRuntimeSurface, any, bool, error) {
	return host.runRemoteEvent(event, optionalHandler, func(request pluginHostEventRequest) (pluginHostEventResponse, error) {
		if request.Probe {
			return pluginHostEventResponse{Handled: plugin.Control != nil && plugin.Control.UpgradeState}, nil
		}
		if pluginNativeDeclarativeOnly(plugin) {
			if request.Optional {
				return pluginHostEventResponse{}, nil
			}
			return pluginHostEventResponse{}, fmt.Errorf("%w: plugin %s declares no control library to handle %s", errPluginRuntimeTargetNotLoaded, plugin.ID, request.Handler)
		}
		instance, err := vm.nativeInstanceFor(plugin, deadline)
		if err != nil {
			return pluginHostEventResponse{}, err
		}
		payload, err := json.Marshal(request.Context)
		if err != nil {
			return pluginHostEventResponse{}, fmt.Errorf("encode handler context: %w", err)
		}
		status, reply, err := instance.exchange(pluginNativeMessageKind(event.Kind), request.Handler, payload, host.nativeCallHandler(), deadline)
		if err != nil {
			return pluginHostEventResponse{}, err
		}
		switch status {
		case pluginNativeStatusOK:
			if len(bytes.TrimSpace(reply)) == 0 {
				return pluginHostEventResponse{Handled: true, Undefined: true}, nil
			}
			return pluginHostEventResponse{Handled: true, Value: append(json.RawMessage(nil), reply...)}, nil
		case pluginNativeStatusUnhandled:
			if request.Optional {
				return pluginHostEventResponse{}, nil
			}
			return pluginHostEventResponse{}, fmt.Errorf("%w: native plugin %s does not handle %s", errPluginRuntimeTargetNotLoaded, plugin.ID, request.Handler)
		case pluginNativeStatusShutdown:
			// The instance is unusable (it panicked, or its worker is going
			// away): drop it so the next message starts a fresh one.
			vm.dropNativeInstance()
			return pluginHostEventResponse{Handled: true}, pluginHostProcessError(fmt.Errorf("native plugin %s: %s", plugin.ID, boundedPluginHostError(string(reply))))
		default:
			message := strings.TrimSpace(string(reply))
			if message == "" {
				message = fmt.Sprintf("status %d", status)
			}
			return pluginHostEventResponse{Handled: true}, fmt.Errorf("control handler %s failed: %s", request.Handler, boundedPluginHostError(message))
		}
	})
}

func (vm *pluginControlVM) nativeInstanceFor(plugin LoadedPlugin, deadline time.Time) (*pluginNativeInstance, error) {
	if vm.native != nil && !vm.native.closed.Load() && vm.native.worker.alive() {
		return vm.native, nil
	}
	vm.dropNativeInstance()
	if vm.rt == nil || vm.rt.nativePool == nil {
		return nil, errPluginRuntimeTargetNotLoaded
	}
	if err := vm.pluginHostRestartAllowed(time.Now()); err != nil {
		return nil, err
	}
	pluginID := plugin.ID
	rt := vm.rt
	instance, err := rt.nativePool.load(plugin, pluginNativeInstanceHooks{
		post: func(payload []byte) { rt.dispatchNativeWake(pluginID, payload) },
		log:  func(level int32, message string) { rt.appendNativePluginLog(pluginID, level, message) },
	}, deadline)
	if err != nil {
		vm.notePluginHostFailure(err)
		if errors.Is(err, errPluginNativeUnsupported) {
			return nil, fmt.Errorf("%w: %v", errPluginRuntimeTargetNotLoaded, err)
		}
		return nil, err
	}
	vm.notePluginHostStarted()
	vm.native = instance
	return instance, nil
}

func (vm *pluginControlVM) dropNativeInstance() {
	if vm.native == nil {
		return
	}
	instance := vm.native
	vm.native = nil
	instance.unload(time.Now().Add(2 * time.Second))
}

// nativeCallHandler serves the plugin's host API calls through the same
// method dispatch, permission checks and validation as every other plugin.
func (h *pluginControlHost) nativeCallHandler() pluginNativeCallHandler {
	return func(method string, arguments []byte) (int32, []byte) {
		if !pluginHostMethodAllowed(method) {
			return pluginNativeStatusInvalid, []byte(fmt.Sprintf("unknown host method %q", method))
		}
		var args []any
		if len(bytes.TrimSpace(arguments)) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(arguments))
			if err := decoder.Decode(&args); err != nil {
				return pluginNativeStatusInvalid, []byte(fmt.Sprintf("%s: arguments must be a JSON array: %v", method, err))
			}
		}
		if err := validatePluginHostJSONValue(args, 0); err != nil {
			return pluginNativeStatusInvalid, []byte(err.Error())
		}
		value, undefined, err := h.callPluginHostMethod(method, args)
		if err != nil {
			return pluginNativeStatusError, []byte(boundedPluginHostError(err.Error()))
		}
		if undefined || value == nil {
			return pluginNativeStatusOK, []byte("null")
		}
		data, err := json.Marshal(value)
		if err != nil {
			return pluginNativeStatusError, []byte(fmt.Sprintf("encode %s result: %v", method, err))
		}
		return pluginNativeStatusOK, data
	}
}

func (rt *pluginControlManager) dispatchNativeWake(pluginID string, payload []byte) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	vm := rt.controlVMs[pluginID]
	plugin, ok := rt.plugins[pluginID]
	rt.mu.Unlock()
	if vm == nil || !ok {
		return
	}
	if !json.Valid(payload) {
		payload = []byte("null")
	}
	if err := vm.dispatch(plugin, pluginControlEvent{Kind: "wake", Payload: append(json.RawMessage(nil), payload...)}, true); err != nil {
		log.Printf("plugin %s wake message dropped: %v", pluginID, err)
	}
}

func (rt *pluginControlManager) appendNativePluginLog(pluginID string, level int32, message string) {
	levelName := "info"
	switch level {
	case 0:
		levelName = "debug"
	case 2:
		levelName = "warn"
	case 3:
		levelName = "error"
	}
	message = boundedPluginControlHealthError(message)
	rt.appendPluginLog(PluginLogEntry{PluginID: pluginID, Level: levelName, Message: message})
	log.Printf("plugin %s %s: %s", pluginID, levelName, message)
}
