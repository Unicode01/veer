package app

import (
	"fmt"
	"strings"

	"github.com/dop251/goja"
)

func (h *pluginControlHost) callPluginHostMethod(method string, arguments []any) (value any, undefined bool, err error) {
	if h == nil || h.vm == nil {
		return nil, false, fmt.Errorf("plugin host capability broker is unavailable")
	}
	if method == pluginHostInternalModuleLoadMethod {
		if len(arguments) != 2 {
			return nil, false, fmt.Errorf("plugin module load expects referrer and request")
		}
		referrer, referrerOK := arguments[0].(string)
		request, requestOK := arguments[1].(string)
		if !referrerOK || !requestOK {
			return nil, false, fmt.Errorf("plugin module load paths must be strings")
		}
		source, resolveErr := resolvePluginControlModule(h.plugin, referrer, request)
		return source, false, resolveErr
	}
	if !pluginHostMethodAllowed(method) {
		return nil, false, fmt.Errorf("plugin host method %q is not allowed", method)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			switch typed := recovered.(type) {
			case *goja.Exception:
				err = fmt.Errorf("%s", typed.String())
			case error:
				err = typed
			default:
				err = fmt.Errorf("plugin host method %s panicked: %v", method, recovered)
			}
			value = nil
			undefined = false
		}
	}()

	parts := strings.Split(method, ".")
	if len(parts) < 2 {
		return nil, false, fmt.Errorf("invalid plugin host method %q", method)
	}
	current := h.vm.Get(parts[0])
	if current == nil || goja.IsUndefined(current) || goja.IsNull(current) {
		return nil, false, fmt.Errorf("plugin host API %s is unavailable", parts[0])
	}
	for _, part := range parts[1 : len(parts)-1] {
		current = current.ToObject(h.vm).Get(part)
		if current == nil || goja.IsUndefined(current) || goja.IsNull(current) {
			return nil, false, fmt.Errorf("plugin host API %s is unavailable", method)
		}
	}
	functionValue := current.ToObject(h.vm).Get(parts[len(parts)-1])
	function, ok := goja.AssertFunction(functionValue)
	if !ok {
		return nil, false, fmt.Errorf("plugin host API %s is not callable", method)
	}
	values := make([]goja.Value, len(arguments))
	for i, argument := range arguments {
		values[i] = h.vm.ToValue(argument)
	}
	result, callErr := function(goja.Undefined(), values...)
	if callErr != nil {
		return nil, false, callErr
	}
	if result == nil || goja.IsUndefined(result) {
		return nil, true, nil
	}
	exported := result.Export()
	if err := validatePluginHostJSONValue(exported, 0); err != nil {
		return nil, false, err
	}
	return exported, false, nil
}

func (h *pluginControlHost) runRemoteEvent(
	event pluginControlEvent,
	optionalHandler bool,
	invoke func(pluginHostEventRequest) (pluginHostEventResponse, error),
) (PluginRuntimeSurface, any, bool, error) {
	if h == nil || h.runtime == nil || invoke == nil {
		return PluginRuntimeSurface{}, nil, false, fmt.Errorf("isolated plugin host is unavailable")
	}
	eventKey := pluginControlEventKey(event)
	if len(h.eventStack) >= pluginControlMaxNestedEvents {
		return h.surface, nil, false, fmt.Errorf("plugin control nested event limit reached: %d", pluginControlMaxNestedEvents)
	}
	for _, active := range h.eventStack {
		if active == eventKey {
			return h.surface, nil, false, fmt.Errorf("plugin control recursive event rejected: %s", eventKey)
		}
	}
	h.eventStack = append(h.eventStack, eventKey)
	defer func() { h.eventStack = h.eventStack[:len(h.eventStack)-1] }()

	previousTimerEvent := h.timerEvent
	previousTimerOps := h.timerOps
	h.timerEvent = event.Timer
	h.timerOps = nil
	defer func() {
		h.timerEvent = previousTimerEvent
		h.timerOps = previousTimerOps
	}()
	handlerName := pluginControlHandlerName(event)
	if handlerName == "" {
		return h.surface, nil, false, nil
	}
	previousUpgradePhase := h.upgradePhase
	previousMigrationPhase := h.migrationPhase
	previousEBPFMigrationPhase := h.ebpfMigrationPhase
	previousResourceMutationTransaction := h.resourceMutationTransaction
	h.upgradePhase = event.Kind == "upgrade_snapshot" || event.Kind == "upgrade_restore"
	h.migrationPhase = event.Kind == "resource_migrate"
	h.ebpfMigrationPhase = event.Kind == "ebpf_state_migrate"
	h.resourceMutationTransaction = ""
	if event.Kind == "reconcile" {
		h.resourceMutationTransaction = h.runtime.currentPluginResourceMigrationTransaction()
	}
	defer func() {
		h.upgradePhase = previousUpgradePhase
		h.migrationPhase = previousMigrationPhase
		h.ebpfMigrationPhase = previousEBPFMigrationPhase
		h.resourceMutationTransaction = previousResourceMutationTransaction
	}()

	request := pluginHostEventRequest{
		Handler:       handlerName,
		Optional:      optionalHandler,
		Probe:         event.Kind == "upgrade_probe",
		CaptureResult: pluginHostEventNeedsResult(event),
		TimeoutMS:     pluginControlTimeout.Milliseconds(),
		Context:       pluginControlContext(h.plugin, event),
	}
	response, handlerErr := invoke(request)
	timerOps := append([]pluginControlTimerOperation(nil), h.timerOps...)
	if pluginHostFatalError(handlerErr) {
		return h.surface, nil, response.Handled, handlerErr
	}
	if timerErr := h.runtime.applyTimerOperations(h.plugin, timerOps); timerErr != nil {
		if handlerErr != nil {
			return h.surface, nil, response.Handled, fmt.Errorf("%v; apply timer operations: %w", handlerErr, timerErr)
		}
		return h.surface, nil, response.Handled, timerErr
	}
	if handlerErr != nil {
		return h.surface, nil, response.Handled, handlerErr
	}
	if !response.Handled {
		return h.surface, nil, false, nil
	}
	if !request.CaptureResult {
		return h.surface, nil, true, nil
	}
	value := goja.Undefined()
	if !response.Undefined && len(response.Value) > 0 {
		exported, err := decodePluginHostJSONValue(response.Value)
		if err != nil {
			return h.surface, nil, true, fmt.Errorf("decode isolated handler result: %w", err)
		}
		value = h.vm.ToValue(exported)
	}
	switch {
	case event.Kind == "upgrade_snapshot":
		result, err := h.exportUpgradeState(value)
		return h.surface, result, true, err
	case event.Kind == "resource_migrate":
		result, err := h.exportResourceMigrationResult(value, event.Resource)
		return h.surface, result, true, err
	case event.Kind == "ebpf_state_migrate":
		result, err := h.exportEBPFStateMigrationResult(value)
		return h.surface, result, true, err
	case event.Kind == "worker":
		result, err := h.exportWorkerResult(value)
		return h.surface, result, true, err
	case event.Kind == "action" && event.Action != nil && event.Action.RuntimeUpdate == "runtime_query":
		result, err := h.exportQueryResult(value)
		return h.surface, result, true, err
	default:
		return h.surface, nil, true, nil
	}
}

func pluginHostEventNeedsResult(event pluginControlEvent) bool {
	if event.Kind == "upgrade_snapshot" || event.Kind == "resource_migrate" || event.Kind == "ebpf_state_migrate" || event.Kind == "worker" {
		return true
	}
	return event.Kind == "action" && event.Action != nil && event.Action.RuntimeUpdate == "runtime_query"
}
