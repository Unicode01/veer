package app

import (
	"bytes"
	"crypto/md5"
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"forward/internal/store"

	"github.com/dop251/goja"
)

const (
	pluginControlKVResourceID          = "__kv"
	pluginControlSecretResourceID      = "__secret"
	pluginControlTimeout               = 20 * time.Second
	pluginControlMaxSecretBytes        = 4096
	pluginControlMaxSecrets            = 128
	pluginControlMaxKVRecords          = 1024
	pluginControlMaxKVRecordBytes      = 64 << 10
	pluginControlMaxLogMessageBytes    = 4096
	pluginControlMaxRandomBytes        = 1024
	pluginControlMaxTimerPayloadBytes  = 16 << 10
	pluginControlMaxTimersPerPlugin    = 64
	pluginControlMinTimerDelay         = 10 * time.Millisecond
	pluginControlMaxTimerDelay         = 24 * time.Hour
	pluginControlExecutionLockTimeout  = pluginControlTimeout + 2*time.Second
	pluginControlQueueSize             = 64
	pluginControlWorkerQueueSize       = 64
	pluginControlMaxWorkersPerPlugin   = 16
	pluginControlWorkerMaxPayloadBytes = 1 << 20
	pluginControlTimerKindTimeout      = "timeout"
	pluginControlTimerKindInterval     = "interval"
	pluginControlTimerOperationSet     = "set"
	pluginControlTimerOperationClear   = "clear"
	pluginControlTimerRuntimeTarget    = "timer"
	pluginControlTimerRuntimeStatusErr = "error"
	pluginControlTimerRuntimeStatusOK  = "completed"
)

var pluginControlReservedMapNames = map[string]string{
	"tc_prog_chain_v4": "shared fvtap TC tail-call chain",
	"tc_plugin_ctx_v4": "shared fvtap TC packet context",
	"xdp_prog_chain":   "shared XDP tail-call chain",
}

type pluginControlRuntime interface {
	pluginRuntimeDataApplier
	Reconcile(catalog PluginCatalog) pluginRuntimeSnapshot
	Snapshot() pluginRuntimeSnapshot
	Close() error
}

type pluginEBPFMapController interface {
	GetPluginMapValue(pluginID string, objectID string, mapName string, key []byte) ([]byte, error)
	PutPluginMapValue(pluginID string, objectID string, mapName string, key []byte, value []byte) error
	DeletePluginMapValue(pluginID string, objectID string, mapName string, key []byte) error
	ClearPluginMap(pluginID string, objectID string, mapName string) error
}

type pluginRuntimeDataApplierProvider interface {
	PluginRuntimeDataAppliers() []pluginRuntimeDataApplier
}

type pluginResourceRuntimeUpdateProvider interface {
	ApplyPluginResourceRuntimeUpdate(plugin LoadedPlugin, resource PluginResource) error
}

type pluginActionRuntimeUpdateProvider interface {
	ApplyPluginActionRuntimeUpdate(plugin LoadedPlugin, action PluginAction, payload json.RawMessage) error
}

type pluginResourceControlReconcileProvider interface {
	ApplyPluginResourceReconcileFromControl(plugin LoadedPlugin, resource PluginResource) error
}

type gojaPluginControlRuntime struct {
	mu                   sync.Mutex
	db                   *sql.DB
	cfg                  *Config
	mapController        pluginEBPFMapController
	dataApplierProvider  pluginRuntimeDataApplierProvider
	updateProvider       pluginResourceRuntimeUpdateProvider
	actionUpdateProvider pluginActionRuntimeUpdateProvider
	l2Transport          pluginControlL2Transport
	udpTransport         pluginControlUDPTransport
	netAdmin             pluginControlNetAdmin
	snapshot             pluginRuntimeSnapshot
	plugins              map[string]LoadedPlugin
	timers               map[pluginControlTimerKey]pluginControlTimerState
	controlVMs           map[string]*pluginControlVM
	pluginWorkers        map[pluginControlWorkerKey]*pluginControlVM
	closed               bool
}

type pluginControlEvent struct {
	Kind     string
	Resource *PluginResource
	Action   *PluginAction
	Timer    *pluginControlTimerSpec
	Records  []PluginResourceRecord
	Payload  json.RawMessage
	Worker   *pluginControlWorkerEvent
}

type pluginControlWorkerEvent struct {
	Name    string
	Handler string
}

type pluginControlRequest struct {
	plugin          LoadedPlugin
	event           pluginControlEvent
	optionalHandler bool
	reply           chan pluginControlResult
}

type pluginControlResult struct {
	surface PluginRuntimeSurface
	value   any
	err     error
}

type pluginControlVM struct {
	rt         *gojaPluginControlRuntime
	pluginID   string
	key        string
	mode       string
	workerName string
	requests   chan pluginControlRequest
	stop       chan struct{}
	done       chan struct{}
	stopOnce   sync.Once
}

type pluginControlWorkerKey struct {
	pluginID string
	name     string
}

type pluginControlHost struct {
	vm                *goja.Runtime
	db                *sql.DB
	cfg               *Config
	runtime           *gojaPluginControlRuntime
	plugin            LoadedPlugin
	mapController     pluginEBPFMapController
	l2Transport       pluginControlL2Transport
	udpTransport      pluginControlUDPTransport
	netAdmin          pluginControlNetAdmin
	timerOps          []pluginControlTimerOperation
	timerEvent        *pluginControlTimerSpec
	surface           PluginRuntimeSurface
	module            *goja.Object
	registrationPhase bool
	workerVM          bool
	workerName        string
}

type pluginControlTimerKey struct {
	pluginID string
	name     string
}

type pluginControlTimerSpec struct {
	Name     string
	Kind     string
	Delay    time.Duration
	Payload  json.RawMessage
	NextFire time.Time
}

type pluginControlTimerState struct {
	spec       pluginControlTimerSpec
	timer      *time.Timer
	generation uint64
}

type pluginControlTimerOperation struct {
	op   string
	spec pluginControlTimerSpec
}

func newPluginControlRuntime(db *sql.DB, cfg *Config, mapController pluginEBPFMapController) pluginControlRuntime {
	provider, _ := mapController.(pluginRuntimeDataApplierProvider)
	updateProvider, _ := mapController.(pluginResourceRuntimeUpdateProvider)
	actionUpdateProvider, _ := mapController.(pluginActionRuntimeUpdateProvider)
	return &gojaPluginControlRuntime{
		db:                   db,
		cfg:                  cfg,
		mapController:        mapController,
		dataApplierProvider:  provider,
		updateProvider:       updateProvider,
		actionUpdateProvider: actionUpdateProvider,
		l2Transport:          newPluginControlL2Transport(),
		udpTransport:         newPluginControlUDPTransport(),
		netAdmin:             newPluginControlNetAdmin(),
		timers:               make(map[pluginControlTimerKey]pluginControlTimerState),
		controlVMs:           make(map[string]*pluginControlVM),
		pluginWorkers:        make(map[pluginControlWorkerKey]*pluginControlVM),
	}
}

func (rt *gojaPluginControlRuntime) Reconcile(catalog PluginCatalog) pluginRuntimeSnapshot {
	activePlugins := make([]LoadedPlugin, 0, len(catalog.Plugins))
	states := make(map[string]PluginRuntimeState)
	surfaces := make(map[string]PluginRuntimeSurface)
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive || plugin.controlMainPath == "" {
			continue
		}
		if ok, reason := pluginControlRegistrationAllowed(plugin); !ok {
			states[plugin.ID] = PluginRuntimeState{
				Mode:       pluginRuntimeModeRegistered,
				Attachable: false,
				Attached:   false,
				Reason:     reason,
			}
			continue
		}
		activePlugins = append(activePlugins, plugin)
	}

	registeredByID := make(map[string]LoadedPlugin, len(activePlugins))
	for _, plugin := range activePlugins {
		surface, err := rt.runPluginControlWithSurface(plugin, pluginControlEvent{Kind: "register"}, true)
		if err != nil {
			state := pluginRuntimeErrorState(err.Error())
			state.Reason = "control script registration failed"
			states[plugin.ID] = state
			continue
		}
		registered := plugin
		applyPluginRuntimeSurface(&registered, surface)
		if registered.Status != pluginStatusActive {
			state := pluginRuntimeErrorState(registered.Error)
			state.Reason = "control script surface validation failed"
			states[plugin.ID] = state
			continue
		}
		surfaces[plugin.ID] = surface
		if ok, reason := pluginControlStabilityAllowed(registered, rt.cfg); !ok {
			states[plugin.ID] = PluginRuntimeState{
				Mode:       pluginRuntimeModeRegistered,
				Attachable: false,
				Attached:   false,
				Reason:     reason,
			}
			continue
		}
		registeredByID[plugin.ID] = registered
	}

	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		return pluginRuntimeSnapshot{}
	}
	rt.plugins = registeredByID
	rt.cancelInactivePluginTimersLocked(registeredByID)
	inactiveVMs := rt.inactivePluginControlVMsLocked(registeredByID)
	rt.mu.Unlock()
	stopPluginControlVMs(inactiveVMs)

	for _, plugin := range registeredByID {
		if _, failed := states[plugin.ID]; failed {
			continue
		}
		state := PluginRuntimeState{
			Mode:       pluginRuntimeModeControl,
			Attachable: false,
			Attached:   false,
			Reason:     "control script loaded",
		}
		if _, err := rt.runPluginControlWithSurface(plugin, pluginControlEvent{Kind: "reconcile"}, true); err != nil {
			state = pluginRuntimeErrorState(err.Error())
			state.Reason = "control script reconcile failed"
		} else if err := rt.applyRuntimeResourcesForReconcile(plugin); err != nil {
			state = pluginRuntimeErrorState(err.Error())
			state.Reason = "control script runtime resource reconcile failed"
		}
		states[plugin.ID] = state
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.snapshot = pluginRuntimeSnapshot{Plugins: states, Surfaces: surfaces}
	return clonePluginRuntimeSnapshot(rt.snapshot)
}

func (rt *gojaPluginControlRuntime) Snapshot() pluginRuntimeSnapshot {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return clonePluginRuntimeSnapshot(rt.snapshot)
}

func (rt *gojaPluginControlRuntime) Close() error {
	rt.mu.Lock()
	rt.closed = true
	rt.snapshot = pluginRuntimeSnapshot{}
	rt.plugins = nil
	for key, state := range rt.timers {
		if state.timer != nil {
			state.timer.Stop()
		}
		delete(rt.timers, key)
	}
	vms := rt.allPluginControlVMsLocked()
	rt.controlVMs = nil
	rt.pluginWorkers = nil
	rt.mu.Unlock()
	stopPluginControlVMs(vms)
	return nil
}

func (rt *gojaPluginControlRuntime) ApplyPluginResourceData(plugin LoadedPlugin, resource PluginResource, records []PluginResourceRecord) error {
	if rt == nil || rt.db == nil || plugin.controlMainPath == "" {
		return errPluginRuntimeTargetNotLoaded
	}
	rt.ensurePluginCatalogForControlEvents()
	rt.registerPluginForControlEvents(plugin)
	return rt.runPluginControl(plugin, pluginControlEvent{
		Kind:     "resource_apply",
		Resource: &resource,
		Records:  records,
	}, false)
}

func (rt *gojaPluginControlRuntime) ApplyPluginAction(plugin LoadedPlugin, action PluginAction, payload json.RawMessage) error {
	if rt == nil || rt.db == nil || plugin.controlMainPath == "" {
		return errPluginRuntimeTargetNotLoaded
	}
	rt.ensurePluginCatalogForControlEvents()
	rt.registerPluginForControlEvents(plugin)
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	return rt.runPluginControl(plugin, pluginControlEvent{
		Kind:    "action",
		Action:  &action,
		Payload: payload,
	}, false)
}

func (rt *gojaPluginControlRuntime) ensurePluginCatalogForControlEvents() {
	if rt == nil || rt.cfg == nil {
		return
	}
	rt.mu.Lock()
	if rt.closed || len(rt.plugins) > 0 {
		rt.mu.Unlock()
		return
	}
	rt.mu.Unlock()

	catalog := loadPluginCatalog(rt.cfg)
	registeredByID := make(map[string]LoadedPlugin)
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive || plugin.controlMainPath == "" {
			continue
		}
		if ok, _ := pluginControlRegistrationAllowed(plugin); !ok {
			continue
		}
		surface, err := rt.runPluginControlWithSurface(plugin, pluginControlEvent{Kind: "register"}, true)
		if err != nil {
			continue
		}
		registered := plugin
		applyPluginRuntimeSurface(&registered, surface)
		if registered.Status == pluginStatusActive {
			registeredByID[registered.ID] = registered
		}
	}

	rt.mu.Lock()
	if rt.closed || len(rt.plugins) > 0 {
		rt.mu.Unlock()
		return
	}
	rt.plugins = registeredByID
	rt.cancelInactivePluginTimersLocked(registeredByID)
	inactiveVMs := rt.inactivePluginControlVMsLocked(registeredByID)
	rt.mu.Unlock()
	stopPluginControlVMs(inactiveVMs)
}

func (rt *gojaPluginControlRuntime) registerPluginForControlEvents(plugin LoadedPlugin) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return
	}
	if rt.plugins == nil {
		rt.plugins = make(map[string]LoadedPlugin)
	}
	if existing, ok := rt.plugins[plugin.ID]; ok && loadedPluginHasRuntimeSurface(existing) && !loadedPluginHasRuntimeSurface(plugin) {
		return
	}
	rt.plugins[plugin.ID] = plugin
}

func loadedPluginHasRuntimeSurface(plugin LoadedPlugin) bool {
	return len(plugin.Capabilities) > 0 ||
		len(plugin.VirtualInterfaces) > 0 ||
		len(plugin.Objects) > 0 ||
		len(plugin.Hooks) > 0 ||
		len(plugin.Resources) > 0 ||
		len(plugin.Actions) > 0 ||
		plugin.UI != nil
}

func (rt *gojaPluginControlRuntime) runPluginControl(plugin LoadedPlugin, event pluginControlEvent, optionalHandler bool) error {
	_, err := rt.runPluginControlWithSurface(plugin, event, optionalHandler)
	return err
}

func (rt *gojaPluginControlRuntime) runPluginControlWithSurface(plugin LoadedPlugin, event pluginControlEvent, optionalHandler bool) (PluginRuntimeSurface, error) {
	vm, err := rt.getPluginControlVM(plugin, "", "")
	if err != nil {
		return PluginRuntimeSurface{}, err
	}
	result, err := vm.run(plugin, event, optionalHandler)
	if err != nil {
		return result.surface, err
	}
	return result.surface, nil
}

func (rt *gojaPluginControlRuntime) getPluginControlVM(plugin LoadedPlugin, mode string, workerName string) (*pluginControlVM, error) {
	if mode == "" {
		mode = "control"
	}
	key, err := pluginControlVMKey(plugin, mode, workerName)
	if err != nil {
		return nil, err
	}

	var old *pluginControlVM
	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		return nil, errPluginRuntimeTargetNotLoaded
	}
	if rt.controlVMs == nil {
		rt.controlVMs = make(map[string]*pluginControlVM)
	}
	if rt.pluginWorkers == nil {
		rt.pluginWorkers = make(map[pluginControlWorkerKey]*pluginControlVM)
	}
	if mode == "worker" {
		workerKey := pluginControlWorkerKey{pluginID: plugin.ID, name: workerName}
		if existing := rt.pluginWorkers[workerKey]; existing != nil && existing.key == key {
			rt.mu.Unlock()
			return existing, nil
		} else if existing != nil {
			old = existing
		}
		if old == nil && rt.pluginWorkerCountLocked(plugin.ID) >= pluginControlMaxWorkersPerPlugin {
			rt.mu.Unlock()
			return nil, fmt.Errorf("plugin worker limit reached: %d", pluginControlMaxWorkersPerPlugin)
		}
		vm := newPluginControlVM(rt, plugin.ID, key, mode, workerName)
		rt.pluginWorkers[workerKey] = vm
		rt.mu.Unlock()
		if old != nil {
			old.stopVM()
		}
		return vm, nil
	}
	if existing := rt.controlVMs[plugin.ID]; existing != nil && existing.key == key {
		rt.mu.Unlock()
		return existing, nil
	} else if existing != nil {
		old = existing
	}
	oldWorkers := rt.pluginControlWorkersLocked(plugin.ID)
	vm := newPluginControlVM(rt, plugin.ID, key, mode, "")
	rt.controlVMs[plugin.ID] = vm
	rt.mu.Unlock()
	if old != nil {
		old.stopVM()
	}
	stopPluginControlVMs(oldWorkers)
	return vm, nil
}

func newPluginControlVM(rt *gojaPluginControlRuntime, pluginID string, key string, mode string, workerName string) *pluginControlVM {
	queueSize := pluginControlQueueSize
	if mode == "worker" {
		queueSize = pluginControlWorkerQueueSize
	}
	vm := &pluginControlVM{
		rt:         rt,
		pluginID:   pluginID,
		key:        key,
		mode:       mode,
		workerName: workerName,
		requests:   make(chan pluginControlRequest, queueSize),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	go vm.loop()
	return vm
}

func (vm *pluginControlVM) run(plugin LoadedPlugin, event pluginControlEvent, optionalHandler bool) (pluginControlResult, error) {
	reply := make(chan pluginControlResult, 1)
	req := pluginControlRequest{
		plugin:          plugin,
		event:           event,
		optionalHandler: optionalHandler,
		reply:           reply,
	}
	queueTimer := time.NewTimer(pluginControlExecutionLockTimeout)
	select {
	case vm.requests <- req:
		queueTimer.Stop()
	case <-vm.done:
		queueTimer.Stop()
		return pluginControlResult{}, errPluginRuntimeTargetNotLoaded
	case <-queueTimer.C:
		return pluginControlResult{}, fmt.Errorf("plugin control queue timed out for %s", vm.pluginID)
	}
	execTimer := time.NewTimer(pluginControlExecutionLockTimeout)
	defer execTimer.Stop()
	select {
	case result := <-reply:
		return result, result.err
	case <-vm.done:
		return pluginControlResult{}, errPluginRuntimeTargetNotLoaded
	case <-execTimer.C:
		return pluginControlResult{}, fmt.Errorf("plugin control execution timed out for %s", vm.pluginID)
	}
}

func (vm *pluginControlVM) dispatch(plugin LoadedPlugin, event pluginControlEvent, optionalHandler bool) error {
	req := pluginControlRequest{
		plugin:          plugin,
		event:           event,
		optionalHandler: optionalHandler,
	}
	timer := time.NewTimer(pluginControlExecutionLockTimeout)
	defer timer.Stop()
	select {
	case vm.requests <- req:
		return nil
	case <-vm.done:
		return errPluginRuntimeTargetNotLoaded
	case <-timer.C:
		return fmt.Errorf("plugin worker queue timed out for %s/%s", vm.pluginID, vm.workerName)
	}
}

func (vm *pluginControlVM) loop() {
	defer close(vm.done)
	var host *pluginControlHost
	for {
		select {
		case <-vm.stop:
			return
		case req := <-vm.requests:
			if host == nil {
				var err error
				host, err = vm.init(req.plugin)
				if err != nil {
					vm.reply(req, pluginControlResult{err: err})
					continue
				}
			}
			host.plugin = req.plugin
			result := vm.runWithTimeout(host, req)
			vm.reply(req, result)
		}
	}
}

func (vm *pluginControlVM) init(plugin LoadedPlugin) (*pluginControlHost, error) {
	source, err := readPluginControlScript(plugin)
	if err != nil {
		return nil, err
	}
	runtime := goja.New()
	host := &pluginControlHost{
		vm:                runtime,
		db:                vm.rt.db,
		cfg:               vm.rt.cfg,
		runtime:           vm.rt,
		plugin:            plugin,
		mapController:     vm.rt.mapController,
		l2Transport:       vm.rt.l2Transport,
		udpTransport:      vm.rt.udpTransport,
		netAdmin:          vm.rt.netAdmin,
		registrationPhase: true,
		workerVM:          vm.mode == "worker",
		workerName:        vm.workerName,
	}
	if err := host.install(); err != nil {
		return nil, err
	}
	exports := runtime.NewObject()
	module := runtime.NewObject()
	if err := module.Set("exports", exports); err != nil {
		return nil, err
	}
	if err := runtime.Set("exports", exports); err != nil {
		return nil, err
	}
	if err := runtime.Set("module", module); err != nil {
		return nil, err
	}
	host.module = module
	err = withPluginControlTimeout(runtime, func() error {
		_, runErr := runtime.RunScript(plugin.Control.Main, source)
		return runErr
	})
	host.registrationPhase = false
	if err != nil {
		return nil, fmt.Errorf("run control script %s: %w", plugin.Control.Main, err)
	}
	return host, nil
}

func (vm *pluginControlVM) runWithTimeout(host *pluginControlHost, req pluginControlRequest) pluginControlResult {
	var result pluginControlResult
	err := withPluginControlTimeout(host.vm, func() error {
		var runErr error
		result.surface, result.value, runErr = host.runEvent(req.event, req.optionalHandler)
		return runErr
	})
	if err != nil {
		result.err = err
	}
	return result
}

func (vm *pluginControlVM) reply(req pluginControlRequest, result pluginControlResult) {
	if req.reply != nil {
		req.reply <- result
		return
	}
	if result.err != nil {
		if req.event.Worker != nil {
			log.Printf("plugin worker %s/%s handler %s failed: %v", vm.pluginID, vm.workerName, req.event.Worker.Handler, result.err)
			return
		}
		log.Printf("plugin control %s event %s failed: %v", vm.pluginID, req.event.Kind, result.err)
	}
}

func (vm *pluginControlVM) stopVM() {
	vm.stopOnce.Do(func() {
		close(vm.stop)
		select {
		case <-vm.done:
		case <-time.After(pluginControlExecutionLockTimeout):
			log.Printf("plugin control VM %s/%s did not stop before timeout", vm.pluginID, vm.workerName)
		}
	})
}

func withPluginControlTimeout(vm *goja.Runtime, fn func() error) error {
	interruptDone := make(chan struct{})
	timer := time.AfterFunc(pluginControlTimeout, func() {
		vm.Interrupt("plugin control script timed out")
		close(interruptDone)
	})
	err := fn()
	if !timer.Stop() {
		<-interruptDone
	}
	vm.ClearInterrupt()
	return err
}

func (h *pluginControlHost) runEvent(event pluginControlEvent, optionalHandler bool) (PluginRuntimeSurface, any, error) {
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
		return h.surface, nil, nil
	}
	handlerValue := h.module.Get("exports").ToObject(h.vm).Get(handlerName)
	if handlerValue == nil || goja.IsUndefined(handlerValue) || goja.IsNull(handlerValue) {
		if optionalHandler {
			return h.surface, nil, nil
		}
		return h.surface, nil, fmt.Errorf("%w: control script %s does not export %s", errPluginRuntimeTargetNotLoaded, h.plugin.Control.Main, handlerName)
	}
	handler, ok := goja.AssertFunction(handlerValue)
	if !ok {
		return h.surface, nil, fmt.Errorf("control export %s is not a function", handlerName)
	}
	value, handlerErr := handler(goja.Undefined(), h.vm.ToValue(pluginControlContext(h.plugin, event)))
	if handlerErr != nil {
		handlerErr = fmt.Errorf("control handler %s failed: %w", handlerName, handlerErr)
	}
	timerOps := append([]pluginControlTimerOperation(nil), h.timerOps...)
	if err := h.runtime.applyTimerOperations(h.plugin, timerOps); err != nil {
		if handlerErr != nil {
			return h.surface, nil, fmt.Errorf("%v; apply timer operations: %w", handlerErr, err)
		}
		return h.surface, nil, err
	}
	if handlerErr != nil {
		return h.surface, nil, handlerErr
	}
	if event.Kind == "worker" {
		result, err := h.exportWorkerResult(value)
		if err != nil {
			return h.surface, nil, err
		}
		return h.surface, result, nil
	}
	return h.surface, nil, nil
}

func (h *pluginControlHost) exportWorkerResult(value goja.Value) (any, error) {
	if value == nil || goja.IsUndefined(value) {
		return nil, nil
	}
	data, err := json.Marshal(value.Export())
	if err != nil {
		return nil, fmt.Errorf("worker result is not JSON serializable: %w", err)
	}
	if len(data) > pluginControlWorkerMaxPayloadBytes {
		return nil, fmt.Errorf("worker result exceeds %d bytes", pluginControlWorkerMaxPayloadBytes)
	}
	return pluginControlDecodeJSON(json.RawMessage(data)), nil
}

func pluginControlVMKey(plugin LoadedPlugin, mode string, workerName string) (string, error) {
	if plugin.Control == nil || plugin.controlMainPath == "" {
		return "", errPluginRuntimeTargetNotLoaded
	}
	sum := plugin.Control.ResolvedSHA256
	if sum == "" {
		var err error
		sum, err = sha256File(plugin.controlMainPath)
		if err != nil {
			return "", fmt.Errorf("hash control.main: %w", err)
		}
	}
	controlJSON, err := json.Marshal(plugin.Control)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{mode, workerName, plugin.controlMainPath, sum, string(controlJSON)}, "\x00"), nil
}

func (rt *gojaPluginControlRuntime) applyRuntimeResourcesForReconcile(plugin LoadedPlugin) error {
	if rt == nil || rt.db == nil {
		return nil
	}
	failures := make([]string, 0)
	for _, resource := range plugin.Resources {
		if resource.RuntimeUpdate != "runtime_apply" {
			continue
		}
		current := resource
		records, err := loadPluginResourceRecords(rt.db, plugin, current)
		if err != nil {
			_ = markPluginRuntimeError(rt.db, plugin.ID, "resource", current.ID, err)
			failures = append(failures, current.ID+": "+err.Error())
			continue
		}
		status, err := store.PluginRuntimeStatusOrNil(rt.db, plugin.ID, "resource", current.ID)
		if err != nil {
			_ = markPluginRuntimeError(rt.db, plugin.ID, "resource", current.ID, err)
			failures = append(failures, current.ID+": "+err.Error())
			continue
		}
		if len(records) == 0 && (status == nil || status.Status == "applied") {
			continue
		}
		err = rt.runPluginControl(plugin, pluginControlEvent{
			Kind:     "resource_apply",
			Resource: &current,
			Records:  records,
		}, false)
		if err != nil {
			_ = markPluginRuntimeError(rt.db, plugin.ID, "resource", current.ID, err)
			failures = append(failures, current.ID+": "+err.Error())
			continue
		}
		if err := markPluginRuntimeAppliedToCurrentRevision(rt.db, plugin.ID, "resource", current.ID); err != nil {
			failures = append(failures, current.ID+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("runtime_apply resource reconcile failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

func readPluginControlScript(plugin LoadedPlugin) (string, error) {
	if plugin.controlMainPath == "" {
		return "", errPluginRuntimeTargetNotLoaded
	}
	info, err := os.Stat(plugin.controlMainPath)
	if err != nil {
		return "", fmt.Errorf("control.main: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("control.main is a directory")
	}
	if info.Size() > pluginControlMaxSize {
		return "", fmt.Errorf("control.main exceeds %d bytes", pluginControlMaxSize)
	}
	data, err := os.ReadFile(plugin.controlMainPath) // #nosec G304 -- controlMainPath is symlink-resolved and checked against plugin root at load time.
	if err != nil {
		return "", fmt.Errorf("read control.main: %w", err)
	}
	return string(data), nil
}

func pluginControlHandlerName(event pluginControlEvent) string {
	switch event.Kind {
	case "register":
		return ""
	case "resource_apply":
		return "onResourceApply"
	case "action":
		return "onAction"
	case "timer":
		return "onTimer"
	case "worker":
		if event.Worker == nil {
			return ""
		}
		return event.Worker.Handler
	default:
		return "onReconcile"
	}
}

func pluginControlContext(plugin LoadedPlugin, event pluginControlEvent) map[string]any {
	ctx := map[string]any{
		"kind": event.Kind,
		"plugin": map[string]any{
			"id":      plugin.ID,
			"name":    plugin.Name,
			"version": plugin.Version,
		},
	}
	if event.Resource != nil {
		ctx["resource"] = map[string]any{
			"id":             event.Resource.ID,
			"runtime_update": event.Resource.RuntimeUpdate,
		}
		records := make([]map[string]any, 0, len(event.Records))
		for _, record := range event.Records {
			records = append(records, map[string]any{
				"key":        record.Key,
				"data":       pluginControlDecodeJSON(record.Data),
				"enabled":    record.Enabled,
				"revision":   record.Revision,
				"updated_at": record.UpdatedAt,
			})
		}
		ctx["records"] = records
	}
	if event.Action != nil {
		ctx["action"] = map[string]any{
			"id":             event.Action.ID,
			"runtime_update": event.Action.RuntimeUpdate,
		}
		ctx["payload"] = pluginControlDecodeJSON(event.Payload)
	}
	if event.Timer != nil {
		ctx["timer"] = map[string]any{
			"name":      event.Timer.Name,
			"kind":      event.Timer.Kind,
			"delay_ms":  event.Timer.Delay.Milliseconds(),
			"payload":   pluginControlDecodeJSON(event.Timer.Payload),
			"next_fire": event.Timer.NextFire.UTC().Format(time.RFC3339Nano),
			"fired_at":  time.Now().UTC().Format(time.RFC3339Nano),
		}
	}
	if event.Worker != nil {
		ctx["worker"] = map[string]any{
			"name":    event.Worker.Name,
			"handler": event.Worker.Handler,
		}
		ctx["payload"] = pluginControlDecodeJSON(event.Payload)
	}
	return ctx
}

func pluginControlDecodeJSON(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return string(raw)
	}
	return value
}

func (h *pluginControlHost) install() error {
	pluginAPI := h.vm.NewObject()
	if err := pluginAPI.Set("capabilities", h.pluginRegisterCapabilities); err != nil {
		return err
	}
	if err := pluginAPI.Set("resource", h.pluginRegisterResource); err != nil {
		return err
	}
	if err := pluginAPI.Set("action", h.pluginRegisterAction); err != nil {
		return err
	}
	if err := pluginAPI.Set("virtualInterface", h.pluginRegisterVirtualInterface); err != nil {
		return err
	}
	if err := h.vm.Set("plugin", pluginAPI); err != nil {
		return err
	}

	kv := h.vm.NewObject()
	if err := kv.Set("get", h.kvGet); err != nil {
		return err
	}
	if err := kv.Set("set", h.kvSet); err != nil {
		return err
	}
	if err := kv.Set("delete", h.kvDelete); err != nil {
		return err
	}
	if err := kv.Set("list", h.kvList); err != nil {
		return err
	}
	if err := h.vm.Set("kv", kv); err != nil {
		return err
	}

	resources := h.vm.NewObject()
	if err := resources.Set("get", h.resourceGet); err != nil {
		return err
	}
	if err := resources.Set("set", h.resourceSet); err != nil {
		return err
	}
	if err := resources.Set("delete", h.resourceDelete); err != nil {
		return err
	}
	if err := resources.Set("list", h.resourceList); err != nil {
		return err
	}
	if err := h.vm.Set("resources", resources); err != nil {
		return err
	}

	pluginsAPI := h.vm.NewObject()
	pluginResourcesAPI := h.vm.NewObject()
	if err := pluginResourcesAPI.Set("get", h.pluginResourceGet); err != nil {
		return err
	}
	if err := pluginResourcesAPI.Set("list", h.pluginResourceList); err != nil {
		return err
	}
	if err := pluginResourcesAPI.Set("set", h.pluginResourceSet); err != nil {
		return err
	}
	if err := pluginResourcesAPI.Set("delete", h.pluginResourceDelete); err != nil {
		return err
	}
	if err := pluginsAPI.Set("resources", pluginResourcesAPI); err != nil {
		return err
	}
	pluginActionsAPI := h.vm.NewObject()
	if err := pluginActionsAPI.Set("call", h.pluginActionCall); err != nil {
		return err
	}
	if err := pluginsAPI.Set("actions", pluginActionsAPI); err != nil {
		return err
	}
	if err := h.vm.Set("plugins", pluginsAPI); err != nil {
		return err
	}

	ebpfAPI := h.vm.NewObject()
	if err := ebpfAPI.Set("loadObject", h.ebpfLoadObject); err != nil {
		return err
	}
	if err := ebpfAPI.Set("mapPut", h.ebpfMapPut); err != nil {
		return err
	}
	if err := ebpfAPI.Set("mapGet", h.ebpfMapGet); err != nil {
		return err
	}
	if err := ebpfAPI.Set("mapDelete", h.ebpfMapDelete); err != nil {
		return err
	}
	if err := ebpfAPI.Set("mapClear", h.ebpfMapClear); err != nil {
		return err
	}
	if err := h.vm.Set("ebpf", ebpfAPI); err != nil {
		return err
	}

	hooksAPI := h.vm.NewObject()
	if err := hooksAPI.Set("attach", h.hookAttach); err != nil {
		return err
	}
	if err := h.vm.Set("hooks", hooksAPI); err != nil {
		return err
	}

	uiAPI := h.vm.NewObject()
	if err := uiAPI.Set("register", h.uiRegister); err != nil {
		return err
	}
	if err := h.vm.Set("ui", uiAPI); err != nil {
		return err
	}

	netAPI := h.vm.NewObject()
	l2API := h.vm.NewObject()
	if err := l2API.Set("send", h.l2Send); err != nil {
		return err
	}
	if err := l2API.Set("recv", h.l2Recv); err != nil {
		return err
	}
	if err := l2API.Set("recvMany", h.l2RecvMany); err != nil {
		return err
	}
	if err := l2API.Set("exchange", h.l2Exchange); err != nil {
		return err
	}
	if err := l2API.Set("exchangeMany", h.l2ExchangeMany); err != nil {
		return err
	}
	if err := netAPI.Set("l2", l2API); err != nil {
		return err
	}
	udpAPI := h.vm.NewObject()
	if err := udpAPI.Set("send", h.udpSend); err != nil {
		return err
	}
	if err := udpAPI.Set("recv", h.udpRecv); err != nil {
		return err
	}
	if err := udpAPI.Set("exchange", h.udpExchange); err != nil {
		return err
	}
	if err := netAPI.Set("udp", udpAPI); err != nil {
		return err
	}
	linkAPI := h.vm.NewObject()
	if err := linkAPI.Set("get", h.netLinkGet); err != nil {
		return err
	}
	if err := linkAPI.Set("list", h.netLinkList); err != nil {
		return err
	}
	if err := linkAPI.Set("ensureBridge", h.netLinkEnsureBridge); err != nil {
		return err
	}
	if err := linkAPI.Set("ensureVeth", h.netLinkEnsureVeth); err != nil {
		return err
	}
	if err := linkAPI.Set("delete", h.netLinkDelete); err != nil {
		return err
	}
	if err := linkAPI.Set("setMaster", h.netLinkSetMaster); err != nil {
		return err
	}
	if err := linkAPI.Set("clearMaster", h.netLinkClearMaster); err != nil {
		return err
	}
	if err := linkAPI.Set("setUp", h.netLinkSetUp); err != nil {
		return err
	}
	if err := linkAPI.Set("setMTU", h.netLinkSetMTU); err != nil {
		return err
	}
	if err := linkAPI.Set("setOffloads", h.netLinkSetOffloads); err != nil {
		return err
	}
	if err := netAPI.Set("link", linkAPI); err != nil {
		return err
	}
	addrAPI := h.vm.NewObject()
	if err := addrAPI.Set("replace", h.netAddrReplace); err != nil {
		return err
	}
	if err := addrAPI.Set("delete", h.netAddrDelete); err != nil {
		return err
	}
	if err := netAPI.Set("addr", addrAPI); err != nil {
		return err
	}
	routeAPI := h.vm.NewObject()
	if err := routeAPI.Set("replace", h.netRouteReplace); err != nil {
		return err
	}
	if err := routeAPI.Set("delete", h.netRouteDelete); err != nil {
		return err
	}
	if err := netAPI.Set("route", routeAPI); err != nil {
		return err
	}
	if err := h.vm.Set("net", netAPI); err != nil {
		return err
	}

	timerAPI := h.vm.NewObject()
	if err := timerAPI.Set("setTimeout", h.timerSetTimeout); err != nil {
		return err
	}
	if err := timerAPI.Set("setInterval", h.timerSetInterval); err != nil {
		return err
	}
	if err := timerAPI.Set("clear", h.timerClear); err != nil {
		return err
	}
	if err := timerAPI.Set("list", h.timerList); err != nil {
		return err
	}
	if err := h.vm.Set("timer", timerAPI); err != nil {
		return err
	}

	workerAPI := h.vm.NewObject()
	if err := workerAPI.Set("call", h.workerCall); err != nil {
		return err
	}
	if err := workerAPI.Set("dispatch", h.workerDispatch); err != nil {
		return err
	}
	if err := workerAPI.Set("list", h.workerList); err != nil {
		return err
	}
	if err := h.vm.Set("worker", workerAPI); err != nil {
		return err
	}

	cryptoAPI := h.vm.NewObject()
	if err := cryptoAPI.Set("md5", h.cryptoMD5); err != nil {
		return err
	}
	if err := cryptoAPI.Set("randomBytes", h.cryptoRandomBytes); err != nil {
		return err
	}
	if err := cryptoAPI.Set("sha256File", h.cryptoSHA256File); err != nil {
		return err
	}
	if err := h.vm.Set("crypto", cryptoAPI); err != nil {
		return err
	}

	secretAPI := h.vm.NewObject()
	if err := secretAPI.Set("get", h.secretGet); err != nil {
		return err
	}
	if err := secretAPI.Set("set", h.secretSet); err != nil {
		return err
	}
	if err := secretAPI.Set("delete", h.secretDelete); err != nil {
		return err
	}
	if err := h.vm.Set("secret", secretAPI); err != nil {
		return err
	}

	logAPI := h.vm.NewObject()
	if err := logAPI.Set("info", h.logInfo); err != nil {
		return err
	}
	if err := logAPI.Set("error", h.logError); err != nil {
		return err
	}
	return h.vm.Set("log", logAPI)
}

func (h *pluginControlHost) pluginRegisterCapabilities(call goja.FunctionCall) goja.Value {
	h.requireRegistrationPermission("plugin.register", "plugin.capabilities")
	values := make([]string, 0, len(call.Arguments))
	if len(call.Arguments) == 1 {
		if exported := call.Arguments[0].Export(); exported != nil {
			if list, ok := exported.([]any); ok {
				for _, item := range list {
					values = append(values, fmt.Sprint(item))
				}
			}
		}
	}
	if len(values) == 0 {
		for _, arg := range call.Arguments {
			if goja.IsUndefined(arg) || goja.IsNull(arg) {
				continue
			}
			values = append(values, arg.String())
		}
	}
	normalized, err := normalizePluginTokens(values, "capability")
	if err != nil {
		h.throwf("plugin.capabilities: %v", err)
	}
	h.surface.Capabilities = normalized
	return goja.Undefined()
}

func (h *pluginControlHost) pluginRegisterResource(call goja.FunctionCall) goja.Value {
	h.requireRegistrationPermission("plugin.register", "plugin.resource")
	var resource PluginResource
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("plugin.resource: spec is required")
	}
	h.exportJSONValue(call.Arguments[0], &resource, "plugin.resource")
	if err := normalizePluginResource(&resource); err != nil {
		h.throwf("plugin.resource: %v", err)
	}
	if pluginResourceIndex(h.surface.Resources, resource.ID) >= 0 {
		h.throwf("plugin.resource: duplicate resource %q", resource.ID)
	}
	h.surface.Resources = append(h.surface.Resources, resource)
	return goja.Undefined()
}

func (h *pluginControlHost) pluginRegisterAction(call goja.FunctionCall) goja.Value {
	h.requireRegistrationPermission("plugin.register", "plugin.action")
	var action PluginAction
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("plugin.action: spec is required")
	}
	h.exportJSONValue(call.Arguments[0], &action, "plugin.action")
	if err := normalizePluginAction(&action); err != nil {
		h.throwf("plugin.action: %v", err)
	}
	if pluginActionIndex(h.surface.Actions, action.ID) >= 0 {
		h.throwf("plugin.action: duplicate action %q", action.ID)
	}
	h.surface.Actions = append(h.surface.Actions, action)
	return goja.Undefined()
}

func (h *pluginControlHost) pluginRegisterVirtualInterface(call goja.FunctionCall) goja.Value {
	h.requireRegistrationPermission("plugin.register", "plugin.virtualInterface")
	var vif PluginVirtualInterface
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("plugin.virtualInterface: spec is required")
	}
	h.exportJSONValue(call.Arguments[0], &vif, "plugin.virtualInterface")
	if err := normalizePluginVirtualInterface(&vif); err != nil {
		h.throwf("plugin.virtualInterface: %v", err)
	}
	if pluginVirtualInterfaceIndex(h.surface.VirtualInterfaces, vif.ID) >= 0 {
		h.throwf("plugin.virtualInterface: duplicate virtual interface %q", vif.ID)
	}
	h.surface.VirtualInterfaces = append(h.surface.VirtualInterfaces, vif)
	return goja.Undefined()
}

func (h *pluginControlHost) ebpfLoadObject(call goja.FunctionCall) goja.Value {
	h.requireRegistrationPermission("ebpf.load", "ebpf.loadObject")
	var object PluginObject
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("ebpf.loadObject: spec is required")
	}
	h.exportJSONValue(call.Arguments[0], &object, "ebpf.loadObject")
	if err := normalizePluginObject(&object); err != nil {
		h.throwf("ebpf.loadObject: %v", err)
	}
	if pluginObjectIndex(h.surface.Objects, object.ID) >= 0 {
		h.throwf("ebpf.loadObject: duplicate object %q", object.ID)
	}
	h.surface.Objects = append(h.surface.Objects, object)
	return goja.Undefined()
}

func (h *pluginControlHost) hookAttach(call goja.FunctionCall) goja.Value {
	h.requireRegistrationPermission("hook.attach", "hooks.attach")
	var hook PluginHook
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("hooks.attach: spec is required")
	}
	h.exportJSONValue(call.Arguments[0], &hook, "hooks.attach")
	if err := normalizePluginHook(&hook); err != nil {
		h.throwf("hooks.attach: %v", err)
	}
	if pluginHookIndex(h.surface.Hooks, hook.ID) >= 0 {
		h.throwf("hooks.attach: duplicate hook %q", hook.ID)
	}
	h.surface.Hooks = append(h.surface.Hooks, hook)
	return goja.Undefined()
}

type pluginControlUIRegistration struct {
	StaticDir string `json:"static_dir"`
	Entry     string `json:"entry"`
	SHA256    string `json:"sha256"`
	Page      string `json:"page"`
	PageTitle string `json:"page_title"`
}

func (h *pluginControlHost) uiRegister(call goja.FunctionCall) goja.Value {
	h.requireRegistrationPermission("ui", "ui.register")
	var spec pluginControlUIRegistration
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("ui.register: spec is required")
	}
	h.exportJSONValue(call.Arguments[0], &spec, "ui.register")
	ui := PluginUI{
		StaticDir: spec.StaticDir,
		Entry:     spec.Entry,
		Page:      spec.Page,
		PageTitle: spec.PageTitle,
		SHA256:    spec.SHA256,
	}
	if err := normalizePluginUI(&ui); err != nil {
		h.throwf("ui.register: %v", err)
	}
	if ui.StaticDir == "" && ui.Entry != "" {
		h.throwf("ui.register: static_dir is required when entry is set")
	}
	if ui.StaticDir != "" || ui.Entry != "" {
		h.surface.UI = &ui
	}
	return goja.Undefined()
}

func (h *pluginControlHost) exportJSONValue(value goja.Value, out any, api string) {
	raw, err := json.Marshal(value.Export())
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		h.throwf("%s: %v", api, err)
	}
}

func pluginResourceIndex(resources []PluginResource, id string) int {
	for i, resource := range resources {
		if resource.ID == id {
			return i
		}
	}
	return -1
}

func pluginActionIndex(actions []PluginAction, id string) int {
	for i, action := range actions {
		if action.ID == id {
			return i
		}
	}
	return -1
}

func pluginVirtualInterfaceIndex(vifs []PluginVirtualInterface, id string) int {
	for i, vif := range vifs {
		if vif.ID == id {
			return i
		}
	}
	return -1
}

func pluginObjectIndex(objects []PluginObject, id string) int {
	for i, object := range objects {
		if object.ID == id {
			return i
		}
	}
	return -1
}

func pluginHookIndex(hooks []PluginHook, id string) int {
	for i, hook := range hooks {
		if hook.ID == id {
			return i
		}
	}
	return -1
}

func (h *pluginControlHost) kvGet(call goja.FunctionCall) goja.Value {
	h.requirePermission("kv")
	key := h.requiredTokenArg(call, 0, "key")
	record, err := store.GetPluginRecord(h.db, h.plugin.ID, pluginControlKVResourceID, key)
	if errors.Is(err, sql.ErrNoRows) {
		return goja.Null()
	}
	if err != nil {
		h.throwf("kv.get: %v", err)
	}
	return h.valueFromRecord(*record)
}

func (h *pluginControlHost) kvSet(call goja.FunctionCall) goja.Value {
	h.requirePermission("kv")
	key := h.requiredTokenArg(call, 0, "key")
	if len(call.Arguments) < 2 {
		h.throwf("kv.set: value is required")
	}
	dataJSON := h.jsonFromValue(call.Arguments[1])
	if len(dataJSON) > pluginControlMaxKVRecordBytes {
		h.throwf("kv.set: value exceeds %d bytes", pluginControlMaxKVRecordBytes)
	}
	if err := upsertPluginControlRecord(h.db, h.plugin.ID, pluginControlKVResourceID, key, dataJSON, true, pluginControlMaxKVRecords); err != nil {
		h.throwf("kv.set: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) kvDelete(call goja.FunctionCall) goja.Value {
	h.requirePermission("kv")
	key := h.requiredTokenArg(call, 0, "key")
	if err := store.DeletePluginRecord(h.db, h.plugin.ID, pluginControlKVResourceID, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.throwf("kv.delete: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) kvList(call goja.FunctionCall) goja.Value {
	h.requirePermission("kv")
	page := h.listPageFromArg(call, 0, "kv.list")
	records, err := store.GetPluginRecordsPage(h.db, h.plugin.ID, pluginControlKVResourceID, page.Limit, page.Offset)
	if err != nil {
		h.throwf("kv.list: %v", err)
	}
	return h.vm.ToValue(h.recordsForScript(records))
}

func (h *pluginControlHost) resourceGet(call goja.FunctionCall) goja.Value {
	h.requirePermission("resource")
	resource := h.requiredResource(call, 0)
	key := h.requiredTokenArg(call, 1, "key")
	if !pluginResourceControlAllows(resource, "get") {
		h.throwf("resources.get: resource %s does not allow get", resource.ID)
	}
	record, err := store.GetPluginRecord(h.db, h.plugin.ID, resource.ID, key)
	if errors.Is(err, sql.ErrNoRows) {
		return goja.Null()
	}
	if err != nil {
		h.throwf("resources.get: %v", err)
	}
	return h.valueFromRecord(*record)
}

func (h *pluginControlHost) resourceSet(call goja.FunctionCall) goja.Value {
	h.requirePermission("resource")
	resource := h.requiredResource(call, 0)
	key := h.requiredTokenArg(call, 1, "key")
	if len(call.Arguments) < 3 {
		h.throwf("resources.set: value is required")
	}
	tx, err := h.db.Begin()
	if err != nil {
		h.throwf("resources.set: %v", err)
	}
	defer tx.Rollback()
	existing, err := store.GetPluginRecord(tx, h.plugin.ID, resource.ID, key)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.throwf("resources.set: %v", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		if !pluginResourceControlAllows(resource, "create") {
			h.throwf("resources.set: resource %s does not allow create", resource.ID)
		}
	} else if !pluginResourceControlAllows(resource, "update") {
		h.throwf("resources.set: resource %s does not allow update", resource.ID)
	}
	enabled := true
	if len(call.Arguments) > 3 && !goja.IsUndefined(call.Arguments[3]) && !goja.IsNull(call.Arguments[3]) {
		enabled = call.Arguments[3].ToBoolean()
	}
	apply := false
	if len(call.Arguments) > 4 && !goja.IsUndefined(call.Arguments[4]) && !goja.IsNull(call.Arguments[4]) {
		apply = call.Arguments[4].ToBoolean()
	}
	dataJSON := h.pluginResourceJSONFromValue(call.Arguments[2], resource, existing, "resources.set")
	if !apply && existing != nil && existing.DataJSON == dataJSON && existing.Enabled == enabled {
		return goja.Undefined()
	}
	if err := upsertPluginControlRecord(tx, h.plugin.ID, resource.ID, key, dataJSON, enabled, pluginResourceMaxRecords(resource)); err != nil {
		h.throwf("resources.set: %v", err)
	}
	if err := markPluginResourceMutation(tx, h.plugin, resource); err != nil {
		h.throwf("resources.set: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.throwf("resources.set: %v", err)
	}
	if apply {
		if err := h.applyTargetPluginResourceRuntimeUpdate(h.plugin, resource); err != nil {
			_ = markPluginRuntimeError(h.db, h.plugin.ID, "resource", resource.ID, err)
			h.throwf("resources.set: apply %s: %v", resource.ID, err)
		}
	}
	return goja.Undefined()
}

func (h *pluginControlHost) resourceDelete(call goja.FunctionCall) goja.Value {
	h.requirePermission("resource")
	resource := h.requiredResource(call, 0)
	key := h.requiredTokenArg(call, 1, "key")
	apply := false
	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
		apply = call.Arguments[2].ToBoolean()
	}
	if !pluginResourceControlAllows(resource, "delete") {
		h.throwf("resources.delete: resource %s does not allow delete", resource.ID)
	}
	tx, err := h.db.Begin()
	if err != nil {
		h.throwf("resources.delete: %v", err)
	}
	defer tx.Rollback()
	if err := store.DeletePluginRecord(tx, h.plugin.ID, resource.ID, key); err != nil {
		if errors.Is(err, sql.ErrNoRows) && !apply {
			return goja.Undefined()
		}
		if !errors.Is(err, sql.ErrNoRows) {
			h.throwf("resources.delete: %v", err)
		}
	}
	if err := markPluginResourceMutation(tx, h.plugin, resource); err != nil {
		h.throwf("resources.delete: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.throwf("resources.delete: %v", err)
	}
	if apply {
		if err := h.applyTargetPluginResourceRuntimeUpdate(h.plugin, resource); err != nil {
			_ = markPluginRuntimeError(h.db, h.plugin.ID, "resource", resource.ID, err)
			h.throwf("resources.delete: apply %s: %v", resource.ID, err)
		}
	}
	return goja.Undefined()
}

func (h *pluginControlHost) resourceList(call goja.FunctionCall) goja.Value {
	h.requirePermission("resource")
	resource := h.requiredResource(call, 0)
	if !pluginResourceControlAllows(resource, "list") {
		h.throwf("resources.list: resource %s does not allow list", resource.ID)
	}
	page := h.listPageFromArg(call, 1, "resources.list")
	records, err := store.GetPluginRecordsPage(h.db, h.plugin.ID, resource.ID, page.Limit, page.Offset)
	if err != nil {
		h.throwf("resources.list: %v", err)
	}
	return h.vm.ToValue(h.recordsForScript(records))
}

func (h *pluginControlHost) pluginResourceGet(call goja.FunctionCall) goja.Value {
	h.requirePermission("plugin.resource")
	targetPluginID := h.requiredTokenArg(call, 0, "plugin")
	resourceID := h.requiredTokenArg(call, 1, "resource")
	key := h.requiredTokenArg(call, 2, "key")
	plugin, resource := h.requiredTargetPluginResource(targetPluginID, resourceID)
	h.requirePluginResourceAccess(plugin.ID, resource.ID, "get", "plugins.resources.get")
	if !pluginResourceAllows(resource, "get") {
		h.throwf("plugins.resources.get: resource %s/%s does not allow get", plugin.ID, resource.ID)
	}
	record, err := store.GetPluginRecord(h.db, plugin.ID, resource.ID, key)
	if errors.Is(err, sql.ErrNoRows) {
		return goja.Null()
	}
	if err != nil {
		h.throwf("plugins.resources.get: %v", err)
	}
	return h.valueFromRecordWithResource(*record, resource, true)
}

func (h *pluginControlHost) pluginResourceList(call goja.FunctionCall) goja.Value {
	h.requirePermission("plugin.resource")
	targetPluginID := h.requiredTokenArg(call, 0, "plugin")
	resourceID := h.requiredTokenArg(call, 1, "resource")
	plugin, resource := h.requiredTargetPluginResource(targetPluginID, resourceID)
	h.requirePluginResourceAccess(plugin.ID, resource.ID, "list", "plugins.resources.list")
	if !pluginResourceAllows(resource, "list") {
		h.throwf("plugins.resources.list: resource %s/%s does not allow list", plugin.ID, resource.ID)
	}
	page := h.listPageFromArg(call, 2, "plugins.resources.list")
	records, err := store.GetPluginRecordsPage(h.db, plugin.ID, resource.ID, page.Limit, page.Offset)
	if err != nil {
		h.throwf("plugins.resources.list: %v", err)
	}
	return h.vm.ToValue(h.recordsForScriptWithResource(records, resource, true))
}

func (h *pluginControlHost) pluginResourceSet(call goja.FunctionCall) goja.Value {
	h.requirePermission("plugin.resource")
	targetPluginID := h.requiredTokenArg(call, 0, "plugin")
	resourceID := h.requiredTokenArg(call, 1, "resource")
	key := h.requiredTokenArg(call, 2, "key")
	if len(call.Arguments) < 4 {
		h.throwf("plugins.resources.set: value is required")
	}
	enabled := true
	if len(call.Arguments) > 4 && !goja.IsUndefined(call.Arguments[4]) && !goja.IsNull(call.Arguments[4]) {
		enabled = call.Arguments[4].ToBoolean()
	}
	apply := false
	if len(call.Arguments) > 5 && !goja.IsUndefined(call.Arguments[5]) && !goja.IsNull(call.Arguments[5]) {
		apply = call.Arguments[5].ToBoolean()
	}
	plugin, resource := h.requiredTargetPluginResource(targetPluginID, resourceID)
	tx, err := h.db.Begin()
	if err != nil {
		h.throwf("plugins.resources.set: %v", err)
	}
	defer tx.Rollback()
	existing, err := store.GetPluginRecord(tx, plugin.ID, resource.ID, key)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.throwf("plugins.resources.set: %v", err)
	}
	method := "update"
	if existing == nil {
		method = "create"
	}
	h.requirePluginResourceAccess(plugin.ID, resource.ID, method, "plugins.resources.set")
	if !pluginResourceAllows(resource, method) {
		h.throwf("plugins.resources.set: resource %s/%s does not allow %s", plugin.ID, resource.ID, method)
	}
	dataJSON := h.pluginResourceJSONFromValue(call.Arguments[3], resource, existing, "plugins.resources.set")
	if !apply && existing != nil && existing.DataJSON == dataJSON && existing.Enabled == enabled {
		return h.valueFromRecordWithResource(*existing, resource, true)
	}
	if err := upsertPluginControlRecord(tx, plugin.ID, resource.ID, key, dataJSON, enabled, pluginResourceMaxRecords(resource)); err != nil {
		h.throwf("plugins.resources.set: %v", err)
	}
	if err := markPluginResourceMutation(tx, plugin, resource); err != nil {
		h.throwf("plugins.resources.set: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.throwf("plugins.resources.set: %v", err)
	}
	if apply {
		if err := h.applyTargetPluginResourceRuntimeUpdate(plugin, resource); err != nil {
			_ = markPluginRuntimeError(h.db, plugin.ID, "resource", resource.ID, err)
			h.throwf("plugins.resources.set: apply %s/%s: %v", plugin.ID, resource.ID, err)
		}
	}
	record, err := store.GetPluginRecord(h.db, plugin.ID, resource.ID, key)
	if err != nil {
		h.throwf("plugins.resources.set: %v", err)
	}
	return h.valueFromRecordWithResource(*record, resource, true)
}

func (h *pluginControlHost) pluginResourceDelete(call goja.FunctionCall) goja.Value {
	h.requirePermission("plugin.resource")
	targetPluginID := h.requiredTokenArg(call, 0, "plugin")
	resourceID := h.requiredTokenArg(call, 1, "resource")
	key := h.requiredTokenArg(call, 2, "key")
	apply := false
	if len(call.Arguments) > 3 && !goja.IsUndefined(call.Arguments[3]) && !goja.IsNull(call.Arguments[3]) {
		apply = call.Arguments[3].ToBoolean()
	}
	plugin, resource := h.requiredTargetPluginResource(targetPluginID, resourceID)
	h.requirePluginResourceAccess(plugin.ID, resource.ID, "delete", "plugins.resources.delete")
	if !pluginResourceAllows(resource, "delete") {
		h.throwf("plugins.resources.delete: resource %s/%s does not allow delete", plugin.ID, resource.ID)
	}
	tx, err := h.db.Begin()
	if err != nil {
		h.throwf("plugins.resources.delete: %v", err)
	}
	defer tx.Rollback()
	if err := store.DeletePluginRecord(tx, plugin.ID, resource.ID, key); err != nil {
		if errors.Is(err, sql.ErrNoRows) && !apply {
			return h.vm.ToValue(map[string]any{"status": "not_found"})
		}
		if !errors.Is(err, sql.ErrNoRows) {
			h.throwf("plugins.resources.delete: %v", err)
		}
	}
	if err := markPluginResourceMutation(tx, plugin, resource); err != nil {
		h.throwf("plugins.resources.delete: %v", err)
	}
	if err := tx.Commit(); err != nil {
		h.throwf("plugins.resources.delete: %v", err)
	}
	if apply {
		if err := h.applyTargetPluginResourceRuntimeUpdate(plugin, resource); err != nil {
			_ = markPluginRuntimeError(h.db, plugin.ID, "resource", resource.ID, err)
			h.throwf("plugins.resources.delete: apply %s/%s: %v", plugin.ID, resource.ID, err)
		}
	}
	return h.vm.ToValue(map[string]any{"status": "deleted"})
}

func (h *pluginControlHost) pluginActionCall(call goja.FunctionCall) goja.Value {
	h.requirePermission("plugin.action")
	targetPluginID := h.requiredTokenArg(call, 0, "plugin")
	actionID := h.requiredTokenArg(call, 1, "action")
	plugin, action := h.requiredTargetPluginAction(targetPluginID, actionID)
	if plugin.ID == h.plugin.ID {
		h.throwf("plugins.actions.call: self action calls are not supported")
	}
	h.requirePluginActionAccess(plugin.ID, action.ID, "plugins.actions.call")
	payload := json.RawMessage(`{}`)
	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
		payload = json.RawMessage(h.jsonFromValue(call.Arguments[2]))
	}
	if len(payload) > pluginActionMaxPayloadBytes(action) || !json.Valid(payload) {
		h.throwf("plugins.actions.call: invalid action payload")
	}
	if err := h.applyTargetPluginActionRuntimeUpdate(plugin, action, payload); err != nil {
		_ = markPluginRuntimeError(h.db, plugin.ID, "action", action.ID, err)
		h.throwf("plugins.actions.call: apply %s/%s: %v", plugin.ID, action.ID, err)
	}
	return h.vm.ToValue(map[string]any{
		"status":         "completed",
		"plugin":         plugin.ID,
		"action":         action.ID,
		"runtime_update": action.RuntimeUpdate,
	})
}

func (h *pluginControlHost) applyTargetPluginResourceRuntimeUpdate(plugin LoadedPlugin, resource PluginResource) error {
	if h.runtime == nil {
		return fmt.Errorf("plugin control runtime is unavailable")
	}
	if err := h.targetPluginRuntimeUpdateAllowed(plugin, resource); err != nil {
		return err
	}
	if resource.RuntimeUpdate == "plugin_reconcile" {
		if provider, ok := h.runtime.updateProvider.(pluginResourceControlReconcileProvider); ok {
			return provider.ApplyPluginResourceReconcileFromControl(plugin, resource)
		}
	}
	if plugin.ID == h.plugin.ID {
		switch resource.RuntimeUpdate {
		case "runtime_apply":
			return h.applyCurrentPluginResourceRuntimeApply(plugin, resource)
		}
	}
	if h.runtime.updateProvider != nil {
		return h.runtime.updateProvider.ApplyPluginResourceRuntimeUpdate(plugin, resource)
	}
	switch resource.RuntimeUpdate {
	case "none", "manual", "":
		return nil
	case "plugin_reconcile":
		return fmt.Errorf("plugin_reconcile runtime update requires process manager")
	case "runtime_apply":
		records, err := loadPluginResourceRecords(h.db, plugin, resource)
		if err != nil {
			return err
		}
		if err := h.applyTargetPluginResourceData(plugin, resource, records); err != nil {
			return err
		}
		return markPluginRuntimeAppliedToCurrentRevision(h.db, plugin.ID, "resource", resource.ID)
	default:
		return fmt.Errorf("unsupported resource runtime_update %q", resource.RuntimeUpdate)
	}
}

func (h *pluginControlHost) targetPluginRuntimeUpdateAllowed(plugin LoadedPlugin, resource PluginResource) error {
	switch resource.RuntimeUpdate {
	case "plugin_reconcile", "runtime_apply":
		if ok, reason := pluginControlStabilityAllowed(plugin, h.cfg); !ok {
			return fmt.Errorf("%s", reason)
		}
	}
	return nil
}

func (h *pluginControlHost) applyCurrentPluginResourceRuntimeApply(plugin LoadedPlugin, resource PluginResource) error {
	records, err := loadPluginResourceRecords(h.db, plugin, resource)
	if err != nil {
		return err
	}
	var controlErr error
	if h.runtime != nil && plugin.controlMainPath != "" {
		if h.plugin.ID == plugin.ID {
			_, _, controlErr = h.runEvent(pluginControlEvent{
				Kind:     "resource_apply",
				Resource: &resource,
				Records:  records,
			}, false)
		} else {
			_, controlErr = h.runtime.runPluginControlWithSurface(plugin, pluginControlEvent{
				Kind:     "resource_apply",
				Resource: &resource,
				Records:  records,
			}, false)
		}
		if controlErr == nil {
			return markPluginRuntimeAppliedToCurrentRevision(h.db, plugin.ID, "resource", resource.ID)
		}
		if !errors.Is(controlErr, errPluginRuntimeTargetNotLoaded) {
			return controlErr
		}
	}
	appliers := h.runtime.runtimeDataAppliersExcludingControl()
	if len(appliers) == 0 {
		if controlErr != nil {
			return controlErr
		}
		return fmt.Errorf("plugin runtime data applier is unavailable")
	}
	if err := applyPluginResourceDataWithAppliers(appliers, plugin, resource, records); err != nil {
		return err
	}
	return markPluginRuntimeAppliedToCurrentRevision(h.db, plugin.ID, "resource", resource.ID)
}

func (h *pluginControlHost) applyTargetPluginActionRuntimeUpdate(plugin LoadedPlugin, action PluginAction, payload json.RawMessage) error {
	if h.runtime == nil {
		return fmt.Errorf("plugin control runtime is unavailable")
	}
	if err := h.targetPluginActionRuntimeUpdateAllowed(plugin, action); err != nil {
		return err
	}
	actionStatus := "pending"
	if action.RuntimeUpdate == "none" || action.RuntimeUpdate == "" {
		actionStatus = "completed"
	}
	if err := store.UpsertPluginRuntimeStatus(h.db, store.PluginRuntimeStatus{
		PluginID:   plugin.ID,
		TargetType: "action",
		TargetID:   action.ID,
		Status:     actionStatus,
		LastError:  "",
	}); err != nil {
		return err
	}
	if h.runtime.actionUpdateProvider != nil {
		return h.runtime.actionUpdateProvider.ApplyPluginActionRuntimeUpdate(plugin, action, payload)
	}
	switch action.RuntimeUpdate {
	case "none", "":
		return nil
	case "plugin_reconcile":
		return fmt.Errorf("plugin_reconcile runtime update requires process manager")
	case "runtime_apply":
		if err := h.applyTargetPluginActionData(plugin, action, payload); err != nil {
			return err
		}
		return markPluginRuntimeAppliedToCurrentRevision(h.db, plugin.ID, "action", action.ID)
	default:
		return fmt.Errorf("unsupported action runtime_update %q", action.RuntimeUpdate)
	}
}

func (h *pluginControlHost) targetPluginActionRuntimeUpdateAllowed(plugin LoadedPlugin, action PluginAction) error {
	switch action.RuntimeUpdate {
	case "plugin_reconcile", "runtime_apply":
		if ok, reason := pluginControlStabilityAllowed(plugin, h.cfg); !ok {
			return fmt.Errorf("%s", reason)
		}
	}
	return nil
}

func (h *pluginControlHost) applyTargetPluginActionData(plugin LoadedPlugin, action PluginAction, payload json.RawMessage) error {
	if h.runtime == nil {
		return fmt.Errorf("plugin control runtime is unavailable")
	}
	appliers := h.runtime.runtimeDataAppliers()
	return applyPluginActionWithAppliers(appliers, plugin, action, payload)
}

func (h *pluginControlHost) applyTargetPluginResourceData(plugin LoadedPlugin, resource PluginResource, records []PluginResourceRecord) error {
	if h.runtime == nil {
		return fmt.Errorf("plugin control runtime is unavailable")
	}
	appliers := h.runtime.runtimeDataAppliers()
	return applyPluginResourceDataWithAppliers(appliers, plugin, resource, records)
}

func (rt *gojaPluginControlRuntime) runtimeDataAppliers() []pluginRuntimeDataApplier {
	if rt == nil {
		return nil
	}
	if rt.dataApplierProvider != nil {
		if appliers := rt.dataApplierProvider.PluginRuntimeDataAppliers(); len(appliers) > 0 {
			return appliers
		}
	}
	return []pluginRuntimeDataApplier{rt}
}

func (rt *gojaPluginControlRuntime) runtimeDataAppliersExcludingControl() []pluginRuntimeDataApplier {
	appliers := rt.runtimeDataAppliers()
	out := make([]pluginRuntimeDataApplier, 0, len(appliers))
	for _, applier := range appliers {
		if applier == rt {
			continue
		}
		out = append(out, applier)
	}
	return out
}

func (h *pluginControlHost) ebpfMapPut(call goja.FunctionCall) goja.Value {
	h.requirePermission("ebpf.map_write")
	if h.mapController == nil {
		h.throwf("ebpf.mapPut: eBPF map controller is unavailable")
	}
	objectID, mapName, key, value := h.ebpfMapPutArgs(call)
	h.requirePluginObjectID(objectID, "ebpf.mapPut")
	h.requireWritablePluginMap(mapName, "ebpf.mapPut")
	if err := h.mapController.PutPluginMapValue(h.plugin.ID, objectID, mapName, key, value); err != nil {
		h.throwf("ebpf.mapPut: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) ebpfMapGet(call goja.FunctionCall) goja.Value {
	h.requirePermission("ebpf.map_read")
	if h.mapController == nil {
		h.throwf("ebpf.mapGet: eBPF map controller is unavailable")
	}
	objectID, mapName, key := h.ebpfMapDeleteArgs(call)
	h.requirePluginObjectID(objectID, "ebpf.mapGet")
	h.requirePluginMap(mapName, "ebpf.mapGet")
	value, err := h.mapController.GetPluginMapValue(h.plugin.ID, objectID, mapName, key)
	if err != nil {
		h.throwf("ebpf.mapGet: %v", err)
	}
	return h.vm.ToValue(hex.EncodeToString(value))
}

func (h *pluginControlHost) ebpfMapDelete(call goja.FunctionCall) goja.Value {
	h.requirePermission("ebpf.map_write")
	if h.mapController == nil {
		h.throwf("ebpf.mapDelete: eBPF map controller is unavailable")
	}
	objectID, mapName, key := h.ebpfMapDeleteArgs(call)
	h.requirePluginObjectID(objectID, "ebpf.mapDelete")
	h.requireWritablePluginMap(mapName, "ebpf.mapDelete")
	if err := h.mapController.DeletePluginMapValue(h.plugin.ID, objectID, mapName, key); err != nil {
		h.throwf("ebpf.mapDelete: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) ebpfMapClear(call goja.FunctionCall) goja.Value {
	h.requirePermission("ebpf.map_write")
	if h.mapController == nil {
		h.throwf("ebpf.mapClear: eBPF map controller is unavailable")
	}
	objectID, mapName := h.ebpfMapClearArgs(call)
	h.requirePluginObjectID(objectID, "ebpf.mapClear")
	h.requireWritablePluginMap(mapName, "ebpf.mapClear")
	if err := h.mapController.ClearPluginMap(h.plugin.ID, objectID, mapName); err != nil {
		h.throwf("ebpf.mapClear: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) timerSetTimeout(call goja.FunctionCall) goja.Value {
	h.requirePermission("timer")
	spec := h.timerSpecFromCall(call, pluginControlTimerKindTimeout)
	h.timerOps = append(h.timerOps, pluginControlTimerOperation{op: pluginControlTimerOperationSet, spec: spec})
	return goja.Undefined()
}

func (h *pluginControlHost) timerSetInterval(call goja.FunctionCall) goja.Value {
	h.requirePermission("timer")
	spec := h.timerSpecFromCall(call, pluginControlTimerKindInterval)
	h.timerOps = append(h.timerOps, pluginControlTimerOperation{op: pluginControlTimerOperationSet, spec: spec})
	return goja.Undefined()
}

func (h *pluginControlHost) timerClear(call goja.FunctionCall) goja.Value {
	h.requirePermission("timer")
	name := h.requiredTokenArg(call, 0, "timer")
	h.timerOps = append(h.timerOps, pluginControlTimerOperation{
		op: pluginControlTimerOperationClear,
		spec: pluginControlTimerSpec{
			Name: name,
		},
	})
	return goja.Undefined()
}

func (h *pluginControlHost) timerList(call goja.FunctionCall) goja.Value {
	h.requirePermission("timer")
	if h.runtime == nil {
		return h.vm.ToValue([]map[string]any(nil))
	}
	return h.vm.ToValue(h.runtime.pluginTimerList(h.plugin.ID))
}

func (h *pluginControlHost) workerCall(call goja.FunctionCall) goja.Value {
	h.requirePermission("worker")
	name, handler, payload := h.workerRequestFromCall(call, "worker.call")
	vm, err := h.runtime.getPluginControlVM(h.plugin, "worker", name)
	if err != nil {
		h.throwf("worker.call: %v", err)
	}
	result, err := vm.run(h.plugin, pluginControlEvent{
		Kind:    "worker",
		Payload: payload,
		Worker:  &pluginControlWorkerEvent{Name: name, Handler: handler},
	}, false)
	if err != nil {
		h.throwf("worker.call: %v", err)
	}
	return h.vm.ToValue(result.value)
}

func (h *pluginControlHost) workerDispatch(call goja.FunctionCall) goja.Value {
	h.requirePermission("worker")
	name, handler, payload := h.workerRequestFromCall(call, "worker.dispatch")
	vm, err := h.runtime.getPluginControlVM(h.plugin, "worker", name)
	if err != nil {
		h.throwf("worker.dispatch: %v", err)
	}
	if err := vm.dispatch(h.plugin, pluginControlEvent{
		Kind:    "worker",
		Payload: payload,
		Worker:  &pluginControlWorkerEvent{Name: name, Handler: handler},
	}, false); err != nil {
		h.throwf("worker.dispatch: %v", err)
	}
	return h.vm.ToValue(map[string]any{"queued": true, "worker": name, "handler": handler})
}

func (h *pluginControlHost) workerList(call goja.FunctionCall) goja.Value {
	h.requirePermission("worker")
	if h.runtime == nil {
		return h.vm.ToValue([]map[string]any(nil))
	}
	return h.vm.ToValue(h.runtime.pluginWorkerList(h.plugin.ID))
}

func (h *pluginControlHost) l2Send(call goja.FunctionCall) goja.Value {
	h.requirePermission("net.l2")
	if h.l2Transport == nil {
		h.throwf("net.l2.send: raw l2 transport is unavailable")
	}
	req := h.l2SendRequest(call)
	if err := h.l2Transport.Send(req); err != nil {
		h.throwf("net.l2.send: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) l2Recv(call goja.FunctionCall) goja.Value {
	h.requirePermission("net.l2")
	if h.l2Transport == nil {
		h.throwf("net.l2.recv: raw l2 transport is unavailable")
	}
	req := h.l2RecvRequest(call)
	frame, err := h.l2Transport.Recv(req)
	if errors.Is(err, errPluginControlL2Timeout) {
		return goja.Null()
	}
	if err != nil {
		h.throwf("net.l2.recv: %v", err)
	}
	return h.l2FrameValue(frame)
}

func (h *pluginControlHost) l2RecvMany(call goja.FunctionCall) goja.Value {
	h.requirePermission("net.l2")
	if h.l2Transport == nil {
		h.throwf("net.l2.recvMany: raw l2 transport is unavailable")
	}
	req := h.l2RecvManyRequest(call)
	frames, err := h.l2Transport.RecvMany(req)
	if err != nil {
		h.throwf("net.l2.recvMany: %v", err)
	}
	out := make([]any, 0, len(frames))
	for _, frame := range frames {
		out = append(out, h.l2FrameObject(frame))
	}
	return h.vm.ToValue(out)
}

func (h *pluginControlHost) l2Exchange(call goja.FunctionCall) goja.Value {
	h.requirePermission("net.l2")
	if h.l2Transport == nil {
		h.throwf("net.l2.exchange: raw l2 transport is unavailable")
	}
	req := h.l2ExchangeRequest(call)
	frame, err := h.l2Transport.Exchange(req)
	if errors.Is(err, errPluginControlL2Timeout) {
		return goja.Null()
	}
	if err != nil {
		h.throwf("net.l2.exchange: %v", err)
	}
	return h.l2FrameValue(frame)
}

func (h *pluginControlHost) l2ExchangeMany(call goja.FunctionCall) goja.Value {
	h.requirePermission("net.l2")
	if h.l2Transport == nil {
		h.throwf("net.l2.exchangeMany: raw l2 transport is unavailable")
	}
	req := h.l2ExchangeManyRequest(call)
	frames, err := h.l2Transport.ExchangeMany(req)
	if err != nil {
		h.throwf("net.l2.exchangeMany: %v", err)
	}
	out := make([]any, 0, len(frames))
	for _, frame := range frames {
		out = append(out, h.l2FrameObject(frame))
	}
	return h.vm.ToValue(out)
}

func (h *pluginControlHost) udpSend(call goja.FunctionCall) goja.Value {
	h.requirePermission("net.udp")
	if h.udpTransport == nil {
		h.throwf("net.udp.send: udp transport is unavailable")
	}
	req := h.udpSendRequest(call)
	result, err := h.udpTransport.Send(req)
	if err != nil {
		h.throwf("net.udp.send: %v", err)
	}
	return h.vm.ToValue(h.udpResultObject(result))
}

func (h *pluginControlHost) udpRecv(call goja.FunctionCall) goja.Value {
	h.requirePermission("net.udp")
	if h.udpTransport == nil {
		h.throwf("net.udp.recv: udp transport is unavailable")
	}
	req := h.udpRecvRequest(call)
	datagram, err := h.udpTransport.Recv(req)
	if errors.Is(err, errPluginControlUDPTimeout) {
		return goja.Null()
	}
	if err != nil {
		h.throwf("net.udp.recv: %v", err)
	}
	return h.vm.ToValue(h.udpDatagramObject(datagram))
}

func (h *pluginControlHost) udpExchange(call goja.FunctionCall) goja.Value {
	h.requirePermission("net.udp")
	if h.udpTransport == nil {
		h.throwf("net.udp.exchange: udp transport is unavailable")
	}
	req := h.udpExchangeRequest(call)
	datagram, err := h.udpTransport.Exchange(req)
	if errors.Is(err, errPluginControlUDPTimeout) {
		return goja.Null()
	}
	if err != nil {
		h.throwf("net.udp.exchange: %v", err)
	}
	return h.vm.ToValue(h.udpDatagramObject(datagram))
}

func (h *pluginControlHost) cryptoMD5(call goja.FunctionCall) goja.Value {
	h.requirePermission("crypto")
	if len(call.Arguments) == 0 {
		h.throwf("crypto.md5: at least one value is required")
	}
	hash := md5.New() // #nosec G401 -- CHAP requires MD5 for protocol compatibility, not password storage.
	for i, arg := range call.Arguments {
		part, err := h.bytesFromCryptoArg(arg)
		if err != nil {
			h.throwf("crypto.md5 argument %d: %v", i+1, err)
		}
		if _, err := hash.Write(part); err != nil {
			h.throwf("crypto.md5: %v", err)
		}
	}
	return h.vm.ToValue(hex.EncodeToString(hash.Sum(nil)))
}

func (h *pluginControlHost) cryptoRandomBytes(call goja.FunctionCall) goja.Value {
	h.requirePermission("crypto")
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("crypto.randomBytes: length is required")
	}
	length := call.Arguments[0].ToInteger()
	if length <= 0 || length > pluginControlMaxRandomBytes {
		h.throwf("crypto.randomBytes: length must be between 1 and %d", pluginControlMaxRandomBytes)
	}
	out := make([]byte, int(length))
	if _, err := cryptorand.Read(out); err != nil {
		h.throwf("crypto.randomBytes: %v", err)
	}
	return h.vm.ToValue(hex.EncodeToString(out))
}

func (h *pluginControlHost) cryptoSHA256File(call goja.FunctionCall) goja.Value {
	if !pluginControlHasPermission(h.plugin, "crypto") {
		h.throwf("permission crypto is required")
	}
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("crypto.sha256File: path is required")
	}
	realPath, err := h.resolvePluginFileArg(call.Arguments[0].String(), "crypto.sha256File")
	if err != nil {
		h.throwf("crypto.sha256File: %v", err)
	}
	info, err := os.Stat(realPath)
	if err != nil {
		h.throwf("crypto.sha256File: %v", err)
	}
	if info.IsDir() {
		h.throwf("crypto.sha256File: path is a directory")
	}
	if info.Size() > pluginObjectMaxSize {
		h.throwf("crypto.sha256File: file exceeds %d bytes", pluginObjectMaxSize)
	}
	sum, err := sha256File(realPath)
	if err != nil {
		h.throwf("crypto.sha256File: %v", err)
	}
	return h.vm.ToValue(sum)
}

func (h *pluginControlHost) resolvePluginFileArg(value string, label string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("path is required")
	}
	if strings.Contains(value, "\x00") || filepath.IsAbs(value) {
		return "", fmt.Errorf("path must be relative to plugin directory")
	}
	cleanRoot, err := filepath.Abs(h.plugin.rootDir)
	if err != nil {
		return "", fmt.Errorf("resolve plugin root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		return "", fmt.Errorf("resolve plugin root: %w", err)
	}
	target := filepath.Join(cleanRoot, filepath.FromSlash(value))
	cleanTarget, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", label, err)
	}
	if !pathWithinRoot(cleanRoot, cleanTarget) {
		return "", fmt.Errorf("path escapes plugin root")
	}
	realTarget, err := filepath.EvalSymlinks(cleanTarget)
	if err != nil {
		return "", err
	}
	if !pathWithinRoot(realRoot, realTarget) {
		return "", fmt.Errorf("path escapes plugin root")
	}
	return realTarget, nil
}

func (h *pluginControlHost) secretGet(call goja.FunctionCall) goja.Value {
	h.requirePermission("secret")
	key := h.requiredTokenArg(call, 0, "key")
	record, err := store.GetPluginRecord(h.db, h.plugin.ID, pluginControlSecretResourceID, key)
	if errors.Is(err, sql.ErrNoRows) {
		return goja.Null()
	}
	if err != nil {
		h.throwf("secret.get: %v", err)
	}
	return h.vm.ToValue(pluginControlDecodeJSON(json.RawMessage(record.DataJSON)))
}

func (h *pluginControlHost) secretSet(call goja.FunctionCall) goja.Value {
	h.requirePermission("secret")
	key := h.requiredTokenArg(call, 0, "key")
	if len(call.Arguments) < 2 || goja.IsUndefined(call.Arguments[1]) {
		h.throwf("secret.set: value is required")
	}
	dataJSON := h.jsonFromValue(call.Arguments[1])
	if len(dataJSON) > pluginControlMaxSecretBytes {
		h.throwf("secret.set: value exceeds %d bytes", pluginControlMaxSecretBytes)
	}
	if err := upsertPluginControlRecord(h.db, h.plugin.ID, pluginControlSecretResourceID, key, dataJSON, true, pluginControlMaxSecrets); err != nil {
		h.throwf("secret.set: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) secretDelete(call goja.FunctionCall) goja.Value {
	h.requirePermission("secret")
	key := h.requiredTokenArg(call, 0, "key")
	if err := store.DeletePluginRecord(h.db, h.plugin.ID, pluginControlSecretResourceID, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.throwf("secret.delete: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) logInfo(call goja.FunctionCall) goja.Value {
	log.Printf("plugin %s: %s", h.plugin.ID, h.logMessage(call))
	return goja.Undefined()
}

func (h *pluginControlHost) logError(call goja.FunctionCall) goja.Value {
	log.Printf("plugin %s error: %s", h.plugin.ID, h.logMessage(call))
	return goja.Undefined()
}

func (h *pluginControlHost) logMessage(call goja.FunctionCall) string {
	parts := make([]string, 0, len(call.Arguments))
	for _, arg := range call.Arguments {
		if goja.IsUndefined(arg) {
			continue
		}
		parts = append(parts, arg.String())
	}
	message := strings.Join(parts, " ")
	if len(message) > pluginControlMaxLogMessageBytes {
		return message[:pluginControlMaxLogMessageBytes] + "...<truncated>"
	}
	return message
}

func (h *pluginControlHost) requirePermission(permission string) {
	if h.registrationPhase && !pluginControlRegistrationPermissionAllowed(permission) {
		h.throwf("permission %s is unavailable during plugin registration", permission)
	}
	if !pluginControlHasPermission(h.plugin, permission) {
		h.throwf("permission %s is required", permission)
	}
}

func (h *pluginControlHost) requireRegistrationPermission(permission string, api string) {
	if !h.registrationPhase {
		h.throwf("%s is only available during plugin registration", api)
	}
	h.requirePermission(permission)
}

func pluginControlRegistrationPermissionAllowed(permission string) bool {
	switch permission {
	case "plugin.register", "ebpf.load", "hook.attach", "ui":
		return true
	default:
		return false
	}
}

func (h *pluginControlHost) requirePluginResourceAccess(targetPluginID string, resourceID string, method string, api string) {
	if !pluginControlHasResourceAccess(h.plugin, targetPluginID, resourceID, method) {
		h.throwf("%s: resource access %s/%s method %s is not declared", api, targetPluginID, resourceID, method)
	}
}

func (h *pluginControlHost) requirePluginActionAccess(targetPluginID string, actionID string, api string) {
	if !pluginControlHasActionAccess(h.plugin, targetPluginID, actionID) {
		h.throwf("%s: action access %s/%s is not declared", api, targetPluginID, actionID)
	}
}

func (h *pluginControlHost) requireWritablePluginMap(mapName string, api string) {
	h.requirePluginMap(mapName, api)
}

func (h *pluginControlHost) requirePluginMap(mapName string, api string) {
	mapName = strings.TrimSpace(mapName)
	if reason, reserved := pluginControlReservedMapNames[mapName]; reserved {
		h.throwf("%s: map %s is reserved for %s", api, mapName, reason)
	}
}

func (h *pluginControlHost) requirePluginObjectID(objectID string, api string) {
	if objectID == "" {
		return
	}
	for _, object := range h.surface.Objects {
		if object.ID == objectID {
			return
		}
	}
	for _, object := range h.plugin.Objects {
		if object.ID == objectID {
			return
		}
	}
	h.throwf("%s: object %s is not declared", api, objectID)
}

func (h *pluginControlHost) requiredResource(call goja.FunctionCall, index int) PluginResource {
	resourceID := h.requiredTokenArg(call, index, "resource")
	for _, resource := range h.surface.Resources {
		if resource.ID == resourceID {
			return resource
		}
	}
	for _, resource := range h.plugin.Resources {
		if resource.ID == resourceID {
			return resource
		}
	}
	h.throwf("resource %s is not declared", resourceID)
	return PluginResource{}
}

func (h *pluginControlHost) requiredTargetPluginResource(pluginID string, resourceID string) (LoadedPlugin, PluginResource) {
	pluginID, err := pluginPathToken(pluginID)
	if err != nil {
		h.throwf("plugin: %v", err)
	}
	resourceID, err = pluginPathToken(resourceID)
	if err != nil {
		h.throwf("resource: %v", err)
	}
	var plugin LoadedPlugin
	found := false
	if h.runtime != nil {
		h.runtime.mu.Lock()
		if h.runtime.plugins != nil {
			plugin, found = h.runtime.plugins[pluginID]
		}
		h.runtime.mu.Unlock()
	}
	if !found {
		catalog := loadPluginCatalogWithControlRegistration(h.cfg)
		for _, candidate := range catalog.Plugins {
			if candidate.ID == pluginID {
				plugin = candidate
				found = true
				break
			}
		}
	}
	if !found || plugin.Builtin || plugin.Status != pluginStatusActive {
		h.throwf("plugin %s is not active", pluginID)
	}
	for _, resource := range plugin.Resources {
		if resource.ID == resourceID {
			return plugin, resource
		}
	}
	h.throwf("resource %s/%s is not declared", pluginID, resourceID)
	return LoadedPlugin{}, PluginResource{}
}

func (h *pluginControlHost) requiredTargetPluginAction(pluginID string, actionID string) (LoadedPlugin, PluginAction) {
	pluginID, err := pluginPathToken(pluginID)
	if err != nil {
		h.throwf("plugin: %v", err)
	}
	actionID, err = pluginPathToken(actionID)
	if err != nil {
		h.throwf("action: %v", err)
	}
	var plugin LoadedPlugin
	found := false
	if h.runtime != nil {
		h.runtime.mu.Lock()
		if h.runtime.plugins != nil {
			plugin, found = h.runtime.plugins[pluginID]
		}
		h.runtime.mu.Unlock()
	}
	if !found {
		catalog := loadPluginCatalogWithControlRegistration(h.cfg)
		for _, candidate := range catalog.Plugins {
			if candidate.ID == pluginID {
				plugin = candidate
				found = true
				break
			}
		}
	}
	if !found || plugin.Builtin || plugin.Status != pluginStatusActive {
		h.throwf("plugin %s is not active", pluginID)
	}
	for _, action := range plugin.Actions {
		if action.ID == actionID {
			return plugin, action
		}
	}
	h.throwf("action %s/%s is not declared", pluginID, actionID)
	return LoadedPlugin{}, PluginAction{}
}

func (h *pluginControlHost) requiredTokenArg(call goja.FunctionCall, index int, name string) string {
	if len(call.Arguments) <= index || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		h.throwf("%s is required", name)
	}
	value, err := pluginPathToken(call.Arguments[index].String())
	if err != nil {
		h.throwf("%s: %v", name, err)
	}
	return value
}

func (h *pluginControlHost) requiredHandlerArg(call goja.FunctionCall, index int, name string) string {
	if len(call.Arguments) <= index || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		h.throwf("%s is required", name)
	}
	value := strings.TrimSpace(call.Arguments[index].String())
	if !validPluginControlHandlerName(value) {
		h.throwf("%s contains invalid handler name", name)
	}
	return value
}

func (h *pluginControlHost) requiredMapNameArg(call goja.FunctionCall, index int, name string) string {
	if len(call.Arguments) <= index || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		h.throwf("%s is required", name)
	}
	value := strings.TrimSpace(call.Arguments[index].String())
	if value == "" || strings.Contains(value, "\x00") || len(value) > 64 {
		h.throwf("%s contains invalid characters", name)
	}
	return value
}

func (h *pluginControlHost) jsonFromValue(value goja.Value) string {
	if goja.IsUndefined(value) {
		h.throwf("value must not be undefined")
	}
	data, err := json.Marshal(value.Export())
	if err != nil {
		h.throwf("marshal json: %v", err)
	}
	out, err := canonicalPluginRecordJSON(data)
	if err != nil {
		h.throwf("%v", err)
	}
	return out
}

func (h *pluginControlHost) workerRequestFromCall(call goja.FunctionCall, api string) (string, string, json.RawMessage) {
	if h.workerVM {
		h.throwf("%s is unavailable inside plugin workers", api)
	}
	name := h.requiredTokenArg(call, 0, "worker")
	handler := h.requiredHandlerArg(call, 1, "handler")
	payload := json.RawMessage(`{}`)
	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
		payload = json.RawMessage(h.jsonFromValue(call.Arguments[2]))
	}
	if len(payload) > pluginControlWorkerMaxPayloadBytes {
		h.throwf("%s payload exceeds %d bytes", api, pluginControlWorkerMaxPayloadBytes)
	}
	return name, handler, append(json.RawMessage(nil), payload...)
}

func validPluginControlHandlerName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for i, r := range value {
		if r == '_' || r == '$' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func (h *pluginControlHost) pluginResourceJSONFromValue(value goja.Value, resource PluginResource, existing *store.PluginRecord, api string) string {
	if goja.IsUndefined(value) {
		h.throwf("%s: value must not be undefined", api)
	}
	data, err := json.Marshal(value.Export())
	if err != nil {
		h.throwf("%s: marshal json: %v", api, err)
	}
	var out string
	if existing != nil {
		out, err = pluginRecordDataJSONForUpdate(json.RawMessage(data), resource, existing.DataJSON)
	} else {
		out, err = pluginRecordDataJSON(json.RawMessage(data), resource)
	}
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return out
}

func (h *pluginControlHost) listPageFromArg(call goja.FunctionCall, index int, api string) pluginRecordListPage {
	if len(call.Arguments) <= index || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		page, _ := normalizePluginRecordListPage(0, false, 0, false)
		return page
	}
	obj := call.Arguments[index].ToObject(h.vm)
	if obj == nil {
		h.throwf("%s options must be an object", api)
	}
	limit, hasLimit := h.optionalListIntObjectField(obj, "limit")
	offset, hasOffset := h.optionalListIntObjectField(obj, "offset")
	page, err := normalizePluginRecordListPage(limit, hasLimit, offset, hasOffset)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return page
}

func (h *pluginControlHost) optionalListIntObjectField(obj *goja.Object, field string) (int, bool) {
	raw := h.objectField(obj, field)
	if goja.IsUndefined(raw) || goja.IsNull(raw) {
		return 0, false
	}
	return int(raw.ToInteger()), true
}

func (h *pluginControlHost) valueFromRecord(record store.PluginRecord) goja.Value {
	return h.valueFromRecordWithData(record, json.RawMessage(record.DataJSON))
}

func (h *pluginControlHost) valueFromRecordWithResource(record store.PluginRecord, resource PluginResource, redact bool) goja.Value {
	data := json.RawMessage(record.DataJSON)
	if redact {
		data = redactPluginResourceData(record.DataJSON, resource)
	}
	return h.valueFromRecordWithData(record, data)
}

func (h *pluginControlHost) valueFromRecordWithData(record store.PluginRecord, data json.RawMessage) goja.Value {
	return h.vm.ToValue(map[string]any{
		"key":        record.RecordKey,
		"data":       pluginControlDecodeJSON(data),
		"enabled":    record.Enabled,
		"revision":   record.Revision,
		"created_at": record.CreatedAt,
		"updated_at": record.UpdatedAt,
	})
}

func (h *pluginControlHost) recordsForScript(records []store.PluginRecord) []map[string]any {
	return h.recordsForScriptWithResource(records, PluginResource{}, false)
}

func (h *pluginControlHost) recordsForScriptWithResource(records []store.PluginRecord, resource PluginResource, redact bool) []map[string]any {
	out := make([]map[string]any, 0, len(records))
	for _, record := range records {
		data := json.RawMessage(record.DataJSON)
		if redact {
			data = redactPluginResourceData(record.DataJSON, resource)
		}
		out = append(out, map[string]any{
			"key":        record.RecordKey,
			"data":       pluginControlDecodeJSON(data),
			"enabled":    record.Enabled,
			"revision":   record.Revision,
			"created_at": record.CreatedAt,
			"updated_at": record.UpdatedAt,
		})
	}
	return out
}

func (h *pluginControlHost) ebpfMapPutArgs(call goja.FunctionCall) (string, string, []byte, []byte) {
	offset := 0
	objectID := ""
	if len(call.Arguments) == 4 {
		objectID = h.requiredTokenArg(call, 0, "object")
		offset = 1
	}
	mapName := h.requiredMapNameArg(call, offset, "map")
	key := h.hexArg(call, offset+1, "key")
	value := h.hexArg(call, offset+2, "value")
	return objectID, mapName, key, value
}

func (h *pluginControlHost) ebpfMapDeleteArgs(call goja.FunctionCall) (string, string, []byte) {
	offset := 0
	objectID := ""
	if len(call.Arguments) == 3 {
		objectID = h.requiredTokenArg(call, 0, "object")
		offset = 1
	}
	mapName := h.requiredMapNameArg(call, offset, "map")
	key := h.hexArg(call, offset+1, "key")
	return objectID, mapName, key
}

func (h *pluginControlHost) ebpfMapClearArgs(call goja.FunctionCall) (string, string) {
	offset := 0
	objectID := ""
	if len(call.Arguments) == 2 {
		objectID = h.requiredTokenArg(call, 0, "object")
		offset = 1
	}
	mapName := h.requiredMapNameArg(call, offset, "map")
	return objectID, mapName
}

func (h *pluginControlHost) timerSpecFromCall(call goja.FunctionCall, kind string) pluginControlTimerSpec {
	name := h.requiredTokenArg(call, 0, "timer")
	if len(call.Arguments) <= 1 || goja.IsUndefined(call.Arguments[1]) || goja.IsNull(call.Arguments[1]) {
		h.throwf("timer delay is required")
	}
	delayMs := call.Arguments[1].ToInteger()
	delay := time.Duration(delayMs) * time.Millisecond
	if delay < pluginControlMinTimerDelay || delay > pluginControlMaxTimerDelay {
		h.throwf("timer delay must be between %d and %d ms", pluginControlMinTimerDelay.Milliseconds(), pluginControlMaxTimerDelay.Milliseconds())
	}
	payload := json.RawMessage(`{}`)
	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
		payload = json.RawMessage(h.jsonFromValue(call.Arguments[2]))
	}
	if len(payload) > pluginControlMaxTimerPayloadBytes {
		h.throwf("timer payload exceeds %d bytes", pluginControlMaxTimerPayloadBytes)
	}
	return pluginControlTimerSpec{
		Name:    name,
		Kind:    kind,
		Delay:   delay,
		Payload: append(json.RawMessage(nil), payload...),
	}
}

func (h *pluginControlHost) l2SendRequest(call goja.FunctionCall) pluginControlL2SendRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	req := h.l2SendRequestFromObject(obj)
	h.requireNetAccess("l2", req.Interface, "net.l2.send")
	return req
}

func (h *pluginControlHost) l2RecvRequest(call goja.FunctionCall) pluginControlL2RecvRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	req := h.l2RecvRequestFromObject(obj)
	h.requireNetAccess("l2", req.Interface, "net.l2.recv")
	return req
}

func (h *pluginControlHost) l2RecvManyRequest(call goja.FunctionCall) pluginControlL2RecvManyRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	req := h.l2RecvManyRequestFromObject(obj)
	h.requireNetAccess("l2", req.Recv.Interface, "net.l2.recvMany")
	return req
}

func (h *pluginControlHost) l2ExchangeRequest(call goja.FunctionCall) pluginControlL2ExchangeRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlL2ExchangeRequest{
		Send: h.l2SendRequestFromObject(obj),
		Recv: h.l2RecvRequestFromObject(obj),
	}
	h.requireNetAccess("l2", req.Send.Interface, "net.l2.exchange")
	h.requireNetAccess("l2", req.Recv.Interface, "net.l2.exchange")
	return req
}

func (h *pluginControlHost) l2ExchangeManyRequest(call goja.FunctionCall) pluginControlL2ExchangeManyRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlL2ExchangeManyRequest{
		Send: h.l2SendRequestFromObject(obj),
		Recv: h.l2RecvManyRequestFromObject(obj),
	}
	h.requireNetAccess("l2", req.Send.Interface, "net.l2.exchangeMany")
	h.requireNetAccess("l2", req.Recv.Recv.Interface, "net.l2.exchangeMany")
	return req
}

func (h *pluginControlHost) udpSendRequest(call goja.FunctionCall) pluginControlUDPSendRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	req := h.udpSendRequestFromObject(obj)
	h.requireNetAccess("udp", req.Interface, "net.udp.send")
	return req
}

func (h *pluginControlHost) udpRecvRequest(call goja.FunctionCall) pluginControlUDPRecvRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	req := h.udpRecvRequestFromObject(obj)
	h.requireNetAccess("udp", req.Interface, "net.udp.recv")
	return req
}

func (h *pluginControlHost) udpExchangeRequest(call goja.FunctionCall) pluginControlUDPExchangeRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	send := h.udpSendRequestFromObject(obj)
	req := pluginControlUDPExchangeRequest{
		Send: send,
		Recv: h.udpRecvRequestFromObjectWithDefaults(obj, send.Interface, send.LocalIP, send.LocalPort, false, false),
	}
	if req.Recv.RemoteIP == nil {
		req.Recv.RemoteIP = req.Send.RemoteIP
	}
	if req.Recv.RemotePort <= 0 {
		req.Recv.RemotePort = req.Send.RemotePort
	}
	req.Recv.HasRemoteFilter = true
	if req.Send.Interface != req.Recv.Interface {
		h.throwf("net.udp.exchange: send and receive interface must match")
	}
	h.requireNetAccess("udp", req.Send.Interface, "net.udp.exchange")
	return req
}

func (h *pluginControlHost) l2SendRequestFromObject(obj *goja.Object) pluginControlL2SendRequest {
	payload := h.optionalHexObjectField(obj, "payload")
	if len(payload) > pluginControlL2MaxPayloadBytes {
		h.throwf("net.l2.send: payload exceeds %d bytes", pluginControlL2MaxPayloadBytes)
	}
	req := pluginControlL2SendRequest{
		Interface: h.requiredStringObjectField(obj, "interface"),
		EtherType: h.requiredEtherTypeObjectField(obj, "ethertype"),
		DstMAC:    h.requiredMACObjectField(obj, "dst_mac"),
		Payload:   payload,
	}
	if err := validatePluginControlInterfaceName(req.Interface, "interface"); err != nil {
		h.throwf("net.l2.send: %v", err)
	}
	if src := h.optionalStringObjectField(obj, "src_mac"); src != "" {
		mac, err := parsePluginControlMAC(src)
		if err != nil {
			h.throwf("net.l2.send src_mac: %v", err)
		}
		req.SrcMAC = mac
		req.HasSrcMAC = true
	}
	return req
}

func (h *pluginControlHost) l2RecvRequestFromObject(obj *goja.Object) pluginControlL2RecvRequest {
	timeout := pluginControlL2DefaultTimeout
	if raw := h.objectField(obj, "timeout_ms"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		timeout = time.Duration(raw.ToInteger()) * time.Millisecond
		if timeout <= 0 || timeout > pluginControlL2MaxTimeout {
			h.throwf("net.l2.recv timeout_ms must be between 1 and %d", pluginControlL2MaxTimeout.Milliseconds())
		}
	}
	maxBytes := 2048
	if raw := h.objectField(obj, "max_bytes"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		maxBytes = int(raw.ToInteger())
		if maxBytes < 64 || maxBytes > pluginControlL2MaxPayloadBytes+14 {
			h.throwf("net.l2.recv max_bytes must be between 64 and %d", pluginControlL2MaxPayloadBytes+14)
		}
	}
	req := pluginControlL2RecvRequest{
		Interface: h.requiredStringObjectField(obj, "interface"),
		EtherType: h.requiredEtherTypeObjectField(obj, "ethertype"),
		Timeout:   timeout,
		MaxBytes:  maxBytes,
	}
	if err := validatePluginControlInterfaceName(req.Interface, "interface"); err != nil {
		h.throwf("net.l2.recv: %v", err)
	}
	if src := h.optionalStringObjectField(obj, "recv_src_mac"); src != "" {
		mac, err := parsePluginControlMAC(src)
		if err != nil {
			h.throwf("net.l2.recv recv_src_mac: %v", err)
		}
		req.SrcMAC = mac
		req.HasSrcMAC = true
	}
	if dst := h.optionalStringObjectField(obj, "recv_dst_mac"); dst != "" {
		mac, err := parsePluginControlMAC(dst)
		if err != nil {
			h.throwf("net.l2.recv recv_dst_mac: %v", err)
		}
		req.DstMAC = mac
		req.HasDstMAC = true
	}
	if code, ok := h.optionalUintObjectField(obj, "pppoe_code", 8); ok {
		req.PPPoECode = uint8(code)
		req.HasPPPoECode = true
	}
	if sessionID, ok := h.optionalUintObjectField(obj, "pppoe_session_id", 16); ok {
		req.PPPoESessionID = uint16(sessionID)
		req.HasPPPoESessionID = true
	}
	return req
}

func (h *pluginControlHost) l2RecvManyRequestFromObject(obj *goja.Object) pluginControlL2RecvManyRequest {
	maxFrames := 8
	if raw := h.objectField(obj, "max_frames"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		maxFrames = int(raw.ToInteger())
		if maxFrames <= 0 || maxFrames > pluginControlL2MaxRecvFrames {
			h.throwf("net.l2.recvMany max_frames must be between 1 and %d", pluginControlL2MaxRecvFrames)
		}
	}
	idleTimeout := 10 * time.Millisecond
	if raw := h.objectField(obj, "idle_timeout_ms"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		idleTimeout = time.Duration(raw.ToInteger()) * time.Millisecond
		if idleTimeout <= 0 || idleTimeout > pluginControlL2MaxTimeout {
			h.throwf("net.l2.recvMany idle_timeout_ms must be between 1 and %d", pluginControlL2MaxTimeout.Milliseconds())
		}
	}
	return pluginControlL2RecvManyRequest{
		Recv:        h.l2RecvRequestFromObject(obj),
		MaxFrames:   maxFrames,
		IdleTimeout: idleTimeout,
	}
}

func (h *pluginControlHost) udpSendRequestFromObject(obj *goja.Object) pluginControlUDPSendRequest {
	payload := h.optionalHexObjectField(obj, "payload", "payload_hex")
	if len(payload) > pluginControlUDPMaxPayloadBytes {
		h.throwf("net.udp.send: payload exceeds %d bytes", pluginControlUDPMaxPayloadBytes)
	}
	return pluginControlUDPSendRequest{
		Interface:  h.requiredUDPInterfaceObjectField(obj, "interface"),
		LocalIP:    h.optionalIPObjectField(obj, "local_ip", "bind_ip", "source_ip"),
		LocalPort:  h.optionalPortObjectField(obj, 0, "local_port", "bind_port", "source_port"),
		RemoteIP:   h.requiredIPObjectField(obj, "remote_ip", "dst_ip", "target_ip"),
		RemotePort: h.requiredPortObjectField(obj, "remote_port", "dst_port", "target_port", "port"),
		Payload:    payload,
		Timeout:    h.udpTimeoutObjectField(obj, "timeout_ms"),
	}
}

func (h *pluginControlHost) udpRecvRequestFromObject(obj *goja.Object) pluginControlUDPRecvRequest {
	req := h.udpRecvRequestFromObjectWithDefaults(obj, "", nil, 0, true, true)
	return req
}

func (h *pluginControlHost) udpRecvRequestFromObjectWithDefaults(obj *goja.Object, defaultInterface string, defaultLocalIP net.IP, defaultLocalPort int, requireLocalPort bool, allowPortAlias bool) pluginControlUDPRecvRequest {
	maxBytes := 2048
	if raw := h.objectField(obj, "max_bytes"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		maxBytes = int(raw.ToInteger())
		if maxBytes < 1 || maxBytes > pluginControlUDPMaxPayloadBytes {
			h.throwf("net.udp.recv max_bytes must be between 1 and %d", pluginControlUDPMaxPayloadBytes)
		}
	}
	localPortFields := []string{"local_port", "bind_port"}
	if allowPortAlias {
		localPortFields = append(localPortFields, "port")
	}
	localPort := h.optionalPortObjectField(obj, defaultLocalPort, localPortFields...)
	if requireLocalPort && localPort <= 0 {
		h.throwf("net.udp.recv: local_port is required")
	}
	req := pluginControlUDPRecvRequest{
		Interface: h.optionalUDPInterfaceObjectField(obj, defaultInterface, "interface"),
		LocalIP:   h.optionalIPObjectFieldWithDefault(obj, defaultLocalIP, "local_ip", "bind_ip"),
		LocalPort: localPort,
		Timeout:   h.udpTimeoutObjectField(obj, "timeout_ms"),
		MaxBytes:  maxBytes,
	}
	if req.Interface == "" {
		h.throwf("net.udp.recv: interface is required")
	}
	if remoteIP := h.optionalIPObjectField(obj, "remote_ip", "src_ip", "peer_ip"); remoteIP != nil {
		req.RemoteIP = remoteIP
		req.HasRemoteFilter = true
	}
	if remotePort := h.optionalPortObjectField(obj, 0, "remote_port", "src_port", "peer_port"); remotePort > 0 {
		req.RemotePort = remotePort
		req.HasRemoteFilter = true
	}
	return req
}

func (h *pluginControlHost) l2FrameValue(frame pluginControlL2Frame) goja.Value {
	return h.vm.ToValue(h.l2FrameObject(frame))
}

func (h *pluginControlHost) l2FrameObject(frame pluginControlL2Frame) map[string]any {
	return map[string]any{
		"interface":   frame.Interface,
		"ifindex":     frame.IfIndex,
		"ethertype":   fmt.Sprintf("0x%04x", frame.EtherType),
		"dst_mac":     formatPluginControlMAC(frame.DstMAC),
		"src_mac":     formatPluginControlMAC(frame.SrcMAC),
		"payload_hex": hex.EncodeToString(frame.Payload),
		"frame_hex":   hex.EncodeToString(frame.Frame),
	}
}

func (h *pluginControlHost) udpResultObject(result pluginControlUDPResult) map[string]any {
	out := map[string]any{
		"interface": result.Interface,
		"bytes":     result.Bytes,
	}
	if result.LocalAddr != nil {
		out["local_ip"] = result.LocalAddr.IP.String()
		out["local_port"] = result.LocalAddr.Port
		out["local_addr"] = result.LocalAddr.String()
	}
	if result.RemoteAddr != nil {
		out["remote_ip"] = result.RemoteAddr.IP.String()
		out["remote_port"] = result.RemoteAddr.Port
		out["remote_addr"] = result.RemoteAddr.String()
	}
	return out
}

func (h *pluginControlHost) udpDatagramObject(datagram pluginControlUDPDatagram) map[string]any {
	out := map[string]any{
		"interface":   datagram.Interface,
		"payload_hex": hex.EncodeToString(datagram.Payload),
		"bytes":       len(datagram.Payload),
	}
	if datagram.LocalAddr != nil {
		out["local_ip"] = datagram.LocalAddr.IP.String()
		out["local_port"] = datagram.LocalAddr.Port
		out["local_addr"] = datagram.LocalAddr.String()
	}
	if datagram.RemoteAddr != nil {
		out["remote_ip"] = datagram.RemoteAddr.IP.String()
		out["remote_port"] = datagram.RemoteAddr.Port
		out["remote_addr"] = datagram.RemoteAddr.String()
	}
	return out
}

func (h *pluginControlHost) requiredObjectArg(call goja.FunctionCall, index int, name string) *goja.Object {
	if len(call.Arguments) <= index || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		h.throwf("%s is required", name)
	}
	obj := call.Arguments[index].ToObject(h.vm)
	if obj == nil {
		h.throwf("%s must be an object", name)
	}
	return obj
}

func (h *pluginControlHost) objectField(obj *goja.Object, field string) goja.Value {
	value := obj.Get(field)
	if value == nil {
		return goja.Undefined()
	}
	return value
}

func (h *pluginControlHost) requiredStringObjectField(obj *goja.Object, field string) string {
	raw := h.objectField(obj, field)
	if goja.IsUndefined(raw) || goja.IsNull(raw) {
		h.throwf("%s is required", field)
	}
	value := strings.TrimSpace(raw.String())
	if value == "" || strings.Contains(value, "\x00") || len(value) > 64 {
		h.throwf("%s is required", field)
	}
	return value
}

func (h *pluginControlHost) optionalStringObjectField(obj *goja.Object, field string) string {
	value := h.objectField(obj, field)
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return ""
	}
	return strings.TrimSpace(value.String())
}

func (h *pluginControlHost) requiredUDPInterfaceObjectField(obj *goja.Object, field string) string {
	return h.optionalUDPInterfaceObjectField(obj, "", field)
}

func (h *pluginControlHost) optionalUDPInterfaceObjectField(obj *goja.Object, fallback string, fields ...string) string {
	value := strings.TrimSpace(fallback)
	for _, field := range fields {
		if current := h.optionalStringObjectField(obj, field); current != "" {
			value = current
			break
		}
	}
	if value == "" {
		h.throwf("%s is required", fields[0])
	}
	if err := validatePluginControlInterfaceName(value, fields[0]); err != nil {
		h.throwf("%v", err)
	}
	return value
}

func (h *pluginControlHost) requiredIPObjectField(obj *goja.Object, fields ...string) net.IP {
	ip := h.optionalIPObjectField(obj, fields...)
	if ip == nil {
		h.throwf("%s is required", fields[0])
	}
	return ip
}

func (h *pluginControlHost) optionalIPObjectField(obj *goja.Object, fields ...string) net.IP {
	return h.optionalIPObjectFieldWithDefault(obj, nil, fields...)
}

func (h *pluginControlHost) optionalIPObjectFieldWithDefault(obj *goja.Object, fallback net.IP, fields ...string) net.IP {
	for _, field := range fields {
		raw := h.optionalStringObjectField(obj, field)
		if raw == "" {
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			h.throwf("%s must be a valid IP address", field)
		}
		return ip
	}
	return fallback
}

func (h *pluginControlHost) requiredPortObjectField(obj *goja.Object, fields ...string) int {
	port := h.optionalPortObjectField(obj, 0, fields...)
	if port <= 0 {
		h.throwf("%s is required", fields[0])
	}
	return port
}

func (h *pluginControlHost) optionalPortObjectField(obj *goja.Object, fallback int, fields ...string) int {
	for _, field := range fields {
		raw := h.objectField(obj, field)
		if goja.IsUndefined(raw) || goja.IsNull(raw) {
			continue
		}
		port := int(raw.ToInteger())
		if port < 0 || port > 65535 {
			h.throwf("%s must be between 0 and 65535", field)
		}
		return port
	}
	return fallback
}

func (h *pluginControlHost) udpTimeoutObjectField(obj *goja.Object, field string) time.Duration {
	timeout := pluginControlUDPDefaultTimeout
	if raw := h.objectField(obj, field); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		timeout = time.Duration(raw.ToInteger()) * time.Millisecond
		if timeout <= 0 || timeout > pluginControlUDPMaxTimeout {
			h.throwf("net.udp timeout_ms must be between 1 and %d", pluginControlUDPMaxTimeout.Milliseconds())
		}
	}
	return timeout
}

func (h *pluginControlHost) optionalUintObjectField(obj *goja.Object, field string, bits int) (uint64, bool) {
	value := h.objectField(obj, field)
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return 0, false
	}
	parsed, err := parsePluginControlUint(value, bits)
	if err != nil {
		h.throwf("%s: %v", field, err)
	}
	return parsed, true
}

func (h *pluginControlHost) requiredEtherTypeObjectField(obj *goja.Object, field string) uint16 {
	etherType, err := parsePluginControlEtherType(h.objectField(obj, field))
	if err != nil {
		h.throwf("%s: %v", field, err)
	}
	return etherType
}

func (h *pluginControlHost) requiredMACObjectField(obj *goja.Object, field string) [6]byte {
	mac, err := parsePluginControlMAC(h.requiredStringObjectField(obj, field))
	if err != nil {
		h.throwf("%s: %v", field, err)
	}
	return mac
}

func (h *pluginControlHost) optionalHexObjectField(obj *goja.Object, fields ...string) []byte {
	for _, field := range fields {
		value := h.objectField(obj, field)
		if goja.IsUndefined(value) || goja.IsNull(value) {
			continue
		}
		raw := strings.TrimSpace(value.String())
		if raw == "" {
			continue
		}
		out, err := decodePluginControlHexBytes(raw)
		if err != nil {
			h.throwf("%s: %v", field, err)
		}
		return out
	}
	return nil
}

func (h *pluginControlHost) hexArg(call goja.FunctionCall, index int, name string) []byte {
	if len(call.Arguments) <= index || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		h.throwf("%s is required", name)
	}
	value, err := decodePluginControlHexBytes(call.Arguments[index].String())
	if err != nil {
		h.throwf("%s: %v", name, err)
	}
	return value
}

func (rt *gojaPluginControlRuntime) applyTimerOperations(plugin LoadedPlugin, ops []pluginControlTimerOperation) error {
	if len(ops) == 0 {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return nil
	}
	if _, ok := rt.plugins[plugin.ID]; !ok {
		return nil
	}
	if err := rt.validateTimerOperationsLocked(plugin.ID, ops); err != nil {
		return err
	}
	for _, op := range ops {
		key := pluginControlTimerKey{pluginID: plugin.ID, name: op.spec.Name}
		switch op.op {
		case pluginControlTimerOperationSet:
			rt.setPluginTimerLocked(key, op.spec)
		case pluginControlTimerOperationClear:
			rt.clearPluginTimerLocked(key)
		}
	}
	return nil
}

func (rt *gojaPluginControlRuntime) validateTimerOperationsLocked(pluginID string, ops []pluginControlTimerOperation) error {
	names := make(map[string]struct{})
	for key := range rt.timers {
		if key.pluginID == pluginID {
			names[key.name] = struct{}{}
		}
	}
	for _, op := range ops {
		name := strings.TrimSpace(op.spec.Name)
		if name == "" {
			continue
		}
		switch op.op {
		case pluginControlTimerOperationSet:
			names[name] = struct{}{}
		case pluginControlTimerOperationClear:
			delete(names, name)
		}
	}
	if len(names) > pluginControlMaxTimersPerPlugin {
		return fmt.Errorf("plugin timer limit reached: %d > %d", len(names), pluginControlMaxTimersPerPlugin)
	}
	return nil
}

func (rt *gojaPluginControlRuntime) setPluginTimerLocked(key pluginControlTimerKey, spec pluginControlTimerSpec) {
	if key.pluginID == "" || key.name == "" {
		return
	}
	spec.Name = key.name
	if spec.Kind == "" {
		spec.Kind = pluginControlTimerKindTimeout
	}
	if spec.Delay < pluginControlMinTimerDelay {
		spec.Delay = pluginControlMinTimerDelay
	}
	if spec.Payload == nil {
		spec.Payload = json.RawMessage(`{}`)
	}
	if rt.timers == nil {
		rt.timers = make(map[pluginControlTimerKey]pluginControlTimerState)
	}
	state := rt.timers[key]
	if state.timer != nil {
		state.timer.Stop()
	}
	state.spec = spec
	state.generation++
	rt.armPluginTimerLocked(key, state)
}

func (rt *gojaPluginControlRuntime) armPluginTimerLocked(key pluginControlTimerKey, state pluginControlTimerState) {
	if state.spec.Delay <= 0 {
		state.spec.Delay = pluginControlMinTimerDelay
	}
	state.spec.NextFire = time.Now().Add(state.spec.Delay)
	generation := state.generation
	state.timer = time.AfterFunc(state.spec.Delay, func() {
		rt.firePluginTimer(key, generation)
	})
	rt.timers[key] = state
}

func (rt *gojaPluginControlRuntime) clearPluginTimerLocked(key pluginControlTimerKey) {
	state, ok := rt.timers[key]
	if !ok {
		return
	}
	if state.timer != nil {
		state.timer.Stop()
	}
	delete(rt.timers, key)
}

func (rt *gojaPluginControlRuntime) cancelInactivePluginTimersLocked(active map[string]LoadedPlugin) {
	for key := range rt.timers {
		if _, ok := active[key.pluginID]; ok {
			continue
		}
		rt.clearPluginTimerLocked(key)
	}
}

func (rt *gojaPluginControlRuntime) inactivePluginControlVMsLocked(active map[string]LoadedPlugin) []*pluginControlVM {
	out := make([]*pluginControlVM, 0)
	for pluginID, vm := range rt.controlVMs {
		if _, ok := active[pluginID]; ok {
			continue
		}
		out = append(out, vm)
		delete(rt.controlVMs, pluginID)
	}
	for key, vm := range rt.pluginWorkers {
		if _, ok := active[key.pluginID]; ok {
			continue
		}
		out = append(out, vm)
		delete(rt.pluginWorkers, key)
	}
	return out
}

func (rt *gojaPluginControlRuntime) allPluginControlVMsLocked() []*pluginControlVM {
	out := make([]*pluginControlVM, 0, len(rt.controlVMs)+len(rt.pluginWorkers))
	for _, vm := range rt.controlVMs {
		out = append(out, vm)
	}
	for _, vm := range rt.pluginWorkers {
		out = append(out, vm)
	}
	return out
}

func stopPluginControlVMs(vms []*pluginControlVM) {
	for _, vm := range vms {
		if vm != nil {
			vm.stopVM()
		}
	}
}

func (rt *gojaPluginControlRuntime) pluginWorkerCountLocked(pluginID string) int {
	count := 0
	for key := range rt.pluginWorkers {
		if key.pluginID == pluginID {
			count++
		}
	}
	return count
}

func (rt *gojaPluginControlRuntime) pluginControlWorkersLocked(pluginID string) []*pluginControlVM {
	out := make([]*pluginControlVM, 0)
	for key, vm := range rt.pluginWorkers {
		if key.pluginID != pluginID {
			continue
		}
		out = append(out, vm)
		delete(rt.pluginWorkers, key)
	}
	return out
}

func (rt *gojaPluginControlRuntime) firePluginTimer(key pluginControlTimerKey, generation uint64) {
	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		return
	}
	state, ok := rt.timers[key]
	if !ok || state.generation != generation {
		rt.mu.Unlock()
		return
	}
	plugin, ok := rt.plugins[key.pluginID]
	if !ok {
		rt.clearPluginTimerLocked(key)
		rt.mu.Unlock()
		return
	}
	spec := state.spec
	state.timer = nil
	if spec.Kind == pluginControlTimerKindTimeout {
		delete(rt.timers, key)
	} else {
		rt.timers[key] = state
	}
	rt.mu.Unlock()

	timerErr := rt.runPluginControl(plugin, pluginControlEvent{Kind: "timer", Timer: &spec}, true)
	if timerErr == nil {
		timerErr = rt.applyStaleRuntimeResourcesAfterTimer(plugin)
	}
	if timerErr != nil {
		log.Printf("plugin control timer %s/%s failed: %v", key.pluginID, key.name, timerErr)
		_ = store.UpsertPluginRuntimeStatus(rt.db, store.PluginRuntimeStatus{
			PluginID:   key.pluginID,
			TargetType: pluginControlTimerRuntimeTarget,
			TargetID:   key.name,
			Status:     pluginControlTimerRuntimeStatusErr,
			LastError:  timerErr.Error(),
		})
	} else {
		rt.clearPluginTimerRuntimeError(key)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return
	}
	state, ok = rt.timers[key]
	if !ok || state.generation != generation || state.spec.Kind != pluginControlTimerKindInterval {
		return
	}
	if _, ok := rt.plugins[key.pluginID]; !ok {
		rt.clearPluginTimerLocked(key)
		return
	}
	rt.armPluginTimerLocked(key, state)
}

func (rt *gojaPluginControlRuntime) applyStaleRuntimeResourcesAfterTimer(plugin LoadedPlugin) error {
	if rt == nil || rt.db == nil {
		return nil
	}
	failures := make([]string, 0)
	for _, resource := range plugin.Resources {
		if resource.RuntimeUpdate != "runtime_apply" {
			continue
		}
		current := resource
		status, err := store.PluginRuntimeStatusOrNil(rt.db, plugin.ID, "resource", current.ID)
		if err != nil {
			failures = append(failures, current.ID+": "+err.Error())
			continue
		}
		if !pluginRuntimeStatusNeedsRecovery(status) {
			continue
		}
		records, err := loadPluginResourceRecords(rt.db, plugin, current)
		if err != nil {
			_ = markPluginRuntimeError(rt.db, plugin.ID, "resource", current.ID, err)
			failures = append(failures, current.ID+": "+err.Error())
			continue
		}
		err = rt.runPluginControl(plugin, pluginControlEvent{
			Kind:     "resource_apply",
			Resource: &current,
			Records:  records,
		}, false)
		if err != nil {
			_ = markPluginRuntimeError(rt.db, plugin.ID, "resource", current.ID, err)
			failures = append(failures, current.ID+": "+err.Error())
			continue
		}
		if err := markPluginRuntimeAppliedToCurrentRevision(rt.db, plugin.ID, "resource", current.ID); err != nil {
			failures = append(failures, current.ID+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("runtime_apply resource recovery failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

func pluginRuntimeStatusNeedsRecovery(status *store.PluginRuntimeStatus) bool {
	if status == nil {
		return false
	}
	return status.Status != "applied" || status.LastError != "" || status.AppliedRevision != status.Revision
}

func (rt *gojaPluginControlRuntime) clearPluginTimerRuntimeError(key pluginControlTimerKey) {
	if rt == nil || rt.db == nil || key.pluginID == "" || key.name == "" {
		return
	}
	status, err := store.PluginRuntimeStatusOrNil(rt.db, key.pluginID, pluginControlTimerRuntimeTarget, key.name)
	if err != nil {
		log.Printf("plugin control timer %s/%s status lookup failed: %v", key.pluginID, key.name, err)
		return
	}
	if status == nil || status.Status != pluginControlTimerRuntimeStatusErr {
		return
	}
	if err := store.UpsertPluginRuntimeStatus(rt.db, store.PluginRuntimeStatus{
		PluginID:   key.pluginID,
		TargetType: pluginControlTimerRuntimeTarget,
		TargetID:   key.name,
		Status:     pluginControlTimerRuntimeStatusOK,
		LastError:  "",
	}); err != nil {
		log.Printf("plugin control timer %s/%s status recovery failed: %v", key.pluginID, key.name, err)
	}
}

func (rt *gojaPluginControlRuntime) pluginTimerList(pluginID string) []map[string]any {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]map[string]any, 0)
	for key, state := range rt.timers {
		if key.pluginID != pluginID {
			continue
		}
		out = append(out, map[string]any{
			"name":      state.spec.Name,
			"kind":      state.spec.Kind,
			"delay_ms":  state.spec.Delay.Milliseconds(),
			"next_fire": state.spec.NextFire.UTC().Format(time.RFC3339Nano),
		})
	}
	return out
}

func (rt *gojaPluginControlRuntime) pluginWorkerList(pluginID string) []map[string]any {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]map[string]any, 0)
	for key, vm := range rt.pluginWorkers {
		if key.pluginID != pluginID {
			continue
		}
		out = append(out, map[string]any{
			"name": key.name,
			"mode": vm.mode,
		})
	}
	return out
}

func (h *pluginControlHost) bytesFromCryptoArg(value goja.Value) ([]byte, error) {
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return nil, fmt.Errorf("value is required")
	}
	exported := value.Export()
	switch typed := exported.(type) {
	case string:
		return []byte(typed), nil
	case []byte:
		return typed, nil
	case []any:
		return bytesFromNumberSlice(typed)
	case map[string]any:
		if rawHex, ok := typed["hex"]; ok {
			return decodePluginControlHexBytes(fmt.Sprint(rawHex))
		}
		if rawText, ok := typed["text"]; ok {
			return []byte(fmt.Sprint(rawText)), nil
		}
		return nil, fmt.Errorf("object must contain hex or text")
	default:
		return nil, fmt.Errorf("unsupported value type %T", exported)
	}
}

func bytesFromNumberSlice(values []any) ([]byte, error) {
	out := make([]byte, 0, len(values))
	for i, value := range values {
		number, ok := numericByte(value)
		if !ok {
			return nil, fmt.Errorf("byte array item %d must be an integer between 0 and 255", i)
		}
		out = append(out, number)
	}
	return out, nil
}

func numericByte(value any) (byte, bool) {
	switch typed := value.(type) {
	case int:
		if typed < 0 || typed > 255 {
			return 0, false
		}
		return byte(typed), true
	case int64:
		if typed < 0 || typed > 255 {
			return 0, false
		}
		return byte(typed), true
	case float64:
		if typed < 0 || typed > 255 || typed != float64(byte(typed)) {
			return 0, false
		}
		return byte(typed), true
	default:
		return 0, false
	}
}

func parsePluginControlEtherType(value goja.Value) (uint16, error) {
	parsed, err := parsePluginControlUint(value, 16)
	if err != nil {
		return 0, err
	}
	if parsed == 0 {
		return 0, fmt.Errorf("ethertype must be non-zero")
	}
	return uint16(parsed), nil
}

func parsePluginControlUint(value goja.Value, bits int) (uint64, error) {
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return 0, fmt.Errorf("value is required")
	}
	raw := strings.TrimSpace(value.String())
	if raw == "" {
		return 0, fmt.Errorf("value is required")
	}
	base := 10
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		raw = raw[2:]
		base = 16
	}
	parsed, err := strconv.ParseUint(raw, base, bits)
	if err != nil {
		return 0, err
	}
	return parsed, nil
}

func parsePluginControlMAC(value string) ([6]byte, error) {
	var out [6]byte
	mac, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil {
		return out, err
	}
	if len(mac) != 6 {
		return out, fmt.Errorf("expected 6-byte ethernet MAC")
	}
	copy(out[:], mac)
	return out, nil
}

func formatPluginControlMAC(value [6]byte) string {
	return net.HardwareAddr(value[:]).String()
}

func (h *pluginControlHost) throwf(format string, args ...any) {
	panic(h.vm.NewTypeError(fmt.Sprintf(format, args...)))
}

func upsertPluginControlRecord(db store.RuleStore, pluginID string, resourceID string, recordKey string, dataJSON string, enabled bool, maxRecords int) error {
	_, err := store.GetPluginRecord(db, pluginID, resourceID, recordKey)
	if err == nil {
		return store.UpdatePluginRecord(db, &store.PluginRecord{
			PluginID:   pluginID,
			ResourceID: resourceID,
			RecordKey:  recordKey,
			DataJSON:   dataJSON,
			Enabled:    enabled,
		})
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if maxRecords > 0 {
		count, err := store.CountPluginRecords(db, pluginID, resourceID)
		if err != nil {
			return err
		}
		if count >= maxRecords {
			return fmt.Errorf("resource record limit reached")
		}
	}
	_, err = store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   pluginID,
		ResourceID: resourceID,
		RecordKey:  recordKey,
		DataJSON:   dataJSON,
		Enabled:    enabled,
	})
	if store.SQLiteUniqueConstraintIndexName(err) == store.ConstraintIndexPluginRecordKey {
		return store.UpdatePluginRecord(db, &store.PluginRecord{
			PluginID:   pluginID,
			ResourceID: resourceID,
			RecordKey:  recordKey,
			DataJSON:   dataJSON,
			Enabled:    enabled,
		})
	}
	return err
}

func decodePluginControlHexBytes(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	replacer := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	value = replacer.Replace(value)
	if value == "" {
		return nil, fmt.Errorf("empty hex string")
	}
	if len(value)%2 != 0 {
		return nil, fmt.Errorf("hex string must contain an even number of characters")
	}
	out, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return out, nil
}
