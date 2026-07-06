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
	pluginControlTimeout               = 8 * time.Second
	pluginControlMaxSecretBytes        = 4096
	pluginControlMaxRandomBytes        = 1024
	pluginControlMaxTimerPayloadBytes  = 16 << 10
	pluginControlMinTimerDelay         = 10 * time.Millisecond
	pluginControlMaxTimerDelay         = 24 * time.Hour
	pluginControlTimerKindTimeout      = "timeout"
	pluginControlTimerKindInterval     = "interval"
	pluginControlTimerOperationSet     = "set"
	pluginControlTimerOperationClear   = "clear"
	pluginControlTimerRuntimeTarget    = "timer"
	pluginControlTimerRuntimeStatusErr = "error"
)

type pluginControlRuntime interface {
	pluginRuntimeDataApplier
	Reconcile(catalog PluginCatalog) pluginRuntimeSnapshot
	Snapshot() pluginRuntimeSnapshot
	Close() error
}

type pluginEBPFMapController interface {
	PutPluginMapValue(pluginID string, objectID string, mapName string, key []byte, value []byte) error
	DeletePluginMapValue(pluginID string, objectID string, mapName string, key []byte) error
	ClearPluginMap(pluginID string, objectID string, mapName string) error
}

type gojaPluginControlRuntime struct {
	mu            sync.Mutex
	db            *sql.DB
	cfg           *Config
	mapController pluginEBPFMapController
	l2Transport   pluginControlL2Transport
	netAdmin      pluginControlNetAdmin
	snapshot      pluginRuntimeSnapshot
	plugins       map[string]LoadedPlugin
	timers        map[pluginControlTimerKey]pluginControlTimerState
	closed        bool
}

type pluginControlEvent struct {
	Kind     string
	Resource *PluginResource
	Action   *PluginAction
	Timer    *pluginControlTimerSpec
	Records  []PluginResourceRecord
	Payload  json.RawMessage
}

type pluginControlHost struct {
	vm            *goja.Runtime
	db            *sql.DB
	cfg           *Config
	runtime       *gojaPluginControlRuntime
	plugin        LoadedPlugin
	mapController pluginEBPFMapController
	l2Transport   pluginControlL2Transport
	netAdmin      pluginControlNetAdmin
	timerOps      []pluginControlTimerOperation
	timerEvent    *pluginControlTimerSpec
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
	return &gojaPluginControlRuntime{
		db:            db,
		cfg:           cfg,
		mapController: mapController,
		l2Transport:   newPluginControlL2Transport(),
		netAdmin:      newPluginControlNetAdmin(),
		timers:        make(map[pluginControlTimerKey]pluginControlTimerState),
	}
}

func (rt *gojaPluginControlRuntime) Reconcile(catalog PluginCatalog) pluginRuntimeSnapshot {
	activePlugins := make([]LoadedPlugin, 0, len(catalog.Plugins))
	activeByID := make(map[string]LoadedPlugin)
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive || plugin.controlMainPath == "" {
			continue
		}
		activePlugins = append(activePlugins, plugin)
		activeByID[plugin.ID] = plugin
	}

	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		return pluginRuntimeSnapshot{}
	}
	rt.plugins = activeByID
	rt.cancelInactivePluginTimersLocked(activeByID)
	rt.mu.Unlock()

	states := make(map[string]PluginRuntimeState)
	for _, plugin := range activePlugins {
		state := PluginRuntimeState{
			Mode:       pluginRuntimeModeControl,
			Attachable: false,
			Attached:   false,
			Reason:     "control script loaded",
		}
		if err := rt.runPluginControl(plugin, pluginControlEvent{Kind: "reconcile"}, true); err != nil {
			state = pluginRuntimeErrorState(err.Error())
			state.Reason = "control script reconcile failed"
		}
		states[plugin.ID] = state
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.snapshot = pluginRuntimeSnapshot{Plugins: states}
	return clonePluginRuntimeSnapshot(rt.snapshot)
}

func (rt *gojaPluginControlRuntime) Snapshot() pluginRuntimeSnapshot {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return clonePluginRuntimeSnapshot(rt.snapshot)
}

func (rt *gojaPluginControlRuntime) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.closed = true
	rt.snapshot = pluginRuntimeSnapshot{}
	rt.plugins = nil
	for key, state := range rt.timers {
		if state.timer != nil {
			state.timer.Stop()
		}
		delete(rt.timers, key)
	}
	return nil
}

func (rt *gojaPluginControlRuntime) ApplyPluginResourceData(plugin LoadedPlugin, resource PluginResource, records []PluginResourceRecord) error {
	if rt == nil || rt.db == nil || plugin.controlMainPath == "" {
		return errPluginRuntimeTargetNotLoaded
	}
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

func (rt *gojaPluginControlRuntime) registerPluginForControlEvents(plugin LoadedPlugin) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return
	}
	if rt.plugins == nil {
		rt.plugins = make(map[string]LoadedPlugin)
	}
	rt.plugins[plugin.ID] = plugin
}

func (rt *gojaPluginControlRuntime) runPluginControl(plugin LoadedPlugin, event pluginControlEvent, optionalHandler bool) error {
	source, err := readPluginControlScript(plugin)
	if err != nil {
		return err
	}
	vm := goja.New()
	host := &pluginControlHost{
		vm:            vm,
		db:            rt.db,
		cfg:           rt.cfg,
		runtime:       rt,
		plugin:        plugin,
		mapController: rt.mapController,
		l2Transport:   rt.l2Transport,
		netAdmin:      rt.netAdmin,
		timerEvent:    event.Timer,
	}
	if err := host.install(); err != nil {
		return err
	}

	exports := vm.NewObject()
	module := vm.NewObject()
	if err := module.Set("exports", exports); err != nil {
		return err
	}
	if err := vm.Set("exports", exports); err != nil {
		return err
	}
	if err := vm.Set("module", module); err != nil {
		return err
	}

	timer := time.AfterFunc(pluginControlTimeout, func() {
		vm.Interrupt("plugin control script timed out")
	})
	defer timer.Stop()

	if _, err := vm.RunScript(plugin.Control.Main, source); err != nil {
		return fmt.Errorf("run control script %s: %w", plugin.Control.Main, err)
	}
	handlerName := pluginControlHandlerName(event.Kind)
	handlerValue := module.Get("exports").ToObject(vm).Get(handlerName)
	if goja.IsUndefined(handlerValue) || goja.IsNull(handlerValue) {
		if optionalHandler {
			return nil
		}
		return fmt.Errorf("control script %s does not export %s", plugin.Control.Main, handlerName)
	}
	handler, ok := goja.AssertFunction(handlerValue)
	if !ok {
		return fmt.Errorf("control export %s is not a function", handlerName)
	}
	if _, err := handler(goja.Undefined(), vm.ToValue(pluginControlContext(plugin, event))); err != nil {
		return fmt.Errorf("control handler %s failed: %w", handlerName, err)
	}
	rt.applyTimerOperations(plugin, host.timerOps)
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

func pluginControlHandlerName(kind string) string {
	switch kind {
	case "resource_apply":
		return "onResourceApply"
	case "action":
		return "onAction"
	case "timer":
		return "onTimer"
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
	if err := pluginResourcesAPI.Set("set", h.pluginResourceSet); err != nil {
		return err
	}
	if err := pluginsAPI.Set("resources", pluginResourcesAPI); err != nil {
		return err
	}
	if err := h.vm.Set("plugins", pluginsAPI); err != nil {
		return err
	}

	ebpfAPI := h.vm.NewObject()
	if err := ebpfAPI.Set("mapPut", h.ebpfMapPut); err != nil {
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
	linkAPI := h.vm.NewObject()
	if err := linkAPI.Set("get", h.netLinkGet); err != nil {
		return err
	}
	if err := linkAPI.Set("list", h.netLinkList); err != nil {
		return err
	}
	if err := linkAPI.Set("ensureVeth", h.netLinkEnsureVeth); err != nil {
		return err
	}
	if err := linkAPI.Set("delete", h.netLinkDelete); err != nil {
		return err
	}
	if err := linkAPI.Set("setUp", h.netLinkSetUp); err != nil {
		return err
	}
	if err := linkAPI.Set("setMTU", h.netLinkSetMTU); err != nil {
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

	cryptoAPI := h.vm.NewObject()
	if err := cryptoAPI.Set("md5", h.cryptoMD5); err != nil {
		return err
	}
	if err := cryptoAPI.Set("randomBytes", h.cryptoRandomBytes); err != nil {
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
	if err := upsertPluginControlRecord(h.db, h.plugin.ID, pluginControlKVResourceID, key, dataJSON, true, 0); err != nil {
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
	records, err := store.GetPluginRecords(h.db, h.plugin.ID, pluginControlKVResourceID)
	if err != nil {
		h.throwf("kv.list: %v", err)
	}
	return h.vm.ToValue(h.recordsForScript(records))
}

func (h *pluginControlHost) resourceGet(call goja.FunctionCall) goja.Value {
	h.requirePermission("resource")
	resource := h.requiredResource(call, 0)
	key := h.requiredTokenArg(call, 1, "key")
	if !pluginResourceAllows(resource, "get") {
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
	_, err := store.GetPluginRecord(h.db, h.plugin.ID, resource.ID, key)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.throwf("resources.set: %v", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		if !pluginResourceAllows(resource, "create") {
			h.throwf("resources.set: resource %s does not allow create", resource.ID)
		}
	} else if !pluginResourceAllows(resource, "update") {
		h.throwf("resources.set: resource %s does not allow update", resource.ID)
	}
	enabled := true
	if len(call.Arguments) > 3 && !goja.IsUndefined(call.Arguments[3]) && !goja.IsNull(call.Arguments[3]) {
		enabled = call.Arguments[3].ToBoolean()
	}
	dataJSON := h.jsonFromValue(call.Arguments[2])
	if len(dataJSON) > pluginResourceMaxRecordBytes(resource) {
		h.throwf("resources.set: data exceeds resource max_record_bytes")
	}
	if err := upsertPluginControlRecord(h.db, h.plugin.ID, resource.ID, key, dataJSON, enabled, pluginResourceMaxRecords(resource)); err != nil {
		h.throwf("resources.set: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) resourceDelete(call goja.FunctionCall) goja.Value {
	h.requirePermission("resource")
	resource := h.requiredResource(call, 0)
	key := h.requiredTokenArg(call, 1, "key")
	if !pluginResourceAllows(resource, "delete") {
		h.throwf("resources.delete: resource %s does not allow delete", resource.ID)
	}
	if err := store.DeletePluginRecord(h.db, h.plugin.ID, resource.ID, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.throwf("resources.delete: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) resourceList(call goja.FunctionCall) goja.Value {
	h.requirePermission("resource")
	resource := h.requiredResource(call, 0)
	if !pluginResourceAllows(resource, "list") {
		h.throwf("resources.list: resource %s does not allow list", resource.ID)
	}
	records, err := store.GetPluginRecords(h.db, h.plugin.ID, resource.ID)
	if err != nil {
		h.throwf("resources.list: %v", err)
	}
	return h.vm.ToValue(h.recordsForScript(records))
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
	_, err := store.GetPluginRecord(h.db, plugin.ID, resource.ID, key)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.throwf("plugins.resources.set: %v", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		if !pluginResourceAllows(resource, "create") {
			h.throwf("plugins.resources.set: resource %s/%s does not allow create", plugin.ID, resource.ID)
		}
	} else if !pluginResourceAllows(resource, "update") {
		h.throwf("plugins.resources.set: resource %s/%s does not allow update", plugin.ID, resource.ID)
	}
	dataJSON := h.jsonFromValue(call.Arguments[3])
	if len(dataJSON) > pluginResourceMaxRecordBytes(resource) {
		h.throwf("plugins.resources.set: data exceeds resource max_record_bytes")
	}
	if err := upsertPluginControlRecord(h.db, plugin.ID, resource.ID, key, dataJSON, enabled, pluginResourceMaxRecords(resource)); err != nil {
		h.throwf("plugins.resources.set: %v", err)
	}
	if err := markPluginResourceMutation(h.db, plugin, resource); err != nil {
		h.throwf("plugins.resources.set: %v", err)
	}
	if apply && resource.RuntimeUpdate == "runtime_apply" {
		if h.runtime == nil {
			h.throwf("plugins.resources.set: plugin control runtime is unavailable")
		}
		records, err := loadPluginResourceRecords(h.db, plugin, resource)
		if err != nil {
			h.throwf("plugins.resources.set: %v", err)
		}
		if err := h.runtime.ApplyPluginResourceData(plugin, resource, records); err != nil {
			h.throwf("plugins.resources.set: apply %s/%s: %v", plugin.ID, resource.ID, err)
		}
		if err := markPluginRuntimeAppliedToCurrentRevision(h.db, plugin.ID, "resource", resource.ID); err != nil {
			h.throwf("plugins.resources.set: %v", err)
		}
	}
	record, err := store.GetPluginRecord(h.db, plugin.ID, resource.ID, key)
	if err != nil {
		h.throwf("plugins.resources.set: %v", err)
	}
	return h.valueFromRecord(*record)
}

func (h *pluginControlHost) ebpfMapPut(call goja.FunctionCall) goja.Value {
	h.requirePermission("ebpf.map_write")
	if h.mapController == nil {
		h.throwf("ebpf.mapPut: eBPF map controller is unavailable")
	}
	objectID, mapName, key, value := h.ebpfMapPutArgs(call)
	if err := h.mapController.PutPluginMapValue(h.plugin.ID, objectID, mapName, key, value); err != nil {
		h.throwf("ebpf.mapPut: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) ebpfMapDelete(call goja.FunctionCall) goja.Value {
	h.requirePermission("ebpf.map_write")
	if h.mapController == nil {
		h.throwf("ebpf.mapDelete: eBPF map controller is unavailable")
	}
	objectID, mapName, key := h.ebpfMapDeleteArgs(call)
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
	if err := upsertPluginControlRecord(h.db, h.plugin.ID, pluginControlSecretResourceID, key, dataJSON, true, 0); err != nil {
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
	return strings.Join(parts, " ")
}

func (h *pluginControlHost) requirePermission(permission string) {
	if !pluginControlHasPermission(h.plugin, permission) {
		h.throwf("permission %s is required", permission)
	}
}

func (h *pluginControlHost) requiredResource(call goja.FunctionCall, index int) PluginResource {
	resourceID := h.requiredTokenArg(call, index, "resource")
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
		catalog := loadPluginCatalog(h.cfg)
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
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		h.throwf("compact json: %v", err)
	}
	return buf.String()
}

func (h *pluginControlHost) valueFromRecord(record store.PluginRecord) goja.Value {
	return h.vm.ToValue(map[string]any{
		"key":        record.RecordKey,
		"data":       pluginControlDecodeJSON(json.RawMessage(record.DataJSON)),
		"enabled":    record.Enabled,
		"revision":   record.Revision,
		"created_at": record.CreatedAt,
		"updated_at": record.UpdatedAt,
	})
}

func (h *pluginControlHost) recordsForScript(records []store.PluginRecord) []map[string]any {
	out := make([]map[string]any, 0, len(records))
	for _, record := range records {
		out = append(out, map[string]any{
			"key":        record.RecordKey,
			"data":       pluginControlDecodeJSON(json.RawMessage(record.DataJSON)),
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
	return h.l2SendRequestFromObject(obj)
}

func (h *pluginControlHost) l2RecvRequest(call goja.FunctionCall) pluginControlL2RecvRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	return h.l2RecvRequestFromObject(obj)
}

func (h *pluginControlHost) l2RecvManyRequest(call goja.FunctionCall) pluginControlL2RecvManyRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	return h.l2RecvManyRequestFromObject(obj)
}

func (h *pluginControlHost) l2ExchangeRequest(call goja.FunctionCall) pluginControlL2ExchangeRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	return pluginControlL2ExchangeRequest{
		Send: h.l2SendRequestFromObject(obj),
		Recv: h.l2RecvRequestFromObject(obj),
	}
}

func (h *pluginControlHost) l2ExchangeManyRequest(call goja.FunctionCall) pluginControlL2ExchangeManyRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	return pluginControlL2ExchangeManyRequest{
		Send: h.l2SendRequestFromObject(obj),
		Recv: h.l2RecvManyRequestFromObject(obj),
	}
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
	return pluginControlL2RecvRequest{
		Interface: h.requiredStringObjectField(obj, "interface"),
		EtherType: h.requiredEtherTypeObjectField(obj, "ethertype"),
		Timeout:   timeout,
		MaxBytes:  maxBytes,
	}
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

func (h *pluginControlHost) optionalHexObjectField(obj *goja.Object, field string) []byte {
	value := h.objectField(obj, field)
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return nil
	}
	raw := strings.TrimSpace(value.String())
	if raw == "" {
		return nil
	}
	out, err := decodePluginControlHexBytes(raw)
	if err != nil {
		h.throwf("%s: %v", field, err)
	}
	return out
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

func (rt *gojaPluginControlRuntime) applyTimerOperations(plugin LoadedPlugin, ops []pluginControlTimerOperation) {
	if len(ops) == 0 {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return
	}
	if _, ok := rt.plugins[plugin.ID]; !ok {
		return
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

	if err := rt.runPluginControl(plugin, pluginControlEvent{Kind: "timer", Timer: &spec}, true); err != nil {
		log.Printf("plugin control timer %s/%s failed: %v", key.pluginID, key.name, err)
		_ = store.UpsertPluginRuntimeStatus(rt.db, store.PluginRuntimeStatus{
			PluginID:   key.pluginID,
			TargetType: pluginControlTimerRuntimeTarget,
			TargetID:   key.name,
			Status:     pluginControlTimerRuntimeStatusErr,
			LastError:  err.Error(),
		})
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
	parsed, err := strconv.ParseUint(raw, base, 16)
	if err != nil {
		return 0, err
	}
	if parsed == 0 {
		return 0, fmt.Errorf("ethertype must be non-zero")
	}
	return uint16(parsed), nil
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
