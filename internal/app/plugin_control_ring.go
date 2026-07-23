package app

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
)

const (
	pluginRingMaxSubscriptions       = 16
	pluginRingDefaultQueueSize       = 16
	pluginRingMaxQueueSize           = 64
	pluginRingDefaultBatchRecords    = 64
	pluginRingMaxBatchRecords        = 128
	pluginRingDefaultBatchBytes      = 64 << 10
	pluginRingMaxBatchBytes          = 256 << 10
	pluginRingDefaultPollTimeoutMS   = 500
	pluginRingMinPollTimeoutMS       = 10
	pluginRingMaxPollTimeoutMS       = 1000
	pluginRingPluginPendingByteLimit = 16 << 20
	pluginRingReadRetryMin           = 100 * time.Millisecond
	pluginRingReadRetryMax           = 5 * time.Second
)

type PluginRingSubscription struct {
	ID            string `json:"id"`
	Object        string `json:"object"`
	Map           string `json:"map"`
	Worker        string `json:"worker"`
	Handler       string `json:"handler"`
	QueueSize     int    `json:"queue_size"`
	MaxRecords    int    `json:"max_records"`
	MaxBytes      int    `json:"max_bytes"`
	PollTimeoutMS int64  `json:"poll_timeout_ms"`
}

type PluginRingSubscriptionState struct {
	PluginRingSubscription
	Pending            int    `json:"pending"`
	PendingBytes       int64  `json:"pending_bytes"`
	PeakPendingBytes   int64  `json:"peak_pending_bytes"`
	ReadCalls          uint64 `json:"read_calls"`
	ReadRecords        uint64 `json:"read_records"`
	ReadBytes          uint64 `json:"read_bytes"`
	ReadDroppedRecords uint64 `json:"read_dropped_records"`
	EnqueuedBatches    uint64 `json:"enqueued_batches"`
	DeliveredBatches   uint64 `json:"delivered_batches"`
	DroppedBatches     uint64 `json:"dropped_batches"`
	DroppedRecords     uint64 `json:"dropped_records"`
	ReadErrors         uint64 `json:"read_errors"`
	HandlerErrors      uint64 `json:"handler_errors"`
	LastReadAt         string `json:"last_read_at,omitempty"`
	LastDeliveryAt     string `json:"last_delivery_at,omitempty"`
	LastError          string `json:"last_error,omitempty"`
}

type PluginRingBusState struct {
	SubscriptionCount  int                           `json:"subscription_count"`
	Pending            int                           `json:"pending"`
	PendingBytes       int64                         `json:"pending_bytes"`
	PendingByteLimit   int64                         `json:"pending_byte_limit"`
	ReadRecords        uint64                        `json:"read_records"`
	ReadBytes          uint64                        `json:"read_bytes"`
	ReadDroppedRecords uint64                        `json:"read_dropped_records"`
	EnqueuedBatches    uint64                        `json:"enqueued_batches"`
	DeliveredBatches   uint64                        `json:"delivered_batches"`
	DroppedBatches     uint64                        `json:"dropped_batches"`
	DroppedRecords     uint64                        `json:"dropped_records"`
	ReadErrors         uint64                        `json:"read_errors"`
	HandlerErrors      uint64                        `json:"handler_errors"`
	Subscriptions      []PluginRingSubscriptionState `json:"subscriptions,omitempty"`
}

type pluginRingBatch struct {
	payload []byte
	records int
}

type pluginRingSubscriptionRuntime struct {
	key          string
	pluginID     string
	spec         PluginRingSubscription
	queue        chan pluginRingBatch
	stop         chan struct{}
	readerDone   chan struct{}
	deliveryDone chan struct{}
	stopOnce     sync.Once
	stopped      atomic.Bool
	pendingBytes atomic.Int64
	peakBytes    atomic.Int64
	readCalls    atomic.Uint64
	readRecords  atomic.Uint64
	readBytes    atomic.Uint64
	readDropped  atomic.Uint64
	enqueued     atomic.Uint64
	delivered    atomic.Uint64
	dropped      atomic.Uint64
	dropRecords  atomic.Uint64
	readErrors   atomic.Uint64
	handlerErrs  atomic.Uint64
	lastMu       sync.Mutex
	lastReadAt   string
	lastDelivery string
	lastError    string
}

func (h *pluginControlHost) ebpfRingSubscribe(call goja.FunctionCall) goja.Value {
	h.requireRegistrationPermission("ebpf.load", "ebpf.ringSubscribe")
	if !pluginControlHasPermission(h.plugin, "ebpf.map_read") {
		h.throwf("ebpf.ringSubscribe requires ebpf.map_read permission")
	}
	if !pluginControlHasPermission(h.plugin, "worker") {
		h.throwf("ebpf.ringSubscribe requires worker permission")
	}
	if len(call.Arguments) != 1 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("ebpf.ringSubscribe: spec is required")
	}
	var spec PluginRingSubscription
	h.exportJSONValue(call.Arguments[0], &spec, "ebpf.ringSubscribe")
	if err := normalizePluginRingSubscription(&spec); err != nil {
		h.throwf("ebpf.ringSubscribe: %v", err)
	}
	h.requirePluginObjectID(spec.Object, "ebpf.ringSubscribe")
	h.requirePluginMap(spec.Map, "ebpf.ringSubscribe")
	if len(h.surface.RingSubscriptions) >= pluginRingMaxSubscriptions {
		h.throwf("ebpf.ringSubscribe: subscription limit reached: %d", pluginRingMaxSubscriptions)
	}
	for _, current := range h.surface.RingSubscriptions {
		if current.ID == spec.ID {
			h.throwf("ebpf.ringSubscribe: duplicate subscription %q", spec.ID)
		}
		if current.Object == spec.Object && current.Map == spec.Map {
			h.throwf("ebpf.ringSubscribe: map %s:%s already has a consumer", spec.Object, spec.Map)
		}
	}
	h.surface.RingSubscriptions = append(h.surface.RingSubscriptions, spec)
	return goja.Undefined()
}

func (h *pluginControlHost) ebpfRingStats(goja.FunctionCall) goja.Value {
	h.requirePermission("ebpf.map_read")
	if h.runtime == nil {
		return h.vm.ToValue(PluginRingBusState{PendingByteLimit: pluginRingPluginPendingByteLimit})
	}
	return h.vm.ToValue(h.runtime.pluginRingBusSnapshot(h.plugin.ID))
}

func normalizePluginRingSubscription(spec *PluginRingSubscription) error {
	if spec == nil {
		return fmt.Errorf("subscription is required")
	}
	var err error
	if spec.ID, err = pluginPathToken(spec.ID); err != nil {
		return fmt.Errorf("id: %w", err)
	}
	if spec.Object, err = pluginPathToken(spec.Object); err != nil {
		return fmt.Errorf("object: %w", err)
	}
	spec.Map = strings.TrimSpace(spec.Map)
	if !pluginBPFMapPattern.MatchString(spec.Map) {
		return fmt.Errorf("map is invalid")
	}
	if reason, reserved := pluginControlReservedMapNames[spec.Map]; reserved {
		return fmt.Errorf("map %s is reserved for %s", spec.Map, reason)
	}
	if spec.Worker, err = pluginPathToken(spec.Worker); err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	spec.Handler = strings.TrimSpace(spec.Handler)
	if !validPluginControlHandlerName(spec.Handler) {
		return fmt.Errorf("handler contains invalid characters")
	}
	if spec.QueueSize == 0 {
		spec.QueueSize = pluginRingDefaultQueueSize
	}
	if spec.QueueSize < 1 || spec.QueueSize > pluginRingMaxQueueSize {
		return fmt.Errorf("queue_size must be between 1 and %d", pluginRingMaxQueueSize)
	}
	if spec.MaxRecords == 0 {
		spec.MaxRecords = pluginRingDefaultBatchRecords
	}
	if spec.MaxRecords < 1 || spec.MaxRecords > pluginRingMaxBatchRecords {
		return fmt.Errorf("max_records must be between 1 and %d", pluginRingMaxBatchRecords)
	}
	if spec.MaxBytes == 0 {
		spec.MaxBytes = pluginRingDefaultBatchBytes
	}
	if spec.MaxBytes < 1 || spec.MaxBytes > pluginRingMaxBatchBytes {
		return fmt.Errorf("max_bytes must be between 1 and %d", pluginRingMaxBatchBytes)
	}
	if spec.PollTimeoutMS == 0 {
		spec.PollTimeoutMS = pluginRingDefaultPollTimeoutMS
	}
	if spec.PollTimeoutMS < pluginRingMinPollTimeoutMS || spec.PollTimeoutMS > pluginRingMaxPollTimeoutMS {
		return fmt.Errorf("poll_timeout_ms must be between %d and %d", pluginRingMinPollTimeoutMS, pluginRingMaxPollTimeoutMS)
	}
	return nil
}

func validatePluginRingSubscriptions(plugin *LoadedPlugin) error {
	if plugin == nil || len(plugin.RingSubscriptions) == 0 {
		return nil
	}
	if !pluginControlHasPermission(*plugin, "ebpf.load") || !pluginControlHasPermission(*plugin, "ebpf.map_read") || !pluginControlHasPermission(*plugin, "worker") {
		return fmt.Errorf("ring subscriptions require ebpf.load, ebpf.map_read, and worker permissions")
	}
	if len(plugin.RingSubscriptions) > pluginRingMaxSubscriptions {
		return fmt.Errorf("ring subscription count exceeds %d", pluginRingMaxSubscriptions)
	}
	objectIDs := make(map[string]struct{}, len(plugin.Objects))
	for _, object := range plugin.Objects {
		objectIDs[object.ID] = struct{}{}
	}
	ids := make(map[string]struct{}, len(plugin.RingSubscriptions))
	targets := make(map[string]struct{}, len(plugin.RingSubscriptions))
	for index := range plugin.RingSubscriptions {
		spec := plugin.RingSubscriptions[index]
		if err := normalizePluginRingSubscription(&spec); err != nil {
			return fmt.Errorf("ring subscription %d: %w", index, err)
		}
		if _, ok := objectIDs[spec.Object]; !ok {
			return fmt.Errorf("ring subscription %s references unknown object %s", spec.ID, spec.Object)
		}
		if _, duplicate := ids[spec.ID]; duplicate {
			return fmt.Errorf("duplicate ring subscription %q", spec.ID)
		}
		target := spec.Object + "\x00" + spec.Map
		if _, duplicate := targets[target]; duplicate {
			return fmt.Errorf("ring map %s:%s has multiple consumers", spec.Object, spec.Map)
		}
		ids[spec.ID] = struct{}{}
		targets[target] = struct{}{}
		plugin.RingSubscriptions[index] = spec
	}
	return nil
}

func pluginHasRingSubscription(plugin LoadedPlugin, objectID, mapName string) bool {
	for _, spec := range plugin.RingSubscriptions {
		if spec.Object == objectID && spec.Map == mapName {
			return true
		}
	}
	return false
}

func (rt *gojaPluginControlRuntime) reconcilePluginRingSubscriptions(plugins map[string]LoadedPlugin, snapshot pluginRuntimeSnapshot) {
	if rt == nil {
		return
	}
	rt.stopAllPluginRingSubscriptions()
	controller, ok := rt.mapController.(pluginEBPFRingReadController)
	if !ok || controller == nil {
		return
	}
	started := make([]*pluginRingSubscriptionRuntime, 0)
	rt.ringMu.Lock()
	if rt.ringSubscriptions == nil {
		rt.ringSubscriptions = make(map[string]*pluginRingSubscriptionRuntime)
	}
	if rt.ringPendingBytes == nil {
		rt.ringPendingBytes = make(map[string]int64)
	}
	for pluginID, plugin := range plugins {
		state, active := snapshot.stateFor(pluginID)
		if !active || !state.Attached || strings.TrimSpace(state.Error) != "" {
			continue
		}
		for _, spec := range plugin.RingSubscriptions {
			key := pluginID + "\x00" + spec.ID
			sub := &pluginRingSubscriptionRuntime{
				key: key, pluginID: pluginID, spec: spec, queue: make(chan pluginRingBatch, spec.QueueSize),
				stop: make(chan struct{}), readerDone: make(chan struct{}), deliveryDone: make(chan struct{}),
			}
			rt.ringSubscriptions[key] = sub
			started = append(started, sub)
		}
	}
	rt.ringMu.Unlock()
	for _, sub := range started {
		go rt.runPluginRingReader(controller, sub)
		go rt.runPluginRingDelivery(sub)
	}
}

func (rt *gojaPluginControlRuntime) runPluginRingReader(controller pluginEBPFRingReadController, sub *pluginRingSubscriptionRuntime) {
	defer close(sub.readerDone)
	retry := pluginRingReadRetryMin
	for !sub.stopped.Load() {
		result, err := controller.ReadPluginRingBuffer(sub.pluginID, sub.spec.Object, sub.spec.Map, pluginEBPFRingReadRequest{
			MaxRecords: sub.spec.MaxRecords, MaxBytes: sub.spec.MaxBytes, TimeoutMS: sub.spec.PollTimeoutMS,
		})
		if sub.stopped.Load() {
			return
		}
		sub.readCalls.Add(1)
		if err != nil {
			sub.readErrors.Add(1)
			sub.noteRingError(err)
			if !waitPluginRingRetry(sub.stop, retry) {
				return
			}
			if retry < pluginRingReadRetryMax/2 {
				retry *= 2
			} else {
				retry = pluginRingReadRetryMax
			}
			continue
		}
		retry = pluginRingReadRetryMin
		sub.noteRingRead(result)
		if len(result.Records) == 0 {
			continue
		}
		payload, err := pluginRingBatchPayload(sub.spec, result)
		if err != nil {
			sub.readErrors.Add(1)
			sub.noteRingError(err)
			continue
		}
		batch := pluginRingBatch{payload: payload, records: len(result.Records)}
		if !rt.enqueuePluginRingBatch(sub, batch) {
			sub.dropped.Add(1)
			sub.dropRecords.Add(uint64(batch.records))
		}
	}
}

func (rt *gojaPluginControlRuntime) runPluginRingDelivery(sub *pluginRingSubscriptionRuntime) {
	defer close(sub.deliveryDone)
	for {
		select {
		case batch := <-sub.queue:
			rt.releasePluginRingPending(sub, int64(len(batch.payload)))
			if sub.stopped.Load() {
				continue
			}
			plugin := rt.pluginByID(sub.pluginID)
			if plugin.ID == "" {
				sub.handlerErrs.Add(1)
				sub.noteRingError(fmt.Errorf("plugin is no longer active"))
				continue
			}
			vm, err := rt.getPluginControlVM(plugin, "worker", sub.spec.Worker)
			if err == nil {
				_, err = vm.run(plugin, pluginControlEvent{
					Kind: "worker", Payload: append(json.RawMessage(nil), batch.payload...),
					Worker: &pluginControlWorkerEvent{Name: sub.spec.Worker, Handler: sub.spec.Handler},
				}, false)
			}
			if err != nil {
				sub.handlerErrs.Add(1)
				sub.noteRingError(err)
			} else {
				sub.delivered.Add(1)
				sub.noteRingDelivery()
			}
		case <-sub.stop:
			<-sub.readerDone
			for {
				select {
				case batch := <-sub.queue:
					rt.releasePluginRingPending(sub, int64(len(batch.payload)))
				default:
					return
				}
			}
		}
	}
}

func pluginRingBatchPayload(spec PluginRingSubscription, result pluginEBPFRingReadResult) ([]byte, error) {
	records := make([]map[string]any, 0, len(result.Records))
	for _, record := range result.Records {
		records = append(records, map[string]any{
			"data": hex.EncodeToString(record.RawSample), "size": len(record.RawSample), "remaining": record.Remaining,
		})
	}
	return json.Marshal(map[string]any{
		"subscription": spec.ID, "object": spec.Object, "map": spec.Map,
		"records": records, "bytes": result.Bytes, "dropped_records": result.DroppedRecords,
		"remaining": result.Remaining, "limit_reached": result.LimitReached,
		"read_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (rt *gojaPluginControlRuntime) enqueuePluginRingBatch(sub *pluginRingSubscriptionRuntime, batch pluginRingBatch) bool {
	bytes := int64(len(batch.payload))
	rt.ringMu.Lock()
	if rt.ringPendingBytes == nil {
		rt.ringPendingBytes = make(map[string]int64)
	}
	if sub.stopped.Load() || rt.ringSubscriptions[sub.key] != sub || bytes > pluginRingPluginPendingByteLimit-rt.ringPendingBytes[sub.pluginID] {
		rt.ringMu.Unlock()
		return false
	}
	rt.ringPendingBytes[sub.pluginID] += bytes
	pending := sub.pendingBytes.Add(bytes)
	for {
		peak := sub.peakBytes.Load()
		if pending <= peak || sub.peakBytes.CompareAndSwap(peak, pending) {
			break
		}
	}
	rt.ringMu.Unlock()
	select {
	case sub.queue <- batch:
		sub.enqueued.Add(1)
		return true
	default:
		rt.releasePluginRingPending(sub, bytes)
		return false
	}
}

func (rt *gojaPluginControlRuntime) releasePluginRingPending(sub *pluginRingSubscriptionRuntime, bytes int64) {
	if bytes <= 0 {
		return
	}
	rt.ringMu.Lock()
	current := rt.ringPendingBytes[sub.pluginID]
	if bytes >= current {
		delete(rt.ringPendingBytes, sub.pluginID)
	} else {
		rt.ringPendingBytes[sub.pluginID] = current - bytes
	}
	sub.pendingBytes.Add(-bytes)
	rt.ringMu.Unlock()
}

func (rt *gojaPluginControlRuntime) stopPluginRingSubscriptions(pluginID string) {
	if rt == nil {
		return
	}
	rt.ringMu.Lock()
	stopped := make([]*pluginRingSubscriptionRuntime, 0)
	for key, sub := range rt.ringSubscriptions {
		if sub.pluginID != pluginID {
			continue
		}
		delete(rt.ringSubscriptions, key)
		sub.stopRuntime()
		stopped = append(stopped, sub)
	}
	rt.ringMu.Unlock()
	waitPluginRingReaders(stopped)
}

func (rt *gojaPluginControlRuntime) stopAllPluginRingSubscriptions() {
	if rt == nil {
		return
	}
	rt.ringMu.Lock()
	stopped := make([]*pluginRingSubscriptionRuntime, 0, len(rt.ringSubscriptions))
	for _, sub := range rt.ringSubscriptions {
		sub.stopRuntime()
		stopped = append(stopped, sub)
	}
	rt.ringSubscriptions = make(map[string]*pluginRingSubscriptionRuntime)
	rt.ringMu.Unlock()
	waitPluginRingReaders(stopped)
}

func (sub *pluginRingSubscriptionRuntime) stopRuntime() {
	if sub == nil {
		return
	}
	sub.stopOnce.Do(func() {
		sub.stopped.Store(true)
		close(sub.stop)
	})
}

func waitPluginRingReaders(subscriptions []*pluginRingSubscriptionRuntime) {
	for _, sub := range subscriptions {
		select {
		case <-sub.readerDone:
		case <-time.After(time.Duration(sub.spec.PollTimeoutMS)*time.Millisecond + time.Second):
		}
	}
}

func waitPluginRingRetry(stop <-chan struct{}, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-stop:
		return false
	case <-timer.C:
		return true
	}
}

func (sub *pluginRingSubscriptionRuntime) noteRingRead(result pluginEBPFRingReadResult) {
	sub.readRecords.Add(uint64(len(result.Records)))
	sub.readBytes.Add(uint64(result.Bytes))
	sub.readDropped.Add(uint64(result.DroppedRecords))
	sub.lastMu.Lock()
	sub.lastReadAt = time.Now().UTC().Format(time.RFC3339Nano)
	sub.lastError = ""
	sub.lastMu.Unlock()
}

func (sub *pluginRingSubscriptionRuntime) noteRingDelivery() {
	sub.lastMu.Lock()
	sub.lastDelivery = time.Now().UTC().Format(time.RFC3339Nano)
	sub.lastError = ""
	sub.lastMu.Unlock()
}

func (sub *pluginRingSubscriptionRuntime) noteRingError(err error) {
	if err == nil {
		return
	}
	sub.lastMu.Lock()
	sub.lastError = boundedPluginControlHealthError(err.Error())
	sub.lastMu.Unlock()
}

func (rt *gojaPluginControlRuntime) pluginRingBusSnapshot(pluginID string) PluginRingBusState {
	state := PluginRingBusState{PendingByteLimit: pluginRingPluginPendingByteLimit}
	if rt == nil {
		return state
	}
	rt.ringMu.Lock()
	state.PendingBytes = rt.ringPendingBytes[pluginID]
	for _, sub := range rt.ringSubscriptions {
		if sub.pluginID != pluginID {
			continue
		}
		item := PluginRingSubscriptionState{
			PluginRingSubscription: sub.spec,
			Pending:                len(sub.queue), PendingBytes: sub.pendingBytes.Load(), PeakPendingBytes: sub.peakBytes.Load(),
			ReadCalls: sub.readCalls.Load(), ReadRecords: sub.readRecords.Load(), ReadBytes: sub.readBytes.Load(),
			ReadDroppedRecords: sub.readDropped.Load(), EnqueuedBatches: sub.enqueued.Load(), DeliveredBatches: sub.delivered.Load(),
			DroppedBatches: sub.dropped.Load(), DroppedRecords: sub.dropRecords.Load(), ReadErrors: sub.readErrors.Load(), HandlerErrors: sub.handlerErrs.Load(),
		}
		sub.lastMu.Lock()
		item.LastReadAt = sub.lastReadAt
		item.LastDeliveryAt = sub.lastDelivery
		item.LastError = sub.lastError
		sub.lastMu.Unlock()
		state.SubscriptionCount++
		state.Pending += item.Pending
		state.ReadRecords += item.ReadRecords
		state.ReadBytes += item.ReadBytes
		state.ReadDroppedRecords += item.ReadDroppedRecords
		state.EnqueuedBatches += item.EnqueuedBatches
		state.DeliveredBatches += item.DeliveredBatches
		state.DroppedBatches += item.DroppedBatches
		state.DroppedRecords += item.DroppedRecords
		state.ReadErrors += item.ReadErrors
		state.HandlerErrors += item.HandlerErrors
		state.Subscriptions = append(state.Subscriptions, item)
	}
	rt.ringMu.Unlock()
	sort.Slice(state.Subscriptions, func(i, j int) bool { return state.Subscriptions[i].ID < state.Subscriptions[j].ID })
	return state
}

func pluginRingReadConflictError(plugin LoadedPlugin, objectID, mapName string) error {
	if pluginHasRingSubscription(plugin, objectID, mapName) {
		return errors.New("ring map has an active push subscription; use ebpf.ringStats instead of a second consumer")
	}
	return nil
}
