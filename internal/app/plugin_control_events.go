package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Unicode01/veer/internal/store"
	"github.com/dop251/goja"
)

const (
	pluginEventDefaultQueueSize     = 64
	pluginEventMaxQueueSize         = 256
	pluginEventMaxSubscriptions     = 64
	pluginEventMaxAccessEntries     = 64
	pluginEventMaxAccessTopics      = 256
	pluginEventMaxPayloadBytes      = 64 << 10
	pluginEventDefaultWorker        = "events"
	pluginEventDefaultHandler       = "onEvent"
	pluginEventMatchExact           = "exact"
	pluginEventMatchPrefix          = "prefix"
	pluginEventDeliveryVolatile     = "volatile"
	pluginEventDeliveryDurable      = "durable"
	pluginEventDurableMaxAttempts   = 16
	pluginEventDurableDefaultTries  = 8
	pluginEventDurableMinRetryMS    = 100
	pluginEventDurableMaxRetryMS    = 60_000
	pluginEventDurableDefaultRetry  = 500
	pluginEventDurablePollInterval  = 250 * time.Millisecond
	pluginEventDurablePerPluginMax  = 2048
	pluginEventDurableGlobalMax     = 16_384
	pluginEventDeadLetterListMax    = 100
	pluginEventTopicNetLink         = "net.link"
	pluginEventTopicNetAddr         = "net.addr"
	pluginEventTopicNetNeigh        = "net.neigh"
	pluginEventTopicNetRoute        = "net.route"
	pluginEventTopicResourceChanged = "resource.changed"
	pluginEventTopicPluginLifecycle = "plugin.lifecycle"
)

type PluginEventSubscription struct {
	ID            string          `json:"id"`
	Topic         string          `json:"topic"`
	Match         string          `json:"match,omitempty"`
	Worker        string          `json:"worker,omitempty"`
	Handler       string          `json:"handler,omitempty"`
	QueueSize     int             `json:"queue_size,omitempty"`
	Delivery      string          `json:"delivery,omitempty"`
	MaxAttempts   int             `json:"max_attempts,omitempty"`
	RetryDelayMS  int             `json:"retry_delay_ms,omitempty"`
	SchemaVersion int             `json:"schema_version,omitempty"`
	Schema        json.RawMessage `json:"schema,omitempty"`
	SchemaDigest  string          `json:"schema_digest,omitempty"`
}

type PluginEventSubscriptionState struct {
	ID             string `json:"id"`
	Topic          string `json:"topic"`
	Match          string `json:"match"`
	Worker         string `json:"worker"`
	Handler        string `json:"handler"`
	Delivery       string `json:"delivery"`
	SchemaVersion  int    `json:"schema_version"`
	SchemaDigest   string `json:"schema_digest,omitempty"`
	Pending        int    `json:"pending"`
	QueueSize      int    `json:"queue_size"`
	Enqueued       uint64 `json:"enqueued"`
	Delivered      uint64 `json:"delivered"`
	Dropped        uint64 `json:"dropped"`
	Rejected       uint64 `json:"rejected"`
	Errors         uint64 `json:"errors"`
	Retried        uint64 `json:"retried"`
	DurablePending int64  `json:"durable_pending"`
	DeadLetters    int64  `json:"dead_letters"`
	LastEventAt    string `json:"last_event_at,omitempty"`
	LastError      string `json:"last_error,omitempty"`
}

type PluginEventBusState struct {
	SubscriptionCount int                            `json:"subscription_count"`
	Pending           int                            `json:"pending"`
	QueueCapacity     int                            `json:"queue_capacity"`
	Enqueued          uint64                         `json:"enqueued"`
	Delivered         uint64                         `json:"delivered"`
	Dropped           uint64                         `json:"dropped"`
	Rejected          uint64                         `json:"rejected"`
	Errors            uint64                         `json:"errors"`
	Retried           uint64                         `json:"retried"`
	DurablePending    int64                          `json:"durable_pending"`
	DeadLetters       int64                          `json:"dead_letters"`
	Subscriptions     []PluginEventSubscriptionState `json:"subscriptions,omitempty"`
}

type pluginControlBusEvent struct {
	Topic               string
	SubscriptionID      string
	Sequence            uint64
	PublishedAt         string
	SourcePlugin        string
	TargetPlugin        string
	ResourceID          string
	SchemaVersion       int
	Payload             json.RawMessage
	DeliveryID          string
	DeliveryAttempt     int
	DeliveryMaxAttempts int
	Durable             bool
}

type pluginControlEventPublication struct {
	Topic         string
	SourcePlugin  string
	TargetPlugin  string
	ResourceID    string
	SchemaVersion int
	Payload       json.RawMessage
}

type pluginControlEventPublishResult struct {
	Matched   int `json:"matched"`
	Enqueued  int `json:"enqueued"`
	Persisted int `json:"persisted,omitempty"`
	Deferred  int `json:"deferred,omitempty"`
	Dropped   int `json:"dropped"`
	Rejected  int `json:"rejected"`
}

type pluginDurableEventTarget struct {
	sub   *pluginControlEventSubscriptionRuntime
	event pluginControlBusEvent
	item  store.PluginEventDelivery
}

type pluginControlEventSubscriptionRuntime struct {
	pluginID        string
	spec            PluginEventSubscription
	queue           chan pluginControlBusEvent
	stop            chan struct{}
	wake            chan struct{}
	stopOnce        sync.Once
	stopped         atomic.Bool
	enqueued        atomic.Uint64
	delivered       atomic.Uint64
	dropped         atomic.Uint64
	rejected        atomic.Uint64
	errors          atomic.Uint64
	retried         atomic.Uint64
	durablePending  atomic.Int64
	deadLetters     atomic.Int64
	durableMu       sync.Mutex
	durableInFlight map[string]struct{}
	lastMu          sync.Mutex
	lastEventAt     string
	lastError       string
}

func (h *pluginControlHost) eventSubscribe(call goja.FunctionCall) goja.Value {
	h.requireRegistrationPermission("event", "events.subscribe")
	if !pluginControlHasPermission(h.plugin, "worker") {
		h.throwf("events.subscribe requires worker permission")
	}
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("events.subscribe: spec is required")
	}
	var spec PluginEventSubscription
	h.exportJSONValue(call.Arguments[0], &spec, "events.subscribe")
	if err := normalizePluginEventSubscription(h.plugin, &spec); err != nil {
		h.throwf("events.subscribe: %v", err)
	}
	if len(h.surface.EventSubscriptions) >= pluginEventMaxSubscriptions {
		h.throwf("events.subscribe: subscription limit reached: %d", pluginEventMaxSubscriptions)
	}
	if pluginEventSubscriptionIndex(h.surface.EventSubscriptions, spec.ID) >= 0 {
		h.throwf("events.subscribe: duplicate subscription %q", spec.ID)
	}
	h.surface.EventSubscriptions = append(h.surface.EventSubscriptions, spec)
	return goja.Undefined()
}

func (h *pluginControlHost) eventPublish(call goja.FunctionCall) goja.Value {
	h.requirePermission("event")
	if h.registrationPhase {
		h.throwf("events.publish is unavailable during plugin registration")
	}
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("events.publish: topic is required")
	}
	topic := normalizePluginEventTopic(call.Arguments[0].String())
	prefix := "plugin." + h.plugin.ID + "."
	if !validPluginEventTopic(topic) || !strings.HasPrefix(topic, prefix) || len(topic) <= len(prefix) {
		h.throwf("events.publish: custom topics must use %s*", prefix)
	}
	payload := json.RawMessage(`{}`)
	if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
		payload = json.RawMessage(h.jsonFromValue(call.Arguments[1]))
	}
	if len(payload) > pluginEventMaxPayloadBytes {
		h.throwf("events.publish: payload exceeds %d bytes", pluginEventMaxPayloadBytes)
	}
	options := struct {
		SchemaVersion int `json:"schema_version,omitempty"`
	}{SchemaVersion: 1}
	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
		h.exportJSONValue(call.Arguments[2], &options, "events.publish")
	}
	if options.SchemaVersion <= 0 || options.SchemaVersion > pluginSchemaMaxVersion {
		h.throwf("events.publish: schema_version must be between 1 and %d", pluginSchemaMaxVersion)
	}
	if h.runtime == nil {
		return h.vm.ToValue(pluginControlEventPublishResult{})
	}
	result := h.runtime.publishPluginControlEvent(pluginControlEventPublication{
		Topic: topic, SourcePlugin: h.plugin.ID, TargetPlugin: h.plugin.ID, SchemaVersion: options.SchemaVersion,
		Payload: append(json.RawMessage(nil), payload...),
	})
	return h.vm.ToValue(result)
}

func (h *pluginControlHost) eventStats(goja.FunctionCall) goja.Value {
	h.requirePermission("event")
	if h.runtime == nil {
		return h.vm.ToValue(PluginEventBusState{})
	}
	return h.vm.ToValue(h.runtime.pluginEventBusSnapshot(h.plugin.ID))
}

func (h *pluginControlHost) eventDeadLetters(call goja.FunctionCall) goja.Value {
	h.requirePermission("event")
	if h.registrationPhase {
		h.throwf("events.deadLetters is unavailable during plugin registration")
	}
	limit := 50
	if len(call.Arguments) > 1 {
		h.throwf("events.deadLetters accepts at most one options object")
	}
	if len(call.Arguments) == 1 && !goja.IsUndefined(call.Arguments[0]) && !goja.IsNull(call.Arguments[0]) {
		var options struct {
			Limit int `json:"limit,omitempty"`
		}
		h.exportJSONValue(call.Arguments[0], &options, "events.deadLetters")
		if options.Limit != 0 {
			limit = options.Limit
		}
	}
	if limit < 1 || limit > pluginEventDeadLetterListMax {
		h.throwf("events.deadLetters: limit must be between 1 and %d", pluginEventDeadLetterListMax)
	}
	if h.runtime == nil || h.runtime.db == nil {
		h.throwf("events.deadLetters: durable event delivery store is unavailable")
	}
	items, err := store.GetDeadPluginEventDeliveries(h.runtime.db, h.plugin.ID, limit)
	if err != nil {
		h.throwf("events.deadLetters: %v", err)
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, pluginEventDeliveryPublicState(item))
	}
	return h.vm.ToValue(out)
}

func (h *pluginControlHost) eventRetry(call goja.FunctionCall) goja.Value {
	h.requirePermission("event")
	if h.registrationPhase {
		h.throwf("events.retry is unavailable during plugin registration")
	}
	deliveryID := h.eventDeliveryIDArg(call, "events.retry")
	if h.runtime == nil || h.runtime.db == nil {
		h.throwf("events.retry: durable event delivery store is unavailable")
	}
	item, err := store.RetryDeadPluginEventDelivery(h.runtime.db, h.plugin.ID, deliveryID, time.Now().UnixMilli())
	if err != nil {
		h.throwf("events.retry: %v", err)
	}
	h.runtime.noteRetriedDeadPluginEvent(*item)
	return h.vm.ToValue(pluginEventDeliveryPublicState(*item))
}

func (h *pluginControlHost) eventDiscard(call goja.FunctionCall) goja.Value {
	h.requirePermission("event")
	if h.registrationPhase {
		h.throwf("events.discard is unavailable during plugin registration")
	}
	deliveryID := h.eventDeliveryIDArg(call, "events.discard")
	if h.runtime == nil || h.runtime.db == nil {
		h.throwf("events.discard: durable event delivery store is unavailable")
	}
	item, err := store.GetPluginEventDelivery(h.runtime.db, h.plugin.ID, deliveryID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.throwf("events.discard: delivery was not found")
		}
		h.throwf("events.discard: %v", err)
	}
	if item.Status != store.PluginEventDeliveryDead {
		h.throwf("events.discard: delivery is not dead-lettered")
	}
	deleted, err := store.DeleteDeadPluginEventDelivery(h.runtime.db, h.plugin.ID, deliveryID)
	if err != nil {
		h.throwf("events.discard: %v", err)
	}
	if deleted {
		h.runtime.noteDiscardedPluginEvent(*item)
	}
	return h.vm.ToValue(deleted)
}

func (h *pluginControlHost) eventDeliveryIDArg(call goja.FunctionCall, api string) string {
	if len(call.Arguments) != 1 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("%s requires one delivery id", api)
	}
	deliveryID := strings.TrimSpace(strings.ToLower(call.Arguments[0].String()))
	if err := validatePluginPackageID(deliveryID); err != nil {
		h.throwf("%s: delivery id is invalid", api)
	}
	return deliveryID
}

func pluginEventDeliveryPublicState(item store.PluginEventDelivery) map[string]any {
	return map[string]any{
		"delivery_id": item.DeliveryID, "subscription": item.SubscriptionID, "topic": item.Topic,
		"sequence": item.Sequence, "published_at": item.PublishedAt, "source_plugin": item.SourcePlugin,
		"target_plugin": item.TargetPlugin, "resource": item.ResourceID, "schema_version": item.SchemaVersion,
		"payload": pluginControlDecodeJSON(json.RawMessage(item.PayloadJSON)), "attempts": item.Attempts,
		"max_attempts": item.MaxAttempts, "status": item.Status, "last_error": item.LastError,
		"created_at": item.CreatedAt, "updated_at": item.UpdatedAt,
	}
}

func normalizePluginEventSubscription(plugin LoadedPlugin, spec *PluginEventSubscription) error {
	if spec == nil {
		return fmt.Errorf("subscription is required")
	}
	id, err := pluginPathToken(spec.ID)
	if err != nil {
		return fmt.Errorf("id: %w", err)
	}
	spec.ID = id
	spec.Topic = normalizePluginEventTopic(spec.Topic)
	if !validPluginEventTopic(spec.Topic) {
		return fmt.Errorf("topic is invalid")
	}
	spec.Match = strings.TrimSpace(strings.ToLower(spec.Match))
	if spec.Match == "" {
		spec.Match = pluginEventMatchExact
	}
	if spec.Match != pluginEventMatchExact && spec.Match != pluginEventMatchPrefix {
		return fmt.Errorf("match must be exact or prefix")
	}
	spec.Worker = strings.TrimSpace(strings.ToLower(spec.Worker))
	if spec.Worker == "" {
		spec.Worker = pluginEventDefaultWorker
	}
	if _, err := pluginPathToken(spec.Worker); err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	spec.Handler = strings.TrimSpace(spec.Handler)
	if spec.Handler == "" {
		spec.Handler = pluginEventDefaultHandler
	}
	if !validPluginControlHandlerName(spec.Handler) {
		return fmt.Errorf("handler contains invalid characters")
	}
	if spec.QueueSize == 0 {
		spec.QueueSize = pluginEventDefaultQueueSize
	}
	if spec.QueueSize < 1 || spec.QueueSize > pluginEventMaxQueueSize {
		return fmt.Errorf("queue_size must be between 1 and %d", pluginEventMaxQueueSize)
	}
	spec.Delivery = strings.TrimSpace(strings.ToLower(spec.Delivery))
	if spec.Delivery == "" {
		spec.Delivery = pluginEventDeliveryVolatile
	}
	if spec.Delivery != pluginEventDeliveryVolatile && spec.Delivery != pluginEventDeliveryDurable {
		return fmt.Errorf("delivery must be volatile or durable")
	}
	if spec.Delivery == pluginEventDeliveryDurable {
		if pluginEventTopicRequiresNetAdmin(spec.Topic) {
			return fmt.Errorf("durable delivery is not available for high-rate network events")
		}
		if spec.MaxAttempts == 0 {
			spec.MaxAttempts = pluginEventDurableDefaultTries
		}
		if spec.MaxAttempts < 1 || spec.MaxAttempts > pluginEventDurableMaxAttempts {
			return fmt.Errorf("max_attempts must be between 1 and %d", pluginEventDurableMaxAttempts)
		}
		if spec.RetryDelayMS == 0 {
			spec.RetryDelayMS = pluginEventDurableDefaultRetry
		}
		if spec.RetryDelayMS < pluginEventDurableMinRetryMS || spec.RetryDelayMS > pluginEventDurableMaxRetryMS {
			return fmt.Errorf("retry_delay_ms must be between %d and %d", pluginEventDurableMinRetryMS, pluginEventDurableMaxRetryMS)
		}
	} else if spec.MaxAttempts != 0 || spec.RetryDelayMS != 0 {
		return fmt.Errorf("max_attempts and retry_delay_ms require durable delivery")
	}
	if err := normalizePluginSchema(&spec.SchemaVersion, &spec.Schema, &spec.SchemaDigest); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	if pluginEventTopicRequiresNetAdmin(spec.Topic) && !pluginControlHasPermission(plugin, "net.admin") {
		return fmt.Errorf("topic %s requires net.admin permission", spec.Topic)
	}
	if pluginEventTopicRequiresNetAdmin(spec.Topic) && !pluginControlHasAnyNetAccess(plugin, "link.read") {
		return fmt.Errorf("topic %s requires net_access link.read", spec.Topic)
	}
	if spec.Topic == pluginEventTopicPluginLifecycle {
		// System lifecycle events use the plugin.* namespace but are published by Veer.
	} else if strings.HasPrefix(spec.Topic, "plugin.") {
		sourcePlugin, ok := pluginCustomEventSource(spec.Topic)
		if !ok {
			return fmt.Errorf("custom topic %q is invalid", spec.Topic)
		}
		if sourcePlugin != plugin.ID {
			if !pluginControlHasPermission(plugin, "plugin.event") {
				return fmt.Errorf("custom topic %s requires plugin.event permission", spec.Topic)
			}
			if !pluginControlHasEventAccess(plugin, sourcePlugin, spec.Topic) {
				return fmt.Errorf("custom topic %s is not declared in event_access for plugin %s", spec.Topic, sourcePlugin)
			}
		}
	} else if !validPluginSystemEventSubscriptionTopic(spec.Topic, spec.Match) {
		return fmt.Errorf("unsupported system topic %q", spec.Topic)
	}
	return nil
}

func normalizePluginEventTopic(value string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(value)), ".")
}

func pluginCustomEventSource(topic string) (string, bool) {
	if topic == pluginEventTopicPluginLifecycle {
		return "", false
	}
	if !validPluginEventTopic(topic) {
		return "", false
	}
	parts := strings.Split(topic, ".")
	if len(parts) < 2 || parts[0] != "plugin" || !pluginIDPattern.MatchString(parts[1]) || reservedBuiltinPluginID(parts[1]) {
		return "", false
	}
	return parts[1], true
}

func pluginEventTopicWithinPrefix(topic, prefix string) bool {
	return topic == prefix || strings.HasPrefix(topic, prefix+".")
}

func validPluginEventTopic(value string) bool {
	if value == "" || len(value) > 128 || strings.Contains(value, "..") {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" || len(part) > 64 {
			return false
		}
		for i, r := range part {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				continue
			}
			if i > 0 && (r == '_' || r == '-') {
				continue
			}
			return false
		}
	}
	return true
}

func validPluginSystemEventSubscriptionTopic(topic, match string) bool {
	if match == pluginEventMatchPrefix && (topic == "net" || topic == "resource" || topic == "plugin") {
		return true
	}
	switch topic {
	case pluginEventTopicNetLink, pluginEventTopicNetAddr, pluginEventTopicNetNeigh, pluginEventTopicNetRoute, pluginEventTopicResourceChanged, pluginEventTopicPluginLifecycle:
		return true
	default:
		return false
	}
}

func pluginEventTopicRequiresNetAdmin(topic string) bool {
	return topic == "net" || strings.HasPrefix(topic, "net.")
}

func pluginEventSubscriptionIndex(values []PluginEventSubscription, id string) int {
	for i := range values {
		if values[i].ID == id {
			return i
		}
	}
	return -1
}

func validatePluginEventSubscriptions(plugin *LoadedPlugin) error {
	if plugin == nil || len(plugin.EventSubscriptions) == 0 {
		return nil
	}
	if !pluginControlHasPermission(*plugin, "event") || !pluginControlHasPermission(*plugin, "worker") {
		return fmt.Errorf("event subscriptions require event and worker permissions")
	}
	if len(plugin.EventSubscriptions) > pluginEventMaxSubscriptions {
		return fmt.Errorf("event subscription count exceeds %d", pluginEventMaxSubscriptions)
	}
	seen := make(map[string]struct{}, len(plugin.EventSubscriptions))
	for i := range plugin.EventSubscriptions {
		spec := plugin.EventSubscriptions[i]
		if err := normalizePluginEventSubscription(*plugin, &spec); err != nil {
			return fmt.Errorf("event subscription %d: %w", i, err)
		}
		if _, duplicate := seen[spec.ID]; duplicate {
			return fmt.Errorf("duplicate event subscription %q", spec.ID)
		}
		seen[spec.ID] = struct{}{}
		plugin.EventSubscriptions[i] = spec
	}
	return nil
}

func (rt *gojaPluginControlRuntime) pluginByID(pluginID string) LoadedPlugin {
	if rt == nil {
		return LoadedPlugin{}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.plugins[pluginID]
}

func (rt *gojaPluginControlRuntime) reconcilePluginEventSubscriptions(plugins map[string]LoadedPlugin) {
	if rt == nil {
		return
	}
	desired := make(map[string]PluginEventSubscription)
	for pluginID, plugin := range plugins {
		if !pluginControlHasPermission(plugin, "event") || !pluginControlHasPermission(plugin, "worker") {
			continue
		}
		for _, spec := range plugin.EventSubscriptions {
			desired[pluginID+"\x00"+spec.ID] = spec
		}
	}

	stopped := make([]*pluginControlEventSubscriptionRuntime, 0)
	started := make([]*pluginControlEventSubscriptionRuntime, 0)
	rt.eventMu.Lock()
	if rt.eventSubscriptions == nil {
		rt.eventSubscriptions = make(map[string]*pluginControlEventSubscriptionRuntime)
	}
	for key, current := range rt.eventSubscriptions {
		spec, keep := desired[key]
		if keep && pluginEventSubscriptionEqual(current.spec, spec) {
			delete(desired, key)
			continue
		}
		delete(rt.eventSubscriptions, key)
		stopped = append(stopped, current)
	}
	for key, spec := range desired {
		pluginID := strings.SplitN(key, "\x00", 2)[0]
		sub := &pluginControlEventSubscriptionRuntime{
			pluginID: pluginID, spec: spec, queue: make(chan pluginControlBusEvent, spec.QueueSize),
			stop: make(chan struct{}), wake: make(chan struct{}, 1), durableInFlight: make(map[string]struct{}),
		}
		rt.eventSubscriptions[key] = sub
		started = append(started, sub)
	}
	rt.eventMu.Unlock()
	for _, sub := range stopped {
		sub.stopRuntime()
	}
	for _, sub := range started {
		if sub.spec.Delivery == pluginEventDeliveryDurable {
			rt.initializeDurablePluginEventSubscription(sub)
		}
		go rt.runPluginEventSubscription(sub)
	}
}

func (rt *gojaPluginControlRuntime) runPluginEventSubscription(sub *pluginControlEventSubscriptionRuntime) {
	var ticker *time.Ticker
	var tick <-chan time.Time
	if sub.spec.Delivery == pluginEventDeliveryDurable {
		ticker = time.NewTicker(pluginEventDurablePollInterval)
		defer ticker.Stop()
		tick = ticker.C
		rt.enqueueDueDurablePluginEvents(sub)
	}
	for {
		if sub.stopped.Load() {
			return
		}
		select {
		case <-sub.stop:
			return
		case <-sub.wake:
			rt.enqueueDueDurablePluginEvents(sub)
		case <-tick:
			rt.enqueueDueDurablePluginEvents(sub)
		case event := <-sub.queue:
			if sub.stopped.Load() {
				return
			}
			rt.deliverPluginControlEvent(sub, event)
		}
	}
}

func (rt *gojaPluginControlRuntime) initializeDurablePluginEventSubscription(sub *pluginControlEventSubscriptionRuntime) {
	if rt == nil || sub == nil || sub.spec.Delivery != pluginEventDeliveryDurable {
		return
	}
	if rt.db == nil {
		sub.noteStoreError(fmt.Errorf("durable event delivery requires a persistent database"))
		return
	}
	pending, err := store.CountPluginEventDeliveries(rt.db, sub.pluginID, sub.spec.ID, store.PluginEventDeliveryPending)
	if err != nil {
		sub.noteStoreError(err)
		return
	}
	dead, err := store.CountPluginEventDeliveries(rt.db, sub.pluginID, sub.spec.ID, store.PluginEventDeliveryDead)
	if err != nil {
		sub.noteStoreError(err)
		return
	}
	sub.durablePending.Store(pending)
	sub.deadLetters.Store(dead)
}

func (rt *gojaPluginControlRuntime) deliverPluginControlEvent(sub *pluginControlEventSubscriptionRuntime, event pluginControlBusEvent) {
	event.SubscriptionID = sub.spec.ID
	var deliveryErr error
	if err := validatePluginEventPayload(sub.spec, event); err != nil {
		deliveryErr = fmt.Errorf("event contract validation before delivery: %w", err)
	} else {
		plugin := rt.pluginByID(sub.pluginID)
		if plugin.ID == "" {
			deliveryErr = fmt.Errorf("plugin is no longer active")
		} else if !pluginEventDeliveryAllowed(plugin, event) {
			deliveryErr = fmt.Errorf("event delivery is no longer authorized")
		} else {
			vm, err := rt.getPluginControlVM(plugin, "worker", sub.spec.Worker)
			if err == nil {
				_, err = vm.run(plugin, pluginControlEvent{
					Kind: "event", Payload: append(json.RawMessage(nil), event.Payload...), BusEvent: &event,
					Worker: &pluginControlWorkerEvent{Name: sub.spec.Worker, Handler: sub.spec.Handler},
				}, false)
			}
			deliveryErr = err
		}
	}
	if !event.Durable {
		sub.noteResult(event.PublishedAt, deliveryErr)
		return
	}
	rt.finishDurablePluginEventDelivery(sub, event, deliveryErr)
}

func (rt *gojaPluginControlRuntime) finishDurablePluginEventDelivery(sub *pluginControlEventSubscriptionRuntime, event pluginControlBusEvent, deliveryErr error) {
	defer func() {
		sub.unmarkDurableInFlight(event.DeliveryID)
		sub.signalDurableWake()
	}()
	if rt == nil || rt.db == nil {
		sub.noteResult(event.PublishedAt, fmt.Errorf("durable event delivery store is unavailable"))
		return
	}
	if deliveryErr == nil {
		deleted, err := store.DeletePluginEventDelivery(rt.db, sub.pluginID, event.DeliveryID)
		if err == nil && deleted {
			sub.durablePending.Add(-1)
			sub.noteResult(event.PublishedAt, nil)
			return
		}
		if err == nil {
			err = fmt.Errorf("durable event delivery disappeared before acknowledgement")
		}
		deliveryErr = fmt.Errorf("acknowledge durable event: %w", err)
	}

	attempt := event.DeliveryAttempt
	if attempt < 1 {
		attempt = 1
	}
	maxAttempts := event.DeliveryMaxAttempts
	if maxAttempts < 1 {
		maxAttempts = sub.spec.MaxAttempts
	}
	dead := attempt >= maxAttempts
	nextAttempt := time.Now().Add(pluginDurableEventRetryDelay(sub.spec.RetryDelayMS, attempt)).UnixMilli()
	if err := store.MarkPluginEventDeliveryFailure(rt.db, sub.pluginID, event.DeliveryID, attempt, nextAttempt, dead, deliveryErr.Error()); err != nil {
		sub.noteResult(event.PublishedAt, fmt.Errorf("record durable event failure: %w", err))
		return
	}
	if dead {
		sub.durablePending.Add(-1)
		sub.deadLetters.Add(1)
	} else {
		sub.retried.Add(1)
	}
	sub.noteResult(event.PublishedAt, deliveryErr)
}

func pluginDurableEventRetryDelay(baseMS, attempt int) time.Duration {
	if baseMS < pluginEventDurableMinRetryMS {
		baseMS = pluginEventDurableMinRetryMS
	}
	delay := int64(baseMS)
	for i := 1; i < attempt && delay < pluginEventDurableMaxRetryMS; i++ {
		delay *= 2
		if delay > pluginEventDurableMaxRetryMS {
			delay = pluginEventDurableMaxRetryMS
		}
	}
	return time.Duration(delay) * time.Millisecond
}

func (rt *gojaPluginControlRuntime) enqueueDueDurablePluginEvents(sub *pluginControlEventSubscriptionRuntime) {
	if rt == nil || rt.db == nil || sub == nil || sub.stopped.Load() || sub.spec.Delivery != pluginEventDeliveryDurable {
		return
	}
	available := cap(sub.queue) - len(sub.queue)
	if available < 1 {
		return
	}
	limit := cap(sub.queue) * 2
	if limit < available {
		limit = available
	}
	items, err := store.GetDuePluginEventDeliveries(rt.db, sub.pluginID, sub.spec.ID, time.Now().UnixMilli(), limit)
	if err != nil {
		sub.noteStoreError(err)
		return
	}
	for _, item := range items {
		if available < 1 {
			break
		}
		if sub.enqueueDurableEvent(pluginControlBusEventFromStore(item)) {
			available--
		}
	}
}

func pluginControlBusEventFromStore(item store.PluginEventDelivery) pluginControlBusEvent {
	return pluginControlBusEvent{
		Topic: item.Topic, SubscriptionID: item.SubscriptionID, Sequence: item.Sequence,
		PublishedAt: item.PublishedAt, SourcePlugin: item.SourcePlugin, TargetPlugin: item.TargetPlugin,
		ResourceID: item.ResourceID, SchemaVersion: item.SchemaVersion, Payload: json.RawMessage(item.PayloadJSON),
		DeliveryID: item.DeliveryID, DeliveryAttempt: item.Attempts + 1, DeliveryMaxAttempts: item.MaxAttempts, Durable: true,
	}
}

func (sub *pluginControlEventSubscriptionRuntime) enqueueDurableEvent(event pluginControlBusEvent) bool {
	if sub == nil || event.DeliveryID == "" || sub.stopped.Load() {
		return false
	}
	sub.durableMu.Lock()
	if _, exists := sub.durableInFlight[event.DeliveryID]; exists {
		sub.durableMu.Unlock()
		return false
	}
	sub.durableInFlight[event.DeliveryID] = struct{}{}
	sub.durableMu.Unlock()
	select {
	case <-sub.stop:
		sub.unmarkDurableInFlight(event.DeliveryID)
		return false
	case sub.queue <- event:
		sub.enqueued.Add(1)
		return true
	default:
		sub.unmarkDurableInFlight(event.DeliveryID)
		return false
	}
}

func (sub *pluginControlEventSubscriptionRuntime) unmarkDurableInFlight(deliveryID string) {
	if sub == nil || deliveryID == "" {
		return
	}
	sub.durableMu.Lock()
	delete(sub.durableInFlight, deliveryID)
	sub.durableMu.Unlock()
}

func (sub *pluginControlEventSubscriptionRuntime) signalDurableWake() {
	if sub == nil || sub.spec.Delivery != pluginEventDeliveryDurable || sub.stopped.Load() {
		return
	}
	select {
	case sub.wake <- struct{}{}:
	default:
	}
}

func (sub *pluginControlEventSubscriptionRuntime) noteStoreError(err error) {
	if sub == nil || err == nil {
		return
	}
	sub.lastMu.Lock()
	sub.lastError = err.Error()
	sub.lastMu.Unlock()
}

func (rt *gojaPluginControlRuntime) noteRetriedDeadPluginEvent(item store.PluginEventDelivery) {
	if rt == nil {
		return
	}
	rt.eventMu.Lock()
	sub := rt.eventSubscriptions[item.PluginID+"\x00"+item.SubscriptionID]
	if sub != nil {
		decrementPluginEventCounter(&sub.deadLetters)
		sub.durablePending.Add(1)
		sub.signalDurableWake()
	}
	rt.eventMu.Unlock()
}

func (rt *gojaPluginControlRuntime) noteDiscardedPluginEvent(item store.PluginEventDelivery) {
	if rt == nil {
		return
	}
	rt.eventMu.Lock()
	sub := rt.eventSubscriptions[item.PluginID+"\x00"+item.SubscriptionID]
	if sub != nil {
		sub.unmarkDurableInFlight(item.DeliveryID)
		switch item.Status {
		case store.PluginEventDeliveryPending:
			decrementPluginEventCounter(&sub.durablePending)
		case store.PluginEventDeliveryDead:
			decrementPluginEventCounter(&sub.deadLetters)
		}
		sub.signalDurableWake()
	}
	rt.eventMu.Unlock()
}

func decrementPluginEventCounter(counter *atomic.Int64) {
	if counter == nil {
		return
	}
	for {
		current := counter.Load()
		if current <= 0 || counter.CompareAndSwap(current, current-1) {
			return
		}
	}
}

func (sub *pluginControlEventSubscriptionRuntime) stopRuntime() {
	if sub == nil {
		return
	}
	sub.stopOnce.Do(func() {
		sub.stopped.Store(true)
		close(sub.stop)
	})
}

func (sub *pluginControlEventSubscriptionRuntime) noteResult(publishedAt string, err error) {
	if err == nil {
		sub.delivered.Add(1)
	} else {
		sub.errors.Add(1)
	}
	sub.lastMu.Lock()
	sub.lastEventAt = publishedAt
	if err == nil {
		sub.lastError = ""
	} else {
		sub.lastError = err.Error()
	}
	sub.lastMu.Unlock()
}

func (sub *pluginControlEventSubscriptionRuntime) noteRejection(publishedAt string, err error) {
	if sub == nil {
		return
	}
	sub.rejected.Add(1)
	sub.lastMu.Lock()
	sub.lastEventAt = publishedAt
	if err != nil {
		sub.lastError = err.Error()
	}
	sub.lastMu.Unlock()
}

func (rt *gojaPluginControlRuntime) stopPluginEventSubscriptions(pluginID string) {
	if rt == nil {
		return
	}
	stopped := make([]*pluginControlEventSubscriptionRuntime, 0)
	rt.eventMu.Lock()
	for key, sub := range rt.eventSubscriptions {
		if sub.pluginID != pluginID {
			continue
		}
		delete(rt.eventSubscriptions, key)
		stopped = append(stopped, sub)
	}
	rt.eventMu.Unlock()
	for _, sub := range stopped {
		sub.stopRuntime()
	}
}

func (rt *gojaPluginControlRuntime) stopAllPluginEventSubscriptions() {
	if rt == nil {
		return
	}
	rt.eventMu.Lock()
	stopped := make([]*pluginControlEventSubscriptionRuntime, 0, len(rt.eventSubscriptions))
	for _, sub := range rt.eventSubscriptions {
		stopped = append(stopped, sub)
	}
	rt.eventSubscriptions = nil
	rt.eventMu.Unlock()
	for _, sub := range stopped {
		sub.stopRuntime()
	}
}

func (rt *gojaPluginControlRuntime) publishPluginControlEvent(publication pluginControlEventPublication) pluginControlEventPublishResult {
	result := pluginControlEventPublishResult{}
	if rt == nil || !validPluginEventTopic(publication.Topic) || len(publication.Payload) > pluginEventMaxPayloadBytes || !json.Valid(publication.Payload) {
		return result
	}
	plugins := make(map[string]LoadedPlugin)
	rt.mu.Lock()
	for id, plugin := range rt.plugins {
		plugins[id] = plugin
	}
	closed := rt.closed
	rt.mu.Unlock()
	if closed {
		return result
	}
	if publication.SchemaVersion == 0 {
		publication.SchemaVersion = 1
	}
	if publication.SchemaVersion < 1 || publication.SchemaVersion > pluginSchemaMaxVersion {
		return result
	}
	event := pluginControlBusEvent{
		Topic: publication.Topic, Sequence: rt.nextPluginEventSequence(), PublishedAt: time.Now().UTC().Format(time.RFC3339Nano),
		SourcePlugin: publication.SourcePlugin, TargetPlugin: publication.TargetPlugin, ResourceID: publication.ResourceID,
		SchemaVersion: publication.SchemaVersion,
		Payload:       append(json.RawMessage(nil), publication.Payload...),
	}
	rt.eventMu.Lock()
	defer rt.eventMu.Unlock()
	durable := make([]pluginDurableEventTarget, 0)
	for _, sub := range rt.eventSubscriptions {
		plugin, active := plugins[sub.pluginID]
		if !active || sub.stopped.Load() || !pluginEventSubscriptionMatches(sub.spec, event.Topic) || !pluginEventDeliveryAllowed(plugin, event) {
			continue
		}
		result.Matched++
		if err := validatePluginEventPayload(sub.spec, event); err != nil {
			sub.noteRejection(event.PublishedAt, err)
			result.Rejected++
			continue
		}
		if sub.spec.Delivery == pluginEventDeliveryDurable {
			deliveryID, err := newPluginPackageID()
			if err != nil {
				sub.noteRejection(event.PublishedAt, fmt.Errorf("create durable event id: %w", err))
				result.Rejected++
				continue
			}
			durableEvent := event
			durableEvent.DeliveryID = deliveryID
			durableEvent.DeliveryAttempt = 1
			durableEvent.DeliveryMaxAttempts = sub.spec.MaxAttempts
			durableEvent.Durable = true
			durable = append(durable, pluginDurableEventTarget{
				sub:   sub,
				event: durableEvent,
				item: store.PluginEventDelivery{
					DeliveryID: deliveryID, PluginID: sub.pluginID, SubscriptionID: sub.spec.ID,
					Topic: event.Topic, Sequence: event.Sequence, PublishedAt: event.PublishedAt,
					SourcePlugin: event.SourcePlugin, TargetPlugin: event.TargetPlugin, ResourceID: event.ResourceID,
					SchemaVersion: event.SchemaVersion, PayloadJSON: string(event.Payload),
					MaxAttempts: sub.spec.MaxAttempts, NextAttemptUnixMS: time.Now().UnixMilli(),
				},
			})
			continue
		}
		select {
		case <-sub.stop:
			continue
		default:
		}
		select {
		case sub.queue <- event:
			sub.enqueued.Add(1)
			result.Enqueued++
		default:
			sub.dropped.Add(1)
			result.Dropped++
		}
	}
	if len(durable) == 0 {
		return result
	}
	items := make([]store.PluginEventDelivery, len(durable))
	for i := range durable {
		items[i] = durable[i].item
	}
	if err := store.CreatePluginEventDeliveries(rt.db, items, pluginEventDurablePerPluginMax, pluginEventDurableGlobalMax); err != nil {
		for _, target := range durable {
			target.sub.noteRejection(event.PublishedAt, fmt.Errorf("persist durable event: %w", err))
		}
		result.Rejected += len(durable)
		return result
	}
	result.Persisted = len(durable)
	for _, target := range durable {
		target.sub.durablePending.Add(1)
		if target.sub.enqueueDurableEvent(target.event) {
			result.Enqueued++
		} else {
			result.Deferred++
			target.sub.signalDurableWake()
		}
	}
	return result
}

func (rt *gojaPluginControlRuntime) nextPluginEventSequence() uint64 {
	if rt == nil {
		return 0
	}
	return rt.eventSequence.Add(1)
}

func pluginEventSubscriptionMatches(spec PluginEventSubscription, topic string) bool {
	if spec.Match == pluginEventMatchExact {
		return topic == spec.Topic
	}
	return topic == spec.Topic || strings.HasPrefix(topic, spec.Topic+".")
}

func pluginEventSubscriptionEqual(left, right PluginEventSubscription) bool {
	return left.ID == right.ID && left.Topic == right.Topic && left.Match == right.Match &&
		left.Worker == right.Worker && left.Handler == right.Handler && left.QueueSize == right.QueueSize &&
		left.Delivery == right.Delivery && left.MaxAttempts == right.MaxAttempts && left.RetryDelayMS == right.RetryDelayMS &&
		left.SchemaVersion == right.SchemaVersion && left.SchemaDigest == right.SchemaDigest
}

func validatePluginEventPayload(spec PluginEventSubscription, event pluginControlBusEvent) error {
	if event.SchemaVersion != spec.SchemaVersion {
		return fmt.Errorf("event %s schema_version %d is incompatible with subscription %s schema_version %d", event.Topic, event.SchemaVersion, spec.ID, spec.SchemaVersion)
	}
	if err := validatePluginSchema(spec.SchemaDigest, spec.Schema, event.Payload); err != nil {
		return fmt.Errorf("event %s payload %w", event.Topic, err)
	}
	return nil
}

func pluginEventDeliveryAllowed(plugin LoadedPlugin, event pluginControlBusEvent) bool {
	if pluginEventTopicRequiresNetAdmin(event.Topic) {
		return pluginControlHasPermission(plugin, "net.admin") && pluginEventNetAccessAllowed(plugin, event.Payload)
	}
	switch event.Topic {
	case pluginEventTopicResourceChanged:
		if event.TargetPlugin == plugin.ID {
			return true
		}
		return pluginControlHasResourceAccess(plugin, event.TargetPlugin, event.ResourceID, "get") ||
			pluginControlHasResourceAccess(plugin, event.TargetPlugin, event.ResourceID, "list")
	case pluginEventTopicPluginLifecycle:
		if event.TargetPlugin == plugin.ID {
			return true
		}
		for _, dependency := range plugin.Dependencies {
			if dependency.ID == event.TargetPlugin {
				return true
			}
		}
		return false
	default:
		sourcePlugin, ok := pluginCustomEventSource(event.Topic)
		if !ok || event.SourcePlugin != sourcePlugin {
			return false
		}
		if sourcePlugin == plugin.ID {
			return true
		}
		return pluginControlHasPermission(plugin, "event") &&
			pluginControlHasPermission(plugin, "worker") &&
			pluginControlHasEventAccess(plugin, sourcePlugin, event.Topic)
	}
}

func pluginEventNetAccessAllowed(plugin LoadedPlugin, payload json.RawMessage) bool {
	var value struct {
		Interface                   string   `json:"interface"`
		Interfaces                  []string `json:"interfaces"`
		InterfaceResolutionComplete *bool    `json:"interface_resolution_complete"`
		Name                        string   `json:"name"`
	}
	if err := json.Unmarshal(payload, &value); err != nil {
		return false
	}
	if value.InterfaceResolutionComplete != nil && !*value.InterfaceResolutionComplete {
		return false
	}
	names := append([]string(nil), value.Interfaces...)
	if name := strings.TrimSpace(value.Interface); name != "" {
		names = append(names, name)
	}
	if name := strings.TrimSpace(value.Name); name != "" {
		names = append(names, name)
	}
	seen := make(map[string]struct{}, len(names))
	allowed := 0
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		if !pluginControlHasNetAccess(plugin, "link.read", name) {
			return false
		}
		allowed++
	}
	return allowed > 0
}

func (rt *gojaPluginControlRuntime) pluginEventBusSnapshot(pluginID string) PluginEventBusState {
	state := PluginEventBusState{}
	if rt == nil {
		return state
	}
	rt.eventMu.Lock()
	for _, sub := range rt.eventSubscriptions {
		if sub.pluginID != pluginID {
			continue
		}
		snapshot := PluginEventSubscriptionState{
			ID: sub.spec.ID, Topic: sub.spec.Topic, Match: sub.spec.Match, Worker: sub.spec.Worker, Handler: sub.spec.Handler,
			Delivery:      sub.spec.Delivery,
			SchemaVersion: sub.spec.SchemaVersion, SchemaDigest: sub.spec.SchemaDigest,
			Pending: len(sub.queue), QueueSize: cap(sub.queue), Enqueued: sub.enqueued.Load(), Delivered: sub.delivered.Load(),
			Dropped: sub.dropped.Load(), Rejected: sub.rejected.Load(), Errors: sub.errors.Load(), Retried: sub.retried.Load(),
			DurablePending: sub.durablePending.Load(), DeadLetters: sub.deadLetters.Load(),
		}
		sub.lastMu.Lock()
		snapshot.LastEventAt = sub.lastEventAt
		snapshot.LastError = sub.lastError
		sub.lastMu.Unlock()
		state.SubscriptionCount++
		state.Pending += snapshot.Pending
		state.QueueCapacity += snapshot.QueueSize
		state.Enqueued += snapshot.Enqueued
		state.Delivered += snapshot.Delivered
		state.Dropped += snapshot.Dropped
		state.Rejected += snapshot.Rejected
		state.Errors += snapshot.Errors
		state.Retried += snapshot.Retried
		state.DurablePending += snapshot.DurablePending
		state.DeadLetters += snapshot.DeadLetters
		state.Subscriptions = append(state.Subscriptions, snapshot)
	}
	rt.eventMu.Unlock()
	sort.Slice(state.Subscriptions, func(i, j int) bool { return state.Subscriptions[i].ID < state.Subscriptions[j].ID })
	return state
}

func (rt *gojaPluginControlRuntime) publishPluginSystemEvent(topic, targetPlugin, resourceID string, payload any) {
	if rt == nil {
		return
	}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) > pluginEventMaxPayloadBytes {
		if err != nil {
			log.Printf("plugin event %s marshal failed: %v", topic, err)
		}
		return
	}
	rt.publishPluginControlEvent(pluginControlEventPublication{
		Topic: normalizePluginEventTopic(topic), SourcePlugin: "veer", TargetPlugin: targetPlugin, ResourceID: resourceID,
		SchemaVersion: 1, Payload: raw,
	})
}

func (rt *gojaPluginControlRuntime) publishPluginResourceChanged(sourcePlugin string, plugin LoadedPlugin, resource PluginResource, operation, key string) {
	raw, _ := json.Marshal(map[string]any{
		"plugin_id": plugin.ID, "resource_id": resource.ID, "operation": operation, "key": key,
	})
	rt.publishPluginControlEvent(pluginControlEventPublication{
		Topic: pluginEventTopicResourceChanged, SourcePlugin: sourcePlugin, TargetPlugin: plugin.ID, ResourceID: resource.ID,
		SchemaVersion: 1, Payload: raw,
	})
}

func validatePluginEventContractUpgrade(previous, candidate LoadedPlugin) error {
	previousSubscriptions := make(map[string]PluginEventSubscription, len(previous.EventSubscriptions))
	for _, subscription := range previous.EventSubscriptions {
		previousSubscriptions[subscription.ID] = subscription
	}
	for _, subscription := range candidate.EventSubscriptions {
		old, ok := previousSubscriptions[subscription.ID]
		if !ok {
			continue
		}
		if err := validatePluginSchemaVersionChange("event subscription", subscription.ID, "payload", old.SchemaVersion, old.SchemaDigest, subscription.SchemaVersion, subscription.SchemaDigest); err != nil {
			return err
		}
	}
	return nil
}

func (rt *gojaPluginControlRuntime) publishPluginLifecycleChanges(previous, current map[string]LoadedPlugin) {
	ids := make(map[string]struct{}, len(previous)+len(current))
	for id := range previous {
		ids[id] = struct{}{}
	}
	for id := range current {
		ids[id] = struct{}{}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		before, hadBefore := previous[id]
		after, hasAfter := current[id]
		operation := ""
		switch {
		case !hadBefore && hasAfter:
			operation = "activated"
		case hadBefore && !hasAfter:
			operation = "deactivated"
		case hadBefore && hasAfter && (before.Version != after.Version || before.sourceFingerprint != after.sourceFingerprint):
			operation = "updated"
		}
		if operation == "" {
			continue
		}
		version := before.Version
		if hasAfter {
			version = after.Version
		}
		rt.publishPluginSystemEvent(pluginEventTopicPluginLifecycle, id, "", map[string]any{
			"plugin_id": id, "operation": operation, "version": version,
		})
	}
}

func (pm *ProcessManager) publishPluginSystemEvent(topic, targetPlugin, resourceID string, payload any) {
	if pm == nil || pm.pluginControlRuntime == nil {
		return
	}
	if rt, ok := pm.pluginControlRuntime.(*gojaPluginControlRuntime); ok {
		rt.publishPluginSystemEvent(topic, targetPlugin, resourceID, payload)
	}
}
