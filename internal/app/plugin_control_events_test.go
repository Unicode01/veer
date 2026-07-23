package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginEventBusDeliversSystemEventToWorker(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "event_plugin", `{
  "api_version": "v1",
  "id": "event_plugin",
  "name": "Event Plugin",
  "version": "1.0.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["event", "kv", "net.admin", "plugin.register", "worker"],
    "net_access": [{"interfaces": ["eth*"], "operations": ["link.read"]}]
  }
}`)
	writePluginControlScript(t, dir, "event_plugin", `
events.subscribe({id: 'links', topic: 'net.link', worker: 'net_events', handler: 'onLink', queue_size: 4});
exports.onLink = function (ctx) {
  kv.set('last_link', {
    topic: ctx.event.topic,
    sequence: ctx.event.sequence,
    operation: ctx.event.payload.operation,
    name: ctx.event.payload.name,
    worker: ctx.worker.name
  });
};
`)

	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	snapshot := rt.Reconcile(loadPluginCatalogWithControlRegistrationAndState(cfg, db))
	state, ok := snapshot.Plugins["event_plugin"]
	if !ok || state.Error != "" {
		t.Fatalf("event plugin reconcile state = %+v", state)
	}

	result := rt.publishPluginControlEvent(pluginControlEventPublication{
		Topic: pluginEventTopicNetLink, SourcePlugin: "veer", Payload: []byte(`{"operation":"update","name":"eth0"}`),
	})
	if result.Matched != 1 || result.Enqueued != 1 || result.Dropped != 0 {
		t.Fatalf("publish result = %+v, want one enqueue", result)
	}
	record := waitForPluginEventRecord(t, db, "event_plugin", "last_link")
	for _, want := range []string{`"topic":"net.link"`, `"operation":"update"`, `"name":"eth0"`, `"worker":"net_events"`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("last_link data = %s, want %s", record.DataJSON, want)
		}
	}
	stats := rt.pluginEventBusSnapshot("event_plugin")
	if stats.SubscriptionCount != 1 || stats.Delivered != 1 || stats.Errors != 0 || stats.Dropped != 0 {
		t.Fatalf("event stats = %+v", stats)
	}
}

func TestPluginEventBusFloodDropsWithoutBlockingPublisher(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "slow_events", `{
  "api_version": "v1",
  "id": "slow_events",
  "name": "Slow Events",
  "version": "1.0.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["event", "plugin.register", "worker"]
  }
}`)
	writePluginControlScript(t, dir, "slow_events", `
events.subscribe({id: 'slow', topic: 'plugin.slow_events.test', worker: 'slow', handler: 'onEvent', queue_size: 1});
exports.onEvent = function () {
  var until = Date.now() + 150;
  while (Date.now() < until) {}
};
`)

	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	rt := newPluginControlRuntime(openTestDB(t), cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	rt.Reconcile(loadPluginCatalogWithControlRegistration(cfg))

	started := time.Now()
	for i := 0; i < 100; i++ {
		rt.publishPluginControlEvent(pluginControlEventPublication{
			Topic: "plugin.slow_events.test", SourcePlugin: "slow_events", TargetPlugin: "slow_events", Payload: []byte(`{}`),
		})
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("100 event publishes blocked for %s", elapsed)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		stats := rt.pluginEventBusSnapshot("slow_events")
		if stats.Dropped > 0 && stats.Delivered > 0 {
			if stats.Enqueued+stats.Dropped != 100 {
				t.Fatalf("event accounting = %+v, want 100 publications", stats)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("event flood did not drain/drop in time: %+v", stats)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPluginEventSubscriptionPermissionsAndCleanup(t *testing.T) {
	t.Run("net topic requires net admin", func(t *testing.T) {
		dir := t.TempDir()
		writeTestPlugin(t, dir, "denied_events", `{
  "api_version": "v1",
  "id": "denied_events",
  "name": "Denied Events",
  "version": "1.0.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["event", "plugin.register", "worker"]
  }
}`)
		writePluginControlScript(t, dir, "denied_events", `events.subscribe({id: 'links', topic: 'net.link'});`)
		cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
		catalog := loadPluginCatalogWithControlRegistration(cfg)
		plugin := pluginByIDForTest(t, catalog, "denied_events")
		if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "requires net.admin permission") {
			t.Fatalf("denied event plugin = %+v", plugin)
		}
	})

	t.Run("deactivate removes subscriptions", func(t *testing.T) {
		dir := t.TempDir()
		writeTestPlugin(t, dir, "cleanup_events", `{
  "api_version": "v1",
  "id": "cleanup_events",
  "name": "Cleanup Events",
  "version": "1.0.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["event", "plugin.register", "worker"]
  }
}`)
		writePluginControlScript(t, dir, "cleanup_events", `
events.subscribe({id: 'own', topic: 'plugin.cleanup_events.test'});
exports.onEvent = function () {};
`)
		cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
		rt := newPluginControlRuntime(openTestDB(t), cfg, nil).(*gojaPluginControlRuntime)
		t.Cleanup(func() { _ = rt.Close() })
		rt.Reconcile(loadPluginCatalogWithControlRegistration(cfg))
		if got := rt.pluginEventBusSnapshot("cleanup_events").SubscriptionCount; got != 1 {
			t.Fatalf("subscription count before deactivate = %d, want 1", got)
		}
		rt.deactivatePluginControl("cleanup_events")
		if got := rt.pluginEventBusSnapshot("cleanup_events").SubscriptionCount; got != 0 {
			t.Fatalf("subscription count after deactivate = %d, want 0", got)
		}
		result := rt.publishPluginControlEvent(pluginControlEventPublication{
			Topic: "plugin.cleanup_events.test", SourcePlugin: "cleanup_events", TargetPlugin: "cleanup_events", Payload: []byte(`{}`),
		})
		if result.Matched != 0 || result.Enqueued != 0 {
			t.Fatalf("publish after deactivate = %+v", result)
		}
	})
}

func TestPluginEventBusCrossPluginAccessIsExplicitAndSourceBound(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "event_source", `{
  "api_version": "v1",
  "id": "event_source",
  "name": "Event Source",
  "version": "1.0.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["event", "plugin.register"]
  }
}`)
	writePluginControlScript(t, dir, "event_source", `
plugin.action({id: 'publish', runtime_update: 'runtime_query'});
exports.onAction = function (ctx) {
  return events.publish('plugin.event_source.session.changed', ctx.payload);
};
`)
	writeTestPlugin(t, dir, "event_sink", `{
  "api_version": "v1",
  "id": "event_sink",
  "name": "Event Sink",
  "version": "1.0.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["event", "kv", "plugin.event", "plugin.register", "worker"],
    "event_access": [{
      "plugin": "event_source",
      "topic_prefixes": ["plugin.event_source.session"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "event_sink", `
events.subscribe({id: 'source_sessions', topic: 'plugin.event_source.session', match: 'prefix', worker: 'events'});
exports.onEvent = function (ctx) {
  kv.set('last_cross_event', {
    topic: ctx.event.topic,
    source_plugin: ctx.event.source_plugin,
    value: ctx.event.payload.value
  });
};
`)

	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	catalog := loadPluginCatalogWithControlRegistrationAndState(cfg, db)
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	snapshot := rt.Reconcile(catalog)
	for _, pluginID := range []string{"event_source", "event_sink"} {
		if state := snapshot.Plugins[pluginID]; state.Error != "" {
			t.Fatalf("%s reconcile state = %+v", pluginID, state)
		}
	}

	source := pluginByIDForTest(t, catalog, "event_source")
	result, err := rt.QueryPluginAction(source, pluginActionByIDForTest(t, source, "publish"), json.RawMessage(`{"value":7}`))
	if err != nil {
		t.Fatalf("publish cross-plugin event: %v", err)
	}
	resultJSON, _ := json.Marshal(result)
	if !strings.Contains(string(resultJSON), `"enqueued":1`) {
		t.Fatalf("publish result = %s, want one enqueue", resultJSON)
	}
	record := waitForPluginEventRecord(t, db, "event_sink", "last_cross_event")
	for _, want := range []string{`"topic":"plugin.event_source.session.changed"`, `"source_plugin":"event_source"`, `"value":7`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("cross event record = %s, want %s", record.DataJSON, want)
		}
	}

	for _, publication := range []pluginControlEventPublication{
		{Topic: "plugin.event_source.private.changed", SourcePlugin: "event_source", Payload: []byte(`{}`)},
		{Topic: "plugin.event_source.session.changed", SourcePlugin: "spoofed_source", Payload: []byte(`{}`)},
	} {
		got := rt.publishPluginControlEvent(publication)
		if got.Matched != 0 || got.Enqueued != 0 {
			t.Fatalf("unauthorized publication %+v matched: %+v", publication, got)
		}
	}
}

func TestPluginEventAccessManifestAndSubscriptionValidation(t *testing.T) {
	t.Run("event access requires cross-plugin permission", func(t *testing.T) {
		dir := t.TempDir()
		writeTestPlugin(t, dir, "missing_event_permission", `{
  "api_version": "v1",
  "id": "missing_event_permission",
  "name": "Missing Event Permission",
  "version": "1.0.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["event", "plugin.register", "worker"],
    "event_access": [{"plugin":"source","topic_prefixes":["plugin.source.status"]}]
  }
}`)
		writePluginControlScript(t, dir, "missing_event_permission", ``)
		catalog := loadPluginCatalog(pluginsEnabledTestConfig(&Config{PluginsDir: dir}))
		plugin := LoadedPlugin{}
		for _, candidate := range catalog.Plugins {
			if candidate.Source == "missing_event_permission" {
				plugin = candidate
				break
			}
		}
		if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "event_access requires plugin.event permission") {
			t.Fatalf("plugin = %+v", plugin)
		}
	})

	t.Run("subscription must stay under declared prefix", func(t *testing.T) {
		dir := t.TempDir()
		writeTestPlugin(t, dir, "narrow_event_access", `{
  "api_version": "v1",
  "id": "narrow_event_access",
  "name": "Narrow Event Access",
  "version": "1.0.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["event", "plugin.event", "plugin.register", "worker"],
    "event_access": [{"plugin":"source","topic_prefixes":["plugin.source.status"]}]
  }
}`)
		writePluginControlScript(t, dir, "narrow_event_access", `events.subscribe({id:'private',topic:'plugin.source.private'});`)
		plugin := pluginByIDForTest(t, loadPluginCatalogWithControlRegistration(pluginsEnabledTestConfig(&Config{PluginsDir: dir})), "narrow_event_access")
		if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "is not declared in event_access") {
			t.Fatalf("plugin = %+v", plugin)
		}
	})

	t.Run("plugin lifecycle remains a system topic", func(t *testing.T) {
		plugin := LoadedPlugin{PluginManifest: PluginManifest{
			ID:      "lifecycle_sink",
			Control: &PluginControl{Permissions: []string{"event", "worker"}},
		}}
		spec := PluginEventSubscription{ID: "lifecycle", Topic: pluginEventTopicPluginLifecycle}
		if err := normalizePluginEventSubscription(plugin, &spec); err != nil {
			t.Fatalf("normalize lifecycle subscription: %v", err)
		}
	})

	t.Run("plugin lifecycle cannot be claimed as custom access", func(t *testing.T) {
		control := &PluginControl{
			Main:        "control.js",
			Permissions: []string{"event", "plugin.event", "worker"},
			EventAccess: []PluginEventAccess{{
				Plugin: "lifecycle", TopicPrefixes: []string{pluginEventTopicPluginLifecycle},
			}},
		}
		if err := normalizePluginControl(control); err == nil || !strings.Contains(err.Error(), "reserved for the Veer lifecycle event") {
			t.Fatalf("normalize lifecycle event access error = %v", err)
		}
	})
}

func TestPluginNetworkEventRequiresAccessToEveryReferencedInterface(t *testing.T) {
	plugin := LoadedPlugin{PluginManifest: PluginManifest{
		ID: "route_sink",
		Control: &PluginControl{
			Permissions: []string{"event", "net.admin", "worker"},
			NetAccess:   []PluginNetAccess{{Interfaces: []string{"eth*"}, Operations: []string{"link.read"}}},
		},
	}}
	complete := true
	if !pluginEventNetAccessAllowed(plugin, json.RawMessage(`{"interfaces":["eth0","eth1"],"interface_resolution_complete":true}`)) {
		t.Fatal("authorized multipath event was rejected")
	}
	if pluginEventNetAccessAllowed(plugin, json.RawMessage(`{"interfaces":["eth0","wan0"],"interface_resolution_complete":true}`)) {
		t.Fatal("partially authorized multipath event was accepted")
	}
	complete = false
	payload, _ := json.Marshal(map[string]any{"interfaces": []string{"eth0"}, "interface_resolution_complete": complete})
	if pluginEventNetAccessAllowed(plugin, payload) {
		t.Fatal("incompletely resolved route event was accepted")
	}
}

func TestStoppedPluginEventSubscriptionDiscardsQueuedEvents(t *testing.T) {
	sub := &pluginControlEventSubscriptionRuntime{
		pluginID: "stopped_events",
		spec:     PluginEventSubscription{ID: "events", QueueSize: 1},
		queue:    make(chan pluginControlBusEvent, 1),
		stop:     make(chan struct{}),
	}
	sub.queue <- pluginControlBusEvent{Topic: "plugin.stopped_events.test", Payload: json.RawMessage(`{}`)}
	sub.stopRuntime()
	sub.stopRuntime()
	done := make(chan struct{})
	go func() {
		(&gojaPluginControlRuntime{}).runPluginEventSubscription(sub)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stopped subscription did not exit")
	}
	if sub.delivered.Load() != 0 || sub.errors.Load() != 0 {
		t.Fatalf("stopped subscription processed queued event: delivered=%d errors=%d", sub.delivered.Load(), sub.errors.Load())
	}
}

func TestPluginEventSchemaRejectsBeforeQueueAndAcceptsMatchingVersion(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "schema_events", `{
  "api_version": "v1",
  "id": "schema_events",
  "name": "Schema Events",
  "version": "1.0.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["event", "kv", "plugin.register", "worker"]
  }
}`)
	writePluginControlScript(t, dir, "schema_events", `
events.subscribe({
  id: 'updates',
  topic: 'plugin.schema_events.updated',
  worker: 'events',
  schema_version: 2,
  schema: {
    type: 'object',
    required: ['value'],
    properties: {value: {type: 'integer'}},
    additionalProperties: false
  }
});
plugin.action({id: 'publish', runtime_update: 'runtime_query'});
exports.onAction = function (ctx) {
  return events.publish('plugin.schema_events.updated', ctx.payload, {schema_version: 2});
};
exports.onEvent = function (ctx) {
  kv.set('schema_event', {value: ctx.event.payload.value, schema_version: ctx.event.schema_version});
};
`)

	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	catalog := loadPluginCatalogWithControlRegistrationAndState(cfg, db)
	snapshot := rt.Reconcile(catalog)
	if state := snapshot.Plugins["schema_events"]; state.Error != "" {
		t.Fatalf("schema event reconcile = %+v", state)
	}

	wrongPayload := rt.publishPluginControlEvent(pluginControlEventPublication{
		Topic: "plugin.schema_events.updated", SourcePlugin: "schema_events", TargetPlugin: "schema_events",
		SchemaVersion: 2, Payload: json.RawMessage(`{"value":"bad"}`),
	})
	if wrongPayload.Matched != 1 || wrongPayload.Rejected != 1 || wrongPayload.Enqueued != 0 {
		t.Fatalf("wrong payload publication = %+v", wrongPayload)
	}
	wrongVersion := rt.publishPluginControlEvent(pluginControlEventPublication{
		Topic: "plugin.schema_events.updated", SourcePlugin: "schema_events", TargetPlugin: "schema_events",
		SchemaVersion: 1, Payload: json.RawMessage(`{"value":7}`),
	})
	if wrongVersion.Matched != 1 || wrongVersion.Rejected != 1 || wrongVersion.Enqueued != 0 {
		t.Fatalf("wrong version publication = %+v", wrongVersion)
	}
	stats := rt.pluginEventBusSnapshot("schema_events")
	if stats.Rejected != 2 || stats.Enqueued != 0 || stats.Pending != 0 {
		t.Fatalf("rejected event stats = %+v", stats)
	}

	plugin := pluginByIDForTest(t, catalog, "schema_events")
	result, err := rt.QueryPluginAction(plugin, pluginActionByIDForTest(t, plugin, "publish"), json.RawMessage(`{"value":7}`))
	if err != nil {
		t.Fatalf("publish schema event action: %v", err)
	}
	accepted, _ := json.Marshal(result)
	if !strings.Contains(string(accepted), `"matched":1`) || !strings.Contains(string(accepted), `"enqueued":1`) || !strings.Contains(string(accepted), `"rejected":0`) {
		t.Fatalf("accepted publication = %s", accepted)
	}
	record := waitForPluginEventRecord(t, db, "schema_events", "schema_event")
	for _, want := range []string{`"value":7`, `"schema_version":2`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("schema event record = %s, want %s", record.DataJSON, want)
		}
	}
}

func waitForPluginEventRecord(t *testing.T, db *sql.DB, pluginID, key string) *store.PluginRecord {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		record, err := store.GetPluginRecord(db, pluginID, pluginControlKVResourceID, key)
		if err == nil {
			return record
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("GetPluginRecord(%s/%s): %v", pluginID, key, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for plugin record %s/%s", pluginID, key)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPluginDurableEventRetriesDeadLettersAndManualRecovery(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "durable_events", `{
  "api_version":"v1",
  "id":"durable_events",
  "name":"Durable Events",
  "version":"1.0.0",
  "kind":"control",
  "control":{
    "main":"control.js",
    "permissions":["event","kv","plugin.register","worker"]
  }
}`)
	writePluginControlScript(t, dir, "durable_events", `
events.subscribe({
  id: 'critical',
  topic: 'plugin.durable_events.changed',
  worker: 'critical_events',
  handler: 'onCritical',
  queue_size: 2,
  delivery: 'durable',
  max_attempts: 2,
  retry_delay_ms: 100
});
plugin.action({id: 'dead_letters', runtime_update: 'runtime_query'});
plugin.action({id: 'allow_delivery', runtime_update: 'runtime_query'});
plugin.action({id: 'retry_delivery', runtime_update: 'runtime_query'});
plugin.action({id: 'discard_delivery', runtime_update: 'runtime_query'});
exports.onCritical = function (ctx) {
  var allowed = kv.get('allow_delivery');
  if (!allowed || allowed.data !== true) throw new Error('delivery is intentionally blocked');
  kv.set('delivered', {
    delivery_id: ctx.event.delivery_id,
    delivery: ctx.event.delivery,
    attempt: ctx.event.attempt,
    value: ctx.event.payload.value
  });
};
exports.onAction = function (ctx) {
  if (ctx.action.id === 'dead_letters') return events.deadLetters({limit: 10});
  if (ctx.action.id === 'allow_delivery') {
    kv.set('allow_delivery', true);
    return {allowed: true};
  }
  if (ctx.action.id === 'retry_delivery') return events.retry(ctx.payload.delivery_id);
  if (ctx.action.id === 'discard_delivery') return events.discard(ctx.payload.delivery_id);
};
`)

	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	catalog := loadPluginCatalogWithControlRegistrationAndState(cfg, db)
	snapshot := rt.Reconcile(catalog)
	if state := snapshot.Plugins["durable_events"]; state.Error != "" {
		t.Fatalf("durable event reconcile = %+v", state)
	}

	publication := rt.publishPluginControlEvent(pluginControlEventPublication{
		Topic: "plugin.durable_events.changed", SourcePlugin: "durable_events", TargetPlugin: "durable_events",
		SchemaVersion: 1, Payload: json.RawMessage(`{"value":17}`),
	})
	if publication.Matched != 1 || publication.Persisted != 1 || publication.Enqueued != 1 || publication.Dropped != 0 {
		t.Fatalf("durable publication = %+v", publication)
	}

	var dead store.PluginEventDelivery
	deadline := time.Now().Add(4 * time.Second)
	for {
		items, err := store.GetDeadPluginEventDeliveries(db, "durable_events", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) == 1 {
			dead = items[0]
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("durable event did not reach dead letter: %+v", rt.pluginEventBusSnapshot("durable_events"))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if dead.Attempts != 2 || dead.MaxAttempts != 2 || dead.Status != store.PluginEventDeliveryDead || !strings.Contains(dead.LastError, "intentionally blocked") {
		t.Fatalf("dead delivery = %+v", dead)
	}

	plugin := pluginByIDForTest(t, catalog, "durable_events")
	deadResult, err := rt.QueryPluginAction(plugin, pluginActionByIDForTest(t, plugin, "dead_letters"), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("list dead letters: %v", err)
	}
	deadJSON, _ := json.Marshal(deadResult)
	if !strings.Contains(string(deadJSON), dead.DeliveryID) || !strings.Contains(string(deadJSON), `"value":17`) {
		t.Fatalf("dead letter API result = %s", deadJSON)
	}
	if _, err := rt.QueryPluginAction(plugin, pluginActionByIDForTest(t, plugin, "allow_delivery"), json.RawMessage(`{}`)); err != nil {
		t.Fatalf("allow durable delivery: %v", err)
	}
	retryPayload, _ := json.Marshal(map[string]string{"delivery_id": dead.DeliveryID})
	if _, err := rt.QueryPluginAction(plugin, pluginActionByIDForTest(t, plugin, "retry_delivery"), retryPayload); err != nil {
		t.Fatalf("retry durable delivery: %v", err)
	}
	record := waitForPluginEventRecord(t, db, "durable_events", "delivered")
	for _, want := range []string{dead.DeliveryID, `"delivery":"durable"`, `"value":17`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("delivered record = %s, want %s", record.DataJSON, want)
		}
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		_, err := store.GetPluginEventDelivery(db, "durable_events", dead.DeliveryID)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("acknowledged durable delivery remained in the outbox")
		}
		time.Sleep(10 * time.Millisecond)
	}
	stats := rt.pluginEventBusSnapshot("durable_events")
	if stats.Delivered != 1 || stats.Retried != 1 || stats.DurablePending != 0 || stats.DeadLetters != 0 || stats.Errors != 2 {
		t.Fatalf("durable event stats = %+v", stats)
	}
}

func TestPluginDurableEventRecoversPendingDeliveryAfterRuntimeStart(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "durable_restart", `{
  "api_version":"v1",
  "id":"durable_restart",
  "name":"Durable Restart",
  "version":"1.0.0",
  "kind":"control",
  "control":{
    "main":"control.js",
    "permissions":["event","kv","plugin.register","worker"]
  }
}`)
	writePluginControlScript(t, dir, "durable_restart", `
events.subscribe({
  id: 'restart',
  topic: 'plugin.durable_restart.pending',
  worker: 'events',
  delivery: 'durable'
});
exports.onEvent = function (ctx) {
  kv.set('recovered', {delivery_id: ctx.event.delivery_id, attempt: ctx.event.attempt, value: ctx.event.payload.value});
};
`)

	db := openTestDB(t)
	deliveryID, err := newPluginPackageID()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreatePluginEventDeliveries(db, []store.PluginEventDelivery{{
		DeliveryID: deliveryID, PluginID: "durable_restart", SubscriptionID: "restart",
		Topic: "plugin.durable_restart.pending", Sequence: 41, PublishedAt: time.Now().UTC().Format(time.RFC3339Nano),
		SourcePlugin: "durable_restart", TargetPlugin: "durable_restart", SchemaVersion: 1,
		PayloadJSON: `{"value":23}`, MaxAttempts: 8, NextAttemptUnixMS: time.Now().Add(-time.Second).UnixMilli(),
	}}, pluginEventDurablePerPluginMax, pluginEventDurableGlobalMax); err != nil {
		t.Fatal(err)
	}

	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	snapshot := rt.Reconcile(loadPluginCatalogWithControlRegistrationAndState(cfg, db))
	if state := snapshot.Plugins["durable_restart"]; state.Error != "" {
		t.Fatalf("restart event reconcile = %+v", state)
	}
	record := waitForPluginEventRecord(t, db, "durable_restart", "recovered")
	if !strings.Contains(record.DataJSON, deliveryID) || !strings.Contains(record.DataJSON, `"attempt":1`) || !strings.Contains(record.DataJSON, `"value":23`) {
		t.Fatalf("recovered delivery record = %s", record.DataJSON)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := store.GetPluginEventDelivery(db, "durable_restart", deliveryID)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("recovered durable delivery was not acknowledged")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPluginDurableEventQueueDefersWithoutDropping(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "durable_queue", `{
  "api_version":"v1",
  "id":"durable_queue",
  "name":"Durable Queue",
  "version":"1.0.0",
  "kind":"control",
  "control":{
    "main":"control.js",
    "permissions":["event","kv","plugin.register","worker"]
  }
}`)
	writePluginControlScript(t, dir, "durable_queue", `
events.subscribe({
  id: 'queue',
  topic: 'plugin.durable_queue.item',
  worker: 'events',
  queue_size: 1,
  delivery: 'durable'
});
exports.onEvent = function () {
  var until = Date.now() + 30;
  while (Date.now() < until) {}
  var current = kv.get('count');
  kv.set('count', {value: current ? Number(current.data.value) + 1 : 1});
};
`)

	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	rt.Reconcile(loadPluginCatalogWithControlRegistrationAndState(cfg, db))
	deferred := 0
	for i := 0; i < 12; i++ {
		result := rt.publishPluginControlEvent(pluginControlEventPublication{
			Topic: "plugin.durable_queue.item", SourcePlugin: "durable_queue", TargetPlugin: "durable_queue",
			SchemaVersion: 1, Payload: json.RawMessage(`{}`),
		})
		if result.Persisted != 1 || result.Dropped != 0 || result.Rejected != 0 {
			t.Fatalf("durable queue publication %d = %+v", i, result)
		}
		deferred += result.Deferred
	}
	if deferred == 0 {
		t.Fatal("durable queue never exercised deferred persistence")
	}
	deadline := time.Now().Add(5 * time.Second)
	var stats PluginEventBusState
	for {
		record, err := store.GetPluginRecord(db, "durable_queue", pluginControlKVResourceID, "count")
		stats = rt.pluginEventBusSnapshot("durable_queue")
		if err == nil && strings.Contains(record.DataJSON, `"value":12`) && stats.Delivered == 12 && stats.DurablePending == 0 {
			break
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("durable queue did not drain: record=%+v err=%v stats=%+v", record, err, stats)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if stats.Delivered != 12 || stats.Dropped != 0 || stats.DurablePending != 0 || stats.Errors != 0 {
		t.Fatalf("durable queue stats = %+v", stats)
	}
}
