package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

func TestManagedRuntimeDriftCheckRunsOnChangeWhileNetlinkIsWatched(t *testing.T) {
	last := time.Unix(1000, 0)
	cases := []struct {
		name           string
		since          time.Duration
		watched, dirty bool
		want           bool
	}{
		{"never checked", 0, true, false, true},
		{"unwatched polls", managedNetworkDriftCheckEvery, false, false, true},
		{"unwatched spacing", managedNetworkDriftCheckEvery - time.Second, false, true, false},
		{"watched and quiet", managedNetworkDriftCheckEvery, true, false, false},
		{"watched after a change", managedNetworkDriftCheckEvery, true, true, true},
		{"change still spaced", time.Second, true, true, false},
		{"safety net", managedNetworkDriftSafetyEvery, true, false, true},
	}
	for _, c := range cases {
		lastChecked := last
		if c.name == "never checked" {
			lastChecked = time.Time{}
		}
		if got := managedRuntimeDriftCheckDue(lastChecked, last.Add(c.since), c.watched, c.dirty); got != c.want {
			t.Errorf("%s: due = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPluginEnabledStateIsCachedUntilItIsWritten(t *testing.T) {
	db := openTestDB(t)
	rt := &pluginControlManager{db: db}
	if err := store.SetPluginEnabled(db, "cached", true); err != nil {
		t.Fatal(err)
	}
	if enabled, err := rt.pluginEnabledForControl("cached"); err != nil || !enabled {
		t.Fatalf("enabled = %v, %v", enabled, err)
	}
	// A write behind the store's back is not seen: the cache holds.
	if _, err := db.Exec(`UPDATE plugin_states SET enabled = 0 WHERE plugin_id = ?`, "cached"); err != nil {
		t.Fatal(err)
	}
	if enabled, _ := rt.pluginEnabledForControl("cached"); !enabled {
		t.Fatal("the cached state was read again without a write through the store")
	}
	// A write through the store is seen at once.
	if err := store.SetPluginEnabled(db, "cached", false); err != nil {
		t.Fatal(err)
	}
	if enabled, _ := rt.pluginEnabledForControl("cached"); enabled {
		t.Fatal("a disabled plugin still reads as enabled")
	}
	// And so is any state once the cache entry is older than its TTL.
	if _, err := db.Exec(`UPDATE plugin_states SET enabled = 1 WHERE plugin_id = ?`, "cached"); err != nil {
		t.Fatal(err)
	}
	rt.enabledMu.Lock()
	entry := rt.enabledCache["cached"]
	entry.readAt = entry.readAt.Add(-pluginEnabledCacheTTL)
	rt.enabledCache["cached"] = entry
	rt.enabledMu.Unlock()
	if enabled, _ := rt.pluginEnabledForControl("cached"); !enabled {
		t.Fatal("an expired cache entry was trusted")
	}
	if enabled, _ := rt.pluginEnabledForControl("never_stored"); !enabled {
		t.Fatal("a plugin without a state row must count as enabled")
	}
}

func TestPluginRuleAndProcessEventsReachOnlyTheirPlugins(t *testing.T) {
	plugin := func(id string, permissions []string, access ...PluginNetAccess) LoadedPlugin {
		return LoadedPlugin{PluginManifest: PluginManifest{ID: id, Control: &PluginControl{Permissions: permissions, NetAccess: access}}}
	}
	ruleWriter := plugin("wan", []string{"net.admin"}, PluginNetAccess{Interfaces: []string{"veer*"}, Operations: []string{"rule.write"}})
	reader := plugin("vpn", []string{"net.admin"}, PluginNetAccess{Interfaces: []string{"*"}, Operations: []string{"link.read"}})
	noAdmin := plugin("plain", nil, PluginNetAccess{Interfaces: []string{"*"}, Operations: []string{"rule.write"}})
	rule := func(payload map[string]any) pluginControlBusEvent {
		raw, _ := json.Marshal(payload)
		return pluginControlBusEvent{Topic: pluginEventTopicNetRule, SourcePlugin: "veer", Payload: raw}
	}
	cases := []struct {
		name   string
		plugin LoadedPlugin
		event  pluginControlBusEvent
		want   bool
	}{
		{"rule without interfaces to a rule writer", ruleWriter, rule(map[string]any{"table": 100}), true},
		{"rule on its interface", ruleWriter, rule(map[string]any{"iif": "veerwan0"}), true},
		{"rule on another interface", ruleWriter, rule(map[string]any{"oif": "eth0"}), false},
		{"rule to a link reader", reader, rule(map[string]any{"table": 100}), false},
		{"rule without net.admin", noAdmin, rule(map[string]any{"table": 100}), false},
		{"own process", reader, pluginControlBusEvent{Topic: pluginEventTopicProcessState, TargetPlugin: "vpn", Payload: json.RawMessage(`{}`)}, true},
		{"another plugin's process", ruleWriter, pluginControlBusEvent{Topic: pluginEventTopicProcessState, TargetPlugin: "vpn", Payload: json.RawMessage(`{}`)}, false},
		{"offload on its interface", reader, pluginControlBusEvent{Topic: pluginEventTopicNetOffload, Payload: json.RawMessage(`{"interface":"eth0"}`)}, true},
		{"offload on a foreign interface", ruleWriter, pluginControlBusEvent{Topic: pluginEventTopicNetOffload, Payload: json.RawMessage(`{"interface":"eth0"}`)}, false},
	}
	for _, c := range cases {
		if got := pluginEventDeliveryAllowed(c.plugin, c.event); got != c.want {
			t.Errorf("%s: delivered = %v, want %v", c.name, got, c.want)
		}
	}
	for _, topic := range []string{pluginEventTopicNetRule, pluginEventTopicNetOffload, pluginEventTopicProcessState} {
		if !validPluginSystemEventSubscriptionTopic(topic, pluginEventMatchExact) {
			t.Errorf("%s cannot be subscribed", topic)
		}
	}
	if !validPluginSystemEventSubscriptionTopic("process", pluginEventMatchPrefix) {
		t.Error("a process prefix subscription is refused")
	}
}

func TestPluginEventSubscriptionsRequireTheirHostFeatures(t *testing.T) {
	plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "events"}}
	plugin.EventSubscriptions = []PluginEventSubscription{
		{ID: "rules", Topic: pluginEventTopicNetRule},
		{ID: "procs", Topic: pluginEventTopicProcessState},
	}
	required := map[string]bool{}
	for _, feature := range pluginRequiredHostFeatures(plugin) {
		required[feature] = true
	}
	for _, feature := range []string{"control.net_events.v1", "control.net_policy_events.v1", "control.process_events.v1"} {
		if !required[feature] {
			t.Errorf("%s is not required by %v", feature, plugin.EventSubscriptions)
		}
	}
}

func TestPluginNetResyncReachesNetSubscribersWhenEventsAreLost(t *testing.T) {
	plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "wan", Control: &PluginControl{
		Permissions: []string{"net.admin", "event", "worker"},
		NetAccess:   []PluginNetAccess{{Interfaces: []string{"veer*"}, Operations: []string{"link.read"}}},
	}}}
	resync := pluginControlBusEvent{Topic: pluginEventTopicNetLink, SourcePlugin: "veer", Payload: json.RawMessage(`{"operation":"resync","reason":"netlink_resubscribe"}`)}
	if !pluginEventDeliveryAllowed(plugin, resync) {
		t.Fatal("a resync names no interface and must reach every net.admin subscriber")
	}
	plain := plugin
	plain.Control = &PluginControl{Permissions: []string{"event", "worker"}}
	if pluginEventDeliveryAllowed(plain, resync) {
		t.Fatal("a resync reached a plugin without net.admin")
	}

	rt := &pluginControlManager{
		plugins:            map[string]LoadedPlugin{"wan": plugin},
		eventSubscriptions: map[string]*pluginControlEventSubscriptionRuntime{},
	}
	newSub := func(id, topic, match string) *pluginControlEventSubscriptionRuntime {
		sub := &pluginControlEventSubscriptionRuntime{
			pluginID: "wan", spec: PluginEventSubscription{ID: id, Topic: topic, Match: match, SchemaVersion: 1, QueueSize: 1},
			queue: make(chan pluginControlBusEvent, 1), stop: make(chan struct{}), wake: make(chan struct{}, 1),
		}
		rt.eventSubscriptions["wan\x00"+id] = sub
		return sub
	}
	prefix := newSub("all_net", "net", pluginEventMatchPrefix)
	exact := newSub("routes", pluginEventTopicNetRoute, pluginEventMatchExact)
	custom := newSub("custom", "plugin.wan.state", pluginEventMatchExact)

	// A new network subscription starts with a resync, on its own topic.
	for sub, topic := range map[*pluginControlEventSubscriptionRuntime]string{prefix: pluginEventTopicNetLink, exact: pluginEventTopicNetRoute} {
		rt.queuePluginNetResync(sub, "subscription_started")
		got := <-sub.queue
		if got.Topic != topic || !strings.Contains(string(got.Payload), `"operation":"resync"`) || got.SourcePlugin != "veer" {
			t.Fatalf("%s resync = %+v", sub.spec.ID, got)
		}
	}
	rt.queuePluginNetResync(custom, "subscription_started")
	if len(custom.queue) != 0 {
		t.Fatal("a custom topic got a network resync")
	}

	// A network event that does not fit marks the subscription for a resync.
	link := pluginControlEventPublication{Topic: pluginEventTopicNetLink, SourcePlugin: "veer", SchemaVersion: 1, Payload: json.RawMessage(`{"operation":"update","name":"veerwan0"}`)}
	rt.publishPluginControlEvent(link)
	if prefix.lost.Load() {
		t.Fatal("an event that fitted marked the subscription")
	}
	rt.publishPluginControlEvent(link)
	if !prefix.lost.Load() {
		t.Fatal("a dropped network event did not mark the subscription for a resync")
	}
	// A full queue also defers the start-up resync instead of losing it.
	exact.queue <- pluginControlBusEvent{}
	rt.queuePluginNetResync(exact, "subscription_started")
	if !exact.lost.Load() {
		t.Fatal("a resync that did not fit was lost")
	}
}

func TestPluginCatalogSafetyScanTrustsStatButAWatchedChangeHashes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plugin", "control.js")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1700000000, 0)
	write := func(content string) {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	write("one")
	cache := &pluginCatalogFingerprintCache{}
	now := time.Now()
	first, err := cache.fingerprint(dir, now, pluginCatalogScanFull)
	if err != nil {
		t.Fatal(err)
	}
	write("two") // same size, same mtime
	later := now.Add(pluginCatalogDriftSafetyEvery)
	if got, err := cache.fingerprint(dir, later, pluginCatalogScanTrustStat); err != nil || got != first {
		t.Fatalf("safety scan rehashed an unchanged-looking file: %v", err)
	}
	if got, err := cache.fingerprint(dir, later, pluginCatalogScanFull); err != nil || got == first {
		t.Fatalf("a watched change kept size and mtime and was missed: %v", err)
	}
}
