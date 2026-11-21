package app

import (
	"encoding/json"
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

func TestPluginHostRSSSampleIntervalByHeadroom(t *testing.T) {
	const limit = 224 << 20
	cases := []struct {
		rss  uint64
		hard bool
		want time.Duration
	}{
		{10 << 20, true, pluginHostRSSSampleFar},
		{limit / 2, true, pluginHostRSSSampleNear},
		{10 << 20, false, pluginHostRSSSampleNear},
	}
	for _, c := range cases {
		if got := pluginHostRSSSampleInterval(c.rss, limit, c.hard); got != c.want {
			t.Errorf("rss %d hard %v: %v, want %v", c.rss, c.hard, got, c.want)
		}
	}
}

func TestPluginEnabledStateIsCachedUntilItIsWritten(t *testing.T) {
	db := openTestDB(t)
	rt := &gojaPluginControlRuntime{db: db}
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
