package app

import (
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginDurableEventSchedulesNextRetryAndIdleRecovery(t *testing.T) {
	db := openTestDB(t)
	rt := &gojaPluginControlRuntime{db: db}
	sub := &pluginControlEventSubscriptionRuntime{pluginID: "scheduler", spec: PluginEventSubscription{ID: "events", Delivery: pluginEventDeliveryDurable},
		queue: make(chan pluginControlBusEvent, 2), stop: make(chan struct{}), wake: make(chan struct{}, 1), durableInFlight: make(map[string]struct{})}
	if delay := rt.enqueueDueDurablePluginEvents(sub); delay != pluginEventDurableRecoveryInterval {
		t.Fatalf("idle recovery = %s", delay)
	}
	next := time.Now().Add(3 * time.Second)
	item := store.PluginEventDelivery{DeliveryID: "11111111111111111111111111111111", PluginID: sub.pluginID, SubscriptionID: sub.spec.ID,
		Topic: "plugin.scheduler.pending", PublishedAt: time.Now().UTC().Format(time.RFC3339Nano), SourcePlugin: sub.pluginID,
		SchemaVersion: 1, PayloadJSON: `{}`, MaxAttempts: 3, NextAttemptUnixMS: next.UnixMilli()}
	if err := store.CreatePluginEventDeliveries(db, []store.PluginEventDelivery{item}, 10, 20); err != nil {
		t.Fatal(err)
	}
	if delay := rt.enqueueDueDurablePluginEvents(sub); delay < time.Second || delay > 3*time.Second {
		t.Fatalf("retry schedule = %s, want remaining time until stored retry", delay)
	}
	if len(sub.queue) != 0 {
		t.Fatal("future event delivered early")
	}
	if err := store.MarkPluginEventDeliveryFailure(db, item.PluginID, item.DeliveryID, 1, time.Now().Add(-time.Second).UnixMilli(), false, "retry"); err != nil {
		t.Fatal(err)
	}
	rt.enqueueDueDurablePluginEvents(sub)
	if len(sub.queue) != 1 {
		t.Fatal("due delivery was not queued")
	}
	// A partially drained batch must not query the database or enqueue duplicates.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	rt.enqueueDueDurablePluginEvents(sub)
	if len(sub.queue) != 1 || sub.lastError != "" {
		t.Fatalf("queued batch reread database: %q", sub.lastError)
	}
}
