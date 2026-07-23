package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPluginEventDeliveryQuotaIncludesDeadLetters(t *testing.T) {
	db, err := InitDB(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	makeDelivery := func(id, pluginID string) PluginEventDelivery {
		return PluginEventDelivery{
			DeliveryID: id, PluginID: pluginID, SubscriptionID: "critical", Topic: "plugin.source.changed",
			Sequence: 1, PublishedAt: time.Now().UTC().Format(time.RFC3339Nano), SourcePlugin: "source",
			TargetPlugin: pluginID, SchemaVersion: 1, PayloadJSON: `{}`, MaxAttempts: 2,
			NextAttemptUnixMS: time.Now().UnixMilli(),
		}
	}
	a1 := makeDelivery("00000000000000000000000000000001", "sink_a")
	a2 := makeDelivery("00000000000000000000000000000002", "sink_a")
	if err := CreatePluginEventDeliveries(db, []PluginEventDelivery{a1, a2}, 2, 3); err != nil {
		t.Fatal(err)
	}
	if err := CreatePluginEventDeliveries(db, []PluginEventDelivery{makeDelivery("00000000000000000000000000000003", "sink_a")}, 2, 3); err == nil || !strings.Contains(err.Error(), "record limit 2") {
		t.Fatalf("per-plugin quota error = %v", err)
	}
	b1 := makeDelivery("00000000000000000000000000000004", "sink_b")
	if err := CreatePluginEventDeliveries(db, []PluginEventDelivery{b1}, 2, 3); err != nil {
		t.Fatal(err)
	}
	if err := MarkPluginEventDeliveryFailure(db, "sink_a", a1.DeliveryID, 2, time.Now().UnixMilli(), true, "failed"); err != nil {
		t.Fatal(err)
	}
	if err := CreatePluginEventDeliveries(db, []PluginEventDelivery{makeDelivery("00000000000000000000000000000005", "sink_b")}, 2, 3); err == nil || !strings.Contains(err.Error(), "record limit 3") {
		t.Fatalf("global quota with dead letter error = %v", err)
	}
	if deleted, err := DeletePluginEventDelivery(db, "sink_a", a1.DeliveryID); err != nil || !deleted {
		t.Fatalf("delete dead letter = %v, %v", deleted, err)
	}
	if err := CreatePluginEventDeliveries(db, []PluginEventDelivery{makeDelivery("00000000000000000000000000000006", "sink_b")}, 2, 3); err != nil {
		t.Fatalf("create after dead letter deletion: %v", err)
	}
}

func TestDeletePluginDataRemovesSourcedAndTargetedEventDeliveries(t *testing.T) {
	db, err := InitDB(filepath.Join(t.TempDir(), "purge.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now()
	items := []PluginEventDelivery{
		{
			DeliveryID: "10000000000000000000000000000001", PluginID: "target", SubscriptionID: "events",
			Topic: "plugin.source.changed", PublishedAt: now.UTC().Format(time.RFC3339Nano), SourcePlugin: "source",
			TargetPlugin: "target", SchemaVersion: 1, PayloadJSON: `{}`, MaxAttempts: 2, NextAttemptUnixMS: now.UnixMilli(),
		},
		{
			DeliveryID: "10000000000000000000000000000002", PluginID: "source", SubscriptionID: "events",
			Topic: "plugin.source.changed", PublishedAt: now.UTC().Format(time.RFC3339Nano), SourcePlugin: "source",
			TargetPlugin: "source", SchemaVersion: 1, PayloadJSON: `{}`, MaxAttempts: 2, NextAttemptUnixMS: now.UnixMilli(),
		},
	}
	if err := CreatePluginEventDeliveries(db, items, 10, 20); err != nil {
		t.Fatal(err)
	}
	if err := DeletePluginData(db, "source"); err != nil {
		t.Fatal(err)
	}
	for _, pluginID := range []string{"source", "target"} {
		count, err := CountPluginEventDeliveries(db, pluginID, "", PluginEventDeliveryPending)
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("pending deliveries for %s = %d, want 0", pluginID, count)
		}
	}
}

func TestListAndDeleteDeadPluginEventDeliveries(t *testing.T) {
	db, err := InitDB(filepath.Join(t.TempDir(), "dead.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now()
	items := []PluginEventDelivery{
		{DeliveryID: "20000000000000000000000000000001", PluginID: "sink_a", SubscriptionID: "critical", Topic: "plugin.source.changed", PublishedAt: now.UTC().Format(time.RFC3339Nano), SourcePlugin: "source", TargetPlugin: "sink_a", SchemaVersion: 1, PayloadJSON: `{}`, MaxAttempts: 2, NextAttemptUnixMS: now.UnixMilli()},
		{DeliveryID: "20000000000000000000000000000002", PluginID: "sink_b", SubscriptionID: "critical", Topic: "plugin.source.changed", PublishedAt: now.UTC().Format(time.RFC3339Nano), SourcePlugin: "source", TargetPlugin: "sink_b", SchemaVersion: 1, PayloadJSON: `{}`, MaxAttempts: 2, NextAttemptUnixMS: now.UnixMilli()},
		{DeliveryID: "20000000000000000000000000000003", PluginID: "sink_a", SubscriptionID: "critical", Topic: "plugin.source.changed", PublishedAt: now.UTC().Format(time.RFC3339Nano), SourcePlugin: "source", TargetPlugin: "sink_a", SchemaVersion: 1, PayloadJSON: `{}`, MaxAttempts: 2, NextAttemptUnixMS: now.UnixMilli()},
	}
	if err := CreatePluginEventDeliveries(db, items, 10, 20); err != nil {
		t.Fatal(err)
	}
	for _, item := range items[:2] {
		if err := MarkPluginEventDeliveryFailure(db, item.PluginID, item.DeliveryID, 2, now.UnixMilli(), true, "handler failed"); err != nil {
			t.Fatal(err)
		}
	}
	all, err := ListDeadPluginEventDeliveries(db, "", 0, 10)
	if err != nil || len(all) != 2 || all[0].ID <= all[1].ID {
		t.Fatalf("ListDeadPluginEventDeliveries(all) = %+v/%v", all, err)
	}
	filtered, err := ListDeadPluginEventDeliveries(db, "sink_a", 0, 10)
	if err != nil || len(filtered) != 1 || filtered[0].PluginID != "sink_a" {
		t.Fatalf("ListDeadPluginEventDeliveries(filtered) = %+v/%v", filtered, err)
	}
	older, err := ListDeadPluginEventDeliveries(db, "", all[0].ID, 10)
	if err != nil || len(older) != 1 || older[0].ID != all[1].ID {
		t.Fatalf("ListDeadPluginEventDeliveries(cursor) = %+v/%v", older, err)
	}
	if deleted, err := DeleteDeadPluginEventDelivery(db, "sink_a", items[2].DeliveryID); err != nil || deleted {
		t.Fatalf("DeleteDeadPluginEventDelivery(pending) = %t/%v", deleted, err)
	}
	if deleted, err := DeleteDeadPluginEventDelivery(db, "sink_a", items[0].DeliveryID); err != nil || !deleted {
		t.Fatalf("DeleteDeadPluginEventDelivery(dead) = %t/%v", deleted, err)
	}
}
