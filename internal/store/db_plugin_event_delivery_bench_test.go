package store

import (
	"path/filepath"
	"testing"
	"time"
)

func BenchmarkEmptyPluginEventDeliveryQuery(b *testing.B) {
	db, err := InitDB(filepath.Join(b.TempDir(), "events.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		items, err := GetDuePluginEventDeliveries(db, "idle_plugin", "events", time.Now().UnixMilli(), 128)
		if err != nil || len(items) != 0 {
			b.Fatalf("empty query = %d items, %v", len(items), err)
		}
	}
}
