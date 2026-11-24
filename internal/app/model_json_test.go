package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A timestamp that was never set must not reach the panel: it checks these
// fields for presence, and "0001-01-01T00:00:00Z" showed up as a warning
// such as "degraded since 08:05:43" on a healthy engine.
func TestRuntimeViewsLeaveUnsetTimestampsOut(t *testing.T) {
	views := map[string]any{
		"KernelEngineRuntimeView":           KernelEngineRuntimeView{Name: "tc"},
		"KernelRuntimeResponse":             KernelRuntimeResponse{Engines: []KernelEngineRuntimeView{{Name: "tc"}}},
		"ManagedNetworkRuntimeReloadStatus": ManagedNetworkRuntimeReloadStatus{},
	}
	for name, view := range views {
		data, err := json.Marshal(view)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(string(data), "0001-01-01") {
			t.Errorf("%s carries a zero timestamp: %s", name, data)
		}
	}

	since := time.Date(2026, 11, 24, 20, 23, 0, 0, time.UTC)
	data, err := json.Marshal(KernelEngineRuntimeView{Name: "tc", Degraded: true, DegradedSince: since})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"degraded_since":"2026-11-24T20:23:00Z"`) {
		t.Fatalf("a set timestamp is missing: %s", data)
	}
}
