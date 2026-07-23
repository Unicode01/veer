package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPluginPrometheusMetricsRequiresAuth(t *testing.T) {
	cfg := &Config{WebToken: "metrics-token"}
	handler := buildAPIHandler(cfg, openTestDB(t), nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated metrics status = %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.WebToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("metrics POST status = %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.WebToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics GET status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Fatalf("metrics content type = %q", got)
	}
	if !strings.Contains(rec.Body.String(), `veer_plugin_info{`) {
		t.Fatalf("metrics response does not contain plugin info: %s", rec.Body.String())
	}
}

func TestRenderPluginPrometheusMetricsExportsBoundedRuntimeState(t *testing.T) {
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{
		PluginManifest: PluginManifest{ID: "metrics_plugin", Name: "Metrics Plugin", Version: "1.2.3", Stability: pluginStabilityStable},
		Status:         pluginStatusActive,
		Runtime: PluginRuntimeState{
			Attached: true, AttachmentCount: 1,
			ControlHealth: &PluginControlHealthState{Calls: 9, Failures: 2, Rejected: 1, OpenCircuits: 1, DroppedLogs: 3, LastError: "must-not-export"},
			WorkerQueue:   &PluginControlWorkerQueueState{PendingRequests: 2, PendingBytes: 128, RejectedRequests: 4},
			EventBus:      &PluginEventBusState{Delivered: 7, Dropped: 1, Rejected: 2, Errors: 3, Retried: 4, DurablePending: 5, DeadLetters: 6},
			Operations:    &PluginOperationRuntimeState{Total: 4, Resumable: 2, Bytes: 8192, ByStatus: map[string]int{"completed": 1, "running": 3}},
			RingBuffers:   &PluginRingBusState{PendingBytes: 256, DroppedRecords: 8, ReadDroppedRecords: 9, ReadErrors: 1, HandlerErrors: 2},
			Isolation:     &PluginControlIsolationState{ProcessCount: 2, RSSBytes: 4096, RestartCount: 3, LastError: "private-host-error"},
			Attachments: []PluginAttachmentState{{
				HookID: "guard", Engine: "tc", Interface: "eth0", Attach: "ingress", Stage: "pre_forward",
				Metrics: &PluginAttachmentMetrics{Total: PluginPacketMetrics{Packets: 100, Bytes: 6400, DroppedPackets: 3, TailCallMisses: 1}},
			}},
			Metrics: []PluginMetricState{{
				Name: "session.count", Type: "gauge", Value: 12.5,
				Labels: map[string]string{"zone": "a\"b\nc"},
			}},
		},
		ResourceUsage: &PluginResourceUsage{DatabaseBytes: 1024, EstimatedMapMemoryBytes: 2048},
	}}}

	output := string(renderPluginPrometheusMetrics(catalog))
	for _, want := range []string{
		`veer_plugin_runtime_attached{plugin_id="metrics_plugin"} 1`,
		`veer_plugin_control_failures_total{plugin_id="metrics_plugin"} 2`,
		`veer_plugin_event_durable_pending{plugin_id="metrics_plugin"} 5`,
		`veer_plugin_event_dead_letters{plugin_id="metrics_plugin"} 6`,
		`veer_plugin_operations_resumable{plugin_id="metrics_plugin"} 2`,
		`veer_plugin_operation_bytes{plugin_id="metrics_plugin"} 8192`,
		`veer_plugin_operations{plugin_id="metrics_plugin",status="running"} 3`,
		`veer_plugin_ring_dropped_records_total{plugin_id="metrics_plugin"} 17`,
		`veer_plugin_hook_packets_total{attach="ingress",engine="tc",hook_id="guard",interface="eth0",plugin_id="metrics_plugin",stage="pre_forward"} 100`,
		`veer_plugin_custom_metric{label_zone="a\"b\nc",metric="session.count",metric_type="gauge",plugin_id="metrics_plugin"} 12.5`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("metrics output is missing %q:\n%s", want, output)
		}
	}
	for _, secret := range []string{"must-not-export", "private-host-error"} {
		if strings.Contains(output, secret) {
			t.Fatalf("metrics output leaked runtime error %q", secret)
		}
	}
}
