package app

import (
	"bytes"
	"database/sql"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func handlePluginPrometheusMetrics(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var catalog PluginCatalog
	if pm != nil {
		catalog = pm.pluginCatalogWithConfig(cfg)
	} else {
		catalog = loadPluginCatalogWithControlRegistrationAndState(cfg, db)
	}
	payload := renderPluginPrometheusMetrics(catalog)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func renderPluginPrometheusMetrics(catalog PluginCatalog) []byte {
	var out bytes.Buffer
	pluginPrometheusHeader(&out, "veer_plugin_info", "Installed plugin identity and current catalog status.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_runtime_attached", "Whether the plugin currently has an attached runtime.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_attachment_count", "Current plugin dataplane attachment count.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_control_calls_total", "Plugin control handler calls.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_control_failures_total", "Plugin control handler failures.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_control_rejected_total", "Plugin control calls rejected by circuit protection.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_control_open_circuits", "Open plugin control circuits.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_logs_dropped_total", "Plugin log records dropped by bounded buffering.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_worker_pending_requests", "Pending plugin worker requests.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_worker_pending_bytes", "Pending plugin worker payload bytes.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_worker_rejected_total", "Plugin worker requests rejected by queue limits.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_event_delivered_total", "Plugin events delivered successfully.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_event_dropped_total", "Volatile plugin events dropped because queues were full.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_event_rejected_total", "Plugin events rejected by authorization or schema checks.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_event_errors_total", "Plugin event handler delivery errors.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_event_retried_total", "Durable plugin event retries scheduled.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_event_durable_pending", "Durable plugin event deliveries waiting for acknowledgement.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_event_dead_letters", "Durable plugin event deliveries requiring operator action.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_operations", "Durable plugin operations by current status.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_operations_resumable", "Durable plugin operations eligible for replay.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_operation_bytes", "Encrypted durable plugin operation storage bytes.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_ring_pending_bytes", "Plugin ring-buffer payload bytes waiting for workers.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_ring_dropped_records_total", "Plugin ring-buffer records dropped by bounded queues.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_ring_errors_total", "Plugin ring-buffer read and handler errors.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_host_processes", "Isolated plugin host process count.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_host_rss_bytes", "Observed RSS across isolated plugin host processes.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_host_restarts_total", "Isolated plugin host restarts.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_database_bytes", "Plugin resource records estimated SQLite bytes.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_estimated_map_bytes", "Estimated kernel map memory admitted for the plugin.", "gauge")
	pluginPrometheusHeader(&out, "veer_plugin_hook_packets_total", "Packets observed by a plugin dataplane hook.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_hook_bytes_total", "Bytes observed by a plugin dataplane hook.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_hook_dropped_packets_total", "Packets dropped by a plugin dataplane hook.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_hook_tail_call_misses_total", "Tail-call misses at a plugin dataplane hook.", "counter")
	pluginPrometheusHeader(&out, "veer_plugin_custom_metric", "Bounded metric series reported by plugin control code.", "gauge")

	plugins := append([]LoadedPlugin(nil), catalog.Plugins...)
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].ID < plugins[j].ID })
	for _, plugin := range plugins {
		base := map[string]string{"plugin_id": plugin.ID}
		pluginPrometheusSample(&out, "veer_plugin_info", map[string]string{
			"plugin_id": plugin.ID, "name": plugin.Name, "version": plugin.Version,
			"status": plugin.Status, "stability": plugin.Stability,
		}, 1)
		pluginPrometheusSample(&out, "veer_plugin_runtime_attached", base, boolPrometheusValue(plugin.Runtime.Attached))
		pluginPrometheusSample(&out, "veer_plugin_attachment_count", base, float64(plugin.Runtime.AttachmentCount))
		if usage := plugin.ResourceUsage; usage != nil {
			pluginPrometheusSample(&out, "veer_plugin_database_bytes", base, float64(usage.DatabaseBytes))
			pluginPrometheusSample(&out, "veer_plugin_estimated_map_bytes", base, float64(usage.EstimatedMapMemoryBytes))
		}
		if health := plugin.Runtime.ControlHealth; health != nil {
			pluginPrometheusSample(&out, "veer_plugin_control_calls_total", base, float64(health.Calls))
			pluginPrometheusSample(&out, "veer_plugin_control_failures_total", base, float64(health.Failures))
			pluginPrometheusSample(&out, "veer_plugin_control_rejected_total", base, float64(health.Rejected))
			pluginPrometheusSample(&out, "veer_plugin_control_open_circuits", base, float64(health.OpenCircuits))
			pluginPrometheusSample(&out, "veer_plugin_logs_dropped_total", base, float64(health.DroppedLogs))
		}
		if queue := plugin.Runtime.WorkerQueue; queue != nil {
			pluginPrometheusSample(&out, "veer_plugin_worker_pending_requests", base, float64(queue.PendingRequests))
			pluginPrometheusSample(&out, "veer_plugin_worker_pending_bytes", base, float64(queue.PendingBytes))
			pluginPrometheusSample(&out, "veer_plugin_worker_rejected_total", base, float64(queue.RejectedRequests))
		}
		if events := plugin.Runtime.EventBus; events != nil {
			pluginPrometheusSample(&out, "veer_plugin_event_delivered_total", base, float64(events.Delivered))
			pluginPrometheusSample(&out, "veer_plugin_event_dropped_total", base, float64(events.Dropped))
			pluginPrometheusSample(&out, "veer_plugin_event_rejected_total", base, float64(events.Rejected))
			pluginPrometheusSample(&out, "veer_plugin_event_errors_total", base, float64(events.Errors))
			pluginPrometheusSample(&out, "veer_plugin_event_retried_total", base, float64(events.Retried))
			pluginPrometheusSample(&out, "veer_plugin_event_durable_pending", base, float64(events.DurablePending))
			pluginPrometheusSample(&out, "veer_plugin_event_dead_letters", base, float64(events.DeadLetters))
		}
		if operations := plugin.Runtime.Operations; operations != nil {
			pluginPrometheusSample(&out, "veer_plugin_operations_resumable", base, float64(operations.Resumable))
			pluginPrometheusSample(&out, "veer_plugin_operation_bytes", base, float64(operations.Bytes))
			statuses := make([]string, 0, len(operations.ByStatus))
			for status := range operations.ByStatus {
				statuses = append(statuses, status)
			}
			sort.Strings(statuses)
			for _, status := range statuses {
				pluginPrometheusSample(&out, "veer_plugin_operations", map[string]string{"plugin_id": plugin.ID, "status": status}, float64(operations.ByStatus[status]))
			}
		}
		if ring := plugin.Runtime.RingBuffers; ring != nil {
			pluginPrometheusSample(&out, "veer_plugin_ring_pending_bytes", base, float64(ring.PendingBytes))
			pluginPrometheusSample(&out, "veer_plugin_ring_dropped_records_total", base, float64(ring.DroppedRecords+ring.ReadDroppedRecords))
			pluginPrometheusSample(&out, "veer_plugin_ring_errors_total", base, float64(ring.ReadErrors+ring.HandlerErrors))
		}
		if isolation := plugin.Runtime.Isolation; isolation != nil {
			pluginPrometheusSample(&out, "veer_plugin_host_processes", base, float64(isolation.ProcessCount))
			pluginPrometheusSample(&out, "veer_plugin_host_rss_bytes", base, float64(isolation.RSSBytes))
			pluginPrometheusSample(&out, "veer_plugin_host_restarts_total", base, float64(isolation.RestartCount))
		}
		for _, attachment := range plugin.Runtime.Attachments {
			if attachment.Metrics == nil {
				continue
			}
			labels := map[string]string{
				"plugin_id": plugin.ID, "hook_id": attachment.HookID, "engine": attachment.Engine,
				"interface": attachment.Interface, "attach": attachment.Attach, "stage": attachment.Stage,
			}
			pluginPrometheusSample(&out, "veer_plugin_hook_packets_total", labels, float64(attachment.Metrics.Total.Packets))
			pluginPrometheusSample(&out, "veer_plugin_hook_bytes_total", labels, float64(attachment.Metrics.Total.Bytes))
			pluginPrometheusSample(&out, "veer_plugin_hook_dropped_packets_total", labels, float64(attachment.Metrics.Total.DroppedPackets))
			pluginPrometheusSample(&out, "veer_plugin_hook_tail_call_misses_total", labels, float64(attachment.Metrics.Total.TailCallMisses))
		}
		metrics := append([]PluginMetricState(nil), plugin.Runtime.Metrics...)
		sort.Slice(metrics, func(i, j int) bool {
			if metrics[i].Name != metrics[j].Name {
				return metrics[i].Name < metrics[j].Name
			}
			return pluginPrometheusLabelKey(metrics[i].Labels) < pluginPrometheusLabelKey(metrics[j].Labels)
		})
		for _, metric := range metrics {
			if math.IsNaN(metric.Value) || math.IsInf(metric.Value, 0) {
				continue
			}
			labels := map[string]string{"plugin_id": plugin.ID, "metric": metric.Name, "metric_type": metric.Type}
			for key, value := range metric.Labels {
				labels["label_"+pluginPrometheusIdentifier(key)] = value
			}
			pluginPrometheusSample(&out, "veer_plugin_custom_metric", labels, metric.Value)
		}
	}
	return out.Bytes()
}

func pluginPrometheusHeader(out *bytes.Buffer, name, help, metricType string) {
	fmt.Fprintf(out, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func pluginPrometheusSample(out *bytes.Buffer, name string, labels map[string]string, value float64) {
	out.WriteString(name)
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for key := range labels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			fmt.Fprintf(out, `%s="%s"`, pluginPrometheusIdentifier(key), pluginPrometheusEscapeLabel(labels[key]))
		}
		out.WriteByte('}')
	}
	out.WriteByte(' ')
	out.WriteString(strconv.FormatFloat(value, 'g', -1, 64))
	out.WriteByte('\n')
}

func pluginPrometheusIdentifier(value string) string {
	var out strings.Builder
	for i, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_' || i > 0 && r >= '0' && r <= '9' {
			out.WriteRune(r)
		} else {
			out.WriteByte('_')
		}
	}
	if out.Len() == 0 {
		return "_"
	}
	return out.String()
}

func pluginPrometheusEscapeLabel(value string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(value)
}

func pluginPrometheusLabelKey(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, key := range keys {
		out.WriteString(key)
		out.WriteByte('=')
		out.WriteString(labels[key])
		out.WriteByte(0)
	}
	return out.String()
}

func boolPrometheusValue(value bool) float64 {
	if value {
		return 1
	}
	return 0
}
