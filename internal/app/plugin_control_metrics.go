package app

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
)

const (
	pluginMetricTypeCounter        = "counter"
	pluginMetricTypeGauge          = "gauge"
	pluginMetricMaxNamesPerPlugin  = 64
	pluginMetricMaxSeriesPerPlugin = 256
	pluginMetricMaxLabelsPerSeries = 8
	pluginMetricMaxLabelValueBytes = 128
)

var (
	pluginMetricNamePattern     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	pluginMetricLabelKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,31}$`)
)

type pluginMetricSeries struct {
	name      string
	typeName  string
	value     float64
	labels    map[string]string
	updatedAt time.Time
}

func (h *pluginControlHost) metricCounter(call goja.FunctionCall) goja.Value {
	h.requirePermission("metrics")
	if len(call.Arguments) == 0 || len(call.Arguments) > 3 {
		h.throwf("metrics.counter: expected name, optional delta, and optional labels")
	}
	name := h.metricNameArg(call.Arguments[0], "metrics.counter")
	delta := 1.0
	var labels map[string]string
	if len(call.Arguments) >= 2 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
		if pluginMetricValueIsLabels(call.Arguments[1]) {
			labels = h.metricLabelsArg(call.Arguments[1], "metrics.counter")
		} else {
			delta = h.metricNumberArg(call.Arguments[1], "metrics.counter")
		}
	}
	if len(call.Arguments) == 3 {
		if pluginMetricValueIsLabels(call.Arguments[1]) {
			h.throwf("metrics.counter: delta must be numeric when labels are the third argument")
		}
		labels = h.metricLabelsArg(call.Arguments[2], "metrics.counter")
	}
	if delta < 0 {
		h.throwf("metrics.counter: delta must not be negative")
	}
	value, err := h.metricRuntime().updatePluginMetric(h.plugin.ID, name, pluginMetricTypeCounter, delta, labels, true)
	if err != nil {
		h.throwf("metrics.counter: %v", err)
	}
	return h.vm.ToValue(value)
}

func (h *pluginControlHost) metricGauge(call goja.FunctionCall) goja.Value {
	h.requirePermission("metrics")
	if len(call.Arguments) < 2 || len(call.Arguments) > 3 {
		h.throwf("metrics.gauge: expected name, value, and optional labels")
	}
	name := h.metricNameArg(call.Arguments[0], "metrics.gauge")
	value := h.metricNumberArg(call.Arguments[1], "metrics.gauge")
	var labels map[string]string
	if len(call.Arguments) == 3 {
		labels = h.metricLabelsArg(call.Arguments[2], "metrics.gauge")
	}
	value, err := h.metricRuntime().updatePluginMetric(h.plugin.ID, name, pluginMetricTypeGauge, value, labels, false)
	if err != nil {
		h.throwf("metrics.gauge: %v", err)
	}
	return h.vm.ToValue(value)
}

func (h *pluginControlHost) metricDelete(call goja.FunctionCall) goja.Value {
	h.requirePermission("metrics")
	if len(call.Arguments) == 0 || len(call.Arguments) > 2 {
		h.throwf("metrics.delete: expected name and optional labels")
	}
	name := h.metricNameArg(call.Arguments[0], "metrics.delete")
	labelsProvided := len(call.Arguments) == 2 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1])
	var labels map[string]string
	if labelsProvided {
		labels = h.metricLabelsArg(call.Arguments[1], "metrics.delete")
	}
	return h.vm.ToValue(h.metricRuntime().deletePluginMetric(h.plugin.ID, name, labels, labelsProvided))
}

func (h *pluginControlHost) metricClear(call goja.FunctionCall) goja.Value {
	h.requirePermission("metrics")
	if len(call.Arguments) != 0 {
		h.throwf("metrics.clear: no arguments are accepted")
	}
	return h.vm.ToValue(h.metricRuntime().clearPluginMetrics(h.plugin.ID))
}

func (h *pluginControlHost) metricList(call goja.FunctionCall) goja.Value {
	h.requirePermission("metrics")
	if len(call.Arguments) != 0 {
		h.throwf("metrics.list: no arguments are accepted")
	}
	return h.vm.ToValue(h.metricRuntime().pluginMetricSnapshot(h.plugin.ID))
}

func (h *pluginControlHost) metricRuntime() *gojaPluginControlRuntime {
	if h.runtime == nil {
		h.throwf("plugin metrics runtime is unavailable")
	}
	return h.runtime
}

func (h *pluginControlHost) metricNameArg(value goja.Value, api string) string {
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		h.throwf("%s: metric name is required", api)
	}
	exported, ok := value.Export().(string)
	if !ok {
		h.throwf("%s: metric name must be a string", api)
	}
	name := strings.TrimSpace(exported)
	if !pluginMetricNamePattern.MatchString(name) {
		h.throwf("%s: metric name must match %s", api, pluginMetricNamePattern.String())
	}
	return name
}

func (h *pluginControlHost) metricNumberArg(value goja.Value, api string) float64 {
	number, ok := pluginMetricNumber(value)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
		h.throwf("%s: metric value must be a finite number", api)
	}
	return number
}

func pluginMetricNumber(value goja.Value) (float64, bool) {
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return 0, false
	}
	switch typed := value.Export().(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case json.Number:
		parsed, err := strconv.ParseFloat(string(typed), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func pluginMetricValueIsLabels(value goja.Value) bool {
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return false
	}
	_, ok := value.Export().(map[string]any)
	return ok
}

func (h *pluginControlHost) metricLabelsArg(value goja.Value, api string) map[string]string {
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return nil
	}
	obj := value.ToObject(h.vm)
	if obj.ClassName() != "Object" {
		h.throwf("%s: labels must be a plain object", api)
	}
	keys := obj.Keys()
	if len(keys) > pluginMetricMaxLabelsPerSeries {
		h.throwf("%s: labels exceed the limit of %d", api, pluginMetricMaxLabelsPerSeries)
	}
	labels := make(map[string]string, len(keys))
	for _, rawKey := range keys {
		key := strings.TrimSpace(rawKey)
		if key != rawKey || !pluginMetricLabelKeyPattern.MatchString(key) {
			h.throwf("%s: label name %q must match %s", api, rawKey, pluginMetricLabelKeyPattern.String())
		}
		rawValue := obj.Get(rawKey)
		label, ok := rawValue.Export().(string)
		if !ok {
			h.throwf("%s: label %q value must be a string", api, key)
		}
		if !utf8.ValidString(label) || len(label) > pluginMetricMaxLabelValueBytes {
			h.throwf("%s: label %q value must be valid UTF-8 and at most %d bytes", api, key, pluginMetricMaxLabelValueBytes)
		}
		labels[key] = label
	}
	return labels
}

func (rt *gojaPluginControlRuntime) updatePluginMetric(pluginID, name, typeName string, value float64, labels map[string]string, add bool) (float64, error) {
	if rt == nil {
		return 0, fmt.Errorf("runtime is unavailable")
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, fmt.Errorf("metric value must be finite")
	}
	key := pluginMetricSeriesKey(name, labels)
	rt.metricMu.Lock()
	defer rt.metricMu.Unlock()
	if rt.pluginMetrics == nil {
		rt.pluginMetrics = make(map[string]map[string]pluginMetricSeries)
	}
	series := rt.pluginMetrics[pluginID]
	if series == nil {
		series = make(map[string]pluginMetricSeries)
		rt.pluginMetrics[pluginID] = series
	}
	current, exists := series[key]
	if exists && current.typeName != typeName {
		return 0, fmt.Errorf("metric %s with these labels is already a %s", name, current.typeName)
	}
	if !exists {
		if len(series) >= pluginMetricMaxSeriesPerPlugin {
			return 0, fmt.Errorf("metric series limit reached: %d", pluginMetricMaxSeriesPerPlugin)
		}
		if !pluginMetricNameExists(series, name) && pluginMetricNameCount(series) >= pluginMetricMaxNamesPerPlugin {
			return 0, fmt.Errorf("metric name limit reached: %d", pluginMetricMaxNamesPerPlugin)
		}
		current = pluginMetricSeries{name: name, typeName: typeName, labels: clonePluginMetricLabels(labels)}
	}
	if add {
		value += current.value
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return 0, fmt.Errorf("metric value overflow")
		}
	}
	current.value = value
	current.updatedAt = time.Now().UTC()
	series[key] = current
	return value, nil
}

func (rt *gojaPluginControlRuntime) deletePluginMetric(pluginID, name string, labels map[string]string, labelsProvided bool) int {
	if rt == nil {
		return 0
	}
	rt.metricMu.Lock()
	defer rt.metricMu.Unlock()
	series := rt.pluginMetrics[pluginID]
	if labelsProvided {
		key := pluginMetricSeriesKey(name, labels)
		if _, ok := series[key]; ok {
			delete(series, key)
			if len(series) == 0 {
				delete(rt.pluginMetrics, pluginID)
			}
			return 1
		}
		return 0
	}
	deleted := 0
	for key, metric := range series {
		if metric.name == name {
			delete(series, key)
			deleted++
		}
	}
	if len(series) == 0 {
		delete(rt.pluginMetrics, pluginID)
	}
	return deleted
}

func (rt *gojaPluginControlRuntime) clearPluginMetrics(pluginID string) int {
	if rt == nil {
		return 0
	}
	rt.metricMu.Lock()
	defer rt.metricMu.Unlock()
	count := len(rt.pluginMetrics[pluginID])
	delete(rt.pluginMetrics, pluginID)
	return count
}

func (rt *gojaPluginControlRuntime) clearInactivePluginMetrics(active map[string]LoadedPlugin) {
	if rt == nil {
		return
	}
	rt.metricMu.Lock()
	defer rt.metricMu.Unlock()
	for pluginID := range rt.pluginMetrics {
		plugin, ok := active[pluginID]
		if !ok || !pluginControlHasPermission(plugin, "metrics") {
			delete(rt.pluginMetrics, pluginID)
		}
	}
}

func (rt *gojaPluginControlRuntime) clearAllPluginMetrics() {
	if rt == nil {
		return
	}
	rt.metricMu.Lock()
	rt.pluginMetrics = make(map[string]map[string]pluginMetricSeries)
	rt.metricMu.Unlock()
}

func (rt *gojaPluginControlRuntime) pluginMetricSnapshot(pluginID string) []PluginMetricState {
	if rt == nil {
		return nil
	}
	rt.metricMu.Lock()
	series := rt.pluginMetrics[pluginID]
	out := make([]PluginMetricState, 0, len(series))
	for _, metric := range series {
		state := PluginMetricState{
			Name:   metric.name,
			Type:   metric.typeName,
			Value:  metric.value,
			Labels: clonePluginMetricLabels(metric.labels),
		}
		if !metric.updatedAt.IsZero() {
			state.UpdatedAt = metric.updatedAt.UTC().Format(time.RFC3339Nano)
		}
		out = append(out, state)
	}
	rt.metricMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return pluginMetricSeriesKey(out[i].Name, out[i].Labels) < pluginMetricSeriesKey(out[j].Name, out[j].Labels)
	})
	return out
}

func pluginMetricSeriesKey(name string, labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	builder.WriteString(name)
	for _, key := range keys {
		value := labels[key]
		builder.WriteByte(0)
		builder.WriteString(strconv.Itoa(len(key)))
		builder.WriteByte(':')
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(strconv.Itoa(len(value)))
		builder.WriteByte(':')
		builder.WriteString(value)
	}
	return builder.String()
}

func pluginMetricNameExists(series map[string]pluginMetricSeries, name string) bool {
	for _, metric := range series {
		if metric.name == name {
			return true
		}
	}
	return false
}

func pluginMetricNameCount(series map[string]pluginMetricSeries) int {
	names := make(map[string]struct{}, len(series))
	for _, metric := range series {
		names[metric.name] = struct{}{}
	}
	return len(names)
}

func clonePluginMetricLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		out[key] = value
	}
	return out
}
