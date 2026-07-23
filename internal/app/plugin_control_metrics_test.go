package app

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dop251/goja"
)

func TestPluginMetricsGojaAPIValidatesAndAggregates(t *testing.T) {
	runtime := &gojaPluginControlRuntime{pluginMetrics: make(map[string]map[string]pluginMetricSeries)}
	plugin := LoadedPlugin{PluginManifest: PluginManifest{
		ID: "metric_plugin",
		Control: &PluginControl{
			Main:        "control.js",
			Permissions: []string{"metrics"},
		},
	}}
	host := &pluginControlHost{vm: goja.New(), runtime: runtime, plugin: plugin}
	if err := host.install(); err != nil {
		t.Fatal(err)
	}
	if _, err := host.vm.RunString(`
metrics.counter('requests_total', {direction: 'forward'});
metrics.counter('requests_total', 2, {direction: 'forward'});
metrics.gauge('session_up', 1, {wan: 'wan0'});
`); err != nil {
		t.Fatal(err)
	}
	metrics := runtime.pluginMetricSnapshot(plugin.ID)
	if len(metrics) != 2 {
		t.Fatalf("metrics = %+v, want two series", metrics)
	}
	if metrics[0].Name != "requests_total" || metrics[0].Type != pluginMetricTypeCounter || metrics[0].Value != 3 || metrics[0].Labels["direction"] != "forward" {
		t.Fatalf("counter = %+v", metrics[0])
	}
	if metrics[1].Name != "session_up" || metrics[1].Type != pluginMetricTypeGauge || metrics[1].Value != 1 || metrics[1].Labels["wan"] != "wan0" {
		t.Fatalf("gauge = %+v", metrics[1])
	}
	if _, err := host.vm.RunString(`metrics.gauge('requests_total', 1, {direction: 'forward'});`); err == nil || !strings.Contains(err.Error(), "already a counter") {
		t.Fatalf("type conflict error = %v", err)
	}
	if _, err := host.vm.RunString(`metrics.counter('bad name');`); err == nil || !strings.Contains(err.Error(), "must match") {
		t.Fatalf("invalid name error = %v", err)
	}
	if _, err := host.vm.RunString(`metrics.gauge('bad_label', 1, {key: 1});`); err == nil || !strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("invalid label error = %v", err)
	}
	if _, err := host.vm.RunString(`metrics.gauge('not_finite', Infinity);`); err == nil || !strings.Contains(err.Error(), "finite number") {
		t.Fatalf("non-finite metric error = %v", err)
	}
	if _, err := host.vm.RunString(`metrics.counter('requests_total', -1);`); err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Fatalf("negative counter error = %v", err)
	}
	if _, err := host.vm.RunString(`metrics.delete('requests_total', {direction: 'forward'});`); err != nil {
		t.Fatal(err)
	}
	if metrics := runtime.pluginMetricSnapshot(plugin.ID); len(metrics) != 1 || metrics[0].Name != "session_up" {
		t.Fatalf("metrics after delete = %+v", metrics)
	}
	if _, err := host.vm.RunString(`metrics.clear();`); err != nil {
		t.Fatal(err)
	}
	if metrics := runtime.pluginMetricSnapshot(plugin.ID); len(metrics) != 0 {
		t.Fatalf("metrics after clear = %+v", metrics)
	}
}

func TestPluginMetricsPermissionIsRequired(t *testing.T) {
	runtime := &gojaPluginControlRuntime{pluginMetrics: make(map[string]map[string]pluginMetricSeries)}
	plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "no_metrics", Control: &PluginControl{Main: "control.js"}}}
	host := &pluginControlHost{vm: goja.New(), runtime: runtime, plugin: plugin}
	if err := host.install(); err != nil {
		t.Fatal(err)
	}
	if _, err := host.vm.RunString(`metrics.counter('requests_total');`); err == nil || !strings.Contains(err.Error(), "permission metrics is required") {
		t.Fatalf("permission error = %v", err)
	}
}

func TestPluginMetricRuntimeEnforcesCardinalityLimits(t *testing.T) {
	runtime := &gojaPluginControlRuntime{pluginMetrics: make(map[string]map[string]pluginMetricSeries)}
	for i := 0; i < pluginMetricMaxNamesPerPlugin; i++ {
		name := fmt.Sprintf("metric_%d", i)
		if _, err := runtime.updatePluginMetric("names", name, pluginMetricTypeGauge, float64(i), nil, false); err != nil {
			t.Fatalf("add metric name %d: %v", i, err)
		}
	}
	if _, err := runtime.updatePluginMetric("names", "one_too_many", pluginMetricTypeGauge, 1, nil, false); err == nil || !strings.Contains(err.Error(), "name limit") {
		t.Fatalf("name limit error = %v", err)
	}

	for i := 0; i < pluginMetricMaxSeriesPerPlugin; i++ {
		labels := map[string]string{"id": fmt.Sprintf("%d", i)}
		if _, err := runtime.updatePluginMetric("series", "connections", pluginMetricTypeGauge, float64(i), labels, false); err != nil {
			t.Fatalf("add metric series %d: %v", i, err)
		}
	}
	if _, err := runtime.updatePluginMetric("series", "connections", pluginMetricTypeGauge, 1, map[string]string{"id": "overflow"}, false); err == nil || !strings.Contains(err.Error(), "series limit") {
		t.Fatalf("series limit error = %v", err)
	}
}

func TestPluginMetricsCrossIsolatedHostBoundary(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_metrics", `{
  "api_version":"v1",
  "id":"isolated_metrics",
  "name":"Isolated Metrics",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "control":{"main":"control.js","permissions":["metrics","worker"]}
}`)
	writePluginControlScript(t, dir, "isolated_metrics", `
exports.onReconcile = function () {
  metrics.counter('reconciles_total', 2, {source: 'isolated'});
  metrics.gauge('ready', 1);
  worker.call('metrics', 'onWork', {});
};
exports.onWork = function () {
  metrics.counter('worker_calls_total', {worker: 'metrics'});
  return {ok: true};
};
`)

	db := openTestDB(t)
	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer runtime.Close()
	snapshot := runtime.Reconcile(loadPluginCatalogWithState(cfg, db))
	state, ok := snapshot.stateFor("isolated_metrics")
	if !ok || state.Error != "" {
		t.Fatalf("isolated metric plugin state = %+v", state)
	}
	if len(state.Metrics) != 3 {
		t.Fatalf("isolated metric snapshot = %+v, want three metrics", state.Metrics)
	}
	if state.Metrics[0].Name != "ready" || state.Metrics[0].Value != 1 || state.Metrics[1].Name != "reconciles_total" || state.Metrics[1].Value != 2 || state.Metrics[2].Name != "worker_calls_total" || state.Metrics[2].Value != 1 {
		t.Fatalf("isolated metric snapshot = %+v", state.Metrics)
	}
}

func TestPluginMetricsSurviveHotReloadAndClearOnDisable(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "reload_metrics", `{
  "api_version":"v1",
  "id":"reload_metrics",
  "name":"Reload Metrics",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "control":{"main":"control.js","permissions":["metrics"]}
}`)
	writeMetricReloadControl := func(version int) {
		t.Helper()
		writePluginControlScript(t, dir, "reload_metrics", fmt.Sprintf(`
var version = %d;
exports.onReconcile = function () { metrics.counter('reconciles_total'); };
exports.onUpgradeSnapshot = function () { return {version: version}; };
exports.onUpgradeRestore = function () {};
`, version))
	}
	writeMetricReloadControl(1)

	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer runtime.Close()
	assertMetricValue := func(want float64) {
		t.Helper()
		metrics := runtime.pluginMetricSnapshot("reload_metrics")
		if len(metrics) != 1 || metrics[0].Name != "reconciles_total" || metrics[0].Value != want {
			t.Fatalf("metrics = %+v, want reconciles_total=%v", metrics, want)
		}
	}

	first := runtime.Reconcile(loadPluginCatalogWithState(cfg, db))
	if state, ok := first.stateFor("reload_metrics"); !ok || state.Error != "" {
		t.Fatalf("initial state = %+v", state)
	}
	assertMetricValue(1)

	writeMetricReloadControl(2)
	second := runtime.Reconcile(loadPluginCatalogWithState(cfg, db))
	if state, ok := second.stateFor("reload_metrics"); !ok || state.Error != "" {
		t.Fatalf("updated state = %+v", state)
	}
	assertMetricValue(2)

	writePluginControlScript(t, dir, "reload_metrics", `this is not valid javascript`)
	failed := runtime.Reconcile(loadPluginCatalogWithState(cfg, db))
	state, ok := failed.stateFor("reload_metrics")
	if !ok || !strings.Contains(state.Reason, "previous runtime preserved") {
		t.Fatalf("failed update state = %+v", state)
	}
	assertMetricValue(2)

	runtime.Reconcile(PluginCatalog{})
	if metrics := runtime.pluginMetricSnapshot("reload_metrics"); len(metrics) != 0 {
		t.Fatalf("disabled plugin metrics = %+v, want empty", metrics)
	}
}

func TestClearInactivePluginMetricsRemovesRevokedPermission(t *testing.T) {
	runtime := &gojaPluginControlRuntime{pluginMetrics: make(map[string]map[string]pluginMetricSeries)}
	if _, err := runtime.updatePluginMetric("active", "value", pluginMetricTypeGauge, 1, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.updatePluginMetric("revoked", "value", pluginMetricTypeGauge, 1, nil, false); err != nil {
		t.Fatal(err)
	}
	runtime.clearInactivePluginMetrics(map[string]LoadedPlugin{
		"active":  {PluginManifest: PluginManifest{ID: "active", Control: &PluginControl{Permissions: []string{"metrics"}}}},
		"revoked": {PluginManifest: PluginManifest{ID: "revoked", Control: &PluginControl{Permissions: nil}}},
	})
	if len(runtime.pluginMetricSnapshot("active")) != 1 {
		t.Fatal("active plugin metric was removed")
	}
	if len(runtime.pluginMetricSnapshot("revoked")) != 0 {
		t.Fatal("revoked plugin metric was retained")
	}
}
