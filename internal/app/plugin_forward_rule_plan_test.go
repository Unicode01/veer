package app

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginForwardRulePlanCompilesActivePluginRecord(t *testing.T) {
	pluginsDir := t.TempDir()
	writeForwardRulePlanPluginForTest(t, pluginsDir, "forward_orchestrator")
	db := openTestDB(t)
	insertPluginForwardRulePlanForTest(t, db, "forward_orchestrator", "web", `{
	  "enabled": true,
	  "in_ip": "0.0.0.0",
	  "in_port": 18080,
	  "out_ip": "198.51.100.10",
	  "out_port": 80,
	  "protocol": "tcp+udp",
	  "remark": "generated-web",
	  "tag": "plugin",
	  "engine_preference": "kernel"
	}`, true)

	nextID := int64(1)
	rules, warnings, err := loadPluginForwardRules(db, pluginsEnabledTestConfig(&Config{PluginsDir: pluginsDir}), nil, nil, nil, &nextID)
	if err != nil {
		t.Fatalf("loadPluginForwardRules() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %+v, want one plugin forward rule", rules)
	}
	rule := rules[0]
	if rule.ID <= 0 {
		t.Fatalf("rule ID = %d, want positive synthetic ID for kernel dataplane", rule.ID)
	}
	if rule.InIP != "0.0.0.0" || rule.InPort != 18080 || rule.OutIP != "198.51.100.10" || rule.OutPort != 80 || rule.Protocol != "tcp+udp" || rule.EnginePreference != ruleEngineKernel || !rule.Enabled {
		t.Fatalf("rule = %+v, want normalized plugin plan", rule)
	}
}

func TestPluginForwardRulePlanRequiresActivePluginAndNoConflict(t *testing.T) {
	pluginsDir := t.TempDir()
	writeForwardRulePlanPluginForTest(t, pluginsDir, "forward_orchestrator")
	db := openTestDB(t)
	insertPluginForwardRulePlanForTest(t, db, "forward_orchestrator", "web", `{
	  "enabled": true,
	  "in_ip": "0.0.0.0",
	  "in_port": 18080,
	  "out_ip": "198.51.100.10",
	  "out_port": 80,
	  "protocol": "tcp"
	}`, true)

	disabled := false
	nextID := int64(1)
	rules, warnings, err := loadPluginForwardRules(db, pluginsEnabledTestConfig(&Config{PluginsDir: pluginsDir, PluginsEnabledSetting: &disabled}), nil, nil, nil, &nextID)
	if err != nil {
		t.Fatalf("loadPluginForwardRules(disabled plugins) error = %v", err)
	}
	if len(rules) != 0 || len(warnings) != 0 {
		t.Fatalf("disabled plugin rules=%+v warnings=%+v, want none", rules, warnings)
	}

	enabled := true
	if err := store.SetPluginEnabled(db, "forward_orchestrator", false); err != nil {
		t.Fatalf("SetPluginEnabled(false) error = %v", err)
	}
	nextID = 1
	rules, warnings, err = loadPluginForwardRules(db, pluginsEnabledTestConfig(&Config{PluginsDir: pluginsDir, PluginsEnabledSetting: &enabled}), nil, nil, nil, &nextID)
	if err != nil {
		t.Fatalf("loadPluginForwardRules(disabled plugin state) error = %v", err)
	}
	if len(rules) != 0 || len(warnings) != 0 {
		t.Fatalf("plugin-state disabled rules=%+v warnings=%+v, want none", rules, warnings)
	}
	if err := store.SetPluginEnabled(db, "forward_orchestrator", true); err != nil {
		t.Fatalf("SetPluginEnabled(true) error = %v", err)
	}

	explicit := Rule{
		ID:       7,
		InIP:     "0.0.0.0",
		InPort:   18080,
		OutIP:    "203.0.113.7",
		OutPort:  8080,
		Protocol: "tcp",
		Enabled:  true,
	}
	nextID = 8
	rules, warnings, err = loadPluginForwardRules(db, pluginsEnabledTestConfig(&Config{PluginsDir: pluginsDir}), []Rule{explicit}, nil, nil, &nextID)
	if err != nil {
		t.Fatalf("loadPluginForwardRules(conflict) error = %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("conflicting plugin rules = %+v, want none", rules)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "listener conflicts") {
		t.Fatalf("warnings = %+v, want listener conflict warning", warnings)
	}
}

func TestPluginForwardRulePlanRedistributesToKernelRuntime(t *testing.T) {
	pluginsDir := t.TempDir()
	writeForwardRulePlanPluginForTest(t, pluginsDir, "forward_orchestrator")
	rootDir := filepath.Join(pluginsDir, "forward_orchestrator")
	plugin, err := loadPluginFromDir(rootDir, "forward_orchestrator")
	if err != nil {
		t.Fatalf("load forward_orchestrator plugin: %v", err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	resource := pluginResourceByIDForTest(t, plugin, pluginForwardRulePlansResourceID)

	db := openTestDB(t)
	insertPluginForwardRulePlanForTest(t, db, "forward_orchestrator", "web", `{
	  "enabled": true,
	  "in_ip": "0.0.0.0",
	  "in_port": 18080,
	  "out_ip": "198.51.100.10",
	  "out_port": 80,
	  "protocol": "tcp",
	  "engine_preference": "kernel"
	}`, true)

	kernelRuntime := &pluginRuntimeApplyTestRuntime{kernelSupported: true}
	pm := newPluginForwardRulePlanProcessManagerForTest(db, pluginsEnabledTestConfig(&Config{
		PluginsDir:    pluginsDir,
		DefaultEngine: ruleEngineKernel}),

		kernelRuntime)

	if err := applyPluginResourceRuntimeUpdate(db, pm, plugin, resource); err != nil {
		t.Fatalf("applyPluginResourceRuntimeUpdate(forward_rule_plans) error = %v", err)
	}
	if len(kernelRuntime.lastRules) != 1 {
		t.Fatalf("kernel runtime rules = %+v, want one plugin forward rule", kernelRuntime.lastRules)
	}
	rule := kernelRuntime.lastRules[0]
	if rule.ID <= 0 || rule.InPort != 18080 || rule.OutIP != "198.51.100.10" || rule.Protocol != "tcp" {
		t.Fatalf("kernel runtime rule = %+v, want synthetic forward rule", rule)
	}
	pm.mu.Lock()
	rulePlans := cloneRuleDataplanePlans(pm.rulePlans)
	kernelRules := cloneKernelOwnerMap(pm.kernelRules)
	pm.mu.Unlock()
	if len(rulePlans) != 1 || len(kernelRules) != 1 {
		t.Fatalf("pm kernel state plans=%+v kernelRules=%+v, want one active synthetic rule", rulePlans, kernelRules)
	}
	if !kernelRules[rule.ID] {
		t.Fatalf("kernelRules = %+v, missing synthetic rule ID %d", kernelRules, rule.ID)
	}
}

func TestPluginForwardRulePlanAppearsInEffectiveRuleAPIs(t *testing.T) {
	pluginsDir := t.TempDir()
	writeForwardRulePlanPluginForTest(t, pluginsDir, "forward_orchestrator")
	db := openTestDB(t)
	insertPluginForwardRulePlanForTest(t, db, "forward_orchestrator", "web", `{
	  "enabled": true,
	  "in_ip": "0.0.0.0",
	  "in_port": 18080,
	  "out_ip": "198.51.100.10",
	  "out_port": 80,
	  "protocol": "udp",
	  "remark": "generated-web",
	  "tag": "plugin",
	  "engine_preference": "kernel"
	}`, true)

	cfg := pluginsEnabledTestConfig(&Config{
		PluginsDir:    pluginsDir,
		DefaultEngine: ruleEngineKernel})

	kernelRuntime := &pluginRuntimeApplyTestRuntime{kernelSupported: true}
	pm := newPluginForwardRulePlanProcessManagerForTest(db, cfg, kernelRuntime)
	pm.redistributeWorkers()
	if len(kernelRuntime.lastRules) != 1 {
		t.Fatalf("kernel runtime rules = %+v, want one plugin forward rule", kernelRuntime.lastRules)
	}
	ruleID := kernelRuntime.lastRules[0].ID

	req := httptest.NewRequest(http.MethodGet, "/api/rules?tag=plugin", nil)
	rec := httptest.NewRecorder()
	handleListRules(rec, req, db, pm)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleListRules status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var rules []RuleStatus
	if err := json.NewDecoder(rec.Body).Decode(&rules); err != nil {
		t.Fatalf("decode rules response: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules response = %+v, want one generated rule", rules)
	}
	if rules[0].ID != ruleID || rules[0].Remark != "generated-web" || rules[0].Tag != "plugin" || rules[0].Protocol != "udp" || rules[0].Status != "running" {
		t.Fatalf("rules response[0] = %+v, want visible generated rule %d", rules[0], ruleID)
	}

	meta, err := loadEffectiveRuleMetaByIDs(db, []int64{ruleID}, cfg)
	if err != nil {
		t.Fatalf("loadEffectiveRuleMetaByIDs() error = %v", err)
	}
	if meta[ruleID].Remark != "generated-web" {
		t.Fatalf("effective rule meta = %+v, want generated-web", meta[ruleID])
	}
	protocols, err := loadEffectiveRuleProtocolByIDs(db, []int64{ruleID}, cfg)
	if err != nil {
		t.Fatalf("loadEffectiveRuleProtocolByIDs() error = %v", err)
	}
	if protocols[ruleID] != "udp" {
		t.Fatalf("effective rule protocol[%d] = %q, want udp", ruleID, protocols[ruleID])
	}

	pm.mu.Lock()
	pm.kernelRuntime = nil
	pm.kernelRuleStats = map[int64]RuleStatsReport{
		ruleID: {RuleID: ruleID, ActiveConns: 3, TotalConns: 7},
	}
	pm.mu.Unlock()
	req = httptest.NewRequest(http.MethodGet, "/api/rules/stats?sort_key=remark", nil)
	rec = httptest.NewRecorder()
	handleListRuleStats(rec, req, db, pm)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleListRuleStats status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var stats RuleStatsListResponse
	if err := json.NewDecoder(rec.Body).Decode(&stats); err != nil {
		t.Fatalf("decode rule stats response: %v", err)
	}
	if len(stats.Items) != 1 || stats.Items[0].RuleID != ruleID || stats.Items[0].Remark != "generated-web" {
		t.Fatalf("rule stats response = %+v, want generated rule metadata", stats.Items)
	}
}

func writeForwardRulePlanPluginForTest(t *testing.T, pluginsDir, id string) {
	t.Helper()
	writeTestPlugin(t, pluginsDir, id, `{
  "api_version": "v1",
  "id": "`+id+`",
  "name": "Rule Orchestrator",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "forward_rule_plans",
    "methods": ["list", "get", "create", "update", "delete"],
    "runtime_update": "manual"
  }]
}`)
}

func insertPluginForwardRulePlanForTest(t *testing.T, db *sql.DB, pluginID, key, dataJSON string, enabled bool) {
	t.Helper()
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   pluginID,
		ResourceID: pluginForwardRulePlansResourceID,
		RecordKey:  key,
		DataJSON:   dataJSON,
		Enabled:    enabled,
	}); err != nil {
		t.Fatalf("AddPluginRecord(%s/%s) error = %v", pluginID, key, err)
	}
}

func newPluginForwardRulePlanProcessManagerForTest(db *sql.DB, cfg *Config, kernelRuntime *pluginRuntimeApplyTestRuntime) *ProcessManager {
	return &ProcessManager{
		ruleWorkers:                          make(map[int]*WorkerInfo),
		rangeWorkers:                         make(map[int]*WorkerInfo),
		db:                                   db,
		cfg:                                  cfg,
		rulePlans:                            make(map[int64]ruleDataplanePlan),
		rangePlans:                           make(map[int64]rangeDataplanePlan),
		egressNATPlans:                       make(map[int64]ruleDataplanePlan),
		dynamicEgressNATParents:              make(map[string]struct{}),
		managedNetworkInterfaces:             make(map[string]struct{}),
		ipv6AssignmentInterfaces:             make(map[string]struct{}),
		kernelRuntime:                        kernelRuntime,
		kernelRules:                          make(map[int64]bool),
		kernelRanges:                         make(map[int64]bool),
		kernelEgressNATs:                     make(map[int64]bool),
		kernelRuleEngines:                    make(map[int64]string),
		kernelRangeEngines:                   make(map[int64]string),
		kernelEgressNATEngines:               make(map[int64]string),
		kernelFlowOwners:                     make(map[uint32]kernelCandidateOwner),
		kernelRuleStats:                      make(map[int64]RuleStatsReport),
		kernelRangeStats:                     make(map[int64]RangeStatsReport),
		kernelEgressNATStats:                 make(map[int64]EgressNATStatsReport),
		kernelStatsSnapshot:                  emptyKernelRuleStatsSnapshot(),
		kernelNetlinkOwnerRetryCooldownUntil: make(map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState),
		kernelNetlinkOwnerRetryFailures:      make(map[kernelCandidateOwner]int),
	}
}
