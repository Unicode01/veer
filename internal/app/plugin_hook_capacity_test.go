package app

import (
	"fmt"
	"strings"
	"testing"
)

var testTCHookCapacityLimits = pluginHookCapacityLimits{Engine: "tc", StageCapacity: 32, InterfaceStage: 8, InterfaceGroup: 14}

func capacityTestPlugin(id string, running bool, hooks ...pluginHookCapacityHook) pluginHookCapacityPlugin {
	return pluginHookCapacityPlugin{ID: id, Running: running, Hooks: hooks}
}

func capacityTestHook(stage, group string, interfaces ...string) pluginHookCapacityHook {
	return pluginHookCapacityHook{HookID: stage, Stage: stage, Group: group, Attaches: []string{"ingress"}, Interfaces: interfaces}
}

func TestAdmitPluginHooksByCapacityCountsPerInterface(t *testing.T) {
	plugins := make([]pluginHookCapacityPlugin, 0, 12)
	for i := 0; i < 12; i++ {
		plugins = append(plugins, capacityTestPlugin(fmt.Sprintf("p%02d", i), false, capacityTestHook("pre_forward", "forward", fmt.Sprintf("eth%d", i))))
	}
	if rejected := admitPluginHooksByCapacity(plugins, testTCHookCapacityLimits); len(rejected) != 0 {
		t.Fatalf("hooks on separate interfaces were rejected: %v", rejected)
	}
}

func TestAdmitPluginHooksByCapacityRejectsOnlyThePluginThatDoesNotFit(t *testing.T) {
	plugins := make([]pluginHookCapacityPlugin, 0, 9)
	for i := 0; i < 9; i++ {
		plugins = append(plugins, capacityTestPlugin(fmt.Sprintf("p%02d", i), false, capacityTestHook("pre_forward", "forward")))
	}
	rejected := admitPluginHooksByCapacity(plugins, testTCHookCapacityLimits)
	if len(rejected) != 1 || rejected["p08"] == "" {
		t.Fatalf("rejected = %v, want only the ninth hook on every interface", rejected)
	}
	if !strings.Contains(rejected["p08"], "limit 8 per interface") || !strings.Contains(rejected["p08"], "other plugins keep running") {
		t.Fatalf("rejection message = %q", rejected["p08"])
	}
}

func TestAdmitPluginHooksByCapacityKeepsRunningPlugins(t *testing.T) {
	plugins := []pluginHookCapacityPlugin{capacityTestPlugin("newcomer", false, capacityTestHook("pre_forward", "forward", "eth0"))}
	for i := 0; i < 8; i++ {
		plugins = append(plugins, capacityTestPlugin(fmt.Sprintf("running%d", i), true, capacityTestHook("pre_forward", "forward", "eth0")))
	}
	rejected := admitPluginHooksByCapacity(plugins, testTCHookCapacityLimits)
	if len(rejected) != 1 || rejected["newcomer"] == "" {
		t.Fatalf("rejected = %v, want the plugin that is not running yet", rejected)
	}
}

func TestAdmitPluginHooksByCapacityAddsWildcardHooksToEveryInterface(t *testing.T) {
	plugins := make([]pluginHookCapacityPlugin, 0, 10)
	for i := 0; i < 7; i++ {
		plugins = append(plugins, capacityTestPlugin(fmt.Sprintf("global%d", i), false, capacityTestHook("pre_forward", "forward")))
	}
	plugins = append(plugins,
		capacityTestPlugin("eth0-a", false, capacityTestHook("pre_forward", "forward", "eth0")),
		capacityTestPlugin("eth0-b", false, capacityTestHook("pre_forward", "forward", "eth0")),
		capacityTestPlugin("eth1-a", false, capacityTestHook("pre_forward", "forward", "eth1")),
	)
	rejected := admitPluginHooksByCapacity(plugins, testTCHookCapacityLimits)
	if len(rejected) != 1 || !strings.Contains(rejected["eth0-b"], `interface "eth0"`) {
		t.Fatalf("rejected = %v, want only the second eth0 hook", rejected)
	}
}

func TestAdmitPluginHooksByCapacityBoundsHooksPerDirection(t *testing.T) {
	stages := []string{"pre_forward", "post_lookup", "post_apply"}
	plugins := make([]pluginHookCapacityPlugin, 0, 15)
	for i := 0; i < 15; i++ {
		plugins = append(plugins, capacityTestPlugin(fmt.Sprintf("p%02d", i), false, capacityTestHook(stages[i%3], "forward", "eth0")))
	}
	rejected := admitPluginHooksByCapacity(plugins, testTCHookCapacityLimits)
	if len(rejected) != 1 || !strings.Contains(rejected["p14"], "15 forward hooks") {
		t.Fatalf("rejected = %v, want the fifteenth forward hook on eth0", rejected)
	}
	reply := capacityTestPlugin("reply", false, capacityTestHook("pre_reply", "reply", "eth0"))
	if rejected := admitPluginHooksByCapacity(append(plugins[:14], reply), testTCHookCapacityLimits); len(rejected) != 0 {
		t.Fatalf("reply hooks share the forward budget: %v", rejected)
	}
}

func TestAdmitPluginHooksByCapacityEnforcesHostStageCapacity(t *testing.T) {
	plugins := make([]pluginHookCapacityPlugin, 0, 33)
	for i := 0; i < 33; i++ {
		plugins = append(plugins, capacityTestPlugin(fmt.Sprintf("p%02d", i), false, capacityTestHook("pre_forward", "forward", fmt.Sprintf("eth%d", i))))
	}
	rejected := admitPluginHooksByCapacity(plugins, testTCHookCapacityLimits)
	if len(rejected) != 1 || !strings.Contains(rejected["p32"], "capacity 32") {
		t.Fatalf("rejected = %v, want the thirty-third hook to hit the host capacity", rejected)
	}
}

func TestAdmitPluginHooksByCapacityAdmitsOrRejectsWholePlugins(t *testing.T) {
	plugins := make([]pluginHookCapacityPlugin, 0, 8)
	for i := 0; i < 7; i++ {
		plugins = append(plugins, capacityTestPlugin(fmt.Sprintf("p%02d", i), false, capacityTestHook("pre_forward", "forward", "eth0")))
	}
	plugins = append(plugins, capacityTestPlugin("pair", false,
		capacityTestHook("pre_forward", "forward", "eth0"),
		capacityTestHook("pre_forward", "forward", "eth0"),
	))
	rejected := admitPluginHooksByCapacity(plugins, testTCHookCapacityLimits)
	if len(rejected) != 1 || rejected["pair"] == "" {
		t.Fatalf("rejected = %v, want the two-hook plugin rejected as a whole", rejected)
	}
}

func TestAdmitPluginHooksByCapacityCountsEachAttachSeparately(t *testing.T) {
	plugins := make([]pluginHookCapacityPlugin, 0, 16)
	for i := 0; i < 8; i++ {
		plugins = append(plugins, capacityTestPlugin(fmt.Sprintf("in%d", i), false, capacityTestHook("pre_forward", "forward", "eth0")))
		egress := capacityTestHook("pre_forward", "forward", "eth0")
		egress.Attaches = []string{"egress"}
		plugins = append(plugins, capacityTestPlugin(fmt.Sprintf("out%d", i), false, egress))
	}
	if rejected := admitPluginHooksByCapacity(plugins, testTCHookCapacityLimits); len(rejected) != 0 {
		t.Fatalf("ingress and egress hooks share a budget: %v", rejected)
	}
}
