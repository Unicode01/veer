package app

import (
	"strings"
	"testing"
)

func TestResolvePluginHookOrderHonorsExplicitEdgesOverPriority(t *testing.T) {
	nodes := []pluginHookOrderNode{
		{PluginID: "alpha", HookID: "first", Stage: "pre_forward", Priority: 10, After: []string{"bravo/second"}},
		{PluginID: "bravo", HookID: "second", Stage: "pre_forward", Priority: 20},
		{PluginID: "charlie", HookID: "third", Stage: "pre_forward", Priority: 15},
	}
	order, invalid := resolvePluginHookOrder(nodes)
	if len(invalid) != 0 {
		t.Fatalf("resolve invalid = %+v", invalid)
	}
	if order["bravo/second"] >= order["alpha/first"] {
		t.Fatalf("explicit after edge was not honored: %+v", order)
	}
	if order["charlie/third"] >= order["bravo/second"] {
		t.Fatalf("unconstrained priority order was not preserved: %+v", order)
	}
}

func TestResolvePluginHookOrderRejectsMissingCrossStageAndCycles(t *testing.T) {
	for name, nodes := range map[string][]pluginHookOrderNode{
		"missing": {
			{PluginID: "alpha", HookID: "first", Stage: "pre_forward", Before: []string{"missing/hook"}},
		},
		"cross_stage": {
			{PluginID: "alpha", HookID: "first", Stage: "pre_forward", Before: []string{"bravo/second"}},
			{PluginID: "bravo", HookID: "second", Stage: "post_lookup"},
		},
		"cycle": {
			{PluginID: "alpha", HookID: "first", Stage: "pre_forward", After: []string{"bravo/second"}},
			{PluginID: "bravo", HookID: "second", Stage: "pre_forward", After: []string{"alpha/first"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, invalid := resolvePluginHookOrder(nodes)
			if len(invalid) == 0 {
				t.Fatal("resolve accepted invalid ordering")
			}
			joined := ""
			for _, message := range invalid {
				joined += message
			}
			if name == "cycle" && !strings.Contains(joined, "ordering cycle") {
				t.Fatalf("cycle error = %q", joined)
			}
		})
	}
}

func TestNormalizePluginHookOrderingReferences(t *testing.T) {
	hook := PluginHook{
		ID: "ordered", Engine: "tc", Stage: "pre_forward", Program: "object:program",
		Before: []string{" FIREWALL / CHECK ", "firewall/check"}, After: []string{"pppoe/decap"},
	}
	if err := normalizePluginHook(&hook); err != nil {
		t.Fatalf("normalizePluginHook() error = %v", err)
	}
	if len(hook.Before) != 1 || hook.Before[0] != "firewall/check" || len(hook.After) != 1 || hook.After[0] != "pppoe/decap" {
		t.Fatalf("normalized ordering = before:%v after:%v", hook.Before, hook.After)
	}
	hook.After = []string{"firewall/check"}
	if err := normalizePluginHook(&hook); err == nil || !strings.Contains(err.Error(), "both before and after") {
		t.Fatalf("conflicting ordering error = %v", err)
	}
}
