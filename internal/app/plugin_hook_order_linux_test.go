//go:build linux

package app

import (
	"sort"
	"strings"
	"testing"
)

func TestKernelPluginPipelineOrderingOverridesPriorityAndContainsCycles(t *testing.T) {
	desired := []kernelPluginPipelineDesiredPlugin{
		{plugin: LoadedPlugin{PluginManifest: PluginManifest{ID: "alpha"}}, hooks: []kernelPluginPipelineHookPlan{{
			PluginID: "alpha", HookID: "first", Stage: kernelPluginPipelineStagePreForward, Priority: 10, After: []string{"bravo/second"},
		}}},
		{plugin: LoadedPlugin{PluginManifest: PluginManifest{ID: "bravo"}}, hooks: []kernelPluginPipelineHookPlan{{
			PluginID: "bravo", HookID: "second", Stage: kernelPluginPipelineStagePreForward, Priority: 20,
		}}},
	}
	ordered, states := applyKernelPluginPipelineOrdering(desired, map[string]PluginRuntimeState{})
	if len(states) != 0 || len(ordered) != 2 {
		t.Fatalf("ordered=%+v states=%+v", ordered, states)
	}
	hooks := []kernelPluginPipelineHookPlan{ordered[0].hooks[0], ordered[1].hooks[0]}
	sort.Slice(hooks, func(i, j int) bool { return kernelPluginPipelineLess(hooks[i], hooks[j]) })
	if hooks[0].PluginID != "bravo" || hooks[1].PluginID != "alpha" {
		t.Fatalf("ordered hooks = %+v", hooks)
	}

	desired[1].hooks[0].After = []string{"alpha/first"}
	ordered, states = applyKernelPluginPipelineOrdering(desired, map[string]PluginRuntimeState{})
	if len(ordered) != 0 || len(states) != 2 || !strings.Contains(states["alpha"].Error, "ordering cycle") {
		t.Fatalf("cycle ordered=%+v states=%+v", ordered, states)
	}
}

func TestKernelXDPPluginOrderingFiltersOnlyInvalidPlugins(t *testing.T) {
	desired := []kernelXDPPluginDesiredPlugin{
		{plugin: LoadedPlugin{PluginManifest: PluginManifest{ID: "broken"}}, hooks: []kernelXDPPluginHookPlan{{
			PluginID: "broken", HookID: "hook", Stage: kernelPluginPipelineStagePreForward, Before: []string{"missing/hook"},
		}}},
		{plugin: LoadedPlugin{PluginManifest: PluginManifest{ID: "healthy"}}, hooks: []kernelXDPPluginHookPlan{{
			PluginID: "healthy", HookID: "hook", Stage: kernelPluginPipelineStagePreForward,
		}}},
	}
	ordered, states := applyKernelXDPPluginOrdering(desired, map[string]PluginRuntimeState{})
	if len(ordered) != 1 || ordered[0].plugin.ID != "healthy" {
		t.Fatalf("ordered = %+v", ordered)
	}
	if state := states["broken"]; state.Error == "" || !strings.Contains(state.Error, "target missing/hook is unavailable") {
		t.Fatalf("broken state = %+v", state)
	}
}
