package app

import (
	"fmt"
	"sort"
	"strings"
)

// Hook limits come from two different places, and only one of them is a real
// kernel constraint.
//
// A packet that walks a plugin chain spends two tail calls per hook, and the
// kernel allows at most 33 per program run. That bounds the hooks one packet
// can pass through on one attach point, so it is enforced per interface and
// attach direction. Hooks bound to different interfaces never stack.
//
// The host-wide capacity only reflects how many program slots the dispatcher
// reserves per stage. It is sized well above the per-interface bound so that
// many plugins can each own hooks on their own interfaces.
type pluginHookCapacityLimits struct {
	Engine string
	// StageCapacity is the number of hooks one stage can hold host-wide.
	StageCapacity int
	// InterfaceStage is the number of hooks of one stage a packet may run on
	// one interface and attach direction.
	InterfaceStage int
	// InterfaceGroup is the same bound summed over the stages of one
	// direction (forward or reply), which is what the tail-call budget limits.
	InterfaceGroup int
}

type pluginHookCapacityHook struct {
	HookID string
	Stage  string
	// Group is the direction whose stages share one tail-call budget.
	Group    string
	Attaches []string
	// Interfaces lists the interfaces the hook runs on. Empty means every
	// interface of its attach directions.
	Interfaces []string
}

type pluginHookCapacityPlugin struct {
	ID string
	// Running plugins are admitted first, so installing a plugin that does not
	// fit never pushes out one that is already attached.
	Running bool
	Hooks   []pluginHookCapacityHook
}

type pluginHookCapacityScope struct {
	Interface string
	Attach    string
}

type pluginHookCapacityCounts struct {
	stage map[string]int
	group map[string]int
}

func newPluginHookCapacityCounts() pluginHookCapacityCounts {
	return pluginHookCapacityCounts{stage: make(map[string]int), group: make(map[string]int)}
}

func (c pluginHookCapacityCounts) clone() pluginHookCapacityCounts {
	out := newPluginHookCapacityCounts()
	for key, value := range c.stage {
		out.stage[key] = value
	}
	for key, value := range c.group {
		out.group[key] = value
	}
	return out
}

type pluginHookCapacityState struct {
	total  map[string]int
	scopes map[pluginHookCapacityScope]pluginHookCapacityCounts
}

func (s pluginHookCapacityState) clone() pluginHookCapacityState {
	out := pluginHookCapacityState{total: make(map[string]int, len(s.total)), scopes: make(map[pluginHookCapacityScope]pluginHookCapacityCounts, len(s.scopes))}
	for key, value := range s.total {
		out.total[key] = value
	}
	for key, value := range s.scopes {
		out.scopes[key] = value.clone()
	}
	return out
}

func (s pluginHookCapacityState) scope(key pluginHookCapacityScope) pluginHookCapacityCounts {
	counts, ok := s.scopes[key]
	if !ok {
		counts = newPluginHookCapacityCounts()
		s.scopes[key] = counts
	}
	return counts
}

func (s pluginHookCapacityState) add(hook pluginHookCapacityHook) {
	s.total[hook.Stage]++
	for _, attach := range hook.Attaches {
		names := hook.Interfaces
		if len(names) == 0 {
			names = []string{""}
		}
		for _, name := range names {
			counts := s.scope(pluginHookCapacityScope{Interface: name, Attach: attach})
			counts.stage[hook.Stage]++
			counts.group[hook.Group]++
		}
	}
}

// violation reports the first limit the state exceeds. A packet on interface
// X runs the hooks bound to X plus every hook bound to all interfaces, so
// each named scope is checked together with the wildcard scope of its attach.
func (s pluginHookCapacityState) violation(limits pluginHookCapacityLimits) string {
	stages := make([]string, 0, len(s.total))
	for stage := range s.total {
		stages = append(stages, stage)
	}
	sort.Strings(stages)
	for _, stage := range stages {
		if limits.StageCapacity > 0 && s.total[stage] > limits.StageCapacity {
			return fmt.Sprintf("%s %s stage is full: %d hooks host-wide, capacity %d", limits.Engine, stage, s.total[stage], limits.StageCapacity)
		}
	}
	scopes := make([]pluginHookCapacityScope, 0, len(s.scopes))
	for key := range s.scopes {
		scopes = append(scopes, key)
	}
	sort.Slice(scopes, func(i, j int) bool {
		if scopes[i].Attach != scopes[j].Attach {
			return scopes[i].Attach < scopes[j].Attach
		}
		return scopes[i].Interface < scopes[j].Interface
	})
	for _, key := range scopes {
		effective := s.scopes[key]
		if key.Interface != "" {
			effective = effective.clone()
			if wildcard, ok := s.scopes[pluginHookCapacityScope{Attach: key.Attach}]; ok {
				for stage, value := range wildcard.stage {
					effective.stage[stage] += value
				}
				for group, value := range wildcard.group {
					effective.group[group] += value
				}
			}
		}
		label := "every interface"
		if key.Interface != "" {
			label = fmt.Sprintf("interface %q", key.Interface)
		}
		names := make([]string, 0, len(effective.stage))
		for stage := range effective.stage {
			names = append(names, stage)
		}
		sort.Strings(names)
		for _, stage := range names {
			if limits.InterfaceStage > 0 && effective.stage[stage] > limits.InterfaceStage {
				return fmt.Sprintf("%s %s %s would run %d %s hooks per packet, limit %d per interface", limits.Engine, label, key.Attach, effective.stage[stage], stage, limits.InterfaceStage)
			}
		}
		groups := make([]string, 0, len(effective.group))
		for group := range effective.group {
			groups = append(groups, group)
		}
		sort.Strings(groups)
		for _, group := range groups {
			if limits.InterfaceGroup > 0 && effective.group[group] > limits.InterfaceGroup {
				return fmt.Sprintf("%s %s %s would run %d %s hooks per packet, limit %d per interface", limits.Engine, label, key.Attach, effective.group[group], group, limits.InterfaceGroup)
			}
		}
	}
	return ""
}

// admitPluginHooksByCapacity admits whole plugins until a limit would be
// exceeded and returns a rejection message for each plugin that did not fit.
// Running plugins are considered first and the rest keep their given order,
// so one plugin too many is rejected on its own instead of taking every other
// plugin of the engine down with it.
func admitPluginHooksByCapacity(plugins []pluginHookCapacityPlugin, limits pluginHookCapacityLimits) map[string]string {
	ordered := make([]pluginHookCapacityPlugin, len(plugins))
	copy(ordered, plugins)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Running && !ordered[j].Running
	})
	state := pluginHookCapacityState{total: make(map[string]int), scopes: make(map[pluginHookCapacityScope]pluginHookCapacityCounts)}
	rejected := make(map[string]string)
	for _, plugin := range ordered {
		candidate := state.clone()
		for _, hook := range plugin.Hooks {
			candidate.add(hook)
		}
		if reason := candidate.violation(limits); reason != "" {
			rejected[plugin.ID] = reason + "; other plugins keep running"
			continue
		}
		state = candidate
	}
	return rejected
}

func normalizePluginHookCapacityInterfaces(names []string) []string {
	out := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}
