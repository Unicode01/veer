package app

import (
	"fmt"
	"sort"
	"strings"
)

const pluginHookOrderReferenceLimit = 32

type pluginHookOrderNode struct {
	PluginID string
	HookID   string
	Stage    string
	Priority int
	Before   []string
	After    []string
}

func pluginHookOrderKey(pluginID, hookID string) string {
	return pluginID + "/" + hookID
}

func normalizePluginHookOrderReferences(values []string, label string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > pluginHookOrderReferenceLimit {
		return nil, fmt.Errorf("%s exceeds the limit of %d", label, pluginHookOrderReferenceLimit)
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		parts := strings.Split(value, "/")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) != 2 || !pluginIDPattern.MatchString(parts[0]) || !pluginIDPattern.MatchString(parts[1]) {
			return nil, fmt.Errorf("%s reference %q must use plugin_id/hook_id", label, value)
		}
		value = pluginHookOrderKey(parts[0], parts[1])
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func validatePluginHookOrderReferenceSets(before, after []string) error {
	seen := make(map[string]struct{}, len(before))
	for _, value := range before {
		seen[value] = struct{}{}
	}
	for _, value := range after {
		if _, exists := seen[value]; exists {
			return fmt.Errorf("hook cannot declare %s in both before and after", value)
		}
	}
	return nil
}

func resolvePluginHookOrder(nodes []pluginHookOrderNode) (map[string]int, map[string]string) {
	if len(nodes) == 0 {
		return nil, nil
	}
	indexes := make(map[string]int, len(nodes))
	invalid := make(map[string]string)
	for index, node := range nodes {
		key := pluginHookOrderKey(node.PluginID, node.HookID)
		if previous, exists := indexes[key]; exists {
			message := fmt.Sprintf("duplicate hook ordering identity %s at indexes %d and %d", key, previous, index)
			invalid[node.PluginID] = message
			invalid[nodes[previous].PluginID] = message
			continue
		}
		indexes[key] = index
	}
	if len(invalid) > 0 {
		return nil, invalid
	}

	edges := make([]map[int]struct{}, len(nodes))
	indegree := make([]int, len(nodes))
	addIssue := func(pluginID, message string) {
		if previous := invalid[pluginID]; previous != "" && !strings.Contains(previous, message) {
			invalid[pluginID] = previous + "; " + message
		} else if previous == "" {
			invalid[pluginID] = message
		}
	}
	addEdge := func(from, to int) {
		if edges[from] == nil {
			edges[from] = make(map[int]struct{})
		}
		if _, exists := edges[from][to]; exists {
			return
		}
		edges[from][to] = struct{}{}
		indegree[to]++
	}
	resolveTarget := func(source int, reference, relation string) (int, bool) {
		target, exists := indexes[reference]
		if !exists {
			addIssue(nodes[source].PluginID, fmt.Sprintf("hook %s %s target %s is unavailable", pluginHookOrderKey(nodes[source].PluginID, nodes[source].HookID), relation, reference))
			return 0, false
		}
		if target == source {
			addIssue(nodes[source].PluginID, fmt.Sprintf("hook %s cannot order relative to itself", reference))
			return 0, false
		}
		if nodes[target].Stage != nodes[source].Stage {
			addIssue(nodes[source].PluginID, fmt.Sprintf("hook %s %s target %s is in stage %s, want %s", pluginHookOrderKey(nodes[source].PluginID, nodes[source].HookID), relation, reference, nodes[target].Stage, nodes[source].Stage))
			return 0, false
		}
		return target, true
	}
	for source, node := range nodes {
		for _, reference := range node.Before {
			if target, ok := resolveTarget(source, reference, "before"); ok {
				addEdge(source, target)
			}
		}
		for _, reference := range node.After {
			if target, ok := resolveTarget(source, reference, "after"); ok {
				addEdge(target, source)
			}
		}
	}
	if len(invalid) > 0 {
		return nil, invalid
	}

	less := func(left, right int) bool {
		if nodes[left].Stage != nodes[right].Stage {
			return nodes[left].Stage < nodes[right].Stage
		}
		if nodes[left].Priority != nodes[right].Priority {
			return nodes[left].Priority < nodes[right].Priority
		}
		if nodes[left].PluginID != nodes[right].PluginID {
			return nodes[left].PluginID < nodes[right].PluginID
		}
		return nodes[left].HookID < nodes[right].HookID
	}
	ready := make([]int, 0, len(nodes))
	for index := range nodes {
		if indegree[index] == 0 {
			ready = append(ready, index)
		}
	}
	order := make(map[string]int, len(nodes))
	stageOrder := make(map[string]int)
	processed := 0
	for len(ready) > 0 {
		sort.Slice(ready, func(i, j int) bool { return less(ready[i], ready[j]) })
		current := ready[0]
		ready = ready[1:]
		key := pluginHookOrderKey(nodes[current].PluginID, nodes[current].HookID)
		order[key] = stageOrder[nodes[current].Stage]
		stageOrder[nodes[current].Stage]++
		processed++
		for next := range edges[current] {
			indegree[next]--
			if indegree[next] == 0 {
				ready = append(ready, next)
			}
		}
	}
	if processed == len(nodes) {
		return order, nil
	}
	cycle := make([]string, 0)
	for index, remaining := range indegree {
		if remaining <= 0 {
			continue
		}
		key := pluginHookOrderKey(nodes[index].PluginID, nodes[index].HookID)
		cycle = append(cycle, key)
	}
	sort.Strings(cycle)
	message := "hook ordering cycle involves " + strings.Join(cycle, ", ")
	for index, remaining := range indegree {
		if remaining > 0 {
			invalid[nodes[index].PluginID] = message
		}
	}
	return nil, invalid
}
