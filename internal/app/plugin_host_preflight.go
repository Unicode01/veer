package app

import (
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/Unicode01/veer/internal/kernelcap"
)

type pluginHostFeatureAvailability struct {
	Available []string
	Status    map[string]PluginHostFeatureStatus
}

var detectPluginHostKernelCapabilities = kernelcap.DetectKernelCapabilities

func currentPluginHostFeatureAvailability() pluginHostFeatureAvailability {
	status := make(map[string]PluginHostFeatureStatus, len(pluginRuntimeFeatures))
	for _, feature := range pluginRuntimeFeatures {
		status[feature] = PluginHostFeatureStatus{Available: true}
	}
	caps := detectPluginHostKernelCapabilities()
	osName := strings.TrimSpace(strings.ToLower(caps.OS))
	if osName == "" {
		osName = runtime.GOOS
	}
	if osName != "linux" {
		reason := "feature requires Linux"
		for _, feature := range []string{
			"control.net_admin",
			"control.net_offloads.v1",
			"control.http_client.v1",
			"control.dns_client.v1",
			"control.net_events.v1",
			"control.net_leases.v1",
			"control.netns_provider.v1",
			"control.netns_scoped.v1",
			"control.net_policy.v1",
			"control.net_transactions.v1",
			"control.raw_l2",
			"control.socket_events.v1",
			"control.sockets",
			"control.tuntap_provider.v1",
			"dataplane.tc_pipeline.v2",
			"dataplane.xdp_pipeline.v1",
			"ebpf.bounded_reads.v1",
			"ebpf.map_transactions.v1",
			"ebpf.private_maps",
			"ebpf.map_state.v1",
			"ebpf.map_migration.v1",
		} {
			status[feature] = PluginHostFeatureStatus{Reason: reason}
		}
		return finalizePluginHostFeatureAvailability(status)
	}

	status["dataplane.tc_pipeline.v2"] = pluginHostFeatureStatusFromChecks("TC pipeline", caps.TC)
	status["dataplane.xdp_pipeline.v1"] = pluginHostFeatureStatusFromChecks(
		"XDP plugin pipeline",
		caps.BPFXDP,
		caps.BPFMapProgArray,
		caps.Netlink.LinkList,
	)
	mapStatus := pluginHostFeatureStatusFromChecks(
		"eBPF private maps",
		caps.BPFMapArray,
		caps.BPFMapHash,
		caps.BPFMapPerCPUHash,
		caps.BPFMapPerCPUArray,
		caps.BPFMapProgArray,
		caps.BPFSchedCLS,
	)
	status["ebpf.private_maps"] = mapStatus
	status["ebpf.map_state.v1"] = mapStatus
	status["ebpf.map_migration.v1"] = mapStatus
	status["ebpf.map_transactions.v1"] = mapStatus
	status["ebpf.bounded_reads.v1"] = pluginHostFeatureStatusFromChecks(
		"bounded eBPF map reads",
		caps.BPFMapArray,
		caps.BPFMapHash,
		caps.BPFMapPerCPUHash,
		caps.BPFMapPerCPUArray,
		caps.BPFMapRingBuf,
	)
	netAdminStatus := pluginHostFeatureStatusFromChecks(
		"route netlink",
		caps.Netlink.RouteSocket,
		caps.Netlink.LinkList,
		caps.Netlink.RouteList,
	)
	status["control.net_admin"] = netAdminStatus
	status["control.net_offloads.v1"] = pluginNetOffloadFeatureStatus()
	status["control.net_leases.v1"] = netAdminStatus
	status["control.net_policy.v1"] = netAdminStatus
	status["control.net_transactions.v1"] = netAdminStatus
	status["control.net_events.v1"] = pluginHostFeatureStatusFromChecks(
		"route netlink events",
		caps.Netlink.LinkSubscribe,
		caps.Netlink.AddressSubscribe,
		caps.Netlink.NeighborSubscribe,
		caps.Netlink.RouteSubscribe,
	)
	status["control.raw_l2"] = pluginRawL2FeatureStatus()
	status["control.netns_provider.v1"] = pluginNetworkNamespaceFeatureStatus()
	status["control.netns_scoped.v1"] = status["control.netns_provider.v1"]
	status["control.tuntap_provider.v1"] = pluginTunTapFeatureStatus()
	return finalizePluginHostFeatureAvailability(status)
}

func pluginHostFeatureStatusFromChecks(label string, checks ...kernelcap.CapabilityCheck) PluginHostFeatureStatus {
	reasons := make([]string, 0)
	for _, check := range checks {
		if check.Available {
			continue
		}
		reason := strings.TrimSpace(check.Reason)
		if reason == "" {
			reason = "required kernel capability is unavailable"
		}
		reasons = append(reasons, reason)
	}
	if len(reasons) == 0 {
		return PluginHostFeatureStatus{Available: true}
	}
	return PluginHostFeatureStatus{Reason: label + " unavailable: " + strings.Join(reasons, "; ")}
}

func finalizePluginHostFeatureAvailability(status map[string]PluginHostFeatureStatus) pluginHostFeatureAvailability {
	available := make([]string, 0, len(status))
	for feature, item := range status {
		if item.Available {
			available = append(available, feature)
		}
	}
	sort.Strings(available)
	return pluginHostFeatureAvailability{Available: available, Status: status}
}

func pluginRequiredHostFeatures(plugin LoadedPlugin) []string {
	required := make(map[string]struct{})
	if plugin.Compatibility != nil {
		for _, feature := range plugin.Compatibility.Features {
			required[feature] = struct{}{}
		}
	}
	if plugin.Control != nil {
		if len(plugin.Control.NamespaceAccess) > 0 {
			required["control.netns_scoped.v1"] = struct{}{}
		}
		for _, permission := range plugin.Control.Permissions {
			switch permission {
			case "ebpf.map_read", "ebpf.map_write":
				required["ebpf.private_maps"] = struct{}{}
			case "net.admin":
				required["control.net_admin"] = struct{}{}
				required["control.net_leases.v1"] = struct{}{}
			case "net.l2":
				required["control.raw_l2"] = struct{}{}
			case "net.http":
				required["control.http_client.v1"] = struct{}{}
			case "net.dns":
				required["control.dns_client.v1"] = struct{}{}
			case "net.namespace":
				required["control.netns_provider.v1"] = struct{}{}
			case "net.tuntap":
				required["control.tuntap_provider.v1"] = struct{}{}
			case "net.tcp", "net.udp":
				required["control.sockets"] = struct{}{}
			}
		}
	}
	for _, object := range plugin.Objects {
		if len(object.Variants) > 0 {
			required["ebpf.object_variants.v1"] = struct{}{}
		}
		if len(object.StateMaps) > 0 {
			required["ebpf.map_state.v1"] = struct{}{}
		}
		for _, stateMap := range object.StateMaps {
			if stateMap.Policy == pluginObjectMapMigrate {
				required["ebpf.map_migration.v1"] = struct{}{}
				break
			}
		}
	}
	for _, hook := range plugin.Hooks {
		if len(hook.Before) > 0 || len(hook.After) > 0 {
			required["dataplane.hook_order.v1"] = struct{}{}
		}
		if hook.Engine == kernelEngineTC && validPluginDataplaneHookStage(hook.Stage) {
			required["dataplane.tc_pipeline.v2"] = struct{}{}
		} else if hook.Engine == kernelEngineXDP {
			required["dataplane.xdp_pipeline.v1"] = struct{}{}
		}
	}
	if len(plugin.Services) > 0 {
		required["control.typed_services.v1"] = struct{}{}
	}
	for _, subscription := range plugin.EventSubscriptions {
		if pluginEventTopicRequiresNetAdmin(subscription.Topic) {
			required["control.net_events.v1"] = struct{}{}
		}
	}
	out := make([]string, 0, len(required))
	for feature := range required {
		out = append(out, feature)
	}
	sort.Strings(out)
	return out
}

func checkPluginHostPrerequisites(plugin LoadedPlugin) error {
	availability := currentPluginHostFeatureAvailability()
	failures := make([]string, 0)
	for _, feature := range pluginRequiredHostFeatures(plugin) {
		state, ok := availability.Status[feature]
		if !ok || state.Available {
			continue
		}
		reason := strings.TrimSpace(state.Reason)
		if reason == "" {
			reason = "feature is unavailable on this host"
		}
		failures = append(failures, fmt.Sprintf("%s: %s", feature, reason))
	}
	if len(failures) > 0 {
		return fmt.Errorf("required host capabilities are unavailable: %s", strings.Join(failures, "; "))
	}
	return nil
}
