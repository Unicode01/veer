package app

import (
	hv "github.com/Unicode01/veer/internal/hostvalue"
)

// pluginAttachmentStatusProvider exposes the dataplane state the host keeps
// for plugins. The ProcessManager implements it; the plugin control host
// reaches it through its map controller, so validation runtimes without a
// dataplane report nothing attached.
type pluginAttachmentStatusProvider interface {
	// PluginAttachmentRuntimeState returns the combined TC/XDP/Netfilter
	// dataplane state of one plugin. It never reconciles.
	PluginAttachmentRuntimeState(pluginID string) PluginRuntimeState
	// PluginCoreEnginePinnedToTC reports whether active plugin hooks
	// currently restrict the core forwarding rules to the TC engine. It must
	// not block on dataplane locks.
	PluginCoreEnginePinnedToTC() bool
}

// kernelCoreEnginePinReporter is implemented by the ordered kernel runtime,
// which drops the XDP core engine while runtime plugin hooks are active.
type kernelCoreEnginePinReporter interface {
	CoreEnginePinnedToTC() bool
}

func (pm *ProcessManager) PluginAttachmentRuntimeState(pluginID string) PluginRuntimeState {
	if pm == nil || pluginID == "" {
		return PluginRuntimeState{}
	}
	snapshots := make([]pluginRuntimeSnapshot, 0, 2)
	if runtime, ok := pm.kernelRuntime.(pluginPipelineRuntime); ok && runtime != nil {
		snapshots = append(snapshots, runtime.PluginSnapshot())
	}
	if pm.pluginRuntime != nil {
		snapshots = append(snapshots, pm.pluginRuntime.Snapshot())
	}
	var state PluginRuntimeState
	for _, snapshot := range snapshots {
		if next, ok := snapshot.stateFor(pluginID); ok {
			state = combinePluginRuntimeStates(state, next)
		}
	}
	return state
}

func (pm *ProcessManager) PluginCoreEnginePinnedToTC() bool {
	if pm == nil {
		return false
	}
	reporter, ok := pm.kernelRuntime.(kernelCoreEnginePinReporter)
	return ok && reporter != nil && reporter.CoreEnginePinnedToTC()
}

func (h *pluginControlHost) attachmentStatusProvider() pluginAttachmentStatusProvider {
	if h == nil || h.mapController == nil {
		return nil
	}
	provider, _ := h.mapController.(pluginAttachmentStatusProvider)
	return provider
}

func (h *pluginControlHost) coreEnginePinnedToTC() bool {
	provider := h.attachmentStatusProvider()
	return provider != nil && provider.PluginCoreEnginePinnedToTC()
}

func (h *pluginControlHost) kernelEngineOrder() []string {
	if h == nil || h.cfg == nil {
		return defaultKernelEngineOrder()
	}
	return normalizeKernelEngineOrder(h.cfg.KernelEngineOrder)
}

// pluginAttachments implements plugin.attachments(): the calling plugin's own
// dataplane attachment state, never another plugin's.
func (h *pluginControlHost) pluginAttachments(hv.FunctionCall) hv.Value {
	h.requireRuntimeHandlerPhase("plugin.attachments")
	var state PluginRuntimeState
	if provider := h.attachmentStatusProvider(); provider != nil {
		state = provider.PluginAttachmentRuntimeState(h.plugin.ID)
	}
	return h.vm.ToValue(pluginAttachmentStatusMap(state))
}

func (h *pluginControlHost) requireRuntimeHandlerPhase(api string) {
	switch {
	case h.registrationPhase:
		h.throwf("%s is unavailable during plugin registration", api)
	case h.migrationPhase:
		h.throwf("%s is unavailable during plugin resource migration", api)
	case h.upgradePhase:
		h.throwf("%s is unavailable during plugin upgrade snapshot/restore", api)
	case h.ebpfMigrationPhase:
		h.throwf("%s is unavailable during eBPF state migration", api)
	}
}

func pluginAttachmentStatusMap(state PluginRuntimeState) map[string]any {
	attachments := make([]any, 0, len(state.Attachments))
	for _, attachment := range state.Attachments {
		item := map[string]any{
			"hook_id":   attachment.HookID,
			"engine":    attachment.Engine,
			"attach":    attachment.Attach,
			"stage":     attachment.Stage,
			"interface": attachment.Interface,
			"program":   attachment.Program,
			"status":    attachment.Status,
			"error":     attachment.Error,
			"xdp_mode":  attachment.XDPMode,
		}
		if attachment.Engine == pluginEngineNetfilter {
			item["namespace"] = attachment.Namespace
			item["family"] = attachment.Family
			item["netfilter_hook"] = attachment.NetfilterHook
			item["phase"] = attachment.Phase
		}
		attachments = append(attachments, item)
	}
	mode := state.Mode
	if mode == "" {
		mode = pluginRuntimeModeRegistered
	}
	return map[string]any{
		"mode":        mode,
		"attached":    state.Attached || len(state.Attachments) > 0,
		"reason":      state.Reason,
		"error":       state.Error,
		"attachments": attachments,
	}
}
