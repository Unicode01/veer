package app

import (
	"fmt"
	"sort"
	"strings"
)

func normalizePluginManifest(manifest *PluginManifest) error {
	manifest.APIVersion = strings.TrimSpace(strings.ToLower(manifest.APIVersion))
	if manifest.APIVersion == "" {
		manifest.APIVersion = pluginAPIVersionV1
	}
	if manifest.APIVersion != pluginAPIVersionV1 {
		return fmt.Errorf("unsupported api_version %q", manifest.APIVersion)
	}

	manifest.ID = strings.TrimSpace(strings.ToLower(manifest.ID))
	if !pluginIDPattern.MatchString(manifest.ID) {
		return fmt.Errorf("id must match %s", pluginIDPattern.String())
	}
	if manifest.ID == "fvtap" {
		return fmt.Errorf("id %q is reserved for the built-in pipeline", manifest.ID)
	}

	manifest.Name = strings.TrimSpace(manifest.Name)
	if manifest.Name == "" {
		return fmt.Errorf("name is required")
	}
	manifest.Version = strings.TrimSpace(manifest.Version)
	if manifest.Version == "" {
		return fmt.Errorf("version is required")
	}
	manifest.Description = strings.TrimSpace(manifest.Description)
	manifest.Kind = strings.TrimSpace(strings.ToLower(manifest.Kind))
	if manifest.Kind == "" {
		manifest.Kind = "pipeline"
	}
	if !validPluginKind(manifest.Kind) {
		return fmt.Errorf("kind must be one of pipeline, control, ui")
	}

	capabilities, err := normalizePluginTokens(manifest.Capabilities, "capability")
	if err != nil {
		return err
	}
	manifest.Capabilities = capabilities

	for i := range manifest.VirtualInterfaces {
		if err := normalizePluginVirtualInterface(&manifest.VirtualInterfaces[i]); err != nil {
			return fmt.Errorf("virtual_interfaces[%d]: %w", i, err)
		}
	}
	if err := normalizePluginObjects(manifest.Objects); err != nil {
		return err
	}
	seenHooks := make(map[string]struct{}, len(manifest.Hooks))
	for i := range manifest.Hooks {
		if err := normalizePluginHook(&manifest.Hooks[i]); err != nil {
			return fmt.Errorf("hooks[%d]: %w", i, err)
		}
		if _, exists := seenHooks[manifest.Hooks[i].ID]; exists {
			return fmt.Errorf("hooks[%d]: duplicate id %q", i, manifest.Hooks[i].ID)
		}
		seenHooks[manifest.Hooks[i].ID] = struct{}{}
	}
	if err := normalizePluginResources(manifest.Resources); err != nil {
		return err
	}
	if err := normalizePluginActions(manifest.Actions); err != nil {
		return err
	}
	if manifest.Control != nil {
		if err := normalizePluginControl(manifest.Control); err != nil {
			return fmt.Errorf("control: %w", err)
		}
		if manifest.Control.Main == "" && len(manifest.Control.Permissions) == 0 {
			manifest.Control = nil
		}
	}
	if manifest.UI != nil {
		if err := normalizePluginUI(manifest.UI); err != nil {
			return fmt.Errorf("ui: %w", err)
		}
		if manifest.UI.StaticDir == "" && manifest.UI.Entry != "" {
			return fmt.Errorf("ui.static_dir is required when ui.entry is set")
		}
		if manifest.UI.StaticDir == "" && manifest.UI.Entry == "" {
			manifest.UI = nil
		}
	}
	if len(manifest.Metadata) == 0 {
		manifest.Metadata = nil
	}
	return nil
}

func normalizePluginControl(control *PluginControl) error {
	var err error
	control.Main, err = normalizePluginRelativePath(control.Main)
	if err != nil {
		return fmt.Errorf("main: %w", err)
	}
	if control.Main == "" {
		return fmt.Errorf("main is required")
	}
	permissions, err := normalizePluginTokens(control.Permissions, "permission")
	if err != nil {
		return err
	}
	for _, permission := range permissions {
		if !validPluginControlPermission(permission) {
			return fmt.Errorf("permission %q must be one of crypto, ebpf.map_write, kv, net.admin, net.l2, plugin.resource, resource, secret, timer", permission)
		}
	}
	control.Permissions = permissions
	return nil
}

func normalizePluginResources(resources []PluginResource) error {
	if len(resources) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(resources))
	for i := range resources {
		if err := normalizePluginResource(&resources[i]); err != nil {
			return fmt.Errorf("resources[%d]: %w", i, err)
		}
		if _, exists := seen[resources[i].ID]; exists {
			return fmt.Errorf("resources[%d]: duplicate id %q", i, resources[i].ID)
		}
		seen[resources[i].ID] = struct{}{}
	}
	return nil
}

func normalizePluginResource(resource *PluginResource) error {
	resource.ID = strings.TrimSpace(strings.ToLower(resource.ID))
	if !pluginTokenPattern.MatchString(resource.ID) {
		return fmt.Errorf("id must match %s", pluginTokenPattern.String())
	}
	resource.Description = strings.TrimSpace(resource.Description)
	methods, err := normalizePluginResourceMethods(resource.Methods)
	if err != nil {
		return err
	}
	resource.Methods = methods
	resource.RuntimeUpdate = strings.TrimSpace(strings.ToLower(resource.RuntimeUpdate))
	if resource.RuntimeUpdate == "" {
		resource.RuntimeUpdate = "none"
	}
	if !validPluginResourceRuntimeUpdate(resource.RuntimeUpdate) {
		return fmt.Errorf("runtime_update must be one of none, manual, plugin_reconcile, runtime_apply")
	}
	if resource.MaxRecords <= 0 {
		resource.MaxRecords = pluginResourceDefaultMaxRecords
	}
	if resource.MaxRecords > pluginResourceHardMaxRecords {
		return fmt.Errorf("max_records exceeds %d", pluginResourceHardMaxRecords)
	}
	if resource.MaxRecordBytes <= 0 {
		resource.MaxRecordBytes = pluginResourceDefaultMaxRecordBytes
	}
	if resource.MaxRecordBytes > pluginResourceHardMaxRecordBytes {
		return fmt.Errorf("max_record_bytes exceeds %d", pluginResourceHardMaxRecordBytes)
	}
	secretFields, err := normalizePluginTokens(resource.SecretFields, "secret field")
	if err != nil {
		return err
	}
	resource.SecretFields = secretFields
	return nil
}

func normalizePluginResourceMethods(values []string) ([]string, error) {
	if len(values) == 0 {
		values = []string{"list"}
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if !validPluginResourceMethod(value) {
			return nil, fmt.Errorf("method %q must be one of list, get, create, update, delete", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("methods cannot be empty")
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginActions(actions []PluginAction) error {
	if len(actions) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(actions))
	for i := range actions {
		if err := normalizePluginAction(&actions[i]); err != nil {
			return fmt.Errorf("actions[%d]: %w", i, err)
		}
		if _, exists := seen[actions[i].ID]; exists {
			return fmt.Errorf("actions[%d]: duplicate id %q", i, actions[i].ID)
		}
		seen[actions[i].ID] = struct{}{}
	}
	return nil
}

func normalizePluginAction(action *PluginAction) error {
	action.ID = strings.TrimSpace(strings.ToLower(action.ID))
	if !pluginTokenPattern.MatchString(action.ID) {
		return fmt.Errorf("id must match %s", pluginTokenPattern.String())
	}
	action.Description = strings.TrimSpace(action.Description)
	action.RuntimeUpdate = strings.TrimSpace(strings.ToLower(action.RuntimeUpdate))
	if action.RuntimeUpdate == "" {
		action.RuntimeUpdate = "none"
	}
	if !validPluginActionRuntimeUpdate(action.RuntimeUpdate) {
		return fmt.Errorf("runtime_update must be one of none, plugin_reconcile, runtime_apply")
	}
	if action.MaxPayloadBytes <= 0 {
		action.MaxPayloadBytes = pluginActionDefaultMaxPayloadBytes
	}
	if action.MaxPayloadBytes > pluginActionHardMaxPayloadBytes {
		return fmt.Errorf("max_payload_bytes exceeds %d", pluginActionHardMaxPayloadBytes)
	}
	return nil
}

func normalizePluginObjects(objects []PluginObject) error {
	if len(objects) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(objects))
	for i := range objects {
		if err := normalizePluginObject(&objects[i]); err != nil {
			return fmt.Errorf("objects[%d]: %w", i, err)
		}
		if _, exists := seen[objects[i].ID]; exists {
			return fmt.Errorf("objects[%d]: duplicate id %q", i, objects[i].ID)
		}
		seen[objects[i].ID] = struct{}{}
	}
	return nil
}

func normalizePluginObject(object *PluginObject) error {
	object.ID = strings.TrimSpace(strings.ToLower(object.ID))
	if !pluginIDPattern.MatchString(object.ID) {
		return fmt.Errorf("id must match %s", pluginIDPattern.String())
	}
	object.Path = strings.TrimSpace(object.Path)
	if object.Path == "" {
		return fmt.Errorf("path is required")
	}
	if !strings.HasPrefix(object.Path, "builtin:") {
		cleanPath, err := normalizePluginRelativePath(object.Path)
		if err != nil {
			return fmt.Errorf("path: %w", err)
		}
		if cleanPath == "" {
			return fmt.Errorf("path is required")
		}
		object.Path = cleanPath
	}
	object.SHA256 = strings.TrimSpace(strings.ToLower(object.SHA256))
	if object.SHA256 != "" && !pluginHashPattern.MatchString(object.SHA256) {
		return fmt.Errorf("sha256 must be a lowercase 64-character hex digest")
	}
	object.Description = strings.TrimSpace(object.Description)

	seenPrograms := make(map[string]struct{}, len(object.Programs))
	for i := range object.Programs {
		if err := normalizePluginObjectProgram(&object.Programs[i]); err != nil {
			return fmt.Errorf("programs[%d]: %w", i, err)
		}
		if _, exists := seenPrograms[object.Programs[i].ID]; exists {
			return fmt.Errorf("programs[%d]: duplicate id %q", i, object.Programs[i].ID)
		}
		seenPrograms[object.Programs[i].ID] = struct{}{}
	}
	return nil
}

func normalizePluginObjectProgram(program *PluginObjectProgram) error {
	program.ID = strings.TrimSpace(strings.ToLower(program.ID))
	if !pluginIDPattern.MatchString(program.ID) {
		return fmt.Errorf("id must match %s", pluginIDPattern.String())
	}
	program.Section = strings.TrimSpace(program.Section)
	if program.Section == "" {
		return fmt.Errorf("section is required")
	}
	if strings.Contains(program.Section, "\x00") || len(program.Section) > 128 {
		return fmt.Errorf("section contains invalid characters")
	}
	program.Type = strings.TrimSpace(strings.ToLower(program.Type))
	if program.Type == "" {
		program.Type = kernelEngineTC
	}
	if !validPluginObjectProgramType(program.Type) {
		return fmt.Errorf("type must be one of tc, xdp, control")
	}
	return nil
}

func normalizePluginVirtualInterface(vif *PluginVirtualInterface) error {
	vif.ID = strings.TrimSpace(strings.ToLower(vif.ID))
	if !pluginIDPattern.MatchString(vif.ID) {
		return fmt.Errorf("id must match %s", pluginIDPattern.String())
	}
	vif.Type = strings.TrimSpace(strings.ToLower(vif.Type))
	if vif.Type == "" {
		vif.Type = "logical"
	}
	if !pluginTokenPattern.MatchString(vif.Type) {
		return fmt.Errorf("type must match %s", pluginTokenPattern.String())
	}
	vif.Description = strings.TrimSpace(vif.Description)
	return nil
}

func normalizePluginHook(hook *PluginHook) error {
	hook.ID = strings.TrimSpace(strings.ToLower(hook.ID))
	if !pluginIDPattern.MatchString(hook.ID) {
		return fmt.Errorf("id must match %s", pluginIDPattern.String())
	}
	hook.Engine = strings.TrimSpace(strings.ToLower(hook.Engine))
	if !validPluginHookEngine(hook.Engine) {
		return fmt.Errorf("engine must be one of tc, xdp, control")
	}
	hook.Attach = strings.TrimSpace(strings.ToLower(hook.Attach))
	if hook.Attach == "" {
		if hook.Engine == "control" {
			hook.Attach = "none"
		} else {
			hook.Attach = "ingress"
		}
	}
	if !validPluginHookAttach(hook.Attach) {
		return fmt.Errorf("attach must be one of ingress, egress, both, none")
	}
	hook.Stage = strings.TrimSpace(strings.ToLower(hook.Stage))
	if !pluginTokenPattern.MatchString(hook.Stage) {
		return fmt.Errorf("stage must match %s", pluginTokenPattern.String())
	}
	if hook.Priority < -100000 || hook.Priority > 100000 {
		return fmt.Errorf("priority out of range")
	}
	hook.Program = strings.TrimSpace(hook.Program)
	if hook.Engine != "control" && hook.Program == "" {
		return fmt.Errorf("program is required for tc/xdp hooks")
	}
	if strings.Contains(hook.Program, "\x00") || len(hook.Program) > 160 {
		return fmt.Errorf("program contains invalid characters")
	}
	hook.Mode = strings.TrimSpace(strings.ToLower(hook.Mode))
	if hook.Mode == "" {
		if hook.Engine == "control" {
			hook.Mode = "control"
		} else {
			hook.Mode = "observe"
		}
	}
	if !validPluginHookMode(hook.Mode) {
		return fmt.Errorf("mode must be one of observe, rewrite, redirect, drop, control")
	}
	context, err := normalizePluginTokens(hook.Context, "context")
	if err != nil {
		return err
	}
	for _, item := range context {
		if !validPluginHookContext(item) {
			return fmt.Errorf("context %q must be one of %s", item, pluginHookContextTCPluginCtxV4)
		}
	}
	hook.Context = context
	interfaces, err := normalizePluginInterfaceNames(hook.Interfaces)
	if err != nil {
		return err
	}
	hook.Interfaces = interfaces
	return nil
}

func normalizePluginUI(ui *PluginUI) error {
	var err error
	ui.StaticDir, err = normalizePluginRelativePath(ui.StaticDir)
	if err != nil {
		return fmt.Errorf("static_dir: %w", err)
	}
	ui.Entry, err = normalizePluginRelativePath(ui.Entry)
	if err != nil {
		return fmt.Errorf("entry: %w", err)
	}
	return nil
}

func normalizePluginTokens(values []string, label string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if !pluginTokenPattern.MatchString(value) {
			return nil, fmt.Errorf("%s %q must match %s", label, value, pluginTokenPattern.String())
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginInterfaceNames(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "\x00") || len(value) > 64 {
			return nil, fmt.Errorf("interface %q contains invalid characters", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func validPluginKind(value string) bool {
	switch value {
	case "pipeline", "control", "ui":
		return true
	default:
		return false
	}
}

func validPluginHookEngine(value string) bool {
	switch value {
	case kernelEngineTC, kernelEngineXDP, "control":
		return true
	default:
		return false
	}
}

func validPluginObjectProgramType(value string) bool {
	switch value {
	case kernelEngineTC, kernelEngineXDP, "control":
		return true
	default:
		return false
	}
}

func validPluginHookAttach(value string) bool {
	switch value {
	case "ingress", "egress", "both", "none":
		return true
	default:
		return false
	}
}

func validPluginHookMode(value string) bool {
	switch value {
	case "observe", "rewrite", "redirect", "drop", "control":
		return true
	default:
		return false
	}
}

func validPluginHookContext(value string) bool {
	switch value {
	case pluginHookContextTCPluginCtxV4:
		return true
	default:
		return false
	}
}

func validPluginResourceMethod(value string) bool {
	switch value {
	case "list", "get", "create", "update", "delete":
		return true
	default:
		return false
	}
}

func validPluginResourceRuntimeUpdate(value string) bool {
	switch value {
	case "none", "manual", "plugin_reconcile", "runtime_apply":
		return true
	default:
		return false
	}
}

func validPluginActionRuntimeUpdate(value string) bool {
	switch value {
	case "none", "plugin_reconcile", "runtime_apply":
		return true
	default:
		return false
	}
}

func validPluginControlPermission(value string) bool {
	switch value {
	case "crypto", "ebpf.map_write", "kv", "net.admin", "net.l2", "plugin.resource", "resource", "secret", "timer":
		return true
	default:
		return false
	}
}
