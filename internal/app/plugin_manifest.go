package app

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

var pluginManifestRuntimeFields = map[string]struct{}{
	"actions":            {},
	"builtin":            {},
	"capabilities":       {},
	"hooks":              {},
	"metadata":           {},
	"objects":            {},
	"resources":          {},
	"ui":                 {},
	"virtual_interfaces": {},
}

func (manifest *PluginManifest) UnmarshalJSON(data []byte) error {
	type rawPluginManifest PluginManifest
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for field := range fields {
		if _, forbidden := pluginManifestRuntimeFields[field]; forbidden {
			return fmt.Errorf("manifest field %q is runtime-owned; register it from control.js instead", field)
		}
	}
	var raw rawPluginManifest
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*manifest = PluginManifest(raw)
	return nil
}

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
	if reservedBuiltinPluginID(manifest.ID) {
		return fmt.Errorf("id %q is reserved for the built-in Veer pipeline", manifest.ID)
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
	manifest.Stability = strings.TrimSpace(strings.ToLower(manifest.Stability))
	if manifest.Stability == "" {
		manifest.Stability = pluginStabilityLab
	}
	if !validPluginStability(manifest.Stability) {
		return fmt.Errorf("stability must be one of lab, preview, stable, deprecated")
	}

	if manifest.Control != nil {
		if err := normalizePluginControl(manifest.Control); err != nil {
			return fmt.Errorf("control: %w", err)
		}
		if manifest.Control.Main == "" && len(manifest.Control.Permissions) == 0 {
			manifest.Control = nil
		}
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
	control.SHA256 = strings.TrimSpace(strings.ToLower(control.SHA256))
	if control.SHA256 != "" && !pluginHashPattern.MatchString(control.SHA256) {
		return fmt.Errorf("sha256 must be a lowercase 64-character hex digest")
	}
	control.ResolvedSHA256 = ""
	permissions, err := normalizePluginTokens(control.Permissions, "permission")
	if err != nil {
		return err
	}
	for _, permission := range permissions {
		if !validPluginControlPermission(permission) {
			return fmt.Errorf("permission %q must be one of crypto, ebpf.load, ebpf.map_read, ebpf.map_write, hook.attach, kv, net.admin, net.l2, net.tcp, net.udp, plugin.action, plugin.register, plugin.resource, resource, secret, timer, ui, worker", permission)
		}
	}
	control.Permissions = permissions
	if err := normalizePluginResourceAccess(control.ResourceAccess); err != nil {
		return fmt.Errorf("resource_access: %w", err)
	}
	if len(control.ResourceAccess) > 0 {
		hasPluginResource := false
		for _, permission := range permissions {
			if permission == "plugin.resource" {
				hasPluginResource = true
				break
			}
		}
		if !hasPluginResource {
			return fmt.Errorf("resource_access requires plugin.resource permission")
		}
	}
	if err := normalizePluginActionAccess(control.ActionAccess); err != nil {
		return fmt.Errorf("action_access: %w", err)
	}
	if len(control.ActionAccess) > 0 {
		hasPluginAction := false
		for _, permission := range permissions {
			if permission == "plugin.action" {
				hasPluginAction = true
				break
			}
		}
		if !hasPluginAction {
			return fmt.Errorf("action_access requires plugin.action permission")
		}
	}
	if err := normalizePluginNetAccess(control.NetAccess); err != nil {
		return fmt.Errorf("net_access: %w", err)
	}
	hasNetAdmin := false
	hasNetL2 := false
	hasNetTCP := false
	hasNetUDP := false
	for _, permission := range permissions {
		switch permission {
		case "net.admin":
			hasNetAdmin = true
		case "net.l2":
			hasNetL2 = true
		case "net.tcp":
			hasNetTCP = true
		case "net.udp":
			hasNetUDP = true
		}
	}
	if (hasNetAdmin || hasNetL2 || hasNetTCP || hasNetUDP) && len(control.NetAccess) == 0 {
		return fmt.Errorf("net_access is required when net.admin, net.l2, net.tcp, or net.udp permission is declared")
	}
	for _, access := range control.NetAccess {
		for _, operation := range access.Operations {
			if operation == "l2" {
				if !hasNetL2 {
					return fmt.Errorf("net_access operation %q requires net.l2 permission", operation)
				}
				continue
			}
			if operation == "udp" {
				if !hasNetUDP {
					return fmt.Errorf("net_access operation %q requires net.udp permission", operation)
				}
				continue
			}
			if operation == "tcp" {
				if !hasNetTCP {
					return fmt.Errorf("net_access operation %q requires net.tcp permission", operation)
				}
				continue
			}
			if !hasNetAdmin {
				return fmt.Errorf("net_access operation %q requires net.admin permission", operation)
			}
		}
	}
	return nil
}

func normalizePluginResourceAccess(access []PluginResourceAccess) error {
	if len(access) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(access))
	for i := range access {
		item := &access[i]
		item.Plugin = strings.TrimSpace(strings.ToLower(item.Plugin))
		if !pluginIDPattern.MatchString(item.Plugin) {
			return fmt.Errorf("[%d].plugin must match %s", i, pluginIDPattern.String())
		}
		if reservedBuiltinPluginID(item.Plugin) {
			return fmt.Errorf("[%d].plugin %q is reserved for the built-in Veer pipeline", i, item.Plugin)
		}
		item.Resource = strings.TrimSpace(strings.ToLower(item.Resource))
		if pluginControlReservedResourceID(item.Resource) {
			return fmt.Errorf("[%d].resource %q is reserved for plugin control internals", i, item.Resource)
		}
		if !pluginTokenPattern.MatchString(item.Resource) {
			return fmt.Errorf("[%d].resource must match %s", i, pluginTokenPattern.String())
		}
		methods, err := normalizePluginResourceAccessMethods(item.Methods)
		if err != nil {
			return fmt.Errorf("[%d].methods: %w", i, err)
		}
		item.Methods = methods
		key := item.Plugin + "/" + item.Resource
		if _, exists := seen[key]; exists {
			return fmt.Errorf("[%d]: duplicate resource access %s", i, key)
		}
		seen[key] = struct{}{}
	}
	sort.Slice(access, func(i, j int) bool {
		if access[i].Plugin == access[j].Plugin {
			return access[i].Resource < access[j].Resource
		}
		return access[i].Plugin < access[j].Plugin
	})
	return nil
}

func normalizePluginResourceAccessMethods(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("methods cannot be empty")
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

func normalizePluginActionAccess(access []PluginActionAccess) error {
	if len(access) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(access))
	for i := range access {
		item := &access[i]
		item.Plugin = strings.TrimSpace(strings.ToLower(item.Plugin))
		if !pluginIDPattern.MatchString(item.Plugin) {
			return fmt.Errorf("[%d].plugin must match %s", i, pluginIDPattern.String())
		}
		if reservedBuiltinPluginID(item.Plugin) {
			return fmt.Errorf("[%d].plugin %q is reserved for the built-in Veer pipeline", i, item.Plugin)
		}
		actions, err := normalizePluginActionAccessActions(item.Actions)
		if err != nil {
			return fmt.Errorf("[%d].actions: %w", i, err)
		}
		item.Actions = actions
		for _, action := range item.Actions {
			key := item.Plugin + "/" + action
			if _, exists := seen[key]; exists {
				return fmt.Errorf("[%d]: duplicate action access %s", i, key)
			}
			seen[key] = struct{}{}
		}
	}
	sort.Slice(access, func(i, j int) bool {
		if access[i].Plugin == access[j].Plugin {
			return strings.Join(access[i].Actions, ",") < strings.Join(access[j].Actions, ",")
		}
		return access[i].Plugin < access[j].Plugin
	})
	return nil
}

func normalizePluginActionAccessActions(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("actions cannot be empty")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if !pluginTokenPattern.MatchString(value) {
			return nil, fmt.Errorf("action must match %s", pluginTokenPattern.String())
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("actions cannot be empty")
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginNetAccess(access []PluginNetAccess) error {
	if len(access) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(access))
	for i := range access {
		item := &access[i]
		interfaces, err := normalizePluginInterfacePatterns(item.Interfaces)
		if err != nil {
			return fmt.Errorf("[%d].interfaces: %w", i, err)
		}
		operations, err := normalizePluginNetOperations(item.Operations)
		if err != nil {
			return fmt.Errorf("[%d].operations: %w", i, err)
		}
		item.Interfaces = interfaces
		item.Operations = operations
		key := strings.Join(interfaces, "\x00") + "\x01" + strings.Join(operations, "\x00")
		if _, exists := seen[key]; exists {
			return fmt.Errorf("[%d]: duplicate net access entry", i)
		}
		seen[key] = struct{}{}
	}
	sort.Slice(access, func(i, j int) bool {
		left := strings.Join(access[i].Interfaces, ",") + ":" + strings.Join(access[i].Operations, ",")
		right := strings.Join(access[j].Interfaces, ",") + ":" + strings.Join(access[j].Operations, ",")
		return left < right
	})
	return nil
}

func normalizePluginInterfacePatterns(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("interfaces cannot be empty")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "\x00") || strings.ContainsAny(value, "/\\ \t\r\n") || len(value) > 64 {
			return nil, fmt.Errorf("interface pattern %q contains invalid characters", value)
		}
		if !strings.Contains(value, "*") && len(value) > linuxInterfaceNameMaxBytes {
			return nil, fmt.Errorf("interface pattern %q exceeds %d bytes", value, linuxInterfaceNameMaxBytes)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("interfaces cannot be empty")
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginNetOperations(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("operations cannot be empty")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if !validPluginNetOperation(value) {
			return nil, fmt.Errorf("operation %q must be one of addr.write, l2, link.create, link.delete, link.master, link.offload, link.read, link.state, route.write, tcp, udp", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("operations cannot be empty")
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginResource(resource *PluginResource) error {
	resource.ID = strings.TrimSpace(strings.ToLower(resource.ID))
	if pluginControlReservedResourceID(resource.ID) {
		return fmt.Errorf("id %q is reserved for plugin control internals", resource.ID)
	}
	if !pluginTokenPattern.MatchString(resource.ID) {
		return fmt.Errorf("id must match %s", pluginTokenPattern.String())
	}
	resource.Description = strings.TrimSpace(resource.Description)
	methods, err := normalizePluginResourceMethods(resource.Methods)
	if err != nil {
		return err
	}
	resource.Methods = methods
	if resource.ControlMethods != nil {
		controlMethods, err := normalizePluginResourceMethodsExplicit(resource.ControlMethods, "control_methods")
		if err != nil {
			return err
		}
		resource.ControlMethods = controlMethods
	}
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
	return normalizePluginResourceMethodsExplicit(values, "methods")
}

func normalizePluginResourceMethodsExplicit(values []string, label string) ([]string, error) {
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
		return nil, fmt.Errorf("%s cannot be empty", label)
	}
	sort.Strings(out)
	return out, nil
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
		return fmt.Errorf("runtime_update must be one of none, plugin_reconcile, runtime_apply, runtime_query")
	}
	if action.MaxPayloadBytes <= 0 {
		action.MaxPayloadBytes = pluginActionDefaultMaxPayloadBytes
	}
	if action.MaxPayloadBytes > pluginActionHardMaxPayloadBytes {
		return fmt.Errorf("max_payload_bytes exceeds %d", pluginActionHardMaxPayloadBytes)
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
	if hook.Engine != "control" && !validPluginDataplaneHookStage(hook.Stage) {
		return fmt.Errorf("stage must be one of forward, reply, pre_forward, post_lookup, pre_reply, post_reply")
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
	ui.Page = strings.TrimSpace(strings.ToLower(ui.Page))
	if ui.Page != "" {
		if !pluginIDPattern.MatchString(ui.Page) {
			return fmt.Errorf("page must match %s", pluginIDPattern.String())
		}
		switch ui.Page {
		case "plugins", "diagnostics":
			return fmt.Errorf("page %q is reserved", ui.Page)
		}
	}
	ui.PageTitle = strings.TrimSpace(ui.PageTitle)
	if strings.Contains(ui.PageTitle, "\x00") || len(ui.PageTitle) > 64 {
		return fmt.Errorf("page_title contains invalid characters")
	}
	ui.SHA256 = strings.TrimSpace(strings.ToLower(ui.SHA256))
	if ui.SHA256 != "" && !pluginHashPattern.MatchString(ui.SHA256) {
		return fmt.Errorf("sha256 must be a lowercase 64-character hex digest")
	}
	ui.ResolvedSHA256 = ""
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
		if strings.Contains(value, "\x00") || strings.ContainsAny(value, "/\\ \t\r\n") || len(value) > linuxInterfaceNameMaxBytes {
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

func validPluginStability(value string) bool {
	switch value {
	case pluginStabilityLab, pluginStabilityPreview, pluginStabilityStable, pluginStabilityDeprecated:
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
	case "none", "plugin_reconcile", "runtime_apply", "runtime_query":
		return true
	default:
		return false
	}
}

func validPluginControlPermission(value string) bool {
	switch value {
	case "crypto", "ebpf.load", "ebpf.map_read", "ebpf.map_write", "hook.attach", "kv", "net.admin", "net.l2", "net.tcp", "net.udp", "plugin.action", "plugin.register", "plugin.resource", "resource", "secret", "timer", "ui", "worker":
		return true
	default:
		return false
	}
}

func validPluginDataplaneHookStage(value string) bool {
	switch value {
	case "forward", "reply", "pre_forward", "post_lookup", "pre_reply", "post_reply":
		return true
	default:
		return false
	}
}

func validPluginNetOperation(value string) bool {
	switch value {
	case "addr.write", "l2", "link.create", "link.delete", "link.master", "link.offload", "link.read", "link.state", "route.write", "tcp", "udp":
		return true
	default:
		return false
	}
}
