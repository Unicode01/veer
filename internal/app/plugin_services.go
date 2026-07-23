package app

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/Unicode01/veer/internal/store"
	"github.com/dop251/goja"
)

const pluginServiceEndpointLimit = 64

type pluginControlServiceQuery struct {
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
	Provider string `json:"provider,omitempty"`
}

type pluginControlServiceCallRequest struct {
	Service  string          `json:"service"`
	Version  string          `json:"version,omitempty"`
	Provider string          `json:"provider,omitempty"`
	Action   string          `json:"action"`
	Payload  json.RawMessage `json:"payload,omitempty"`
}

func normalizePluginService(service *PluginService) error {
	if service == nil {
		return fmt.Errorf("service is required")
	}
	service.ID = strings.TrimSpace(strings.ToLower(service.ID))
	if !pluginTokenPattern.MatchString(service.ID) {
		return fmt.Errorf("id must match %s", pluginTokenPattern.String())
	}
	version, err := normalizePluginSemanticVersion(service.Version)
	if err != nil {
		return fmt.Errorf("version: %w", err)
	}
	service.Version = version
	service.Description = strings.TrimSpace(service.Description)
	if len(service.Description) > 1024 || strings.ContainsRune(service.Description, '\x00') {
		return fmt.Errorf("description exceeds 1024 bytes or contains NUL")
	}
	if len(service.Actions) > pluginServiceEndpointLimit || len(service.Resources) > pluginServiceEndpointLimit {
		return fmt.Errorf("service endpoints exceed %d actions or resources", pluginServiceEndpointLimit)
	}
	service.Actions, err = normalizePluginTokens(service.Actions, "service action")
	if err != nil {
		return err
	}
	service.Resources, err = normalizePluginTokens(service.Resources, "service resource")
	if err != nil {
		return err
	}
	if len(service.Actions) == 0 && len(service.Resources) == 0 {
		return fmt.Errorf("service must expose at least one action or resource")
	}
	return nil
}

func validatePluginServices(plugin *LoadedPlugin) error {
	if plugin == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(plugin.Services))
	for i := range plugin.Services {
		service := &plugin.Services[i]
		if err := normalizePluginService(service); err != nil {
			return fmt.Errorf("service %d: %w", i, err)
		}
		if _, exists := seen[service.ID]; exists {
			return fmt.Errorf("duplicate service %q", service.ID)
		}
		seen[service.ID] = struct{}{}
		for _, actionID := range service.Actions {
			if pluginActionIndex(plugin.Actions, actionID) < 0 {
				return fmt.Errorf("service %s references undeclared action %s", service.ID, actionID)
			}
		}
		for _, resourceID := range service.Resources {
			if pluginResourceIndex(plugin.Resources, resourceID) < 0 {
				return fmt.Errorf("service %s references undeclared resource %s", service.ID, resourceID)
			}
		}
	}
	return nil
}

func pluginServiceIndex(services []PluginService, id string) int {
	for i := range services {
		if services[i].ID == id {
			return i
		}
	}
	return -1
}

func clonePluginServices(services []PluginService) []PluginService {
	if len(services) == 0 {
		return nil
	}
	out := make([]PluginService, len(services))
	for i, service := range services {
		out[i] = service
		out[i].Actions = append([]string(nil), service.Actions...)
		out[i].Resources = append([]string(nil), service.Resources...)
	}
	return out
}

type pluginServiceActionContract struct {
	ID                    string `json:"id"`
	RuntimeUpdate         string `json:"runtime_update"`
	MaxPayloadBytes       int    `json:"max_payload_bytes"`
	RequestSchemaVersion  int    `json:"request_schema_version"`
	RequestSchemaDigest   string `json:"request_schema_digest"`
	ResponseSchemaVersion int    `json:"response_schema_version"`
	ResponseSchemaDigest  string `json:"response_schema_digest"`
}

type pluginServiceResourceContract struct {
	ID             string   `json:"id"`
	Methods        []string `json:"methods"`
	ControlMethods []string `json:"control_methods"`
	RuntimeUpdate  string   `json:"runtime_update"`
	MaxRecords     int      `json:"max_records"`
	MaxRecordBytes int      `json:"max_record_bytes"`
	SecretFields   []string `json:"secret_fields"`
	SchemaVersion  int      `json:"schema_version"`
	SchemaDigest   string   `json:"schema_digest"`
}

func pluginServiceContractSignature(plugin LoadedPlugin, service PluginService) string {
	contract := struct {
		Actions   []pluginServiceActionContract   `json:"actions,omitempty"`
		Resources []pluginServiceResourceContract `json:"resources,omitempty"`
	}{}
	for _, id := range service.Actions {
		index := pluginActionIndex(plugin.Actions, id)
		if index < 0 {
			continue
		}
		action := plugin.Actions[index]
		contract.Actions = append(contract.Actions, pluginServiceActionContract{
			ID: action.ID, RuntimeUpdate: action.RuntimeUpdate, MaxPayloadBytes: action.MaxPayloadBytes,
			RequestSchemaVersion: action.RequestSchemaVersion, RequestSchemaDigest: action.RequestSchemaDigest,
			ResponseSchemaVersion: action.ResponseSchemaVersion, ResponseSchemaDigest: action.ResponseSchemaDigest,
		})
	}
	for _, id := range service.Resources {
		index := pluginResourceIndex(plugin.Resources, id)
		if index < 0 {
			continue
		}
		resource := plugin.Resources[index]
		contract.Resources = append(contract.Resources, pluginServiceResourceContract{
			ID: resource.ID, Methods: append([]string(nil), resource.Methods...),
			ControlMethods: append([]string(nil), resource.ControlMethods...), RuntimeUpdate: resource.RuntimeUpdate,
			MaxRecords: resource.MaxRecords, MaxRecordBytes: resource.MaxRecordBytes,
			SecretFields:  append([]string(nil), resource.SecretFields...),
			SchemaVersion: resource.SchemaVersion, SchemaDigest: resource.SchemaDigest,
		})
	}
	raw, _ := json.Marshal(contract)
	return string(raw)
}

func pluginServiceEndpointsContain(candidate, previous []string) bool {
	available := make(map[string]struct{}, len(candidate))
	for _, value := range candidate {
		available[value] = struct{}{}
	}
	for _, value := range previous {
		if _, ok := available[value]; !ok {
			return false
		}
	}
	return true
}

func validatePluginServiceContractUpgrade(previous, candidate LoadedPlugin) error {
	previousPluginVersion, previousPluginErr := semver.StrictNewVersion(previous.Version)
	candidatePluginVersion, candidatePluginErr := semver.StrictNewVersion(candidate.Version)
	pluginMajorChanged := previousPluginErr == nil && candidatePluginErr == nil && candidatePluginVersion.Major() > previousPluginVersion.Major()

	candidateServices := make(map[string]PluginService, len(candidate.Services))
	for _, service := range candidate.Services {
		candidateServices[service.ID] = service
	}
	for _, oldService := range previous.Services {
		nextService, exists := candidateServices[oldService.ID]
		if !exists {
			if !pluginMajorChanged {
				return fmt.Errorf("service %s was removed without increasing plugin major version", oldService.ID)
			}
			continue
		}
		oldVersion, oldErr := semver.StrictNewVersion(oldService.Version)
		nextVersion, nextErr := semver.StrictNewVersion(nextService.Version)
		if oldErr != nil || nextErr != nil {
			return fmt.Errorf("service %s has an invalid semantic version during upgrade", oldService.ID)
		}
		if nextVersion.LessThan(oldVersion) {
			return fmt.Errorf("service %s version decreased from %s to %s", oldService.ID, oldService.Version, nextService.Version)
		}
		if oldVersion.Major() == nextVersion.Major() {
			if !pluginServiceEndpointsContain(nextService.Actions, oldService.Actions) ||
				!pluginServiceEndpointsContain(nextService.Resources, oldService.Resources) {
				return fmt.Errorf("service %s removed an endpoint without increasing service major version %d", oldService.ID, oldVersion.Major())
			}
		}
		if pluginServiceContractSignature(previous, oldService) != pluginServiceContractSignature(candidate, nextService) && nextVersion.Equal(oldVersion) {
			return fmt.Errorf("service %s contract changed without increasing service version %s", oldService.ID, oldService.Version)
		}
	}
	return nil
}

func (h *pluginControlHost) pluginRegisterService(call goja.FunctionCall) goja.Value {
	h.requireRegistrationPermission("plugin.register", "plugin.service")
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("plugin.service: spec is required")
	}
	var service PluginService
	h.exportJSONValue(call.Arguments[0], &service, "plugin.service")
	if err := normalizePluginService(&service); err != nil {
		h.throwf("plugin.service: %v", err)
	}
	if pluginServiceIndex(h.surface.Services, service.ID) >= 0 {
		h.throwf("plugin.service: duplicate service %q", service.ID)
	}
	h.requirePluginRegistrationCapacity("services", len(h.surface.Services)+1, h.pluginResourceLimits().ServicesPerPlugin)
	h.surface.Services = append(h.surface.Services, service)
	return goja.Undefined()
}

func (h *pluginControlHost) pluginServiceList(call goja.FunctionCall) goja.Value {
	h.requireAnyPermission("plugins.services.list", "plugin.action", "plugin.resource")
	query := h.pluginServiceQuery(call, false, "plugins.services.list")
	providers := h.pluginServiceProviders(query, "")
	values := make([]map[string]any, 0, len(providers))
	for _, provider := range providers {
		value, err := pluginServiceProviderObject(provider)
		if err != nil {
			h.throwf("plugins.services.list: encode provider %s: %v", provider.PluginID, err)
		}
		values = append(values, value)
	}
	return h.vm.ToValue(values)
}

func (h *pluginControlHost) pluginServiceResolve(call goja.FunctionCall) goja.Value {
	h.requireAnyPermission("plugins.services.resolve", "plugin.action", "plugin.resource")
	query := h.pluginServiceQuery(call, true, "plugins.services.resolve")
	provider := h.resolvePluginServiceProvider(query, "", "plugins.services.resolve")
	value, err := pluginServiceProviderObject(provider)
	if err != nil {
		h.throwf("plugins.services.resolve: encode provider %s: %v", provider.PluginID, err)
	}
	return h.vm.ToValue(value)
}

func pluginServiceProviderObject(provider PluginServiceProvider) (map[string]any, error) {
	raw, err := json.Marshal(provider)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func (h *pluginControlHost) pluginServiceCall(call goja.FunctionCall) goja.Value {
	h.requirePermission("plugin.action")
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("plugins.services.call: request is required")
	}
	var request pluginControlServiceCallRequest
	h.exportJSONValue(call.Arguments[0], &request, "plugins.services.call")
	query := normalizePluginServiceQuery(pluginControlServiceQuery{
		Service: request.Service, Version: request.Version, Provider: request.Provider,
	}, true, "plugins.services.call", h)
	actionID, err := pluginPathToken(request.Action)
	if err != nil {
		h.throwf("plugins.services.call: action: %v", err)
	}
	provider := h.resolvePluginServiceProvider(query, actionID, "plugins.services.call")
	plugin, action := h.requiredTargetPluginAction(provider.PluginID, actionID)
	payload := request.Payload
	if len(payload) == 0 || string(payload) == "null" {
		payload = json.RawMessage(`{}`)
	}
	response := h.invokePluginAction(plugin, action, payload, "plugins.services.call")
	response["service"] = provider.Service.ID
	response["service_version"] = provider.Service.Version
	return h.vm.ToValue(response)
}

func (h *pluginControlHost) pluginServiceQuery(call goja.FunctionCall, required bool, api string) pluginControlServiceQuery {
	query := pluginControlServiceQuery{}
	if len(call.Arguments) > 0 && !goja.IsUndefined(call.Arguments[0]) && !goja.IsNull(call.Arguments[0]) {
		h.exportJSONValue(call.Arguments[0], &query, api)
	} else if required {
		h.throwf("%s: query is required", api)
	}
	return normalizePluginServiceQuery(query, required, api, h)
}

func normalizePluginServiceQuery(query pluginControlServiceQuery, required bool, api string, h *pluginControlHost) pluginControlServiceQuery {
	query.Service = strings.TrimSpace(strings.ToLower(query.Service))
	if query.Service == "" {
		if required {
			h.throwf("%s: service is required", api)
		}
	} else if !pluginTokenPattern.MatchString(query.Service) {
		h.throwf("%s: service must match %s", api, pluginTokenPattern.String())
	}
	constraint, err := normalizePluginVersionConstraint(query.Version)
	if err != nil {
		h.throwf("%s: version: %v", api, err)
	}
	query.Version = constraint
	query.Provider = strings.TrimSpace(strings.ToLower(query.Provider))
	if query.Provider != "" && !pluginIDPattern.MatchString(query.Provider) {
		h.throwf("%s: provider must match %s", api, pluginIDPattern.String())
	}
	return query
}

func (h *pluginControlHost) resolvePluginServiceProvider(query pluginControlServiceQuery, requiredAction string, api string) PluginServiceProvider {
	providers := h.pluginServiceProviders(query, requiredAction)
	if len(providers) == 0 {
		h.throwf("%s: no authorized provider satisfies service %s %s", api, query.Service, query.Version)
	}
	if len(providers) > 1 {
		ids := make([]string, len(providers))
		for i := range providers {
			ids[i] = providers[i].PluginID
		}
		sort.Strings(ids)
		h.throwf("%s: service %s is ambiguous across providers %s; select provider explicitly", api, query.Service, strings.Join(ids, ", "))
	}
	return providers[0]
}

func (h *pluginControlHost) pluginServiceProviders(query pluginControlServiceQuery, requiredAction string) []PluginServiceProvider {
	plugins := h.pluginServiceCatalog()
	providers := make([]PluginServiceProvider, 0)
	for _, plugin := range plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive || plugin.ID == h.plugin.ID || !h.pluginServiceTargetEnabled(plugin.ID) {
			continue
		}
		if query.Provider != "" && plugin.ID != query.Provider {
			continue
		}
		for _, service := range plugin.Services {
			if query.Service != "" && service.ID != query.Service {
				continue
			}
			if !pluginVersionSatisfies(service.Version, query.Version) {
				continue
			}
			provider, visible := h.authorizedPluginServiceProvider(plugin, service, requiredAction)
			if visible {
				providers = append(providers, provider)
			}
		}
	}
	sort.Slice(providers, func(i, j int) bool {
		if providers[i].Service.ID != providers[j].Service.ID {
			return providers[i].Service.ID < providers[j].Service.ID
		}
		leftVersion, leftErr := semver.StrictNewVersion(providers[i].Service.Version)
		rightVersion, rightErr := semver.StrictNewVersion(providers[j].Service.Version)
		if leftErr == nil && rightErr == nil && !leftVersion.Equal(rightVersion) {
			return leftVersion.GreaterThan(rightVersion)
		}
		return providers[i].PluginID < providers[j].PluginID
	})
	return providers
}

func (h *pluginControlHost) authorizedPluginServiceProvider(plugin LoadedPlugin, service PluginService, requiredAction string) (PluginServiceProvider, bool) {
	filtered := service
	filtered.Actions = nil
	filtered.Resources = nil
	actions := make([]PluginAction, 0, len(service.Actions))
	resources := make([]PluginResource, 0, len(service.Resources))
	if pluginControlHasPermission(h.plugin, "plugin.action") {
		for _, actionID := range service.Actions {
			if requiredAction != "" && actionID != requiredAction {
				continue
			}
			if !pluginControlHasActionAccess(h.plugin, plugin.ID, actionID) {
				continue
			}
			index := pluginActionIndex(plugin.Actions, actionID)
			if index >= 0 {
				filtered.Actions = append(filtered.Actions, actionID)
				actions = append(actions, plugin.Actions[index])
			}
		}
	}
	if requiredAction == "" && pluginControlHasPermission(h.plugin, "plugin.resource") {
		for _, resourceID := range service.Resources {
			if !pluginControlHasAnyResourceAccess(h.plugin, plugin.ID, resourceID) {
				continue
			}
			index := pluginResourceIndex(plugin.Resources, resourceID)
			if index >= 0 {
				filtered.Resources = append(filtered.Resources, resourceID)
				resources = append(resources, plugin.Resources[index])
			}
		}
	}
	if len(filtered.Actions) == 0 && len(filtered.Resources) == 0 {
		return PluginServiceProvider{}, false
	}
	return PluginServiceProvider{
		PluginID: plugin.ID, PluginName: plugin.Name, PluginVersion: plugin.Version, Stability: plugin.Stability,
		Service: filtered, Actions: actions, Resources: resources,
	}, true
}

func pluginControlHasAnyResourceAccess(plugin LoadedPlugin, targetPluginID string, resourceID string) bool {
	for _, method := range []string{"get", "list", "create", "update", "delete"} {
		if pluginControlHasResourceAccess(plugin, targetPluginID, resourceID, method) {
			return true
		}
	}
	return false
}

func (h *pluginControlHost) pluginServiceCatalog() []LoadedPlugin {
	plugins := make([]LoadedPlugin, 0)
	if h.runtime != nil {
		h.runtime.mu.Lock()
		for _, plugin := range h.runtime.plugins {
			plugins = append(plugins, plugin)
		}
		h.runtime.mu.Unlock()
	}
	if len(plugins) == 0 {
		catalogCfg := pluginCatalogConfigForProcess(pluginControlProcessManager(h.runtime), h.cfg)
		plugins = append(plugins, loadPluginCatalogWithControlRegistrationAndState(catalogCfg, h.db).Plugins...)
	}
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].ID < plugins[j].ID })
	return plugins
}

func (h *pluginControlHost) pluginServiceTargetEnabled(pluginID string) bool {
	if h.db == nil {
		return true
	}
	state, err := store.PluginStateOrNil(h.db, pluginID)
	if err != nil {
		h.throwf("plugin %s state lookup failed: %v", pluginID, err)
	}
	return state == nil || state.Enabled
}

func (h *pluginControlHost) requireAnyPermission(api string, permissions ...string) {
	if h.migrationPhase {
		h.throwf("%s is unavailable during plugin resource migration", api)
	}
	if h.upgradePhase {
		h.throwf("%s is unavailable during plugin upgrade snapshot/restore", api)
	}
	if h.registrationPhase {
		h.throwf("%s is unavailable during plugin registration", api)
	}
	for _, permission := range permissions {
		if pluginControlHasPermission(h.plugin, permission) {
			return
		}
	}
	h.throwf("%s requires one of permissions %s", api, strings.Join(permissions, ", "))
}

func (h *pluginControlHost) invokePluginAction(plugin LoadedPlugin, action PluginAction, payload json.RawMessage, api string) map[string]any {
	if plugin.ID == h.plugin.ID {
		h.throwf("%s: self action calls are not supported", api)
	}
	h.requirePluginActionAccess(plugin.ID, action.ID, api)
	if err := validatePluginActionRequest(action, payload); err != nil {
		h.throwf("%s: invalid action payload: %v", api, err)
	}
	release := h.beginSynchronousPluginCall(plugin.ID, "action "+action.ID)
	defer release()
	var result any
	var err error
	if action.RuntimeUpdate == "runtime_query" {
		result, err = h.runtime.QueryPluginAction(plugin, action, payload)
	} else {
		err = h.applyTargetPluginActionRuntimeUpdate(plugin, action, payload)
	}
	if err != nil {
		if action.RuntimeUpdate != "runtime_query" {
			_ = markPluginRuntimeError(h.db, plugin.ID, "action", action.ID, err)
		}
		h.throwf("%s: apply %s/%s: %v", api, plugin.ID, action.ID, err)
	}
	response := map[string]any{
		"status": "completed", "plugin": plugin.ID, "action": action.ID, "runtime_update": action.RuntimeUpdate,
	}
	if result != nil {
		response["result"] = result
	}
	return response
}
