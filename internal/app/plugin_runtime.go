package app

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/Unicode01/veer/internal/store"
)

const (
	defaultPluginsDir     = "plugins"
	pluginManifestFile    = "plugin.json"
	pluginManifestMaxSize = 1 << 20
	pluginObjectMaxSize   = 16 << 20
	pluginControlMaxSize  = 1 << 20

	pluginStatusActive   = "active"
	pluginStatusBuiltin  = "builtin"
	pluginStatusDisabled = "disabled"
	pluginStatusError    = "error"

	pluginRuntimeModeBuiltin    = "builtin"
	pluginRuntimeModeDataplane  = "dataplane"
	pluginRuntimeModeControl    = "control"
	pluginRuntimeModeDisabled   = "disabled"
	pluginRuntimeModeError      = "error"
	pluginRuntimeModeRegistered = "registered"
	pluginRuntimeModeInvalid    = "invalid"

	pluginObjectStatusBuiltin  = "builtin"
	pluginObjectStatusVerified = "verified"
	pluginObjectStatusError    = "error"

	pluginAPIVersionV1 = "v1"

	builtinPluginID         = "veer_core"
	builtinPluginPipelineID = "veer"

	pluginPipelineCorePriority = 1000

	pluginStabilityLab        = "lab"
	pluginStabilityPreview    = "preview"
	pluginStabilityStable     = "stable"
	pluginStabilityDeprecated = "deprecated"

	pluginResourceDefaultMaxRecords     = 1000
	pluginResourceHardMaxRecords        = 100000
	pluginResourceDefaultMaxRecordBytes = 64 << 10
	pluginResourceHardMaxRecordBytes    = 1 << 20
	pluginResourceListDefaultLimit      = 1000
	pluginResourceListHardLimit         = 5000
	pluginActionDefaultMaxPayloadBytes  = 64 << 10
	pluginActionHardMaxPayloadBytes     = 1 << 20

	pluginHookContextTCPluginCtxV4 = "tc_plugin_ctx_v4"
)

func reservedBuiltinPluginID(id string) bool {
	return id == builtinPluginID || id == builtinPluginPipelineID
}

var (
	pluginIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	pluginTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	pluginHashPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type PluginCatalog struct {
	ExternalPluginsEnabled bool                      `json:"external_plugins_enabled"`
	Directory              string                    `json:"directory"`
	Runtime                PluginRuntimeCapabilities `json:"runtime"`
	HotReload              *PluginCatalogHotReload   `json:"hot_reload,omitempty"`
	Plugins                []LoadedPlugin            `json:"plugins"`
}

type PluginCatalogHotReload struct {
	Enabled                      bool                  `json:"enabled"`
	CheckIntervalMS              int64                 `json:"check_interval_ms"`
	UpdateAvailable              bool                  `json:"update_available"`
	LastCheckAt                  string                `json:"last_check_at,omitempty"`
	LastCheckResult              string                `json:"last_check_result,omitempty"`
	LastCheckError               string                `json:"last_check_error,omitempty"`
	LastReloadAt                 string                `json:"last_reload_at,omitempty"`
	LastReloadSource             string                `json:"last_reload_source,omitempty"`
	LastReloadResult             string                `json:"last_reload_result,omitempty"`
	LastReloadError              string                `json:"last_reload_error,omitempty"`
	CatalogFingerprint           string                `json:"catalog_fingerprint,omitempty"`
	FingerprintShortHash         string                `json:"fingerprint_short_hash,omitempty"`
	AppliedFingerprint           string                `json:"applied_fingerprint,omitempty"`
	AppliedFingerprintShortHash  string                `json:"applied_fingerprint_short_hash,omitempty"`
	DetectedFingerprint          string                `json:"detected_fingerprint,omitempty"`
	DetectedFingerprintShortHash string                `json:"detected_fingerprint_short_hash,omitempty"`
	Updates                      []PluginCatalogUpdate `json:"updates,omitempty"`
}

type PluginCatalogUpdate struct {
	PluginID        string `json:"plugin_id"`
	Source          string `json:"source,omitempty"`
	Name            string `json:"name,omitempty"`
	Kind            string `json:"kind,omitempty"`
	Change          string `json:"change"`
	AppliedVersion  string `json:"applied_version,omitempty"`
	DetectedVersion string `json:"detected_version,omitempty"`
	appliedSource   string
	detectedSource  string
}

type PluginRuntimeCapabilities struct {
	BuiltinPipelineID        string   `json:"builtin_pipeline_id"`
	CorePriority             int      `json:"core_priority"`
	ManifestDiscovery        bool     `json:"manifest_discovery"`
	ObjectValidation         bool     `json:"object_validation"`
	ProtectedAssets          bool     `json:"protected_assets"`
	StabilityLevels          []string `json:"stability_levels"`
	ExternalDataplaneAttach  bool     `json:"external_dataplane_attach"`
	ExternalDataplaneEngines []string `json:"external_dataplane_engines"`
	RegistrationOnlyEngines  []string `json:"registration_only_engines,omitempty"`
	SupportedEngines         []string `json:"supported_engines"`
	SupportedHookModes       []string `json:"supported_hook_modes"`
	Limitations              []string `json:"limitations,omitempty"`
}

type PluginRuntimeState struct {
	Mode            string                         `json:"mode"`
	Attachable      bool                           `json:"attachable"`
	Attached        bool                           `json:"attached"`
	AttachmentCount int                            `json:"attachment_count,omitempty"`
	Attachments     []PluginAttachmentState        `json:"attachments,omitempty"`
	WorkerQueue     *PluginControlWorkerQueueState `json:"worker_queue,omitempty"`
	Reason          string                         `json:"reason,omitempty"`
	Error           string                         `json:"error,omitempty"`
}

type PluginControlWorkerQueueState struct {
	PendingRequests     int    `json:"pending_requests"`
	PendingBytes        int64  `json:"pending_bytes"`
	PeakPendingRequests int    `json:"peak_pending_requests"`
	PeakPendingBytes    int64  `json:"peak_pending_bytes"`
	RejectedRequests    uint64 `json:"rejected_requests"`
	RequestLimit        int    `json:"request_limit"`
	ByteLimit           int64  `json:"byte_limit"`
}

type PluginAttachmentState struct {
	HookID       string   `json:"hook_id"`
	Engine       string   `json:"engine"`
	Attach       string   `json:"attach"`
	Stage        string   `json:"stage,omitempty"`
	Interface    string   `json:"interface"`
	Program      string   `json:"program"`
	Mode         string   `json:"mode"`
	Context      []string `json:"context,omitempty"`
	Priority     int      `json:"priority,omitempty"`
	ChainSlot    int      `json:"chain_slot,omitempty"`
	FilterHandle string   `json:"filter_handle,omitempty"`
	Status       string   `json:"status"`
	Error        string   `json:"error,omitempty"`
}

type PluginManifest struct {
	APIVersion  string         `json:"api_version"`
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	Description string         `json:"description,omitempty"`
	Kind        string         `json:"kind"`
	Stability   string         `json:"stability,omitempty"`
	Control     *PluginControl `json:"control,omitempty"`
}

type PluginVirtualInterface struct {
	ID          string `json:"id"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
}

type PluginObject struct {
	ID             string                `json:"id"`
	Path           string                `json:"path"`
	SHA256         string                `json:"sha256,omitempty"`
	Description    string                `json:"description,omitempty"`
	Programs       []PluginObjectProgram `json:"programs,omitempty"`
	Status         string                `json:"status,omitempty"`
	Error          string                `json:"error,omitempty"`
	ResolvedSHA256 string                `json:"resolved_sha256,omitempty"`
	ProgramCount   int                   `json:"program_count,omitempty"`
	MapCount       int                   `json:"map_count,omitempty"`
}

type PluginObjectProgram struct {
	ID               string `json:"id"`
	Section          string `json:"section"`
	Type             string `json:"type,omitempty"`
	AttachType       string `json:"attach_type,omitempty"`
	InstructionCount int    `json:"instruction_count,omitempty"`
}

type PluginHook struct {
	ID         string   `json:"id"`
	Engine     string   `json:"engine"`
	Attach     string   `json:"attach,omitempty"`
	Stage      string   `json:"stage"`
	Priority   int      `json:"priority,omitempty"`
	Program    string   `json:"program,omitempty"`
	Mode       string   `json:"mode,omitempty"`
	Context    []string `json:"context,omitempty"`
	Interfaces []string `json:"interfaces,omitempty"`
}

type PluginResource struct {
	ID             string   `json:"id"`
	Description    string   `json:"description,omitempty"`
	Methods        []string `json:"methods,omitempty"`
	ControlMethods []string `json:"control_methods,omitempty"`
	RuntimeUpdate  string   `json:"runtime_update,omitempty"`
	MaxRecords     int      `json:"max_records,omitempty"`
	MaxRecordBytes int      `json:"max_record_bytes,omitempty"`
	SecretFields   []string `json:"secret_fields,omitempty"`
}

type PluginAction struct {
	ID              string `json:"id"`
	Description     string `json:"description,omitempty"`
	RuntimeUpdate   string `json:"runtime_update,omitempty"`
	MaxPayloadBytes int    `json:"max_payload_bytes,omitempty"`
}

type PluginControl struct {
	Main           string                 `json:"main,omitempty"`
	SHA256         string                 `json:"sha256,omitempty"`
	ResolvedSHA256 string                 `json:"resolved_sha256,omitempty"`
	Permissions    []string               `json:"permissions,omitempty"`
	ResourceAccess []PluginResourceAccess `json:"resource_access,omitempty"`
	ActionAccess   []PluginActionAccess   `json:"action_access,omitempty"`
	NetAccess      []PluginNetAccess      `json:"net_access,omitempty"`
}

type PluginResourceAccess struct {
	Plugin   string   `json:"plugin"`
	Resource string   `json:"resource"`
	Methods  []string `json:"methods,omitempty"`
}

type PluginActionAccess struct {
	Plugin  string   `json:"plugin"`
	Actions []string `json:"actions,omitempty"`
}

type PluginNetAccess struct {
	Interfaces []string `json:"interfaces,omitempty"`
	Operations []string `json:"operations,omitempty"`
}

type PluginUI struct {
	StaticDir      string `json:"static_dir,omitempty"`
	Entry          string `json:"entry,omitempty"`
	Page           string `json:"page,omitempty"`
	PageTitle      string `json:"page_title,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	ResolvedSHA256 string `json:"resolved_sha256,omitempty"`
}

type LoadedPlugin struct {
	PluginManifest
	Builtin           bool                     `json:"builtin,omitempty"`
	Capabilities      []string                 `json:"capabilities,omitempty"`
	VirtualInterfaces []PluginVirtualInterface `json:"virtual_interfaces,omitempty"`
	Objects           []PluginObject           `json:"objects,omitempty"`
	Hooks             []PluginHook             `json:"hooks,omitempty"`
	Resources         []PluginResource         `json:"resources,omitempty"`
	Actions           []PluginAction           `json:"actions,omitempty"`
	UI                *PluginUI                `json:"ui,omitempty"`
	Enabled           bool                     `json:"enabled"`
	Status            string                   `json:"status"`
	Runtime           PluginRuntimeState       `json:"runtime"`
	Error             string                   `json:"error,omitempty"`
	Source            string                   `json:"source,omitempty"`
	AssetBasePath     string                   `json:"asset_base_path,omitempty"`

	rootDir           string
	staticDir         string
	controlMainPath   string
	sourceFingerprint string
}

func loadPluginCatalog(cfg *Config) PluginCatalog {
	pluginsDir := defaultPluginsDir
	externalEnabled := false
	if cfg != nil {
		pluginsDir = normalizePluginsDir(cfg.PluginsDir)
		externalEnabled = cfg.PluginsEnabled()
	}

	catalog := PluginCatalog{
		ExternalPluginsEnabled: externalEnabled,
		Directory:              pluginsDir,
		Runtime:                pluginRuntimeCapabilities(cfg),
		Plugins:                []LoadedPlugin{builtinVeerPlugin()},
	}
	seen := map[string]struct{}{builtinPluginID: {}, builtinPluginPipelineID: {}}
	if !externalEnabled {
		return catalog
	}

	catalog.Plugins = append(catalog.Plugins, scanExternalPlugins(pluginsDir, seen)...)
	externalPlugins := catalog.Plugins[1:]
	sort.SliceStable(externalPlugins, func(i, j int) bool {
		a := externalPlugins[i]
		b := externalPlugins[j]
		if a.ID == b.ID {
			return a.Source < b.Source
		}
		return a.ID < b.ID
	})
	return catalog
}

func loadPluginCatalogWithState(cfg *Config, db store.RuleStore) PluginCatalog {
	return applyPluginStatesFromDB(loadPluginCatalog(cfg), db)
}

func applyPluginStatesFromDB(catalog PluginCatalog, db store.RuleStore) PluginCatalog {
	for i := range catalog.Plugins {
		catalog.Plugins[i].Enabled = true
		if catalog.Plugins[i].Builtin {
			continue
		}
	}
	if pluginRuleStoreIsNil(db) {
		return catalog
	}
	states, err := store.GetPluginStates(db)
	if err != nil {
		logPluginStateLoadError(err)
		return catalog
	}
	enabledByPlugin := make(map[string]bool, len(states))
	for _, state := range states {
		pluginID := strings.TrimSpace(strings.ToLower(state.PluginID))
		if pluginID == "" {
			continue
		}
		enabledByPlugin[pluginID] = state.Enabled
	}
	for i := range catalog.Plugins {
		plugin := &catalog.Plugins[i]
		if plugin.Builtin {
			plugin.Enabled = true
			continue
		}
		enabled, ok := enabledByPlugin[plugin.ID]
		if !ok || enabled {
			plugin.Enabled = true
			continue
		}
		disableLoadedPlugin(plugin)
	}
	return catalog
}

func pluginRuleStoreIsNil(db store.RuleStore) bool {
	if db == nil {
		return true
	}
	value := reflect.ValueOf(db)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func logPluginStateLoadError(err error) {
	if err != nil {
		log.Printf("plugin state: load failed: %v", err)
	}
}

func disableLoadedPlugin(plugin *LoadedPlugin) {
	if plugin == nil || plugin.Builtin {
		return
	}
	plugin.Enabled = false
	plugin.Status = pluginStatusDisabled
	plugin.Runtime = disabledPluginRuntimeState()
	plugin.Error = ""
	plugin.Capabilities = nil
	plugin.VirtualInterfaces = nil
	plugin.Objects = nil
	plugin.Hooks = nil
	plugin.Resources = nil
	plugin.Actions = nil
	plugin.UI = nil
	plugin.staticDir = ""
	plugin.AssetBasePath = ""
}

func pluginRuntimeCapabilities(cfg *Config) PluginRuntimeCapabilities {
	externalDataplaneAttach := false
	if cfg != nil {
		externalDataplaneAttach = cfg.PluginsEnabled() && cfg.PluginsDataplaneEnabled()
	}
	return PluginRuntimeCapabilities{
		BuiltinPipelineID:        builtinPluginPipelineID,
		CorePriority:             pluginPipelineCorePriority,
		ManifestDiscovery:        true,
		ObjectValidation:         true,
		ProtectedAssets:          true,
		StabilityLevels:          []string{pluginStabilityLab, pluginStabilityPreview, pluginStabilityStable, pluginStabilityDeprecated},
		ExternalDataplaneAttach:  externalDataplaneAttach,
		ExternalDataplaneEngines: []string{kernelEngineTC},
		RegistrationOnlyEngines:  []string{kernelEngineXDP},
		SupportedEngines:         []string{kernelEngineTC, kernelEngineXDP, "control"},
		SupportedHookModes:       []string{"observe", "rewrite", "redirect", "drop", "control"},
		Limitations: []string{
			"veer is a logical tc tail-call pipeline, not a Linux netdev; real interfaces are only attach targets or optional handoff adapters",
			"external dataplane loading is opt-in via plugins_dataplane_enabled and supports tc pipeline.attach direction=forward/reply hooks ordered around the built-in Veer Core priority",
			"tc pipeline plugin priority is compared with Veer Core priority 1000; lower priority runs before core lookup and higher priority runs after core lookup before apply/redirect on the selected packet direction; runtime maps that intent to the concrete pre/post chain",
			"tc pipeline plugins are callable stages in the shared prog-array chain and must tail-call the shared continue slot after processing unless they intentionally return a final tc action",
			"post_lookup and post_reply tc plugins may read the shared tc_plugin_ctx_v4 context after Veer Core has parsed IPv4/L4 and matched a rule or flow",
			"forward post-apply hooks are not available yet; pure eBPF WAN encapsulation after core NAT/rewrite still needs a dedicated post-apply stage or a Linux handoff adapter",
			"control.main scripts run in persistent per-plugin Goja control VMs only; declared worker VMs can offload control tasks but never run in packet hot paths",
			"control permissions gate kv/resource/secret/crypto/timer/worker/net.l2/net.tcp/net.udp/plugin.resource/ebpf map updates; registration APIs are only available during control script initialization",
			"plugin.resource is a two-step grant: the permission enables the API namespace and control.resource_access must explicitly allow each target plugin/resource/method",
			"control timer and worker state is capped at 64 named timers and 16 named workers per plugin to avoid control-plane resource exhaustion",
			"outstanding worker requests are capped per plugin at 256 requests and 16 MiB of payload across all worker queues and executions",
			"persistent TCP/UDP sockets are host-owned and capped at 32 handles per plugin; transactional upgrades transfer compatible handles to the candidate VM, while cold replacement, plugin deactivation, and runtime shutdown close them",
			"plugin dataplane mode is a trust contract for installed eBPF objects; keep external dataplane loading disabled unless the object source is trusted",
			"plugin stability is declared by manifest.stability: lab is for examples/tests only, preview is suitable for controlled deployments, stable is expected to be production-ready, and deprecated should not be used for new deployments",
			"lab, preview, and stable plugins can execute control scripts and join external tc dataplane when the corresponding global plugin switches are enabled; deprecated plugins are always blocked",
			"xdp and non-Veer-pipeline tc hooks are registration-only until their dispatchers are added",
			"plugin UI assets require the same API bearer token; prefer single-file UI assets or authenticated fetches",
			"veer is the built-in forward pipeline and cannot be replaced by an external plugin manifest",
		},
	}
}

func builtinPluginRuntimeState() PluginRuntimeState {
	return PluginRuntimeState{
		Mode:       pluginRuntimeModeBuiltin,
		Attachable: true,
		Attached:   true,
	}
}

func externalPluginRuntimeState() PluginRuntimeState {
	return PluginRuntimeState{
		Mode:       pluginRuntimeModeRegistered,
		Attachable: false,
		Attached:   false,
		Reason:     "external dataplane loading is disabled or no supported tc pipeline hook was registered; the plugin is limited to discovery, control scripts, object validation, and static UI assets",
	}
}

func disabledPluginRuntimeState() PluginRuntimeState {
	return PluginRuntimeState{
		Mode:       pluginRuntimeModeDisabled,
		Attachable: false,
		Attached:   false,
		Reason:     "plugin is disabled",
	}
}

func invalidPluginRuntimeState() PluginRuntimeState {
	return PluginRuntimeState{
		Mode:       pluginRuntimeModeInvalid,
		Attachable: false,
		Attached:   false,
		Reason:     "plugin manifest, object, hook, or UI asset validation failed",
	}
}

func builtinVeerPlugin() LoadedPlugin {
	return LoadedPlugin{
		PluginManifest: PluginManifest{
			APIVersion:  pluginAPIVersionV1,
			ID:          builtinPluginID,
			Name:        "Veer Core",
			Version:     "builtin",
			Kind:        "pipeline",
			Stability:   pluginStabilityStable,
			Description: "Built-in logical pipeline for the Veer TC/XDP dataplane.",
		},
		Builtin: true,
		Capabilities: []string{
			"port_forward",
			"range_forward",
			"shared_site_proxy",
			"egress_nat",
			"managed_network",
			"ipv6_assignment",
			"kernel_tc",
			"kernel_xdp",
			"runtime_stats",
		},
		VirtualInterfaces: []PluginVirtualInterface{
			{
				ID:          builtinPluginPipelineID,
				Type:        "pipeline",
				Description: "Logical node representing the built-in NAT/forward dataplane.",
			},
		},
		Objects: []PluginObject{
			{ID: "veer-tc", Path: "builtin:veer-tc", Description: "Built-in TC object compiled into Veer.", Status: pluginObjectStatusBuiltin},
			{ID: "veer-xdp", Path: "builtin:veer-xdp", Description: "Built-in XDP object compiled into Veer.", Status: pluginObjectStatusBuiltin},
		},
		Hooks: []PluginHook{
			{ID: "tc-ingress", Engine: kernelEngineTC, Attach: "ingress", Stage: "forward", Priority: pluginPipelineCorePriority, Program: "builtin:veer-tc", Mode: "rewrite"},
			{ID: "tc-reply", Engine: kernelEngineTC, Attach: "ingress", Stage: "reply", Priority: pluginPipelineCorePriority, Program: "builtin:veer-tc", Mode: "rewrite"},
			{ID: "xdp-ingress", Engine: kernelEngineXDP, Attach: "ingress", Stage: "forward", Priority: 0, Program: "builtin:veer-xdp", Mode: "rewrite"},
		},
		Enabled: true,
		Status:  pluginStatusBuiltin,
		Runtime: builtinPluginRuntimeState(),
	}
}

func scanExternalPlugins(pluginsDir string, seen map[string]struct{}) []LoadedPlugin {
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return []LoadedPlugin{pluginLoadError("plugins", "", fmt.Sprintf("read plugin directory: %v", err))}
	}

	var out []LoadedPlugin
	errorIndex := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		source := entry.Name()
		rootDir := filepath.Join(pluginsDir, source)
		manifestPath := filepath.Join(rootDir, pluginManifestFile)
		if _, err := os.Lstat(manifestPath); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			errorIndex++
			out = append(out, pluginLoadError(fmt.Sprintf("invalid-%d", errorIndex), source, fmt.Sprintf("stat manifest: %v", err)))
			continue
		}
		plugin, err := loadPluginFromDir(rootDir, source)
		if err != nil {
			errorIndex++
			out = append(out, pluginLoadError(fmt.Sprintf("invalid-%d", errorIndex), source, err.Error()))
			continue
		}
		if _, ok := seen[plugin.ID]; ok {
			plugin.Status = pluginStatusError
			plugin.Runtime = invalidPluginRuntimeState()
			plugin.Error = fmt.Sprintf("duplicate plugin id %q", plugin.ID)
			plugin.staticDir = ""
			plugin.AssetBasePath = ""
			out = append(out, plugin)
			continue
		}
		seen[plugin.ID] = struct{}{}
		out = append(out, plugin)
	}
	return out
}

func loadPluginFromDir(rootDir, source string) (LoadedPlugin, error) {
	manifestPath := filepath.Join(rootDir, pluginManifestFile)
	cleanRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return LoadedPlugin{}, fmt.Errorf("resolve plugin root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		return LoadedPlugin{}, fmt.Errorf("resolve plugin root: %w", err)
	}
	sourceFingerprint, _ := buildPluginDirectoryFingerprint(realRoot)
	cleanManifest, err := filepath.Abs(manifestPath)
	if err != nil {
		return LoadedPlugin{}, fmt.Errorf("resolve manifest: %w", err)
	}
	if !pathWithinRoot(cleanRoot, cleanManifest) {
		return LoadedPlugin{}, fmt.Errorf("%s escapes plugin root", pluginManifestFile)
	}
	realManifest, err := filepath.EvalSymlinks(cleanManifest)
	if err != nil {
		return LoadedPlugin{}, fmt.Errorf("read manifest: %w", err)
	}
	if !pathWithinRoot(realRoot, realManifest) {
		return LoadedPlugin{}, fmt.Errorf("%s escapes plugin root", pluginManifestFile)
	}
	stat, err := os.Stat(realManifest)
	if err != nil {
		return LoadedPlugin{}, fmt.Errorf("read manifest: %w", err)
	}
	if stat.IsDir() {
		return LoadedPlugin{}, fmt.Errorf("%s is a directory", pluginManifestFile)
	}
	if stat.Size() > pluginManifestMaxSize {
		return LoadedPlugin{}, fmt.Errorf("%s exceeds %d bytes", pluginManifestFile, pluginManifestMaxSize)
	}

	data, err := os.ReadFile(realManifest) // #nosec G304 -- realManifest is symlink-resolved and checked against the plugin root.
	if err != nil {
		return LoadedPlugin{}, fmt.Errorf("read manifest: %w", err)
	}

	var manifest PluginManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return LoadedPlugin{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := normalizePluginManifest(&manifest); err != nil {
		return LoadedPlugin{}, err
	}

	plugin := LoadedPlugin{
		PluginManifest:    manifest,
		Enabled:           true,
		Status:            pluginStatusActive,
		Runtime:           externalPluginRuntimeState(),
		Source:            source,
		rootDir:           rootDir,
		sourceFingerprint: sourceFingerprint,
	}
	if plugin.Status == pluginStatusActive {
		if err := resolvePluginControl(&plugin); err != nil {
			plugin.Status = pluginStatusError
			plugin.Error = err.Error()
			plugin.controlMainPath = ""
		}
	}
	if plugin.Status != pluginStatusActive {
		plugin.Runtime = invalidPluginRuntimeState()
		plugin.staticDir = ""
		plugin.AssetBasePath = ""
	}
	return plugin, nil
}

func pluginLoadError(id, source, message string) LoadedPlugin {
	id = strings.TrimSpace(strings.ToLower(id))
	if !pluginIDPattern.MatchString(id) {
		id = "invalid"
	}
	name := id
	if source != "" {
		name = source
	}
	return LoadedPlugin{
		PluginManifest: PluginManifest{
			APIVersion: pluginAPIVersionV1,
			ID:         id,
			Name:       name,
			Kind:       "pipeline",
			Stability:  pluginStabilityLab,
		},
		Status:  pluginStatusError,
		Enabled: true,
		Runtime: invalidPluginRuntimeState(),
		Error:   strings.TrimSpace(message),
		Source:  source,
	}
}
