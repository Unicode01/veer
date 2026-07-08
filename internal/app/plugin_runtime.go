package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	defaultPluginsDir     = "plugins/runtime"
	pluginManifestFile    = "plugin.json"
	pluginManifestMaxSize = 1 << 20
	pluginObjectMaxSize   = 16 << 20
	pluginControlMaxSize  = 1 << 20

	pluginStatusActive  = "active"
	pluginStatusBuiltin = "builtin"
	pluginStatusError   = "error"

	pluginRuntimeModeBuiltin    = "builtin"
	pluginRuntimeModeDataplane  = "dataplane"
	pluginRuntimeModeControl    = "control"
	pluginRuntimeModeError      = "error"
	pluginRuntimeModeRegistered = "registered"
	pluginRuntimeModeInvalid    = "invalid"

	pluginObjectStatusBuiltin  = "builtin"
	pluginObjectStatusVerified = "verified"
	pluginObjectStatusError    = "error"

	pluginAPIVersionV1 = "v1"

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

var (
	pluginIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	pluginTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	pluginHashPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type PluginCatalog struct {
	ExternalPluginsEnabled bool                      `json:"external_plugins_enabled"`
	Directory              string                    `json:"directory"`
	Runtime                PluginRuntimeCapabilities `json:"runtime"`
	Plugins                []LoadedPlugin            `json:"plugins"`
}

type PluginRuntimeCapabilities struct {
	BuiltinPipelineID       string   `json:"builtin_pipeline_id"`
	CorePriority            int      `json:"core_priority"`
	ManifestDiscovery       bool     `json:"manifest_discovery"`
	ObjectValidation        bool     `json:"object_validation"`
	ProtectedAssets         bool     `json:"protected_assets"`
	StabilityLevels         []string `json:"stability_levels"`
	ExternalDataplaneAttach bool     `json:"external_dataplane_attach"`
	SupportedEngines        []string `json:"supported_engines"`
	SupportedHookModes      []string `json:"supported_hook_modes"`
	Limitations             []string `json:"limitations,omitempty"`
}

type PluginRuntimeState struct {
	Mode            string                  `json:"mode"`
	Attachable      bool                    `json:"attachable"`
	Attached        bool                    `json:"attached"`
	AttachmentCount int                     `json:"attachment_count,omitempty"`
	Attachments     []PluginAttachmentState `json:"attachments,omitempty"`
	Reason          string                  `json:"reason,omitempty"`
	Error           string                  `json:"error,omitempty"`
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
	Status            string                   `json:"status"`
	Runtime           PluginRuntimeState       `json:"runtime"`
	Error             string                   `json:"error,omitempty"`
	Source            string                   `json:"source,omitempty"`
	AssetBasePath     string                   `json:"asset_base_path,omitempty"`

	rootDir         string
	staticDir       string
	controlMainPath string
}

func loadPluginCatalog(cfg *Config) PluginCatalog {
	pluginsDir := defaultPluginsDir
	externalEnabled := true
	if cfg != nil {
		pluginsDir = normalizePluginsDir(cfg.PluginsDir)
		externalEnabled = cfg.PluginsEnabled()
	}

	catalog := PluginCatalog{
		ExternalPluginsEnabled: externalEnabled,
		Directory:              pluginsDir,
		Runtime:                pluginRuntimeCapabilities(cfg),
		Plugins:                []LoadedPlugin{builtinFVTapPlugin()},
	}
	seen := map[string]struct{}{"fvtap": {}}
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

func pluginRuntimeCapabilities(cfg *Config) PluginRuntimeCapabilities {
	externalDataplaneAttach := false
	if cfg != nil {
		externalDataplaneAttach = cfg.PluginsEnabled() && cfg.PluginsDataplaneEnabled()
	}
	return PluginRuntimeCapabilities{
		BuiltinPipelineID:       "fvtap",
		CorePriority:            pluginPipelineCorePriority,
		ManifestDiscovery:       true,
		ObjectValidation:        true,
		ProtectedAssets:         true,
		StabilityLevels:         []string{pluginStabilityLab, pluginStabilityPreview, pluginStabilityStable, pluginStabilityDeprecated},
		ExternalDataplaneAttach: externalDataplaneAttach,
		SupportedEngines:        []string{kernelEngineTC, kernelEngineXDP, "control"},
		SupportedHookModes:      []string{"observe", "rewrite", "redirect", "drop", "control"},
		Limitations: []string{
			"external dataplane loading is opt-in via plugins_dataplane_enabled and supports tc stage=forward/reply hooks ordered around the built-in fvtap core priority",
			"tc pipeline plugin priority is compared with fvtap core priority 1000; lower priority runs before core lookup and higher priority runs after core lookup before apply/redirect on the selected packet direction",
			"tc pipeline plugins must tail-call the shared tc_prog_chain_v4 continue slot after processing unless they intentionally return a final tc action",
			"post_lookup and post_reply tc plugins may read the shared tc_plugin_ctx_v4 context after fvtap has parsed IPv4/L4 and matched a rule or flow",
			"control.main scripts run in persistent per-plugin Goja control VMs only; declared worker VMs can offload control tasks but never run in packet hot paths",
			"control permissions gate kv/resource/secret/crypto/timer/worker/net.l2/net.udp/plugin.resource/ebpf map updates; registration APIs are only available during control script initialization",
			"plugin.resource is a two-step grant: the permission enables the API namespace and control.resource_access must explicitly allow each target plugin/resource/method",
			"control timer and worker state is capped at 64 named timers and 16 named workers per plugin to avoid control-plane resource exhaustion",
			"plugin dataplane mode is a trust contract for installed eBPF objects; keep external dataplane loading disabled unless the object source is trusted",
			"plugin stability is declared by manifest.stability: lab is for examples/tests only, preview is suitable for controlled deployments, stable is expected to be production-ready, and deprecated should not be used for new deployments",
			"lab, preview, and stable plugins can execute control scripts and join external tc dataplane when the corresponding global plugin switches are enabled; deprecated plugins are always blocked",
			"xdp and non-fvtap tc hooks are registration-only until their dispatchers are added",
			"plugin UI assets require the same API bearer token; prefer single-file UI assets or authenticated fetches",
			"fvtap is the built-in forward pipeline and cannot be replaced by an external plugin manifest",
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

func invalidPluginRuntimeState() PluginRuntimeState {
	return PluginRuntimeState{
		Mode:       pluginRuntimeModeInvalid,
		Attachable: false,
		Attached:   false,
		Reason:     "plugin manifest, object, hook, or UI asset validation failed",
	}
}

func builtinFVTapPlugin() LoadedPlugin {
	return LoadedPlugin{
		PluginManifest: PluginManifest{
			APIVersion:  pluginAPIVersionV1,
			ID:          "fvtap",
			Name:        "Forward Virtual Tap",
			Version:     "builtin",
			Kind:        "pipeline",
			Stability:   pluginStabilityStable,
			Description: "Built-in logical pipeline for the current forward TC/XDP dataplane.",
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
				ID:          "fvtap",
				Type:        "pipeline",
				Description: "Logical node representing the built-in NAT/forward dataplane.",
			},
		},
		Objects: []PluginObject{
			{ID: "forward-tc", Path: "builtin:forward-tc", Description: "Built-in TC object compiled into the service.", Status: pluginObjectStatusBuiltin},
			{ID: "forward-xdp", Path: "builtin:forward-xdp", Description: "Built-in XDP object compiled into the service.", Status: pluginObjectStatusBuiltin},
		},
		Hooks: []PluginHook{
			{ID: "tc-ingress", Engine: kernelEngineTC, Attach: "ingress", Stage: "forward", Priority: pluginPipelineCorePriority, Program: "builtin:forward-tc", Mode: "rewrite"},
			{ID: "tc-reply", Engine: kernelEngineTC, Attach: "ingress", Stage: "reply", Priority: pluginPipelineCorePriority, Program: "builtin:forward-tc", Mode: "rewrite"},
			{ID: "xdp-ingress", Engine: kernelEngineXDP, Attach: "ingress", Stage: "forward", Priority: 0, Program: "builtin:forward-xdp", Mode: "rewrite"},
		},
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
		PluginManifest: manifest,
		Status:         pluginStatusActive,
		Runtime:        externalPluginRuntimeState(),
		Source:         source,
		rootDir:        rootDir,
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
		Runtime: invalidPluginRuntimeState(),
		Error:   strings.TrimSpace(message),
		Source:  source,
	}
}
