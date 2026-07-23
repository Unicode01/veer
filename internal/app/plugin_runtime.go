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
	pluginObjectMapPreserve    = "preserve"
	pluginObjectMapReset       = "reset"
	pluginObjectMapMigrate     = "migrate"

	pluginAPIVersionV1   = "v1"
	pluginRuntimeVersion = "1.0.0"
	pluginControlAPIABI  = 1
	pluginTCPipelineABI  = 2

	pluginTCPipelineProgramArrayEntries  = 111
	pluginTCPipelineStageHookLimit       = 8
	pluginTCPipelineDirectionHookLimit   = 14
	pluginXDPPipelineProgramArrayEntries = 24
	pluginXDPPipelineHookLimit           = 8

	pluginPipelineDirectionForward = "forward"
	pluginPipelineDirectionReply   = "reply"
	pluginPipelinePhaseAroundCore  = "around_core"
	pluginPipelinePhaseAfterApply  = "after_apply"
	pluginPipelineStagePreForward  = "pre_forward"
	pluginPipelineStagePostLookup  = "post_lookup"
	pluginPipelineStagePostApply   = "post_apply"
	pluginPipelineStagePreReply    = "pre_reply"
	pluginPipelineStagePostReply   = "post_reply"
	pluginPipelineStageReplyApply  = "post_reply_apply"

	pluginSandboxLevelNone    = "none"
	pluginSandboxLevelMinimal = "minimal"
	pluginSandboxLevelPartial = "partial"
	pluginSandboxLevelFull    = "full"

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
	pluginObjectStateMapLimit           = 128
	pluginObjectMapSchemaVersionMax     = 1_000_000
	pluginPacketMetadataBindingLimit    = 16
	pluginPacketMetadataNamespaceLimit  = 32
	pluginPacketMetadataPayloadMaxBytes = 64

	pluginHookContextTCPluginCtxV4      = "tc_plugin_ctx_v4"
	pluginHookContextTCPluginCtxV6      = "tc_plugin_ctx_v6"
	pluginPacketMetadataAccessRead      = "read"
	pluginPacketMetadataAccessReadWrite = "read_write"
)

func reservedBuiltinPluginID(id string) bool {
	return id == builtinPluginID || id == builtinPluginPipelineID
}

var (
	pluginIDPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	pluginTokenPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	pluginHashPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	pluginBPFMapPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
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
	BuiltinPipelineID        string                             `json:"builtin_pipeline_id"`
	RuntimeVersion           string                             `json:"runtime_version"`
	ControlAPIABI            int                                `json:"control_api_abi"`
	TCPipelineABI            int                                `json:"tc_pipeline_abi"`
	HostOS                   string                             `json:"host_os"`
	HostArch                 string                             `json:"host_arch"`
	KernelRelease            string                             `json:"kernel_release,omitempty"`
	Features                 []string                           `json:"features"`
	AvailableFeatures        []string                           `json:"available_features"`
	FeatureStatus            map[string]PluginHostFeatureStatus `json:"feature_status"`
	CorePriority             int                                `json:"core_priority"`
	ManifestDiscovery        bool                               `json:"manifest_discovery"`
	ObjectValidation         bool                               `json:"object_validation"`
	ProtectedAssets          bool                               `json:"protected_assets"`
	MinimumSandboxLevel      string                             `json:"minimum_sandbox_level"`
	RequireSignedPackages    bool                               `json:"require_signed_packages"`
	StabilityLevels          []string                           `json:"stability_levels"`
	ExternalDataplaneAttach  bool                               `json:"external_dataplane_attach"`
	ExternalDataplaneEngines []string                           `json:"external_dataplane_engines"`
	RegistrationOnlyEngines  []string                           `json:"registration_only_engines,omitempty"`
	SupportedEngines         []string                           `json:"supported_engines"`
	SupportedHookModes       []string                           `json:"supported_hook_modes"`
	TCPipeline               PluginTCPipelineCapabilities       `json:"tc_pipeline"`
	PacketMetadata           PluginPacketMetadataCapabilities   `json:"packet_metadata"`
	XDPPipeline              PluginXDPPipelineCapabilities      `json:"xdp_pipeline"`
	ResourceLimits           PluginResourceLimits               `json:"resource_limits"`
	ResourceUsage            PluginResourceUsage                `json:"resource_usage"`
	Limitations              []string                           `json:"limitations,omitempty"`
}

type PluginHostFeatureStatus struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type PluginTCPipelineCapabilities struct {
	ProgramArrayEntries int      `json:"program_array_entries"`
	StageHookLimit      int      `json:"stage_hook_limit"`
	DirectionHookLimit  int      `json:"direction_hook_limit"`
	Directions          []string `json:"directions"`
	Phases              []string `json:"phases"`
	HookStages          []string `json:"hook_stages"`
	Attaches            []string `json:"attaches"`
}

type PluginXDPPipelineCapabilities struct {
	ProgramArrayEntries int      `json:"program_array_entries"`
	HookLimit           int      `json:"hook_limit"`
	HookStages          []string `json:"hook_stages"`
	Attaches            []string `json:"attaches"`
	RequiresInterfaces  bool     `json:"requires_interfaces"`
}

type PluginPacketMetadataCapabilities struct {
	ABI                int      `json:"abi"`
	BindingLimit       int      `json:"binding_limit"`
	NamespaceLimit     int      `json:"namespace_limit"`
	PayloadMaxBytes    int      `json:"payload_max_bytes"`
	SupportedAccess    []string `json:"supported_access"`
	RequiresTC         bool     `json:"requires_tc"`
	GenerationIsolated bool     `json:"generation_isolated"`
}

type PluginRuntimeState struct {
	Mode            string                         `json:"mode"`
	Attachable      bool                           `json:"attachable"`
	Attached        bool                           `json:"attached"`
	AttachmentCount int                            `json:"attachment_count,omitempty"`
	Attachments     []PluginAttachmentState        `json:"attachments,omitempty"`
	WorkerQueue     *PluginControlWorkerQueueState `json:"worker_queue,omitempty"`
	EventBus        *PluginEventBusState           `json:"event_bus,omitempty"`
	Operations      *PluginOperationRuntimeState   `json:"operations,omitempty"`
	RingBuffers     *PluginRingBusState            `json:"ring_buffers,omitempty"`
	ControlHealth   *PluginControlHealthState      `json:"control_health,omitempty"`
	Isolation       *PluginControlIsolationState   `json:"isolation,omitempty"`
	Metrics         []PluginMetricState            `json:"metrics,omitempty"`
	Leases          []PluginResourceLeaseState     `json:"leases,omitempty"`
	Reason          string                         `json:"reason,omitempty"`
	Error           string                         `json:"error,omitempty"`
}

type PluginOperationRuntimeState struct {
	Total     int            `json:"total"`
	Resumable int            `json:"resumable"`
	Bytes     int64          `json:"bytes"`
	ByStatus  map[string]int `json:"by_status"`
}

type PluginMetricState struct {
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
	UpdatedAt string            `json:"updated_at,omitempty"`
}

type PluginResourceLeaseState struct {
	Type      string `json:"type"`
	Key       string `json:"key"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type PluginControlIsolationState struct {
	Enabled               bool   `json:"enabled"`
	Platform              string `json:"platform"`
	ProcessCount          int    `json:"process_count"`
	PIDs                  []int  `json:"pids,omitempty"`
	RestartCount          uint64 `json:"restart_count"`
	RSSBytes              uint64 `json:"rss_bytes"`
	RestartBackoffUntil   string `json:"restart_backoff_until,omitempty"`
	LastError             string `json:"last_error,omitempty"`
	ResourceLimitMode     string `json:"resource_limit_mode"`
	ResourceLimitDegraded string `json:"resource_limit_degraded,omitempty"`
	SandboxMode           string `json:"sandbox_mode,omitempty"`
	SandboxLevel          string `json:"sandbox_level,omitempty"`
	SandboxDegraded       string `json:"sandbox_degraded,omitempty"`
}

type PluginHostSandboxState struct {
	Platform         string   `json:"platform"`
	Mode             string   `json:"mode"`
	Level            string   `json:"level"`
	NoNewPrivileges  bool     `json:"no_new_privileges,omitempty"`
	IdentityIsolated bool     `json:"identity_isolated,omitempty"`
	FilesystemPolicy bool     `json:"filesystem_policy,omitempty"`
	SyscallPolicy    bool     `json:"syscall_policy,omitempty"`
	Degraded         []string `json:"degraded,omitempty"`
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
	HookID         string                        `json:"hook_id"`
	Engine         string                        `json:"engine"`
	Attach         string                        `json:"attach"`
	Stage          string                        `json:"stage,omitempty"`
	Interface      string                        `json:"interface"`
	Program        string                        `json:"program"`
	Mode           string                        `json:"mode"`
	Context        []string                      `json:"context,omitempty"`
	PacketMetadata []PluginPacketMetadataBinding `json:"packet_metadata,omitempty"`
	Priority       int                           `json:"priority,omitempty"`
	Before         []string                      `json:"before,omitempty"`
	After          []string                      `json:"after,omitempty"`
	Order          int                           `json:"order,omitempty"`
	ChainSlot      int                           `json:"chain_slot,omitempty"`
	FilterHandle   string                        `json:"filter_handle,omitempty"`
	Status         string                        `json:"status"`
	Error          string                        `json:"error,omitempty"`
	Metrics        *PluginAttachmentMetrics      `json:"metrics,omitempty"`
}

type PluginAttachmentMetrics struct {
	Total PluginPacketMetrics `json:"total"`
	IPv4  PluginPacketMetrics `json:"ipv4"`
	IPv6  PluginPacketMetrics `json:"ipv6"`
}

type PluginPacketMetrics struct {
	Packets          uint64 `json:"packets"`
	Bytes            uint64 `json:"bytes"`
	ContinuedPackets uint64 `json:"continued_packets"`
	TailCallMisses   uint64 `json:"tail_call_misses"`
	TerminalPackets  uint64 `json:"terminal_packets"`
	DroppedPackets   uint64 `json:"dropped_packets,omitempty"`
}

type PluginManifest struct {
	APIVersion    string               `json:"api_version"`
	ID            string               `json:"id"`
	Name          string               `json:"name"`
	Version       string               `json:"version"`
	Description   string               `json:"description,omitempty"`
	Kind          string               `json:"kind"`
	Stability     string               `json:"stability,omitempty"`
	Compatibility *PluginCompatibility `json:"compatibility,omitempty"`
	Dependencies  []PluginDependency   `json:"dependencies,omitempty"`
	Conflicts     []PluginConflict     `json:"conflicts,omitempty"`
	Control       *PluginControl       `json:"control,omitempty"`
}

type PluginCompatibility struct {
	Runtime       string   `json:"runtime,omitempty"`
	ControlAPIABI int      `json:"control_api_abi,omitempty"`
	TCPipelineABI int      `json:"tc_pipeline_abi,omitempty"`
	OS            []string `json:"os,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Kernel        string   `json:"kernel,omitempty"`
	Features      []string `json:"features,omitempty"`
}

type PluginDependency struct {
	ID       string `json:"id"`
	Version  string `json:"version,omitempty"`
	Optional bool   `json:"optional,omitempty"`
}

type PluginConflict struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
}

type PluginVirtualInterface struct {
	ID          string `json:"id"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
}

type PluginObject struct {
	ID             string                     `json:"id"`
	Path           string                     `json:"path,omitempty"`
	SHA256         string                     `json:"sha256,omitempty"`
	Variants       []PluginObjectVariant      `json:"variants,omitempty"`
	SelectedArch   string                     `json:"selected_architecture,omitempty"`
	Description    string                     `json:"description,omitempty"`
	Programs       []PluginObjectProgram      `json:"programs,omitempty"`
	StateMaps      []PluginObjectStateMap     `json:"state_maps,omitempty"`
	Status         string                     `json:"status,omitempty"`
	Error          string                     `json:"error,omitempty"`
	ResolvedSHA256 string                     `json:"resolved_sha256,omitempty"`
	ProgramCount   int                        `json:"program_count,omitempty"`
	MapCount       int                        `json:"map_count,omitempty"`
	ResourceUsage  *PluginObjectResourceUsage `json:"resource_usage,omitempty"`
}

type PluginObjectStateMap struct {
	Name          string `json:"name"`
	Policy        string `json:"policy"`
	SchemaVersion int    `json:"schema_version,omitempty"`
	MigrateFrom   string `json:"migrate_from,omitempty"`
}

type PluginEBPFStateMigration struct {
	PluginID          string `json:"plugin_id"`
	ObjectID          string `json:"object_id"`
	SourceMap         string `json:"source_map"`
	TargetMap         string `json:"target_map"`
	FromSchemaVersion int    `json:"from_schema_version"`
	ToSchemaVersion   int    `json:"to_schema_version"`
}

func (migration PluginEBPFStateMigration) key() string {
	return migration.PluginID + "\x00" + migration.ObjectID + "\x00" + migration.SourceMap + "\x00" + migration.TargetMap
}

type PluginObjectVariant struct {
	Architecture string `json:"architecture"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256,omitempty"`
}

type PluginObjectProgram struct {
	ID               string `json:"id"`
	Section          string `json:"section"`
	Type             string `json:"type,omitempty"`
	AttachType       string `json:"attach_type,omitempty"`
	InstructionCount int    `json:"instruction_count,omitempty"`
}

type PluginHook struct {
	ID             string                        `json:"id"`
	Engine         string                        `json:"engine"`
	Attach         string                        `json:"attach,omitempty"`
	Stage          string                        `json:"stage"`
	Priority       int                           `json:"priority,omitempty"`
	Before         []string                      `json:"before,omitempty"`
	After          []string                      `json:"after,omitempty"`
	Program        string                        `json:"program,omitempty"`
	Mode           string                        `json:"mode,omitempty"`
	Context        []string                      `json:"context,omitempty"`
	Interfaces     []string                      `json:"interfaces,omitempty"`
	PacketMetadata []PluginPacketMetadataBinding `json:"packet_metadata,omitempty"`
}

type PluginPacketMetadataBinding struct {
	Slot          int    `json:"slot"`
	Namespace     string `json:"namespace"`
	SchemaVersion int    `json:"schema_version"`
	MaxBytes      int    `json:"max_bytes"`
	Access        string `json:"access"`
}

type PluginResource struct {
	ID             string          `json:"id"`
	Description    string          `json:"description,omitempty"`
	Methods        []string        `json:"methods,omitempty"`
	ControlMethods []string        `json:"control_methods,omitempty"`
	RuntimeUpdate  string          `json:"runtime_update,omitempty"`
	MaxRecords     int             `json:"max_records,omitempty"`
	MaxRecordBytes int             `json:"max_record_bytes,omitempty"`
	SecretFields   []string        `json:"secret_fields,omitempty"`
	SchemaVersion  int             `json:"schema_version,omitempty"`
	Schema         json.RawMessage `json:"schema,omitempty"`
	SchemaDigest   string          `json:"schema_digest,omitempty"`
}

type PluginAction struct {
	ID                    string          `json:"id"`
	Description           string          `json:"description,omitempty"`
	RuntimeUpdate         string          `json:"runtime_update,omitempty"`
	MaxPayloadBytes       int             `json:"max_payload_bytes,omitempty"`
	RequestSchemaVersion  int             `json:"request_schema_version,omitempty"`
	RequestSchema         json.RawMessage `json:"request_schema,omitempty"`
	RequestSchemaDigest   string          `json:"request_schema_digest,omitempty"`
	ResponseSchemaVersion int             `json:"response_schema_version,omitempty"`
	ResponseSchema        json.RawMessage `json:"response_schema,omitempty"`
	ResponseSchemaDigest  string          `json:"response_schema_digest,omitempty"`
}

type PluginService struct {
	ID          string   `json:"id"`
	Version     string   `json:"version"`
	Description string   `json:"description,omitempty"`
	Actions     []string `json:"actions,omitempty"`
	Resources   []string `json:"resources,omitempty"`
}

type PluginServiceProvider struct {
	PluginID      string           `json:"plugin_id"`
	PluginName    string           `json:"plugin_name"`
	PluginVersion string           `json:"plugin_version"`
	Stability     string           `json:"stability"`
	Service       PluginService    `json:"service"`
	Actions       []PluginAction   `json:"actions,omitempty"`
	Resources     []PluginResource `json:"resources,omitempty"`
}

type PluginControl struct {
	Main            string                 `json:"main,omitempty"`
	SHA256          string                 `json:"sha256,omitempty"`
	ResolvedSHA256  string                 `json:"resolved_sha256,omitempty"`
	Permissions     []string               `json:"permissions,omitempty"`
	ResourceAccess  []PluginResourceAccess `json:"resource_access,omitempty"`
	ActionAccess    []PluginActionAccess   `json:"action_access,omitempty"`
	EventAccess     []PluginEventAccess    `json:"event_access,omitempty"`
	NetAccess       []PluginNetAccess      `json:"net_access,omitempty"`
	NamespaceAccess []string               `json:"namespace_access,omitempty"`
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

type PluginEventAccess struct {
	Plugin        string   `json:"plugin"`
	TopicPrefixes []string `json:"topic_prefixes,omitempty"`
}

type PluginNetAccess struct {
	Interfaces  []string `json:"interfaces,omitempty"`
	Operations  []string `json:"operations,omitempty"`
	RemoteHosts []string `json:"remote_hosts,omitempty"`
	RemoteCIDRs []string `json:"remote_cidrs,omitempty"`
	RemotePorts []int    `json:"remote_ports,omitempty"`
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
	Builtin            bool                      `json:"builtin,omitempty"`
	Capabilities       []string                  `json:"capabilities,omitempty"`
	VirtualInterfaces  []PluginVirtualInterface  `json:"virtual_interfaces,omitempty"`
	Objects            []PluginObject            `json:"objects,omitempty"`
	Hooks              []PluginHook              `json:"hooks,omitempty"`
	Resources          []PluginResource          `json:"resources,omitempty"`
	Actions            []PluginAction            `json:"actions,omitempty"`
	Services           []PluginService           `json:"services,omitempty"`
	EventSubscriptions []PluginEventSubscription `json:"event_subscriptions,omitempty"`
	RingSubscriptions  []PluginRingSubscription  `json:"ring_subscriptions,omitempty"`
	UI                 *PluginUI                 `json:"ui,omitempty"`
	Enabled            bool                      `json:"enabled"`
	Status             string                    `json:"status"`
	Runtime            PluginRuntimeState        `json:"runtime"`
	Error              string                    `json:"error,omitempty"`
	Source             string                    `json:"source,omitempty"`
	AssetBasePath      string                    `json:"asset_base_path,omitempty"`
	ResourceUsage      *PluginResourceUsage      `json:"resource_usage,omitempty"`

	rootDir            string
	staticDir          string
	controlMainPath    string
	objectArchitecture string
	sourceFingerprint  string
	resolutionError    bool
	resourceLimits     PluginResourceLimits
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

	limits := pluginResourceLimitsFromConfig(cfg)
	external := scanExternalPlugins(pluginsDir, seen)
	for i := range external {
		external[i].resourceLimits = limits
	}
	catalog.Plugins = append(catalog.Plugins, external...)
	externalPlugins := catalog.Plugins[1:]
	sort.SliceStable(externalPlugins, func(i, j int) bool {
		a := externalPlugins[i]
		b := externalPlugins[j]
		if a.ID == b.ID {
			return a.Source < b.Source
		}
		return a.ID < b.ID
	})
	return resolvePluginCatalogRelationships(catalog, currentPluginHostEnvironment())
}

func loadPluginCatalogWithState(cfg *Config, db store.RuleStore) PluginCatalog {
	return applyPluginStatesFromDB(loadPluginCatalog(cfg), db)
}

func applyPluginStatesFromDB(catalog PluginCatalog, db store.RuleStore) PluginCatalog {
	clearPluginResolutionErrors(&catalog)
	for i := range catalog.Plugins {
		catalog.Plugins[i].Enabled = true
		if catalog.Plugins[i].Builtin {
			continue
		}
	}
	if pluginRuleStoreIsNil(db) {
		return resolvePluginCatalogRelationships(catalog, currentPluginHostEnvironment())
	}
	states, err := store.GetPluginStates(db)
	if err != nil {
		logPluginStateLoadError(err)
		catalog = resolvePluginCatalogRelationships(catalog, currentPluginHostEnvironment())
		applyPluginDatabaseResourceUsage(&catalog, db)
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
	catalog = resolvePluginCatalogRelationships(catalog, currentPluginHostEnvironment())
	applyPluginDatabaseResourceUsage(&catalog, db)
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
	plugin.ResourceUsage = nil
	plugin.staticDir = ""
	plugin.AssetBasePath = ""
	plugin.resolutionError = false
}

func pluginRuntimeCapabilities(cfg *Config) PluginRuntimeCapabilities {
	externalDataplaneAttach := false
	if cfg != nil {
		externalDataplaneAttach = cfg.PluginsEnabled() && cfg.PluginsDataplaneEnabled()
	}
	env := currentPluginHostEnvironment()
	availability := currentPluginHostFeatureAvailability()
	return PluginRuntimeCapabilities{
		BuiltinPipelineID:        builtinPluginPipelineID,
		RuntimeVersion:           env.RuntimeVersion,
		ControlAPIABI:            env.ControlAPIABI,
		TCPipelineABI:            env.TCPipelineABI,
		HostOS:                   env.OS,
		HostArch:                 env.Arch,
		KernelRelease:            env.KernelRelease,
		Features:                 append([]string(nil), pluginRuntimeFeatures...),
		AvailableFeatures:        availability.Available,
		FeatureStatus:            availability.Status,
		CorePriority:             pluginPipelineCorePriority,
		ManifestDiscovery:        true,
		ObjectValidation:         true,
		ProtectedAssets:          true,
		MinimumSandboxLevel:      cfg.PluginMinimumSandboxLevel(),
		RequireSignedPackages:    cfg.PluginsRequireSignedPackages(),
		StabilityLevels:          []string{pluginStabilityLab, pluginStabilityPreview, pluginStabilityStable, pluginStabilityDeprecated},
		ExternalDataplaneAttach:  externalDataplaneAttach,
		ExternalDataplaneEngines: []string{kernelEngineTC, kernelEngineXDP},
		RegistrationOnlyEngines:  nil,
		SupportedEngines:         []string{kernelEngineTC, kernelEngineXDP, "control"},
		SupportedHookModes:       []string{"observe", "rewrite", "redirect", "drop", "control"},
		TCPipeline: PluginTCPipelineCapabilities{
			ProgramArrayEntries: pluginTCPipelineProgramArrayEntries,
			StageHookLimit:      pluginTCPipelineStageHookLimit,
			DirectionHookLimit:  pluginTCPipelineDirectionHookLimit,
			Directions:          []string{pluginPipelineDirectionForward, pluginPipelineDirectionReply},
			Phases:              []string{pluginPipelinePhaseAroundCore, pluginPipelinePhaseAfterApply},
			HookStages: []string{
				pluginPipelineDirectionForward,
				pluginPipelineDirectionReply,
				pluginPipelineStagePreForward,
				pluginPipelineStagePostLookup,
				pluginPipelineStagePostApply,
				pluginPipelineStagePreReply,
				pluginPipelineStagePostReply,
				pluginPipelineStageReplyApply,
			},
			Attaches: []string{"ingress", "egress", "both"},
		},
		PacketMetadata: PluginPacketMetadataCapabilities{
			ABI:                1,
			BindingLimit:       pluginPacketMetadataBindingLimit,
			NamespaceLimit:     pluginPacketMetadataNamespaceLimit,
			PayloadMaxBytes:    pluginPacketMetadataPayloadMaxBytes,
			SupportedAccess:    []string{pluginPacketMetadataAccessRead, pluginPacketMetadataAccessReadWrite},
			RequiresTC:         true,
			GenerationIsolated: true,
		},
		XDPPipeline: PluginXDPPipelineCapabilities{
			ProgramArrayEntries: pluginXDPPipelineProgramArrayEntries,
			HookLimit:           pluginXDPPipelineHookLimit,
			HookStages:          []string{pluginPipelineStagePreForward, pluginPipelineDirectionForward},
			Attaches:            []string{"ingress"},
			RequiresInterfaces:  true,
		},
		ResourceLimits: pluginResourceLimitsFromConfig(cfg),
		Limitations: []string{
			"veer is a logical tc tail-call pipeline, not a Linux netdev; real interfaces are only attach targets or optional handoff adapters",
			"external dataplane loading is opt-in via plugins_dataplane_enabled and supports tc pipeline.attach direction=forward/reply hooks around Veer Core or after core apply",
			"tc pipeline plugin priority is compared with Veer Core priority 1000; lower priority runs before core lookup and higher priority runs after core lookup on the selected packet direction; phase=after_apply runs after core rewrite/checksum and before the final redirect",
			"tc pipeline plugins are callable stages in the shared prog-array chain and must tail-call the shared continue slot after processing unless they intentionally return a final tc action",
			"post-core tc plugins may read the family-scoped tc_plugin_ctx_v4 or tc_plugin_ctx_v6 context after Veer Core has parsed L3/L4 and matched a rule or flow",
			"control.main scripts run in persistent per-plugin Goja control VMs only; declared worker VMs can offload control tasks but never run in packet hot paths",
			"control permissions gate kv/resource/secret/crypto/timer/worker/net.l2/net.tcp/net.udp/plugin.resource/ebpf map updates; registration APIs are only available during control script initialization",
			"plugin.resource is a two-step grant: the permission enables the API namespace and control.resource_access must explicitly allow each target plugin/resource/method",
			"typed service discovery exposes only action/resource endpoints already authorized by the caller manifest; ambiguous providers require an explicit provider selection",
			"control timer and worker state is capped at 64 named timers and 16 named workers per plugin to avoid control-plane resource exhaustion",
			"outstanding worker requests are capped per plugin at 256 requests and 16 MiB of payload across all worker queues and executions",
			"persistent TCP/UDP sockets are host-owned and capped at 32 handles per plugin; transactional upgrades transfer compatible handles to the candidate VM, while cold replacement, plugin deactivation, and runtime shutdown close them",
			"plugin dataplane mode is a trust contract for installed eBPF objects; keep external dataplane loading disabled unless the object source is trusted",
			"plugin stability is declared by manifest.stability: lab is for examples/tests only, preview is suitable for controlled deployments, stable is expected to be production-ready, and deprecated should not be used for new deployments",
			"lab, preview, and stable plugins can execute control scripts and join external tc dataplane when the corresponding global plugin switches are enabled; deprecated plugins are always blocked",
			"xdp plugins run only on explicit ingress interfaces before the tc pipeline; Veer refuses to replace an existing XDP program on the same interface",
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
		if _, err := os.Lstat(manifestPath); err != nil { // #nosec G703 -- source is a direct os.ReadDir child name.
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
	cleanRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return LoadedPlugin{}, fmt.Errorf("resolve plugin root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		return LoadedPlugin{}, fmt.Errorf("resolve plugin root: %w", err)
	}
	sourceFingerprint, _ := buildPluginDirectoryFingerprint(realRoot)
	data, _, err := readPluginRootedRegularFile(realRoot, pluginManifestFile, pluginManifestMaxSize)
	if err != nil {
		if pluginPathEscapesRoot(err) {
			return LoadedPlugin{}, fmt.Errorf("%s escapes plugin root", pluginManifestFile)
		}
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
		rootDir:           realRoot,
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
