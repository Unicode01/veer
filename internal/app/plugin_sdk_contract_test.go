package app

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

type pluginControlABIFixture struct {
	FixtureVersion            int      `json:"fixture_version"`
	IntroducedContractVersion int      `json:"introduced_contract_version"`
	ControlAPIABI             int      `json:"control_api_abi"`
	MethodCount               int      `json:"method_count"`
	SortedMethodListSHA256    string   `json:"sorted_method_list_sha256"`
	AllowedAdditions          []string `json:"allowed_additions,omitempty"`
}

type pluginTCPipelineABIFixture struct {
	FixtureVersion            int            `json:"fixture_version"`
	IntroducedContractVersion int            `json:"introduced_contract_version"`
	TCPipelineABI             int            `json:"tc_pipeline_abi"`
	ProgramArrayEntries       int            `json:"program_array_entries"`
	StageHookLimit            int            `json:"stage_hook_limit"`
	DirectionHookLimit        int            `json:"direction_hook_limit"`
	Directions                []string       `json:"directions"`
	Phases                    []string       `json:"phases"`
	HookStages                []string       `json:"hook_stages"`
	SlotDefines               map[string]int `json:"slot_defines"`
	SharedMaps                []string       `json:"shared_maps"`
	ContextStructs            []string       `json:"context_structs"`
}

type pluginPacketMetadataABIFixture struct {
	FixtureVersion            int      `json:"fixture_version"`
	IntroducedContractVersion int      `json:"introduced_contract_version"`
	ABI                       int      `json:"abi"`
	BindingLimit              int      `json:"binding_limit"`
	NamespaceLimit            int      `json:"namespace_limit"`
	PayloadMaxBytes           int      `json:"payload_max_bytes"`
	SupportedAccess           []string `json:"supported_access"`
	SharedMaps                []string `json:"shared_maps"`
	PrivateMaps               []string `json:"private_maps"`
	Structs                   []string `json:"structs"`
}

var pluginSDKMethodPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)+$`)

func TestPluginSDKContractMatchesGojaHost(t *testing.T) {
	contractPath := filepath.Join("..", "..", "sdk", "plugin", "api-contract.json")
	data, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	var contract pluginSDKAPIContract
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		t.Fatal(err)
	}
	if contract.Version != pluginSDKContractVersion || len(contract.ControlMethods) == 0 {
		t.Fatalf("plugin SDK contract = %+v", contract)
	}
	if want := currentPluginSDKAPIContract(); !reflect.DeepEqual(contract, want) {
		t.Fatalf("checked-in plugin SDK contract differs from runtime\nfile:    %+v\nruntime: %+v", contract, want)
	}
	if contract.Runtime.APIVersion != pluginAPIVersionV1 {
		t.Fatalf("SDK api_version = %q, runtime = %q", contract.Runtime.APIVersion, pluginAPIVersionV1)
	}
	if contract.Runtime.RuntimeVersion != pluginRuntimeVersion {
		t.Fatalf("SDK runtime_version = %q, runtime = %q", contract.Runtime.RuntimeVersion, pluginRuntimeVersion)
	}
	if contract.Runtime.ControlAPIABI != pluginControlAPIABI {
		t.Fatalf("SDK control_api_abi = %d, runtime = %d", contract.Runtime.ControlAPIABI, pluginControlAPIABI)
	}
	if contract.Runtime.TCPipelineABI != pluginTCPipelineABI {
		t.Fatalf("SDK tc_pipeline_abi = %d, runtime = %d", contract.Runtime.TCPipelineABI, pluginTCPipelineABI)
	}
	if contract.Runtime.CorePriority != pluginPipelineCorePriority {
		t.Fatalf("SDK core_priority = %d, runtime = %d", contract.Runtime.CorePriority, pluginPipelineCorePriority)
	}
	if !reflect.DeepEqual(contract.Runtime.Features, pluginRuntimeFeatures) {
		t.Fatalf("SDK runtime features = %v, runtime = %v", contract.Runtime.Features, pluginRuntimeFeatures)
	}
	if want := pluginResourceLimitsFromConfig(nil); !reflect.DeepEqual(contract.Runtime.ResourceLimits, want) {
		t.Fatalf("SDK resource limits = %+v, runtime = %+v", contract.Runtime.ResourceLimits, want)
	}
	if contract.Control.HostProtocolABI != pluginHostProtocolVersion ||
		contract.Control.MaxCallsPerEvent != pluginHostMaxCallsPerEvent ||
		contract.Control.MaxJSONDepth != pluginHostMaxJSONDepth ||
		contract.Control.MaxRequestBytes != pluginHostMaxChildFrameBytes ||
		contract.Control.MaxResponseBytes != pluginHostMaxParentFrameBytes {
		t.Fatalf("SDK control host limits = %+v", contract.Control)
	}
	if !reflect.DeepEqual(contract.Control.Capabilities, pluginHostControlCapabilities) {
		t.Fatalf("SDK control capabilities differ from runtime")
	}

	wantPipeline := pluginRuntimeCapabilities(&Config{}).TCPipeline
	if !reflect.DeepEqual(contract.TCPipeline, wantPipeline) {
		t.Fatalf("SDK tc_pipeline = %+v, runtime = %+v", contract.TCPipeline, wantPipeline)
	}
	wantMetadata := pluginRuntimeCapabilities(&Config{}).PacketMetadata
	if !reflect.DeepEqual(contract.PacketMetadata, wantMetadata) {
		t.Fatalf("SDK packet_metadata = %+v, runtime = %+v", contract.PacketMetadata, wantMetadata)
	}
	if contract.EventBus.MaxSubscriptions != pluginEventMaxSubscriptions ||
		contract.EventBus.DefaultQueueSize != pluginEventDefaultQueueSize ||
		contract.EventBus.MaxQueueSize != pluginEventMaxQueueSize ||
		contract.EventBus.MaxPayloadBytes != pluginEventMaxPayloadBytes ||
		contract.EventBus.MaxAccessEntries != pluginEventMaxAccessEntries ||
		contract.EventBus.MaxAccessTopics != pluginEventMaxAccessTopics {
		t.Fatalf("SDK event bus limits = %+v", contract.EventBus)
	}
	if contract.Operations.MaxRecordsPerPlugin != pluginOperationMaxRecordsPerPlugin ||
		contract.Operations.MaxFieldBytes != pluginOperationMaxFieldBytes ||
		contract.Operations.MaxPluginBytes != pluginOperationMaxPluginBytes ||
		contract.Operations.MaxListLimit != pluginOperationMaxListLimit ||
		contract.Operations.MaxRetryDelayMS != pluginOperationMaxRetryDelayMS ||
		!reflect.DeepEqual(contract.Operations.Statuses, []string{"pending", "running", "retry_wait", "completed", "failed", "cancelled"}) {
		t.Fatalf("SDK operation contract = %+v", contract.Operations)
	}
	wantSystemTopics := []string{
		pluginEventTopicNetLink,
		pluginEventTopicNetAddr,
		pluginEventTopicNetNeigh,
		pluginEventTopicNetRoute,
		pluginEventTopicResourceChanged,
		pluginEventTopicPluginLifecycle,
	}
	if !reflect.DeepEqual(contract.EventBus.SystemTopics, wantSystemTopics) {
		t.Fatalf("SDK event bus topics = %v, runtime = %v", contract.EventBus.SystemTopics, wantSystemTopics)
	}
	for _, stage := range contract.TCPipeline.HookStages {
		if !validPluginDataplaneHookStage(stage) {
			t.Fatalf("SDK tc_pipeline hook stage %q is not accepted by the runtime", stage)
		}
	}
	assertPluginSDKTextContract(t, contract)

	seen := make(map[string]struct{}, len(contract.ControlMethods))
	assertions := make([]string, 0, len(contract.ControlMethods)+1)
	for _, method := range contract.ControlMethods {
		if !pluginSDKMethodPattern.MatchString(method) {
			t.Fatalf("invalid SDK method %q", method)
		}
		if _, duplicate := seen[method]; duplicate {
			t.Fatalf("duplicate SDK method %q", method)
		}
		seen[method] = struct{}{}
		assertions = append(assertions, fmt.Sprintf(`if (typeof %s !== "function") throw new Error("missing SDK method %s");`, method, method))
	}
	if len(seen) != len(pluginHostControlMethodSet) {
		t.Fatalf("isolated host method count = %d, SDK count = %d", len(pluginHostControlMethodSet), len(seen))
	}
	for method := range pluginHostControlMethodSet {
		if _, ok := seen[method]; !ok {
			t.Fatalf("isolated host method %q is missing from the SDK contract", method)
		}
	}
	capabilityMethods := pluginHostCapabilityMethods(contract.Control.Capabilities)
	if !reflect.DeepEqual(capabilityMethods, contract.ControlMethods) {
		t.Fatalf("SDK capability methods differ from compatibility method list")
	}
	assertPluginSDKCapability(t, contract, "events.subscribe", []string{"event", "worker"}, []string{pluginHostPhaseRegistration}, []string{pluginHostContextMain, pluginHostContextWorker})
	assertPluginSDKCapability(t, contract, "worker.call", []string{"worker"}, []string{pluginHostPhaseRuntime}, []string{pluginHostContextMain})
	assertPluginSDKCapability(t, contract, "net.http.request", []string{"net.http"}, []string{pluginHostPhaseRuntime}, []string{pluginHostContextMain, pluginHostContextWorker})
	assertPluginSDKCapability(t, contract, "crypto.sha256File", []string{"crypto"}, []string{pluginHostPhaseRegistration, pluginHostPhaseRuntime}, []string{pluginHostContextMain, pluginHostContextWorker})
	assertions = append(assertions, `exports.onReconcile = function () {};`)

	dir := t.TempDir()
	writeTestPlugin(t, dir, "sdk_contract", `{
  "api_version":"v1",
  "id":"sdk_contract",
  "name":"SDK Contract",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "control":{"main":"control.js","permissions":[]}
}`)
	writePluginControlScript(t, dir, "sdk_contract", strings.Join(assertions, "\n"))

	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer runtime.Close()
	assertPluginReconcileSuccess(t, runtime, loadPluginCatalogWithState(cfg, db), "sdk_contract")
}

func TestPluginSDKGeneratedMethodTypesMatchHostRegistry(t *testing.T) {
	path := filepath.Join("..", "..", "sdk", "plugin", "methods.d.ts")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := encodePluginSDKMethodTypes(pluginHostControlMethods)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("checked-in plugin method types differ from runtime; regenerate with veer plugin contract --types-output %s --force", path)
	}
	for _, method := range pluginHostControlMethods {
		declaration := fmt.Sprintf("%q: typeof %s;", method, method)
		if strings.Count(string(got), declaration) != 1 {
			t.Fatalf("generated method types contain %d declarations for %s", strings.Count(string(got), declaration), method)
		}
	}
}

func TestPluginSDKPublicDeclarationsDoNotUseAny(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "sdk", "plugin", "*.d.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("plugin SDK contains no public TypeScript declarations")
	}
	pattern := regexp.MustCompile(`\bany\b`)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if location := pattern.FindIndex(data); location != nil {
			t.Fatalf("public plugin SDK declaration %s uses any at byte %d; use a concrete type or unknown", path, location[0])
		}
	}
}

func assertPluginSDKCapability(t *testing.T, contract pluginSDKAPIContract, method string, permissions, phases, contexts []string) {
	t.Helper()
	for _, capability := range contract.Control.Capabilities {
		if capability.Method != method {
			continue
		}
		if !reflect.DeepEqual(capability.Permissions, permissions) || !reflect.DeepEqual(capability.Phases, phases) || !reflect.DeepEqual(capability.Contexts, contexts) {
			t.Fatalf("SDK capability %s = %+v", method, capability)
		}
		if capability.MaxRequestBytes != pluginHostMaxChildFrameBytes || capability.MaxResponseBytes != pluginHostMaxParentFrameBytes {
			t.Fatalf("SDK capability %s limits = %+v", method, capability)
		}
		return
	}
	t.Fatalf("SDK capability %s is missing", method)
}

func assertPluginSDKTextContract(t *testing.T, contract pluginSDKAPIContract) {
	t.Helper()
	typesPath := filepath.Join("..", "..", "sdk", "plugin", "control.d.ts")
	types, err := os.ReadFile(typesPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range append(append([]string(nil), contract.TCPipeline.HookStages...), contract.TCPipeline.Phases...) {
		if !strings.Contains(string(types), "'"+value+"'") {
			t.Fatalf("SDK TypeScript contract is missing pipeline value %q", value)
		}
	}

	helpersPath := filepath.Join("..", "..", "plugins", "include", "veer_plugin_helpers.h")
	helpers, err := os.ReadFile(helpersPath)
	if err != nil {
		t.Fatal(err)
	}
	defines := []string{
		fmt.Sprintf("#define VEER_TC_PROG_CHAIN_V4_MAX_ENTRIES %d", contract.TCPipeline.ProgramArrayEntries),
		fmt.Sprintf("#define VEER_TC_PROG_V4_PLUGIN_PRE_FORWARD_MAX %d", contract.TCPipeline.StageHookLimit),
		fmt.Sprintf("#define VEER_TC_PROG_V4_PLUGIN_POST_LOOKUP_MAX %d", contract.TCPipeline.StageHookLimit),
		fmt.Sprintf("#define VEER_TC_PROG_V4_PLUGIN_PRE_REPLY_MAX %d", contract.TCPipeline.StageHookLimit),
		fmt.Sprintf("#define VEER_TC_PROG_V4_PLUGIN_POST_REPLY_MAX %d", contract.TCPipeline.StageHookLimit),
		fmt.Sprintf("#define VEER_TC_PROG_V4_PLUGIN_POST_APPLY_MAX %d", contract.TCPipeline.StageHookLimit),
		fmt.Sprintf("#define VEER_TC_PROG_V4_PLUGIN_REPLY_APPLY_MAX %d", contract.TCPipeline.StageHookLimit),
		fmt.Sprintf("#define VEER_PACKET_METADATA_BINDING_MAX_ENTRIES %d", contract.PacketMetadata.BindingLimit),
		fmt.Sprintf("#define VEER_PACKET_METADATA_MAX_NAMESPACES %d", contract.PacketMetadata.NamespaceLimit),
		fmt.Sprintf("#define VEER_PACKET_METADATA_PAYLOAD_BYTES %d", contract.PacketMetadata.PayloadMaxBytes),
	}
	for _, define := range defines {
		if !strings.Contains(string(helpers), define) {
			t.Fatalf("plugin helper contract is missing %q", define)
		}
	}
}

func TestPluginSDKHistoricalABIFixtures(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "sdk", "plugin", "fixtures")
	var controlFixture pluginControlABIFixture
	decodePluginSDKFixture(t, filepath.Join(fixtureDir, "control-api-abi-1.json"), &controlFixture)
	if controlFixture.FixtureVersion != 1 || controlFixture.IntroducedContractVersion >= pluginSDKContractVersion || controlFixture.ControlAPIABI != pluginControlAPIABI {
		t.Fatalf("control ABI fixture = %+v", controlFixture)
	}
	methods := pluginHostCapabilityMethods(pluginHostControlCapabilities)
	additions := make(map[string]struct{}, len(controlFixture.AllowedAdditions))
	for _, method := range controlFixture.AllowedAdditions {
		if _, duplicate := additions[method]; duplicate {
			t.Fatalf("control ABI fixture contains duplicate allowed addition %q", method)
		}
		additions[method] = struct{}{}
	}
	baseline := make([]string, 0, len(methods))
	for _, method := range methods {
		if _, added := additions[method]; added {
			delete(additions, method)
			continue
		}
		baseline = append(baseline, method)
	}
	if len(additions) != 0 {
		t.Fatalf("control ABI fixture allowed additions are missing from runtime: %v", additions)
	}
	methodBytes := []byte(strings.Join(baseline, "\n") + "\n")
	digest := fmt.Sprintf("%x", sha256.Sum256(methodBytes))
	if len(baseline) != controlFixture.MethodCount || digest != controlFixture.SortedMethodListSHA256 {
		t.Fatalf("control ABI %d baseline drifted: methods=%d digest=%s, fixture=%+v", pluginControlAPIABI, len(baseline), digest, controlFixture)
	}

	var pipelineFixture pluginTCPipelineABIFixture
	decodePluginSDKFixture(t, filepath.Join(fixtureDir, "tc-pipeline-abi-2.json"), &pipelineFixture)
	contract := currentPluginSDKAPIContract()
	if pipelineFixture.FixtureVersion != 1 || pipelineFixture.IntroducedContractVersion >= pluginSDKContractVersion || pipelineFixture.TCPipelineABI != pluginTCPipelineABI {
		t.Fatalf("TC pipeline ABI fixture = %+v", pipelineFixture)
	}
	if pipelineFixture.ProgramArrayEntries != contract.TCPipeline.ProgramArrayEntries ||
		pipelineFixture.StageHookLimit != contract.TCPipeline.StageHookLimit ||
		pipelineFixture.DirectionHookLimit != contract.TCPipeline.DirectionHookLimit ||
		!reflect.DeepEqual(pipelineFixture.Directions, contract.TCPipeline.Directions) ||
		!reflect.DeepEqual(pipelineFixture.Phases, contract.TCPipeline.Phases) ||
		!reflect.DeepEqual(pipelineFixture.HookStages, contract.TCPipeline.HookStages) {
		t.Fatalf("TC pipeline ABI %d contract drifted: fixture=%+v contract=%+v", pluginTCPipelineABI, pipelineFixture, contract.TCPipeline)
	}
	header, err := os.ReadFile(filepath.Join("..", "..", "plugins", "include", "veer_plugin_helpers.h"))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range pipelineFixture.SlotDefines {
		if !strings.Contains(string(header), fmt.Sprintf("#define %s %d", name, value)) {
			t.Fatalf("TC pipeline ABI fixture define %s=%d is missing", name, value)
		}
	}
	for _, name := range append(append([]string(nil), pipelineFixture.SharedMaps...), pipelineFixture.ContextStructs...) {
		if !strings.Contains(string(header), name) {
			t.Fatalf("TC pipeline ABI fixture symbol %s is missing", name)
		}
	}

	var metadataFixture pluginPacketMetadataABIFixture
	decodePluginSDKFixture(t, filepath.Join(fixtureDir, "packet-metadata-abi-1.json"), &metadataFixture)
	if metadataFixture.FixtureVersion != 1 || metadataFixture.IntroducedContractVersion != 5 || metadataFixture.IntroducedContractVersion > pluginSDKContractVersion || metadataFixture.ABI != contract.PacketMetadata.ABI {
		t.Fatalf("packet metadata ABI fixture = %+v", metadataFixture)
	}
	if metadataFixture.BindingLimit != contract.PacketMetadata.BindingLimit ||
		metadataFixture.NamespaceLimit != contract.PacketMetadata.NamespaceLimit ||
		metadataFixture.PayloadMaxBytes != contract.PacketMetadata.PayloadMaxBytes ||
		!reflect.DeepEqual(metadataFixture.SupportedAccess, contract.PacketMetadata.SupportedAccess) {
		t.Fatalf("packet metadata ABI contract drifted: fixture=%+v contract=%+v", metadataFixture, contract.PacketMetadata)
	}
	for _, name := range append(append(append([]string(nil), metadataFixture.SharedMaps...), metadataFixture.PrivateMaps...), metadataFixture.Structs...) {
		if !strings.Contains(string(header), name) {
			t.Fatalf("packet metadata ABI fixture symbol %s is missing", name)
		}
	}
}

func decodePluginSDKFixture(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}
