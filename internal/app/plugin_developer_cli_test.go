package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestPluginDeveloperCLIInitLintAndTest(t *testing.T) {
	target := filepath.Join(t.TempDir(), "sample_control")
	output := runPluginPackageCLIForTest(t, "init", "--id", "sample_control", "--name", "Sample Control", "--directory", target)
	var initialized map[string]any
	if err := json.Unmarshal(output, &initialized); err != nil {
		t.Fatal(err)
	}
	if initialized["plugin_id"] != "sample_control" || initialized["kind"] != "control" {
		t.Fatalf("init output = %+v", initialized)
	}
	for _, name := range []string{pluginManifestFile, "control.js"} {
		if info, err := os.Stat(filepath.Join(target, name)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("generated %s info = %+v, error = %v", name, info, err)
		}
	}
	for _, command := range []string{"lint", "test"} {
		result := runPluginPackageCLIForTest(t, command, "--source", target)
		var checked pluginDeveloperLintResult
		if err := json.Unmarshal(result, &checked); err != nil {
			t.Fatal(err)
		}
		if checked.PluginID != "sample_control" || !checked.Compatible {
			t.Fatalf("%s result = %+v", command, checked)
		}
		if checked.Registration != (command == "test") {
			t.Fatalf("%s registration = %t", command, checked.Registration)
		}
		if command == "test" && (!checked.RegistrationStable || !checked.PackageRoundTrip || len(checked.RegistrationDigest) != 64) {
			t.Fatalf("%s conformance result = %+v", command, checked)
		}
		if len(checked.ContractSHA256) != 64 || checked.ControlAPIABI != pluginControlAPIABI {
			t.Fatalf("%s SDK contract result = %+v", command, checked)
		}
	}
	if _, err := runPluginPackageCLIWithError("init", "--id", "sample_control", "--directory", target); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("repeat init error = %v", err)
	}
}

func TestPluginDeveloperCLITestRejectsNondeterministicRegistration(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "random_surface", `{
  "api_version":"v1","id":"random_surface","name":"Random Surface","version":"1.0.0","kind":"control","stability":"lab",
  "control":{"main":"control.js","permissions":["plugin.register"]}
}`)
	writePluginControlScript(t, dir, "random_surface", `
plugin.capabilities(["random_" + Math.random().toString(36).slice(2)]);
exports.onReconcile = function () {};
`)
	pluginDir := filepath.Join(dir, "random_surface")
	if _, err := runPluginPackageCLIWithError("test", "--source", pluginDir); err == nil || !strings.Contains(err.Error(), "not deterministic") {
		t.Fatalf("nondeterministic registration error = %v", err)
	}
}

func TestPluginDeveloperCLITestRequiresStableABI(t *testing.T) {
	dir := t.TempDir()
	controlSource := `exports.onReconcile = function () {};`
	writeTestPlugin(t, dir, "stable_missing_abi", `{
  "api_version":"v1","id":"stable_missing_abi","name":"Stable Missing ABI","version":"1.0.0","kind":"control","stability":"stable",
  "compatibility":{"runtime":">=1.0.0 <2.0.0"},
  "control":{"main":"control.js","sha256":"`+testSHA256Hex(controlSource)+`","permissions":[]}
}`)
	writePluginControlScript(t, dir, "stable_missing_abi", controlSource)
	pluginDir := filepath.Join(dir, "stable_missing_abi")
	if _, err := runPluginPackageCLIWithError("test", "--source", pluginDir); err == nil || !strings.Contains(err.Error(), "control_api_abi=1") {
		t.Fatalf("stable ABI error = %v", err)
	}
}

func TestPluginDeveloperCLIInitPipelineCopiesSDK(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "sample_pipeline")
	runPluginPackageCLIForTest(t,
		"init", "--id", "sample_pipeline", "--kind", "pipeline", "--directory", target,
		"--sdk-include", filepath.Join(repoRoot, "plugins", "include"),
	)
	for _, name := range []string{pluginManifestFile, "control.js", "main.bpf.c", filepath.Join("include", "veer_plugin_helpers.h")} {
		if info, err := os.Stat(filepath.Join(target, name)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("generated %s info = %+v, error = %v", name, info, err)
		}
	}
	result := runPluginPackageCLIForTest(t, "lint", "--source", target, "--os", "linux", "--architecture", runtime.GOARCH)
	var checked pluginDeveloperLintResult
	if err := json.Unmarshal(result, &checked); err != nil || checked.PluginID != "sample_pipeline" {
		t.Fatalf("pipeline lint = %+v, error = %v", checked, err)
	}
}

func TestPluginContractCLIExportsAndChecksCanonicalContract(t *testing.T) {
	output := runPluginPackageCLIForTest(t, "contract")
	contract, err := decodePluginSDKAPIContract(output)
	if err != nil {
		t.Fatal(err)
	}
	if contract.Version != pluginSDKContractVersion || contract.Runtime.ControlAPIABI != pluginControlAPIABI {
		t.Fatalf("exported contract = %+v", contract)
	}

	repoContract, err := filepath.Abs(filepath.Join("..", "..", "sdk", "plugin", "api-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	checkedOutput := runPluginPackageCLIForTest(t, "contract", "--check", repoContract)
	var checked pluginContractCLIResult
	if err := json.Unmarshal(checkedOutput, &checked); err != nil {
		t.Fatal(err)
	}
	if checked.Status != "compatible" || checked.ControlAPIABI != pluginControlAPIABI || len(checked.SHA256) != 64 {
		t.Fatalf("contract check = %+v", checked)
	}

	target := filepath.Join(t.TempDir(), "api-contract.json")
	writtenOutput := runPluginPackageCLIForTest(t, "contract", "--output", target)
	var written pluginContractCLIResult
	if err := json.Unmarshal(writtenOutput, &written); err != nil {
		t.Fatal(err)
	}
	if written.Status != "written" || written.Path != target {
		t.Fatalf("contract write = %+v", written)
	}
	if _, err := runPluginPackageCLIWithError("contract", "--output", target); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("contract overwrite error = %v", err)
	}
	if result := runPluginPackageCLIForTest(t, "contract", "--output", target, "--force"); len(result) == 0 {
		t.Fatal("forced contract write returned no result")
	}

	typesTarget := filepath.Join(t.TempDir(), "methods.d.ts")
	typesOutput := runPluginPackageCLIForTest(t, "contract", "--types-output", typesTarget)
	var typesWritten pluginContractCLIResult
	if err := json.Unmarshal(typesOutput, &typesWritten); err != nil {
		t.Fatal(err)
	}
	if typesWritten.Status != "written" || typesWritten.TypesPath != typesTarget {
		t.Fatalf("contract types write = %+v", typesWritten)
	}
	writtenTypes, err := os.ReadFile(typesTarget)
	if err != nil {
		t.Fatal(err)
	}
	wantTypes, err := encodePluginSDKMethodTypes(pluginHostControlMethods)
	if err != nil {
		t.Fatal(err)
	}
	if string(writtenTypes) != string(wantTypes) {
		t.Fatal("generated contract method types differ from the runtime registry")
	}
	if _, err := runPluginPackageCLIWithError("contract", "--types-output", typesTarget); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("contract types overwrite error = %v", err)
	}
	if _, err := runPluginPackageCLIWithError("contract", "--output", target, "--types-output", typesTarget); err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("contract multiple output error = %v", err)
	}

	mismatched := currentPluginSDKAPIContract()
	mismatched.Runtime.ControlAPIABI++
	mismatchData, _, err := encodePluginSDKAPIContract(mismatched, true)
	if err != nil {
		t.Fatal(err)
	}
	mismatchPath := filepath.Join(t.TempDir(), "mismatch.json")
	if err := os.WriteFile(mismatchPath, mismatchData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runPluginPackageCLIWithError("contract", "--check", mismatchPath); err == nil || !strings.Contains(err.Error(), "contract mismatch") {
		t.Fatalf("mismatched contract error = %v", err)
	}
}

func TestPluginObjectVariantsNormalizeAndSelect(t *testing.T) {
	object := PluginObject{
		ID: "forward",
		Variants: []PluginObjectVariant{
			{Architecture: "x86_64", Path: "build/amd64/main.o", SHA256: strings.Repeat("a", 64)},
			{Architecture: "aarch64", Path: "build/arm64/main.o", SHA256: strings.Repeat("b", 64)},
			{Architecture: "armv7", Path: "build/arm/main.o", SHA256: strings.Repeat("c", 64)},
		},
	}
	if err := normalizePluginObject(&object); err != nil {
		t.Fatal(err)
	}
	if object.Variants[0].Architecture != "amd64" || object.Variants[1].Architecture != "arm64" || object.Variants[2].Architecture != "arm" {
		t.Fatalf("normalized variants = %+v", object.Variants)
	}
	if err := selectPluginObjectVariant(&object, "arm64"); err != nil {
		t.Fatal(err)
	}
	if object.Path != "build/arm64/main.o" || object.SHA256 != strings.Repeat("b", 64) || object.SelectedArch != "arm64" {
		t.Fatalf("selected object = %+v", object)
	}

	missing := PluginObject{ID: "missing", Variants: []PluginObjectVariant{{Architecture: "arm64", Path: "arm64.o"}}}
	if err := normalizePluginObject(&missing); err != nil {
		t.Fatal(err)
	}
	if err := selectPluginObjectVariant(&missing, "amd64"); err == nil || !strings.Contains(err.Error(), "no eBPF object variant") {
		t.Fatalf("missing variant error = %v", err)
	}

	duplicate := PluginObject{ID: "duplicate", Variants: []PluginObjectVariant{
		{Architecture: "x86_64", Path: "one.o"},
		{Architecture: "amd64", Path: "two.o"},
	}}
	if err := normalizePluginObject(&duplicate); err == nil || !strings.Contains(err.Error(), "duplicate architecture") {
		t.Fatalf("duplicate variant error = %v", err)
	}
}

func TestPluginObjectStateMapContracts(t *testing.T) {
	object := PluginObject{
		ID:   "stateful",
		Path: "stateful.o",
		StateMaps: []PluginObjectStateMap{
			{Name: "z_sessions", Policy: " PRESERVE ", SchemaVersion: 3},
			{Name: "z_sessions_v4", Policy: "MIGRATE", SchemaVersion: 4, MigrateFrom: "z_sessions"},
			{Name: "old_state", Policy: "RESET"},
		},
	}
	if err := normalizePluginObject(&object); err != nil {
		t.Fatal(err)
	}
	if object.StateMaps[0].Name != "old_state" || object.StateMaps[1].Name != "z_sessions" || object.StateMaps[1].Policy != pluginObjectMapPreserve || object.StateMaps[2].Policy != pluginObjectMapMigrate {
		t.Fatalf("normalized state maps = %+v", object.StateMaps)
	}
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"z_sessions":    {Name: "z_sessions", Type: ebpf.LRUHash, KeySize: 4, ValueSize: 8, MaxEntries: 1024},
		"z_sessions_v4": {Name: "z_sessions_v4", Type: ebpf.LRUHash, KeySize: 4, ValueSize: 16, MaxEntries: 1024},
	}}
	if err := validatePluginObjectStateMapSpecs(object.StateMaps, spec); err != nil {
		t.Fatalf("state map spec validation: %v", err)
	}

	tests := []struct {
		name    string
		maps    []PluginObjectStateMap
		wantErr string
	}{
		{name: "duplicate", maps: []PluginObjectStateMap{{Name: "sessions", Policy: "preserve", SchemaVersion: 1}, {Name: "sessions", Policy: "reset"}}, wantErr: "duplicate map"},
		{name: "reserved", maps: []PluginObjectStateMap{{Name: "tc_plugin_ctx_v4", Policy: "preserve", SchemaVersion: 1}}, wantErr: "reserved by Veer"},
		{name: "missing schema", maps: []PluginObjectStateMap{{Name: "sessions", Policy: "preserve"}}, wantErr: "schema_version"},
		{name: "reset schema", maps: []PluginObjectStateMap{{Name: "sessions", Policy: "reset", SchemaVersion: 1}}, wantErr: "must be omitted"},
		{name: "bad policy", maps: []PluginObjectStateMap{{Name: "sessions", Policy: "copy", SchemaVersion: 1}}, wantErr: "preserve, migrate, or reset"},
		{name: "missing migration source", maps: []PluginObjectStateMap{{Name: "sessions_v2", Policy: "migrate", SchemaVersion: 2, MigrateFrom: "sessions"}}, wantErr: "must be declared"},
		{name: "newer migration source", maps: []PluginObjectStateMap{{Name: "sessions", Policy: "preserve", SchemaVersion: 2}, {Name: "sessions_v2", Policy: "migrate", SchemaVersion: 2, MigrateFrom: "sessions"}}, wantErr: "must be greater"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := PluginObject{ID: "stateful", Path: "stateful.o", StateMaps: test.maps}
			if err := normalizePluginObject(&candidate); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("normalize error = %v, want %q", err, test.wantErr)
			}
		})
	}

	missing := []PluginObjectStateMap{{Name: "missing", Policy: pluginObjectMapPreserve, SchemaVersion: 1}}
	if err := validatePluginObjectStateMapSpecs(missing, spec); err == nil || !strings.Contains(err.Error(), "not present") {
		t.Fatalf("missing state map error = %v", err)
	}
	unsupported := []PluginObjectStateMap{{Name: "events", Policy: pluginObjectMapPreserve, SchemaVersion: 1}}
	if err := validatePluginObjectStateMapSpecs(unsupported, &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"events": {Name: "events", Type: ebpf.RingBuf, MaxEntries: 4096},
	}}); err == nil || !strings.Contains(err.Error(), "unsupported map type") {
		t.Fatalf("unsupported state map error = %v", err)
	}
}

func TestValidatePluginObjectArtifactsChecksEveryStableVariant(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "amd64.o"), []byte("amd64 object"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "arm64.o"), []byte("arm64 object"), 0o644); err != nil {
		t.Fatal(err)
	}
	plugin := &LoadedPlugin{
		PluginManifest: PluginManifest{ID: "variants", Stability: pluginStabilityStable},
		rootDir:        root,
	}
	missingHash := PluginObject{ID: "dataplane", Variants: []PluginObjectVariant{
		{Architecture: "amd64", Path: "amd64.o"},
		{Architecture: "arm64", Path: "arm64.o", SHA256: strings.Repeat("a", 64)},
	}}
	if err := normalizePluginObject(&missingHash); err != nil {
		t.Fatal(err)
	}
	if err := validatePluginObjectArtifacts(plugin, missingHash); err == nil || !strings.Contains(err.Error(), "variant amd64 sha256 is required") {
		t.Fatalf("missing variant hash error = %v", err)
	}

	mismatch := PluginObject{ID: "dataplane", Variants: []PluginObjectVariant{
		{Architecture: "arm64", Path: "arm64.o", SHA256: strings.Repeat("b", 64)},
		{Architecture: "amd64", Path: "amd64.o", SHA256: strings.Repeat("a", 64)},
	}}
	if err := normalizePluginObject(&mismatch); err != nil {
		t.Fatal(err)
	}
	if err := validatePluginObjectArtifacts(plugin, mismatch); err == nil || !strings.Contains(err.Error(), "variant arm64 sha256 mismatch") {
		t.Fatalf("mismatched variant hash error = %v", err)
	}
}

func TestPluginBuildArchitectureAndFlagValidation(t *testing.T) {
	architectures, err := parsePluginBuildArchitectures("x86_64,aarch64,armv7,amd64")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(architectures, ",") != "amd64,arm64,arm" {
		t.Fatalf("architectures = %v", architectures)
	}
	if _, err := parsePluginBuildArchitectures("mips64"); err == nil {
		t.Fatal("unsupported architecture was accepted")
	}
	if err := validatePluginBuildExtraFlags([]string{"-O3", "-DVALUE=1"}); err != nil {
		t.Fatalf("safe cflags error = %v", err)
	}
	for _, value := range []string{"-o", "-oevil.o", "--target=mips", "@args.txt"} {
		if err := validatePluginBuildExtraFlags([]string{value}); err == nil {
			t.Fatalf("managed cflag %q was accepted", value)
		}
	}
}
