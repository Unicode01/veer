package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

const pluginBuildSourceMaxBytes = 4 << 20

type pluginCLIStringList []string

func (values *pluginCLIStringList) String() string {
	return strings.Join(*values, ",")
}

func (values *pluginCLIStringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

type pluginDeveloperLintResult struct {
	PluginID           string                       `json:"plugin_id"`
	Version            string                       `json:"version"`
	Kind               string                       `json:"kind"`
	Stability          string                       `json:"stability"`
	Control            bool                         `json:"control"`
	Compatible         bool                         `json:"compatible"`
	Registration       bool                         `json:"registration_tested,omitempty"`
	RegistrationDigest string                       `json:"registration_digest,omitempty"`
	RegistrationStable bool                         `json:"registration_deterministic,omitempty"`
	PackageRoundTrip   bool                         `json:"package_round_trip,omitempty"`
	ControlAPIABI      int                          `json:"control_api_abi"`
	ContractSHA256     string                       `json:"contract_sha256"`
	ObjectCount        int                          `json:"object_count,omitempty"`
	HookCount          int                          `json:"hook_count,omitempty"`
	ResourceCount      int                          `json:"resource_count,omitempty"`
	ActionCount        int                          `json:"action_count,omitempty"`
	Checks             []pluginDeveloperCheckResult `json:"checks,omitempty"`
}

type pluginDeveloperCheckResult struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type pluginBuildVariant struct {
	Architecture string `json:"architecture"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
	Programs     int    `json:"programs"`
	Maps         int    `json:"maps"`
}

type pluginBuildObject struct {
	ID       string               `json:"id"`
	Source   string               `json:"source"`
	Variants []pluginBuildVariant `json:"variants"`
}

type pluginBuildResult struct {
	PluginID      string              `json:"plugin_id"`
	Architectures []string            `json:"architectures"`
	OutputDir     string              `json:"output_dir"`
	Objects       []pluginBuildObject `json:"objects"`
}

type pluginContractCLIResult struct {
	Status         string `json:"status"`
	Version        int    `json:"version"`
	ControlAPIABI  int    `json:"control_api_abi"`
	SHA256         string `json:"sha256"`
	ControlMethods int    `json:"control_methods"`
	Path           string `json:"path,omitempty"`
	TypesPath      string `json:"types_path,omitempty"`
}

func runPluginContractCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin contract", flag.ContinueOnError)
	flags.SetOutput(stderr)
	checkPath := flags.String("check", "", "verify a contract file against this Veer runtime")
	outputPath := flags.String("output", "", "write the canonical contract to a file")
	typesOutputPath := flags.String("types-output", "", "write generated TypeScript host method types to a file")
	force := flags.Bool("force", false, "replace an existing regular output file")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	selectedOutputs := 0
	for _, value := range []string{*checkPath, *outputPath, *typesOutputPath} {
		if strings.TrimSpace(value) != "" {
			selectedOutputs++
		}
	}
	if flags.NArg() != 0 || selectedOutputs > 1 {
		return fmt.Errorf("plugin contract accepts no positional arguments and only one of --check, --output or --types-output")
	}
	contract := currentPluginSDKAPIContract()
	pretty, digest, err := encodePluginSDKAPIContract(contract, true)
	if err != nil {
		return err
	}
	result := pluginContractCLIResult{
		Status: "current", Version: contract.Version, ControlAPIABI: contract.Runtime.ControlAPIABI,
		SHA256: digest, ControlMethods: len(contract.ControlMethods),
	}
	if value := strings.TrimSpace(*checkPath); value != "" {
		path, err := filepath.Abs(value)
		if err != nil {
			return err
		}
		data, err := readPluginDeveloperRegularFile(path, pluginPackageMaxEntryBytes)
		if err != nil {
			return err
		}
		got, err := decodePluginSDKAPIContract(data)
		if err != nil {
			return fmt.Errorf("decode contract %s: %w", path, err)
		}
		gotCanonical, _, err := encodePluginSDKAPIContract(got, false)
		if err != nil {
			return err
		}
		wantCanonical, _, err := encodePluginSDKAPIContract(contract, false)
		if err != nil {
			return err
		}
		if string(gotCanonical) != string(wantCanonical) {
			_, gotDigest, _ := encodePluginSDKAPIContract(got, false)
			return fmt.Errorf("plugin SDK contract mismatch: file=%s runtime=%s", gotDigest, digest)
		}
		result.Status = "compatible"
		result.Path = path
		return writePluginPackageCLIJSON(stdout, result)
	}
	if value := strings.TrimSpace(*outputPath); value != "" {
		path, err := filepath.Abs(value)
		if err != nil {
			return err
		}
		if err := writePluginDeveloperFile(path, pretty, *force); err != nil {
			return err
		}
		result.Status = "written"
		result.Path = path
		return writePluginPackageCLIJSON(stdout, result)
	}
	if value := strings.TrimSpace(*typesOutputPath); value != "" {
		path, err := filepath.Abs(value)
		if err != nil {
			return err
		}
		types, err := encodePluginSDKMethodTypes(contract.ControlMethods)
		if err != nil {
			return err
		}
		if err := writePluginDeveloperFile(path, types, *force); err != nil {
			return err
		}
		result.Status = "written"
		result.TypesPath = path
		return writePluginPackageCLIJSON(stdout, result)
	}
	_, err = stdout.Write(pretty)
	return err
}

func runPluginInitCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	id := flags.String("id", "", "plugin id")
	name := flags.String("name", "", "display name")
	kind := flags.String("kind", "control", "control or pipeline")
	directory := flags.String("directory", "", "target directory")
	sdkInclude := flags.String("sdk-include", "", "directory containing veer_plugin_helpers.h")
	force := flags.Bool("force", false, "replace generated files that already exist")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	pluginID := strings.TrimSpace(strings.ToLower(*id))
	if flags.NArg() != 0 || !pluginIDPattern.MatchString(pluginID) {
		return fmt.Errorf("plugin init requires --id matching %s and no positional arguments", pluginIDPattern.String())
	}
	pluginKind := strings.TrimSpace(strings.ToLower(*kind))
	if pluginKind != "control" && pluginKind != "pipeline" {
		return fmt.Errorf("plugin init --kind must be control or pipeline")
	}
	target := strings.TrimSpace(*directory)
	if target == "" {
		target = pluginID
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if err := ensurePluginInitTarget(absTarget); err != nil {
		return err
	}
	displayName := strings.TrimSpace(*name)
	if displayName == "" {
		displayName = pluginDeveloperDisplayName(pluginID)
	}
	manifest, controlSource, bpfSource := pluginDeveloperScaffold(pluginID, displayName, pluginKind)
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestData = append(manifestData, '\n')
	files := map[string][]byte{
		pluginManifestFile: manifestData,
		"control.js":       []byte(controlSource),
	}
	if pluginKind == "pipeline" {
		includeDir, err := locatePluginSDKInclude(*sdkInclude)
		if err != nil {
			return err
		}
		helper, err := readPluginDeveloperRegularFile(filepath.Join(includeDir, "veer_plugin_helpers.h"), pluginObjectMaxSize)
		if err != nil {
			return fmt.Errorf("read plugin SDK helper: %w", err)
		}
		files["main.bpf.c"] = []byte(bpfSource)
		files[filepath.Join("include", "veer_plugin_helpers.h")] = helper
	}
	paths := make([]string, 0, len(files))
	for relative := range files {
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	for _, relative := range paths {
		path := filepath.Join(absTarget, relative)
		if info, err := os.Lstat(path); err == nil {
			if !*force || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("generated file already exists: %s", path)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	for _, relative := range paths {
		if err := writePluginDeveloperFile(filepath.Join(absTarget, relative), files[relative], *force); err != nil {
			return err
		}
	}
	nextCommands := make([][]string, 0, 3)
	if pluginKind == "pipeline" {
		nextCommands = append(nextCommands, []string{"veer", "plugin", "build", "--source", absTarget, "--architectures", "all"})
		targetArchitecture := normalizePluginObjectArchitecture(runtime.GOARCH)
		if targetArchitecture != "amd64" && targetArchitecture != "arm64" && targetArchitecture != "arm" {
			targetArchitecture = "amd64"
		}
		nextCommands = append(nextCommands, []string{
			"veer", "plugin", "test", "--source", absTarget,
			"--os", "linux", "--architecture", targetArchitecture, "--kernel", "6.6.0", "--format", "text",
		})
	} else {
		nextCommands = append(nextCommands, []string{"veer", "plugin", "test", "--source", absTarget, "--format", "text"})
	}
	nextCommands = append(nextCommands, []string{"veer", "plugin", "pack", "--source", absTarget})
	return writePluginPackageCLIJSON(stdout, map[string]any{
		"plugin_id":     pluginID,
		"kind":          pluginKind,
		"directory":     absTarget,
		"files":         paths,
		"next_commands": nextCommands,
	})
}

func runPluginLintCLI(args []string, stdout, stderr io.Writer, registration bool) error {
	name := "plugin lint"
	if registration {
		name = "plugin test"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	source := flags.String("source", "", "plugin source directory")
	targetOS := flags.String("os", runtime.GOOS, "target operating system")
	targetArch := flags.String("architecture", runtime.GOARCH, "target architecture")
	targetKernel := flags.String("kernel", "", "target kernel release")
	outputFormat := flags.String("format", "json", "output format: json or text")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*source) == "" {
		return fmt.Errorf("%s requires --source and no positional arguments", name)
	}
	format, err := pluginDeveloperOutputFormat(*outputFormat)
	if err != nil {
		return err
	}
	absSource, err := filepath.Abs(*source)
	if err != nil {
		return err
	}
	if err := validatePluginDeveloperSourceRoot(absSource); err != nil {
		return err
	}
	plugin, err := loadPluginFromDir(absSource, filepath.Base(absSource))
	if err != nil {
		return err
	}
	if plugin.Status != pluginStatusActive {
		return fmt.Errorf("plugin source is invalid: %s", plugin.Error)
	}
	environment := currentPluginHostEnvironment()
	environment.OS = strings.TrimSpace(strings.ToLower(*targetOS))
	environment.Arch = normalizePluginObjectArchitecture(*targetArch)
	if strings.TrimSpace(*targetKernel) != "" {
		environment.KernelRelease = strings.TrimSpace(*targetKernel)
	}
	if !pluginTokenPattern.MatchString(environment.OS) || !pluginTokenPattern.MatchString(environment.Arch) {
		return fmt.Errorf("target operating system or architecture is invalid")
	}
	if err := checkPluginCompatibility(plugin, environment); err != nil {
		return fmt.Errorf("plugin compatibility: %w", err)
	}
	checks := []pluginDeveloperCheckResult{
		{ID: "manifest", Status: "passed"},
		{ID: "compatibility", Status: "passed", Detail: environment.OS + "/" + environment.Arch},
	}
	registrationDigest := ""
	registrationStable := false
	packageRoundTrip := false
	if registration {
		if err := validatePluginConformanceABI(plugin); err != nil {
			return err
		}
		checks = append(checks, pluginDeveloperCheckResult{ID: "abi", Status: "passed"})
		plugin.objectArchitecture = environment.Arch
		basePlugin := plugin
		enabled := true
		isolation := false
		validationConfig := &Config{
			PluginsEnabledSetting:   &enabled,
			PluginsIsolationSetting: &isolation,
			PluginsMinSandboxLevel:  pluginSandboxLevelNone,
		}
		first, err := registerPluginPackageCandidate(basePlugin, validationConfig)
		if err != nil {
			return err
		}
		second, err := registerPluginPackageCandidate(basePlugin, validationConfig)
		if err != nil {
			return fmt.Errorf("repeat plugin registration: %w", err)
		}
		firstDigest := pluginRuntimeSurfaceDigest(pluginRuntimeSurfaceFromLoaded(first))
		secondDigest := pluginRuntimeSurfaceDigest(pluginRuntimeSurfaceFromLoaded(second))
		if firstDigest == "" || firstDigest != secondDigest {
			return fmt.Errorf("plugin registration is not deterministic: first=%s second=%s", firstDigest, secondDigest)
		}
		plugin = first
		if err := validatePluginConformanceABI(plugin); err != nil {
			return err
		}
		registrationDigest = firstDigest
		registrationStable = true
		checks = append(checks,
			pluginDeveloperCheckResult{ID: "registration", Status: "passed"},
			pluginDeveloperCheckResult{ID: "registration_determinism", Status: "passed", Detail: firstDigest},
		)
		tempDir, err := os.MkdirTemp("", "veer-plugin-conformance-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tempDir)
		if _, err := packPluginDirectory(plugin, filepath.Join(tempDir, plugin.ID+".tar.gz"), false); err != nil {
			return fmt.Errorf("plugin package round trip: %w", err)
		}
		packageRoundTrip = true
		checks = append(checks, pluginDeveloperCheckResult{ID: "package_round_trip", Status: "passed"})
	}
	_, contractDigest, err := encodePluginSDKAPIContract(currentPluginSDKAPIContract(), false)
	if err != nil {
		return err
	}
	result := pluginDeveloperLintResult{
		PluginID:           plugin.ID,
		Version:            plugin.Version,
		Kind:               plugin.Kind,
		Stability:          plugin.Stability,
		Control:            plugin.Control != nil,
		Compatible:         true,
		Registration:       registration,
		RegistrationDigest: registrationDigest,
		RegistrationStable: registrationStable,
		PackageRoundTrip:   packageRoundTrip,
		ControlAPIABI:      pluginControlAPIABI,
		ContractSHA256:     contractDigest,
		ObjectCount:        len(plugin.Objects),
		HookCount:          len(plugin.Hooks),
		ResourceCount:      len(plugin.Resources),
		ActionCount:        len(plugin.Actions),
		Checks:             checks,
	}
	return writePluginDeveloperLintResult(stdout, result, format)
}

func pluginDeveloperOutputFormat(value string) (string, error) {
	format := strings.TrimSpace(strings.ToLower(value))
	switch format {
	case "json", "text":
		return format, nil
	default:
		return "", fmt.Errorf("output format must be json or text")
	}
}

func writePluginDeveloperLintResult(w io.Writer, result pluginDeveloperLintResult, format string) error {
	if format == "json" {
		return writePluginPackageCLIJSON(w, result)
	}
	if _, err := fmt.Fprintf(w, "Plugin: %s %s (%s, %s)\n", result.PluginID, result.Version, result.Kind, result.Stability); err != nil {
		return err
	}
	for _, check := range result.Checks {
		status := strings.ToUpper(check.Status)
		if status == "PASSED" {
			status = "PASS"
		}
		if _, err := fmt.Fprintf(w, "%-6s %s", status, check.ID); err != nil {
			return err
		}
		if check.Detail != "" {
			if _, err := fmt.Fprintf(w, " - %s", check.Detail); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	if result.Registration {
		if _, err := fmt.Fprintf(w, "Surface: %d object(s), %d hook(s), %d resource(s), %d action(s)\n",
			result.ObjectCount, result.HookCount, result.ResourceCount, result.ActionCount); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintln(w, "Runtime surface: not evaluated (run plugin test)"); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "Control API ABI: %d\nContract SHA-256: %s\n", result.ControlAPIABI, result.ContractSHA256)
	return err
}

func validatePluginConformanceABI(plugin LoadedPlugin) error {
	if plugin.Stability != pluginStabilityStable {
		return nil
	}
	if plugin.Compatibility == nil || strings.TrimSpace(plugin.Compatibility.Runtime) == "" {
		return fmt.Errorf("stable plugin %s must declare compatibility.runtime", plugin.ID)
	}
	if plugin.Control != nil && plugin.Compatibility.ControlAPIABI != pluginControlAPIABI {
		return fmt.Errorf("stable plugin %s must declare compatibility.control_api_abi=%d", plugin.ID, pluginControlAPIABI)
	}
	if (len(plugin.Objects) > 0 || len(plugin.Hooks) > 0) && plugin.Compatibility.TCPipelineABI != pluginTCPipelineABI {
		return fmt.Errorf("stable dataplane plugin %s must declare compatibility.tc_pipeline_abi=%d", plugin.ID, pluginTCPipelineABI)
	}
	return nil
}

func runPluginBuildCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin build", flag.ContinueOnError)
	flags.SetOutput(stderr)
	source := flags.String("source", "", "plugin source directory")
	output := flags.String("output-dir", "build", "output directory relative to the plugin")
	architectures := flags.String("architectures", runtime.GOARCH, "comma-separated amd64,arm64,arm or all")
	clang := flags.String("clang", "clang", "clang executable")
	force := flags.Bool("force", false, "replace existing object files")
	var sourceFiles pluginCLIStringList
	var includeDirs pluginCLIStringList
	var extraFlags pluginCLIStringList
	flags.Var(&sourceFiles, "source-file", "relative .bpf.c source; repeatable")
	flags.Var(&includeDirs, "include", "additional include directory; repeatable")
	flags.Var(&extraFlags, "cflag", "additional clang argument; repeatable")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*source) == "" {
		return fmt.Errorf("plugin build requires --source and no positional arguments")
	}
	absSource, err := filepath.Abs(*source)
	if err != nil {
		return err
	}
	if err := validatePluginDeveloperSourceRoot(absSource); err != nil {
		return err
	}
	plugin, err := loadPluginFromDir(absSource, filepath.Base(absSource))
	if err != nil || plugin.Status != pluginStatusActive {
		if err != nil {
			return err
		}
		return fmt.Errorf("plugin source is invalid: %s", plugin.Error)
	}
	targetArchitectures, err := parsePluginBuildArchitectures(*architectures)
	if err != nil {
		return err
	}
	absOutput, err := pluginDeveloperPathWithinRoot(absSource, *output, "output directory", false)
	if err != nil {
		return err
	}
	sources, err := discoverPluginBuildSources(absSource, absOutput, sourceFiles)
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return fmt.Errorf("no *.bpf.c sources found")
	}
	includes := []string{filepath.Join(absSource, "include")}
	for _, value := range includeDirs {
		include, err := pluginDeveloperPathWithinRootOrAbsolute(absSource, value, "include directory")
		if err != nil {
			return err
		}
		includes = append(includes, include)
	}
	if strings.TrimSpace(*clang) == "" || strings.ContainsRune(*clang, '\x00') {
		return fmt.Errorf("clang executable is invalid")
	}
	if err := validatePluginBuildExtraFlags(extraFlags); err != nil {
		return err
	}
	result := pluginBuildResult{PluginID: plugin.ID, Architectures: targetArchitectures, OutputDir: filepath.ToSlash(*output)}
	for _, sourcePath := range sources {
		relSource, _ := filepath.Rel(absSource, sourcePath)
		relSource = filepath.ToSlash(relSource)
		objectRel := strings.TrimSuffix(relSource, ".bpf.c") + ".o"
		object := pluginBuildObject{ID: pluginDeveloperObjectID(objectRel), Source: relSource}
		for _, architecture := range targetArchitectures {
			target := filepath.Join(absOutput, architecture, filepath.FromSlash(objectRel))
			variant, err := compilePluginBPFObject(*clang, sourcePath, target, architecture, includes, extraFlags, absSource, *force)
			if err != nil {
				return fmt.Errorf("build %s for %s: %w", relSource, architecture, err)
			}
			object.Variants = append(object.Variants, variant)
		}
		result.Objects = append(result.Objects, object)
	}
	return writePluginPackageCLIJSON(stdout, result)
}

func pluginDeveloperScaffold(id, name, kind string) (PluginManifest, string, string) {
	manifest := PluginManifest{
		APIVersion:  pluginAPIVersionV1,
		ID:          id,
		Name:        name,
		Version:     "0.1.0",
		Kind:        kind,
		Stability:   pluginStabilityLab,
		Description: "Veer plugin.",
		Compatibility: &PluginCompatibility{
			Runtime:       ">=1.0.0 <2.0.0",
			ControlAPIABI: pluginControlAPIABI,
		},
		Control: &PluginControl{
			Main:        "control.js",
			Permissions: []string{"metrics"},
		},
	}
	control := "exports.onReconcile = function () {\n  metrics.counter('reconciles_total');\n};\n"
	bpf := ""
	if kind == "pipeline" {
		manifest.Compatibility.TCPipelineABI = pluginTCPipelineABI
		manifest.Compatibility.OS = []string{"linux"}
		manifest.Compatibility.Architectures = []string{"amd64", "arm64", "arm"}
		manifest.Compatibility.Features = []string{"dataplane.tc_pipeline.v2", "ebpf.object_variants.v1"}
		manifest.Control.Permissions = []string{"ebpf.load", "hook.attach", "metrics", "plugin.register"}
		control = `plugin.capabilities(['tc']);
ebpf.loadObject({
  id: 'main',
  variants: [
    {architecture: 'amd64', path: 'build/amd64/main.o'},
    {architecture: 'arm64', path: 'build/arm64/main.o'},
    {architecture: 'arm', path: 'build/arm/main.o'}
  ],
  programs: [{id: 'pre_forward', section: 'tc/veer/pre_forward', type: 'tc'}]
});
pipeline.attach({
  id: 'pre-forward',
  direction: 'forward',
  priority: 10,
  program: 'main:pre_forward',
  mode: 'observe'
});

exports.onReconcile = function () {
  metrics.counter('reconciles_total');
};
`
		bpf = `#include "include/veer_plugin_helpers.h"

VEER_DECLARE_PROG_CHAIN_V4();

SEC("tc/veer/pre_forward")
int pre_forward(struct __sk_buff *skb)
{
	(void)veer_packet_family(skb);
	veer_continue_pre_forward(skb);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
`
	}
	return manifest, control, bpf
}

func ensurePluginInitTarget(target string) error {
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("plugin init target must be a regular directory")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(target, 0o755)
}

func writePluginDeveloperFile(path string, data []byte, force bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !force || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("generated file already exists: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".veer-plugin-init-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if force {
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return nil
}

func validatePluginDeveloperSourceRoot(source string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("plugin source must be a regular directory")
	}
	return nil
}

func pluginDeveloperPathWithinRoot(root, value, label string, mustExist bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || filepath.IsAbs(value) || strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("%s must be a relative path", label)
	}
	path := filepath.Clean(filepath.Join(root, filepath.FromSlash(value)))
	if !pathWithinRoot(root, path) {
		return "", fmt.Errorf("%s escapes the plugin source", label)
	}
	if mustExist {
		if _, err := os.Stat(path); err != nil {
			return "", err
		}
	}
	return path, nil
}

func pluginDeveloperPathWithinRootOrAbsolute(root, value, label string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("%s is invalid", label)
	}
	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, filepath.FromSlash(path))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%s must be a regular directory", label)
	}
	return abs, nil
}

func locatePluginSDKInclude(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return pluginDeveloperPathWithinRootOrAbsolute(".", explicit, "SDK include directory")
	}
	candidates := make([]string, 0, 4)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "plugins", "include"))
	}
	if executable, err := os.Executable(); err == nil {
		base := filepath.Dir(executable)
		candidates = append(candidates,
			filepath.Join(base, "plugins", "include"),
			filepath.Join(base, "..", "share", "veer", "plugins", "include"),
		)
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(filepath.Join(candidate, "veer_plugin_helpers.h")); err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("veer_plugin_helpers.h was not found; pass --sdk-include")
}

func readPluginDeveloperRegularFile(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxBytes {
		return nil, fmt.Errorf("file must be a bounded regular file")
	}
	return os.ReadFile(path)
}

func parsePluginBuildArchitectures(value string) ([]string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "all" {
		value = "amd64,arm64,arm"
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, 3)
	for _, raw := range strings.Split(value, ",") {
		architecture := normalizePluginObjectArchitecture(raw)
		switch architecture {
		case "amd64", "arm64", "arm":
		default:
			return nil, fmt.Errorf("unsupported BPF target architecture %q", strings.TrimSpace(raw))
		}
		if _, exists := seen[architecture]; exists {
			continue
		}
		seen[architecture] = struct{}{}
		out = append(out, architecture)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one target architecture is required")
	}
	return out, nil
}

func validatePluginBuildExtraFlags(values []string) error {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		lower := strings.ToLower(trimmed)
		if trimmed == "-o" || (len(trimmed) > 2 && strings.HasPrefix(trimmed, "-o")) || lower == "-c" || lower == "-target" || lower == "--target" ||
			strings.HasPrefix(lower, "--output") ||
			strings.HasPrefix(lower, "-target=") || strings.HasPrefix(lower, "--target=") ||
			strings.HasPrefix(lower, "@") {
			return fmt.Errorf("cflag %q may override a managed compiler argument", value)
		}
	}
	return nil
}

func discoverPluginBuildSources(root, output string, requested []string) ([]string, error) {
	if len(requested) > 0 {
		out := make([]string, 0, len(requested))
		seen := make(map[string]struct{}, len(requested))
		for _, relative := range requested {
			path, err := pluginDeveloperPathWithinRoot(root, relative, "source file", true)
			if err != nil {
				return nil, err
			}
			if !strings.HasSuffix(strings.ToLower(path), ".bpf.c") {
				return nil, fmt.Errorf("source file must end with .bpf.c: %s", relative)
			}
			if _, exists := seen[path]; !exists {
				seen[path] = struct{}{}
				out = append(out, path)
			}
		}
		sort.Strings(out)
		return out, nil
	}
	out := make([]string, 0)
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("plugin source contains symbolic link %s", path)
		}
		if info.IsDir() {
			if path != root && pathWithinRoot(output, path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("plugin source contains unsupported file %s", path)
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".bpf.c") {
			if info.Size() < 0 || info.Size() > pluginBuildSourceMaxBytes {
				return fmt.Errorf("BPF source %s exceeds %d bytes", path, pluginBuildSourceMaxBytes)
			}
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func compilePluginBPFObject(clang, source, target, architecture string, includes, extraFlags []string, root string, force bool) (pluginBuildVariant, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return pluginBuildVariant{}, err
	}
	if info, err := os.Lstat(target); err == nil {
		if !force || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return pluginBuildVariant{}, fmt.Errorf("output already exists: %s", target)
		}
	} else if !os.IsNotExist(err) {
		return pluginBuildVariant{}, err
	}
	temp, err := os.CreateTemp(filepath.Dir(target), ".veer-plugin-bpf-*.o")
	if err != nil {
		return pluginBuildVariant{}, err
	}
	tempPath := temp.Name()
	if err := temp.Close(); err != nil {
		return pluginBuildVariant{}, err
	}
	defer os.Remove(tempPath)
	targetMacro := map[string]string{"amd64": "x86", "arm64": "arm64", "arm": "arm"}[architecture]
	arguments := []string{"-O2", "-target", "bpf", "-D__TARGET_ARCH_" + targetMacro}
	for _, include := range includes {
		if info, err := os.Stat(include); err == nil && info.IsDir() {
			arguments = append(arguments, "-I"+include)
		}
	}
	arguments = append(arguments, extraFlags...)
	arguments = append(arguments, "-c", source, "-o", tempPath)
	command := exec.Command(clang, arguments...)
	command.Dir = filepath.Dir(source)
	output, err := command.CombinedOutput()
	if err != nil {
		return pluginBuildVariant{}, fmt.Errorf("clang: %w: %s", err, strings.TrimSpace(string(output)))
	}
	info, err := os.Stat(tempPath)
	if err != nil {
		return pluginBuildVariant{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > pluginObjectMaxSize {
		return pluginBuildVariant{}, fmt.Errorf("compiled object is empty or exceeds %d bytes", pluginObjectMaxSize)
	}
	spec, err := ebpf.LoadCollectionSpec(tempPath)
	if err != nil {
		return pluginBuildVariant{}, fmt.Errorf("parse compiled eBPF object: %w", err)
	}
	hash, err := sha256File(tempPath)
	if err != nil {
		return pluginBuildVariant{}, err
	}
	if force {
		if existing, err := os.Lstat(target); err == nil && existing.Mode().IsRegular() && existing.Mode()&os.ModeSymlink == 0 {
			if err := os.Remove(target); err != nil {
				return pluginBuildVariant{}, err
			}
		}
	}
	if err := os.Rename(tempPath, target); err != nil {
		return pluginBuildVariant{}, err
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return pluginBuildVariant{}, err
	}
	return pluginBuildVariant{
		Architecture: architecture,
		Path:         filepath.ToSlash(rel),
		SHA256:       hash,
		Bytes:        info.Size(),
		Programs:     len(spec.Programs),
		Maps:         len(spec.Maps),
	}, nil
}

func pluginDeveloperObjectID(path string) string {
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	name = strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(name))
	if pluginIDPattern.MatchString(name) {
		return name
	}
	return "object"
}

func pluginDeveloperDisplayName(id string) string {
	parts := strings.Fields(strings.NewReplacer("_", " ", "-", " ").Replace(id))
	for i := range parts {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, " ")
}
