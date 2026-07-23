package app

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

func resolvePluginObjects(plugin *LoadedPlugin) error {
	architecture := strings.TrimSpace(plugin.objectArchitecture)
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	for i := range plugin.Objects {
		object := &plugin.Objects[i]
		if strings.HasPrefix(object.Path, "builtin:") {
			return fmt.Errorf("objects[%d]: builtin objects are reserved for internal plugins", i)
		}
		if err := validatePluginObjectArtifacts(plugin, *object); err != nil {
			object.Status = pluginObjectStatusError
			object.Error = err.Error()
			return fmt.Errorf("objects[%d]: %w", i, err)
		}
		if err := selectPluginObjectVariant(object, architecture); err != nil {
			object.Status = pluginObjectStatusError
			object.Error = err.Error()
			return fmt.Errorf("objects[%d]: %w", i, err)
		}
		object.Status = ""
		object.Error = ""
		object.ResolvedSHA256 = ""
		object.ProgramCount = 0
		object.MapCount = 0

		realObjectPath, err := resolvePluginObjectRealPath(plugin, *object)
		if err != nil {
			object.Status = pluginObjectStatusError
			object.Error = err.Error()
			return fmt.Errorf("objects[%d]: path escapes plugin root", i)
		}
		info, err := os.Stat(realObjectPath)
		if err != nil {
			object.Status = pluginObjectStatusError
			object.Error = err.Error()
			return fmt.Errorf("objects[%d]: %w", i, err)
		}
		if info.IsDir() {
			object.Status = pluginObjectStatusError
			object.Error = "path is a directory"
			return fmt.Errorf("objects[%d]: path is a directory", i)
		}
		if info.Size() > pluginObjectMaxSize {
			object.Status = pluginObjectStatusError
			object.Error = fmt.Sprintf("object exceeds %d bytes", pluginObjectMaxSize)
			return fmt.Errorf("objects[%d]: object exceeds %d bytes", i, pluginObjectMaxSize)
		}
		got, err := sha256File(realObjectPath)
		if err != nil {
			object.Status = pluginObjectStatusError
			object.Error = "hash object: " + err.Error()
			return fmt.Errorf("objects[%d]: hash object: %w", i, err)
		}
		object.ResolvedSHA256 = got
		if pluginObjectSHA256Required(*plugin, *object) && object.SHA256 == "" {
			object.Status = pluginObjectStatusError
			object.Error = "sha256 is required for stable or preview external objects"
			return fmt.Errorf("objects[%d]: sha256 is required for stable or preview external objects", i)
		}
		if object.SHA256 != "" && got != object.SHA256 {
			object.Status = pluginObjectStatusError
			object.Error = "sha256 mismatch"
			return fmt.Errorf("objects[%d]: sha256 mismatch", i)
		}
		if err := resolvePluginObjectSpec(object, realObjectPath, got, plugin.resourceLimits); err != nil {
			object.Status = pluginObjectStatusError
			object.Error = err.Error()
			return fmt.Errorf("objects[%d]: %w", i, err)
		}
		object.Status = pluginObjectStatusVerified
	}
	return nil
}

type pluginObjectArtifact struct {
	Label  string
	Path   string
	SHA256 string
}

func validatePluginObjectArtifacts(plugin *LoadedPlugin, object PluginObject) error {
	artifacts := make([]pluginObjectArtifact, 0, len(object.Variants)+1)
	if strings.TrimSpace(object.Path) != "" {
		artifacts = append(artifacts, pluginObjectArtifact{Label: "fallback", Path: object.Path, SHA256: object.SHA256})
	}
	for _, variant := range object.Variants {
		artifacts = append(artifacts, pluginObjectArtifact{
			Label:  "variant " + variant.Architecture,
			Path:   variant.Path,
			SHA256: variant.SHA256,
		})
	}
	for _, artifact := range artifacts {
		candidate := object
		candidate.Path = artifact.Path
		candidate.SHA256 = artifact.SHA256
		candidate.Variants = nil
		if pluginObjectSHA256Required(*plugin, candidate) && candidate.SHA256 == "" {
			return fmt.Errorf("%s sha256 is required for stable or preview external objects", artifact.Label)
		}
		realPath, err := resolvePluginObjectRealPath(plugin, candidate)
		if err != nil {
			return fmt.Errorf("%s path escapes plugin root", artifact.Label)
		}
		info, err := os.Stat(realPath)
		if err != nil {
			return fmt.Errorf("%s: %w", artifact.Label, err)
		}
		if info.IsDir() {
			return fmt.Errorf("%s path is a directory", artifact.Label)
		}
		if info.Size() > pluginObjectMaxSize {
			return fmt.Errorf("%s exceeds %d bytes", artifact.Label, pluginObjectMaxSize)
		}
		got, err := sha256File(realPath)
		if err != nil {
			return fmt.Errorf("hash %s: %w", artifact.Label, err)
		}
		if candidate.SHA256 != "" && got != candidate.SHA256 {
			return fmt.Errorf("%s sha256 mismatch", artifact.Label)
		}
		if err := resolvePluginObjectSpec(&candidate, realPath, got, plugin.resourceLimits); err != nil {
			return fmt.Errorf("%s: %w", artifact.Label, err)
		}
	}
	return nil
}

func selectPluginObjectVariant(object *PluginObject, architecture string) error {
	if object == nil {
		return fmt.Errorf("object is nil")
	}
	object.SelectedArch = ""
	architecture = normalizePluginObjectArchitecture(architecture)
	for _, variant := range object.Variants {
		if normalizePluginObjectArchitecture(variant.Architecture) != architecture {
			continue
		}
		object.Path = variant.Path
		object.SHA256 = variant.SHA256
		object.SelectedArch = architecture
		return nil
	}
	if strings.TrimSpace(object.Path) != "" {
		object.SelectedArch = "fallback"
		return nil
	}
	return fmt.Errorf("no eBPF object variant is available for architecture %s", architecture)
}

func pluginObjectSHA256Required(plugin LoadedPlugin, object PluginObject) bool {
	if plugin.Builtin || strings.HasPrefix(object.Path, "builtin:") {
		return false
	}
	switch strings.TrimSpace(strings.ToLower(plugin.Stability)) {
	case pluginStabilityStable, pluginStabilityPreview:
		return true
	default:
		return false
	}
}

func resolvePluginObjectRealPath(plugin *LoadedPlugin, object PluginObject) (string, error) {
	cleanRoot, err := filepath.Abs(plugin.rootDir)
	if err != nil {
		return "", fmt.Errorf("resolve plugin root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		return "", fmt.Errorf("resolve plugin root: %w", err)
	}
	objectPath := filepath.Join(plugin.rootDir, filepath.FromSlash(object.Path))
	if !pathWithinRoot(plugin.rootDir, objectPath) {
		return "", fmt.Errorf("path escapes plugin root")
	}
	realObjectPath, err := filepath.EvalSymlinks(objectPath)
	if err != nil {
		return "", err
	}
	if !pathWithinRoot(realRoot, realObjectPath) {
		return "", fmt.Errorf("path escapes plugin root")
	}
	return realObjectPath, nil
}

func resolvePluginObjectSpec(object *PluginObject, objectPath, expectedSHA256 string, limits PluginResourceLimits) error {
	spec, err := loadVerifiedPluginObjectCollectionSpec(objectPath, expectedSHA256)
	if err != nil {
		return fmt.Errorf("parse eBPF object: %w", err)
	}
	object.ProgramCount = len(spec.Programs)
	object.MapCount = len(spec.Maps)
	if limits.ObjectsPerPlugin == 0 {
		limits = pluginResourceLimitsFromConfig(nil)
	}
	usage, err := pluginObjectResourceUsageFromSpec(spec, limits)
	if err != nil {
		return fmt.Errorf("resource budget: %w", err)
	}
	object.ResourceUsage = usage
	if err := validatePluginObjectStateMapSpecs(object.StateMaps, spec); err != nil {
		return err
	}

	discoveredPrograms := pluginObjectProgramsFromSpec(spec)
	if len(object.Programs) == 0 {
		object.Programs = discoveredPrograms
		return nil
	}

	programsBySection := make(map[string]PluginObjectProgram, len(discoveredPrograms))
	for _, program := range discoveredPrograms {
		programsBySection[program.Section] = program
	}
	for i := range object.Programs {
		declared := &object.Programs[i]
		discovered, ok := programsBySection[declared.Section]
		if !ok {
			return fmt.Errorf("program %q section %q not found in object", declared.ID, declared.Section)
		}
		if declared.Type != "" && declared.Type != discovered.Type {
			return fmt.Errorf("program %q section %q type = %q, want %q", declared.ID, declared.Section, discovered.Type, declared.Type)
		}
		declared.Type = discovered.Type
		declared.AttachType = discovered.AttachType
		declared.InstructionCount = discovered.InstructionCount
	}
	return nil
}

func validatePluginObjectStateMapSpecs(contracts []PluginObjectStateMap, spec *ebpf.CollectionSpec) error {
	if len(contracts) == 0 {
		return nil
	}
	if spec == nil {
		return fmt.Errorf("state map validation requires an eBPF collection spec")
	}
	for _, contract := range contracts {
		if contract.Policy != pluginObjectMapPreserve && contract.Policy != pluginObjectMapMigrate {
			continue
		}
		mapSpec := spec.Maps[contract.Name]
		if mapSpec == nil {
			return fmt.Errorf("state map %q with policy %s is not present in the object", contract.Name, contract.Policy)
		}
		if !pluginObjectMapTypeSupportsStatePreservation(mapSpec.Type) {
			return fmt.Errorf("state map %q with policy %s uses unsupported map type %s", contract.Name, contract.Policy, mapSpec.Type)
		}
	}
	return nil
}

func pluginObjectMapTypeSupportsStatePreservation(mapType ebpf.MapType) bool {
	switch mapType {
	case ebpf.Hash,
		ebpf.Array,
		ebpf.PerCPUHash,
		ebpf.PerCPUArray,
		ebpf.LRUHash,
		ebpf.LRUCPUHash,
		ebpf.LPMTrie:
		return true
	default:
		return false
	}
}

func loadVerifiedPluginObjectCollectionSpec(objectPath, expectedSHA256 string) (*ebpf.CollectionSpec, error) {
	expectedSHA256 = strings.TrimSpace(strings.ToLower(expectedSHA256))
	if expectedSHA256 == "" {
		return nil, fmt.Errorf("verified sha256 is required")
	}

	data, _, err := readBoundedRegularFileAtPath(objectPath, pluginObjectMaxSize, true)
	if err != nil {
		return nil, err
	}
	got := fmt.Sprintf("%x", sha256.Sum256(data))
	if got != expectedSHA256 {
		return nil, fmt.Errorf("sha256 changed after catalog verification: got %s, want %s", got, expectedSHA256)
	}
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
}

func pluginObjectProgramsFromSpec(spec *ebpf.CollectionSpec) []PluginObjectProgram {
	if spec == nil || len(spec.Programs) == 0 {
		return nil
	}
	programs := make([]PluginObjectProgram, 0, len(spec.Programs))
	for name, program := range spec.Programs {
		if program == nil {
			continue
		}
		id := strings.TrimSpace(strings.ToLower(name))
		if !pluginIDPattern.MatchString(id) {
			id = pluginProgramIDFromSection(program.SectionName)
		}
		programs = append(programs, PluginObjectProgram{
			ID:               id,
			Section:          program.SectionName,
			Type:             pluginObjectProgramKind(program),
			AttachType:       fmt.Sprint(program.AttachType),
			InstructionCount: len(program.Instructions),
		})
	}
	sort.Slice(programs, func(i, j int) bool {
		if programs[i].Section == programs[j].Section {
			return programs[i].ID < programs[j].ID
		}
		return programs[i].Section < programs[j].Section
	})
	return programs
}

func pluginProgramIDFromSection(section string) string {
	value := strings.TrimSpace(strings.ToLower(section))
	value = strings.Trim(value, "/")
	value = strings.NewReplacer("/", "_", ".", "_", "-", "_").Replace(value)
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	value = strings.Trim(value, "_")
	if pluginIDPattern.MatchString(value) {
		return value
	}
	return "program"
}

func pluginObjectProgramKind(program *ebpf.ProgramSpec) string {
	if program == nil {
		return "control"
	}
	switch program.Type {
	case ebpf.SchedCLS, ebpf.SchedACT:
		return kernelEngineTC
	case ebpf.XDP:
		return kernelEngineXDP
	default:
		return "control"
	}
}

func sha256File(filePath string) (string, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(filepath.Dir(absPath))
	if err != nil {
		return "", err
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(absPath))
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func validatePluginHookProgramRefs(plugin *LoadedPlugin) error {
	if plugin == nil || len(plugin.Objects) == 0 || len(plugin.Hooks) == 0 {
		return nil
	}

	objects := make(map[string]PluginObject, len(plugin.Objects)*2)
	for _, object := range plugin.Objects {
		if object.Status != pluginObjectStatusVerified {
			continue
		}
		objects[object.ID] = object
		objects[object.Path] = object
	}
	objectEngines := make(map[string]string, len(plugin.Objects))
	for i, hook := range plugin.Hooks {
		if hook.Engine == "control" || strings.HasPrefix(hook.Program, "builtin:") {
			continue
		}
		objectRef, programRef, ok := parsePluginProgramRef(hook.Program)
		if !ok {
			return fmt.Errorf("hooks[%d]: program must use object:program when objects are declared", i)
		}
		object, ok := objects[objectRef]
		if !ok {
			return fmt.Errorf("hooks[%d]: object %q not found", i, objectRef)
		}
		program, ok := pluginObjectProgramByRef(object, programRef)
		if !ok {
			return fmt.Errorf("hooks[%d]: program %q not found in object %q", i, programRef, objectRef)
		}
		if hook.Engine != program.Type {
			return fmt.Errorf("hooks[%d]: program %q type = %q, want hook engine %q", i, programRef, program.Type, hook.Engine)
		}
		if previous := objectEngines[object.ID]; previous != "" && previous != hook.Engine {
			return fmt.Errorf("hooks[%d]: object %q is shared by %s and %s hooks; split cross-engine programs into separate objects so private map ownership remains deterministic", i, object.ID, previous, hook.Engine)
		}
		objectEngines[object.ID] = hook.Engine
	}
	return nil
}

func parsePluginProgramRef(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	idx := strings.LastIndex(value, ":")
	if idx <= 0 || idx >= len(value)-1 {
		return "", "", false
	}
	objectRef := strings.TrimSpace(value[:idx])
	programRef := strings.TrimSpace(value[idx+1:])
	return objectRef, programRef, objectRef != "" && programRef != ""
}

func pluginObjectProgramByRef(object PluginObject, programRef string) (PluginObjectProgram, bool) {
	programRef = strings.TrimSpace(programRef)
	if programRef == "" {
		return PluginObjectProgram{}, false
	}
	for _, program := range object.Programs {
		if program.ID == programRef || program.Section == programRef {
			return program, true
		}
	}
	return PluginObjectProgram{}, false
}
