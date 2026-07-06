package app

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

func resolvePluginObjects(plugin *LoadedPlugin) error {
	for i := range plugin.Objects {
		object := &plugin.Objects[i]
		if strings.HasPrefix(object.Path, "builtin:") {
			return fmt.Errorf("objects[%d]: builtin objects are reserved for internal plugins", i)
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
		if object.SHA256 != "" && got != object.SHA256 {
			object.Status = pluginObjectStatusError
			object.Error = "sha256 mismatch"
			return fmt.Errorf("objects[%d]: sha256 mismatch", i)
		}
		if err := resolvePluginObjectSpec(object, realObjectPath); err != nil {
			object.Status = pluginObjectStatusError
			object.Error = err.Error()
			return fmt.Errorf("objects[%d]: %w", i, err)
		}
		object.Status = pluginObjectStatusVerified
	}
	return nil
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

func resolvePluginObjectSpec(object *PluginObject, objectPath string) error {
	spec, err := loadPluginObjectCollectionSpec(objectPath)
	if err != nil {
		return fmt.Errorf("parse eBPF object: %w", err)
	}
	object.ProgramCount = len(spec.Programs)
	object.MapCount = len(spec.Maps)

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

func loadPluginObjectCollectionSpec(objectPath string) (*ebpf.CollectionSpec, error) {
	file, err := os.Open(objectPath) // #nosec G304 -- objectPath is resolved through resolvePluginObjectRealPath before parsing.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ebpf.LoadCollectionSpecFromReader(file)
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
	file, err := os.Open(filePath) // #nosec G304 -- plugin object paths are symlink-resolved and checked against the plugin root first.
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
