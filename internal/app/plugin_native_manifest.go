package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

const (
	pluginNativeABIMajor           = 1
	pluginNativeWorkerShared       = "shared"
	pluginNativeWorkerDedicated    = "dedicated"
	pluginNativeMaxLibraryBytes    = 64 << 20
	pluginNativeMaxRegisterEntries = 256
)

// pluginNativeControlFeature is the runtime feature of native plugins.
const pluginNativeControlFeature = "control.native.v1"

// pluginNativeTargets are the library builds a native plugin may ship.
var pluginNativeTargets = []string{"x86_64-linux-gnu", "x86_64-linux-musl", "aarch64-linux-gnu", "aarch64-linux-musl"}

var pluginNativeTriples = map[string]struct{}{
	"x86_64-linux-gnu":   {},
	"x86_64-linux-musl":  {},
	"aarch64-linux-gnu":  {},
	"aarch64-linux-musl": {},
}

// PluginNativeLibrary is one build of a native plugin's shared library.
type PluginNativeLibrary struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
}

// PluginNativeRegistration is the plugin surface a native plugin declares in
// its manifest. Each entry is the object the matching registration method
// takes (plugin.resource, ebpf.loadObject, events.subscribe, ...), plus an
// optional "when" condition on host features. The host registers entries in
// a fixed order: capabilities, virtual interfaces, pipeline nodes, handoffs,
// eBPF objects, pipeline attachments, hooks, resources, actions, services,
// subscriptions, UI.
type PluginNativeRegistration struct {
	Capabilities      []string          `json:"capabilities,omitempty"`
	VirtualInterfaces []json.RawMessage `json:"virtual_interfaces,omitempty"`
	PipelineNodes     []json.RawMessage `json:"pipeline_nodes,omitempty"`
	Handoffs          []json.RawMessage `json:"handoffs,omitempty"`
	Objects           []json.RawMessage `json:"ebpf_objects,omitempty"`
	RingSubscriptions []json.RawMessage `json:"ring_subscriptions,omitempty"`
	PipelineAttach    []json.RawMessage `json:"pipeline_attach,omitempty"`
	Hooks             []json.RawMessage `json:"hooks,omitempty"`
	Resources         []json.RawMessage `json:"resources,omitempty"`
	Actions           []json.RawMessage `json:"actions,omitempty"`
	Services          []json.RawMessage `json:"services,omitempty"`
	Subscriptions     []json.RawMessage `json:"subscriptions,omitempty"`
	UI                json.RawMessage   `json:"ui,omitempty"`
}

type pluginNativeRegisterCall struct {
	method string
	args   []any
}

type pluginNativeRegisterCondition struct {
	Feature    string `json:"feature,omitempty"`
	NotFeature string `json:"not_feature,omitempty"`
}

// pluginUsesNativeControl reports whether a plugin's control side is native:
// a shared library, or only a declared surface (eBPF objects, hooks, UI)
// with no code at all.
func pluginUsesNativeControl(plugin LoadedPlugin) bool {
	return plugin.Control != nil && plugin.Control.Main == "" && (len(plugin.Control.Library) > 0 || plugin.Control.Register != nil)
}

// pluginNativeDeclarativeOnly reports a native plugin without a library: it
// registers its surface and has no handlers.
func pluginNativeDeclarativeOnly(plugin LoadedPlugin) bool {
	return pluginUsesNativeControl(plugin) && len(plugin.Control.Library) == 0
}

// pluginHandlesAsyncEvents reports whether a plugin may receive events,
// ring buffer records and socket notifications: a native plugin handles
// them on its own instance, a JavaScript plugin needs worker VMs.
func pluginHandlesAsyncEvents(plugin LoadedPlugin) bool {
	return pluginUsesNativeControl(plugin) || pluginControlHasPermission(plugin, "worker")
}

var pluginNativeTripleOnce struct {
	sync.Once
	value string
}

// pluginNativeHostTriple names the library build this host loads, such as
// x86_64-linux-gnu; it is empty where native plugins cannot run.
func pluginNativeHostTriple() string {
	pluginNativeTripleOnce.Do(func() {
		pluginNativeTripleOnce.value = detectPluginNativeHostTriple()
	})
	return pluginNativeTripleOnce.value
}

func detectPluginNativeHostTriple() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	arch := ""
	switch runtime.GOARCH {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	default:
		return ""
	}
	libc := "gnu"
	if matches, _ := filepath.Glob("/lib/ld-musl-*.so.1"); len(matches) > 0 {
		libc = "musl"
	}
	return arch + "-linux-" + libc
}

func normalizePluginNativeControl(control *PluginControl) error {
	if control.Main != "" {
		return fmt.Errorf("main and library are mutually exclusive")
	}
	if control.SHA256 != "" {
		return fmt.Errorf("sha256 belongs to each library entry")
	}
	normalized := make(map[string]PluginNativeLibrary, len(control.Library))
	for triple, library := range control.Library {
		triple = strings.TrimSpace(strings.ToLower(triple))
		if _, ok := pluginNativeTriples[triple]; !ok {
			return fmt.Errorf("library target %q must be one of x86_64-linux-gnu, x86_64-linux-musl, aarch64-linux-gnu, aarch64-linux-musl", triple)
		}
		path, err := normalizePluginRelativePath(library.Path)
		if err != nil {
			return fmt.Errorf("library %s path: %w", triple, err)
		}
		if path == "" {
			return fmt.Errorf("library %s path is required", triple)
		}
		library.Path = path
		library.SHA256 = strings.TrimSpace(strings.ToLower(library.SHA256))
		if library.SHA256 != "" && !pluginHashPattern.MatchString(library.SHA256) {
			return fmt.Errorf("library %s sha256 must be a lowercase 64-character hex digest", triple)
		}
		normalized[triple] = library
	}
	control.Library = normalized
	control.Worker = strings.TrimSpace(strings.ToLower(control.Worker))
	if control.Worker == "" {
		control.Worker = pluginNativeWorkerShared
	}
	if control.Worker != pluginNativeWorkerShared && control.Worker != pluginNativeWorkerDedicated && !pluginIDPattern.MatchString(control.Worker) {
		return fmt.Errorf("worker must be shared, dedicated or a group name matching %s", pluginIDPattern.String())
	}
	if control.Register != nil {
		if err := validatePluginNativeRegistration(control.Register); err != nil {
			return fmt.Errorf("register: %w", err)
		}
	}
	return nil
}

func validatePluginNativeRegistration(register *PluginNativeRegistration) error {
	total := len(register.Capabilities)
	for _, section := range [][]json.RawMessage{
		register.VirtualInterfaces, register.PipelineNodes, register.Handoffs, register.Objects, register.RingSubscriptions,
		register.PipelineAttach, register.Hooks, register.Resources, register.Actions,
		register.Services, register.Subscriptions,
	} {
		total += len(section)
		for _, entry := range section {
			if _, _, err := decodePluginNativeRegisterEntry(entry); err != nil {
				return err
			}
		}
	}
	if len(register.UI) > 0 {
		total++
		if _, _, err := decodePluginNativeRegisterEntry(register.UI); err != nil {
			return fmt.Errorf("ui: %w", err)
		}
	}
	if total > pluginNativeMaxRegisterEntries {
		return fmt.Errorf("at most %d entries are allowed", pluginNativeMaxRegisterEntries)
	}
	return nil
}

func decodePluginNativeRegisterEntry(raw json.RawMessage) (map[string]any, *pluginNativeRegisterCondition, error) {
	if err := rejectPluginDuplicateJSONKeys(raw); err != nil {
		return nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var entry map[string]any
	if err := decoder.Decode(&entry); err != nil {
		return nil, nil, fmt.Errorf("entry must be a JSON object: %w", err)
	}
	if entry == nil {
		return nil, nil, fmt.Errorf("entry must be a JSON object")
	}
	var condition *pluginNativeRegisterCondition
	if when, ok := entry["when"]; ok {
		delete(entry, "when")
		data, err := json.Marshal(when)
		if err != nil {
			return nil, nil, err
		}
		condition = &pluginNativeRegisterCondition{}
		strict := json.NewDecoder(bytes.NewReader(data))
		strict.DisallowUnknownFields()
		if err := strict.Decode(condition); err != nil {
			return nil, nil, fmt.Errorf("when: %w", err)
		}
		condition.Feature = strings.TrimSpace(condition.Feature)
		condition.NotFeature = strings.TrimSpace(condition.NotFeature)
		// Both together must both hold.
		if condition.Feature == "" && condition.NotFeature == "" {
			return nil, nil, fmt.Errorf("when needs feature, not_feature or both")
		}
	}
	return pluginNativeNormalizeNumbers(entry).(map[string]any), condition, nil
}

// pluginNativeNormalizeNumbers turns json.Number into the int64 or float64
// a registration method expects, as host call arguments carry them.
func pluginNativeNormalizeNumbers(value any) any {
	switch typed := value.(type) {
	case json.Number:
		if integer, err := typed.Int64(); err == nil {
			return integer
		}
		number, _ := typed.Float64()
		return number
	case map[string]any:
		for key, item := range typed {
			typed[key] = pluginNativeNormalizeNumbers(item)
		}
		return typed
	case []any:
		for i, item := range typed {
			typed[i] = pluginNativeNormalizeNumbers(item)
		}
		return typed
	default:
		return value
	}
}

// pluginNativeRegisterCalls lists the registration calls for the features
// this host has, in registration order. An eBPF object or a page entry
// declared without a sha256 gets the digest of the file the plugin ships, as
// a script computing it at registration did.
func pluginNativeRegisterCalls(plugin LoadedPlugin, available []string) ([]pluginNativeRegisterCall, error) {
	var register *PluginNativeRegistration
	if plugin.Control != nil {
		register = plugin.Control.Register
	}
	if register == nil {
		return nil, nil
	}
	has := make(map[string]struct{}, len(available))
	for _, feature := range available {
		has[feature] = struct{}{}
	}
	calls := make([]pluginNativeRegisterCall, 0, 16)
	if len(register.Capabilities) > 0 {
		args := make([]any, len(register.Capabilities))
		for i, capability := range register.Capabilities {
			args[i] = capability
		}
		calls = append(calls, pluginNativeRegisterCall{method: "plugin.capabilities", args: []any{args}})
	}
	sections := []struct {
		method  string
		entries []json.RawMessage
	}{
		{"plugin.virtualInterface", register.VirtualInterfaces},
		{"pipeline.node", register.PipelineNodes},
		{"pipeline.handoff", register.Handoffs},
		{"ebpf.loadObject", register.Objects},
		{"ebpf.ringSubscribe", register.RingSubscriptions},
		{"pipeline.attach", register.PipelineAttach},
		{"hooks.attach", register.Hooks},
		{"plugin.resource", register.Resources},
		{"plugin.action", register.Actions},
		{"plugin.service", register.Services},
		{"events.subscribe", register.Subscriptions},
	}
	if len(register.UI) > 0 {
		sections = append(sections, struct {
			method  string
			entries []json.RawMessage
		}{"ui.register", []json.RawMessage{register.UI}})
	}
	for _, section := range sections {
		for _, raw := range section.entries {
			entry, condition, err := decodePluginNativeRegisterEntry(raw)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", section.method, err)
			}
			if condition != nil {
				if condition.Feature != "" {
					if _, ok := has[condition.Feature]; !ok {
						continue
					}
				}
				if condition.NotFeature != "" {
					if _, ok := has[condition.NotFeature]; ok {
						continue
					}
				}
			}
			if err := fillPluginNativeRegisterDigest(plugin, section.method, entry); err != nil {
				return nil, fmt.Errorf("%s: %w", section.method, err)
			}
			calls = append(calls, pluginNativeRegisterCall{method: section.method, args: []any{entry}})
		}
	}
	return calls, nil
}

// resolvePluginNativeControl verifies the library builds that are present
// and picks the one this host loads. A build that is missing is skipped: a
// plugin without a build for this host still registers its surface, and its
// handlers fail until a matching build exists. A declared sha256 must match;
// without one the loaded build is still hashed and the worker checks that
// the file it maps is the one the host verified.
func resolvePluginNativeControl(plugin *LoadedPlugin) error {
	triples := make([]string, 0, len(plugin.Control.Library))
	for triple := range plugin.Control.Library {
		triples = append(triples, triple)
	}
	sort.Strings(triples)
	hostTriple := pluginNativeHostTriple()
	digests := make([]string, 0, len(triples))
	for _, triple := range triples {
		library := plugin.Control.Library[triple]
		data, _, err := readPluginRootedRegularFile(plugin.rootDir, library.Path, pluginNativeMaxLibraryBytes)
		if err != nil {
			if pluginPathEscapesRoot(err) {
				return fmt.Errorf("library %s escapes plugin root", triple)
			}
			if errors.Is(err, os.ErrNotExist) {
				digests = append(digests, triple+"=missing")
				continue
			}
			return fmt.Errorf("library %s: %w", triple, err)
		}
		got := fmt.Sprintf("%x", sha256.Sum256(data))
		if library.SHA256 != "" && library.SHA256 != got {
			return fmt.Errorf("library %s sha256 mismatch", triple)
		}
		digests = append(digests, triple+"="+got)
		if triple == hostTriple {
			realPath, err := filepath.EvalSymlinks(filepath.Join(plugin.rootDir, filepath.FromSlash(library.Path)))
			if err != nil {
				return fmt.Errorf("library %s: %w", triple, err)
			}
			plugin.nativeLibraryPath = realPath
			plugin.nativeLibrarySHA256 = got
		}
	}
	manifestPath := filepath.Join(plugin.rootDir, "plugin.json")
	if _, err := os.Stat(manifestPath); err != nil {
		manifestPath = plugin.rootDir
	}
	// "Has control" checks across the runtime look at controlMainPath.
	plugin.controlMainPath = manifestPath
	sum := sha256.Sum256([]byte(strings.Join(digests, ";")))
	plugin.Control.ResolvedSHA256 = fmt.Sprintf("%x", sum)
	plugin.nativeFollowsHostFeatures = pluginNativeRegistrationFollowsChangingFeatures(plugin.Control.Register)
	return nil
}

// pluginChangingHostFeatures can become available while the daemon runs:
// the optional kernel module may be loaded after it started.
var pluginChangingHostFeatures = map[string]struct{}{
	"dataplane.kfuncs.handoff.v1":         {},
	"dataplane.kfuncs.handoff_ingress.v1": {},
	"dataplane.kfuncs.wan.v1":             {},
}

// pluginNativeRegistrationFollowsChangingFeatures reports whether an entry
// of register is conditioned on a feature in pluginChangingHostFeatures. Such
// an instance chose its eBPF objects, and a plugin its mode, for the features
// it was registered with.
func pluginNativeRegistrationFollowsChangingFeatures(register *PluginNativeRegistration) bool {
	if register == nil {
		return false
	}
	sections := [][]json.RawMessage{
		register.VirtualInterfaces, register.PipelineNodes, register.Handoffs, register.Objects, register.RingSubscriptions,
		register.PipelineAttach, register.Hooks, register.Resources, register.Actions, register.Services, register.Subscriptions,
	}
	for _, entries := range sections {
		for _, raw := range entries {
			_, condition, err := decodePluginNativeRegisterEntry(raw)
			if err != nil || condition == nil {
				continue
			}
			_, feature := pluginChangingHostFeatures[condition.Feature]
			_, notFeature := pluginChangingHostFeatures[condition.NotFeature]
			if feature || notFeature {
				return true
			}
		}
	}
	return false
}

// pluginChangingHostFeaturesKey identifies which of pluginChangingHostFeatures
// the host has now.
func pluginChangingHostFeaturesKey() string {
	state := func(status PluginHostFeatureStatus) string {
		if status.Available {
			return "1"
		}
		return "0"
	}
	return "kfuncs=" + state(optionalKernelModuleFeatureStatus()) + state(optionalKernelModuleIngressFeatureStatus()) + state(optionalKernelModuleWANFeatureStatus())
}

func fillPluginNativeRegisterDigest(plugin LoadedPlugin, method string, entry map[string]any) error {
	if _, ok := entry["sha256"]; ok || plugin.rootDir == "" {
		return nil
	}
	var relative string
	switch method {
	case "ebpf.loadObject":
		if _, hasVariants := entry["variants"]; hasVariants {
			return nil
		}
		relative, _ = entry["path"].(string)
	case "ui.register":
		staticDir, _ := entry["static_dir"].(string)
		page, _ := entry["entry"].(string)
		if staticDir == "" || page == "" {
			return nil
		}
		relative = path.Join(staticDir, page)
	default:
		return nil
	}
	if relative == "" {
		return nil
	}
	data, _, err := readPluginRootedRegularFile(plugin.rootDir, relative, pluginObjectMaxSize)
	if err != nil {
		return fmt.Errorf("hash %s: %w", relative, err)
	}
	entry["sha256"] = fmt.Sprintf("%x", sha256.Sum256(data))
	return nil
}
