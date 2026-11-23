package app

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
)

// pluginObjectSpecSummary is what the catalog reads from a plugin's eBPF
// object: its programs and the memory its maps need. Parsing the ELF takes
// far longer than anything else the catalog does with an object, and every
// catalog read that overlays a plugin's registered surface verifies its
// objects, so summaries are kept by content hash (pluginObjectSummaries).
// The dataplane loaders parse and verify the object again on their own.
type pluginObjectSpecSummary struct {
	programCount int
	mapCount     int
	// programs are the discovered programs, sorted by section.
	programs []PluginObjectProgram
	// instructions per non-nil program, sorted by program name.
	instructions []pluginObjectProgramSize
	// maps sorted by name, with their memory estimate.
	maps []pluginObjectMapSummary
}

type pluginObjectProgramSize struct {
	name         string
	instructions int
}

type pluginObjectMapSummary struct {
	name    string
	present bool
	mapType ebpf.MapType
	bytes   uint64
	err     error
}

func summarizePluginObjectSpec(spec *ebpf.CollectionSpec) *pluginObjectSpecSummary {
	summary := &pluginObjectSpecSummary{
		programCount: len(spec.Programs),
		mapCount:     len(spec.Maps),
		programs:     pluginObjectProgramsFromSpec(spec),
	}
	for name, program := range spec.Programs {
		if program != nil {
			summary.instructions = append(summary.instructions, pluginObjectProgramSize{name: name, instructions: len(program.Instructions)})
		}
	}
	sort.Slice(summary.instructions, func(i, j int) bool { return summary.instructions[i].name < summary.instructions[j].name })
	cpus := pluginObjectCPUs()
	for name, mapSpec := range spec.Maps {
		item := pluginObjectMapSummary{name: name, present: mapSpec != nil}
		if mapSpec != nil {
			item.mapType = mapSpec.Type
		}
		item.bytes, item.err = estimatePluginMapMemory(mapSpec, cpus, 0)
		summary.maps = append(summary.maps, item)
	}
	sort.Slice(summary.maps, func(i, j int) bool { return summary.maps[i].name < summary.maps[j].name })
	return summary
}

// resourceUsage checks the object against limits and adds up its usage.
func (s *pluginObjectSpecSummary) resourceUsage(limits PluginResourceLimits) (*PluginObjectResourceUsage, error) {
	usage := &PluginObjectResourceUsage{Programs: s.programCount, Maps: s.mapCount}
	for _, program := range s.instructions {
		if program.instructions > limits.InstructionsPerProgram {
			return nil, fmt.Errorf("program %q instructions = %d exceeds per-program limit %d", program.name, program.instructions, limits.InstructionsPerProgram)
		}
		if !safeAddUint64(&usage.Instructions, uint64(program.instructions)) {
			return nil, fmt.Errorf("program instruction count overflow")
		}
	}
	for _, item := range s.maps {
		if item.err != nil {
			return nil, fmt.Errorf("map %q: %w", item.name, item.err)
		}
		if item.bytes > limits.MapMemoryBytes {
			return nil, fmt.Errorf("map %q estimated memory = %d bytes exceeds per-map limit %d", item.name, item.bytes, limits.MapMemoryBytes)
		}
		if !safeAddUint64(&usage.EstimatedMapMemoryBytes, item.bytes) {
			return nil, fmt.Errorf("map memory estimate overflow")
		}
	}
	return usage, nil
}

// validateStateMaps is validatePluginObjectStateMapSpecs on a summary.
func (s *pluginObjectSpecSummary) validateStateMaps(contracts []PluginObjectStateMap) error {
	for _, contract := range contracts {
		if contract.Policy != pluginObjectMapPreserve && contract.Policy != pluginObjectMapMigrate {
			continue
		}
		index := sort.Search(len(s.maps), func(i int) bool { return s.maps[i].name >= contract.Name })
		if index == len(s.maps) || s.maps[index].name != contract.Name || !s.maps[index].present {
			return fmt.Errorf("state map %q with policy %s is not present in the object", contract.Name, contract.Policy)
		}
		if mapType := s.maps[index].mapType; !pluginObjectMapTypeSupportsStatePreservation(mapType) {
			return fmt.Errorf("state map %q with policy %s uses unsupported map type %s", contract.Name, contract.Policy, mapType)
		}
	}
	return nil
}

// pluginObjectSummaryLimit bounds pluginObjectSummaries; past it the memo
// starts over. Bundled plugins ship a handful of objects.
const pluginObjectSummaryLimit = 64

var pluginObjectSummaries struct {
	sync.Mutex
	bySHA256 map[string]*pluginObjectSpecSummary
}

// loadVerifiedPluginObjectSpecSummary reads the object, checks it still has
// the verified hash and returns its summary, parsing it only the first time
// these contents are seen.
func loadVerifiedPluginObjectSpecSummary(objectPath, expectedSHA256 string) (*pluginObjectSpecSummary, error) {
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
	pluginObjectSummaries.Lock()
	summary := pluginObjectSummaries.bySHA256[got]
	pluginObjectSummaries.Unlock()
	if summary != nil {
		return summary, nil
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	summary = summarizePluginObjectSpec(spec)
	pluginObjectSummaries.Lock()
	if pluginObjectSummaries.bySHA256 == nil || len(pluginObjectSummaries.bySHA256) >= pluginObjectSummaryLimit {
		pluginObjectSummaries.bySHA256 = make(map[string]*pluginObjectSpecSummary)
	}
	pluginObjectSummaries.bySHA256[got] = summary
	pluginObjectSummaries.Unlock()
	return summary, nil
}
