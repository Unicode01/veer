//go:build linux

package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	forwardHotRestartMarkerEnv            = "FORWARD_HOT_RESTART_MARKER"
	forwardBPFStateDirEnv                 = "FORWARD_BPF_STATE_DIR"
	forwardRuntimeStateDirEnv             = "FORWARD_RUNTIME_STATE_DIR"
	defaultForwardBPFStateDir             = "/sys/fs/bpf/forward"
	hotRestartSkipStatsSuffix             = ".skip-stats"
	kernelHotRestartMetadataFormatVersion = 1
)

type kernelHotRestartIncompatibleError struct {
	reason string
}

func (err *kernelHotRestartIncompatibleError) Error() string {
	if err == nil {
		return ""
	}
	return err.reason
}

func newKernelHotRestartIncompatibleError(format string, args ...any) error {
	return &kernelHotRestartIncompatibleError{reason: fmt.Sprintf(format, args...)}
}

func isKernelHotRestartIncompatible(err error) bool {
	var target *kernelHotRestartIncompatibleError
	return errors.As(err, &target)
}

func kernelHotRestartIncompatibilityReason(err error) string {
	if err == nil {
		return ""
	}
	var target *kernelHotRestartIncompatibleError
	if errors.As(err, &target) {
		return target.Error()
	}
	return err.Error()
}

type kernelHotRestartMapState struct {
	replacements     map[string]*ebpf.Map
	actualCapacities kernelMapCapacities
	oldStatsMap      *ebpf.Map
}

type kernelHotRestartMapDescriptor struct {
	Type       ebpf.MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

type kernelHotRestartMetadata struct {
	FormatVersion   int                             `json:"format_version,omitempty"`
	Engine          string                          `json:"engine"`
	ObjectHash      string                          `json:"object_hash,omitempty"`
	OwnerPID        int                             `json:"owner_pid,omitempty"`
	OwnerStartTicks uint64                          `json:"owner_start_ticks,omitempty"`
	TCAttachments   []kernelHotRestartTCAttachment  `json:"tc_attachments,omitempty"`
	XDPAttachments  []kernelHotRestartXDPAttachment `json:"xdp_attachments,omitempty"`
}

type kernelHotRestartTCAttachment struct {
	LinkIndex int    `json:"link_index"`
	Parent    uint32 `json:"parent"`
	Priority  uint16 `json:"priority"`
	Handle    uint32 `json:"handle"`
}

type kernelHotRestartXDPAttachment struct {
	Ifindex int `json:"ifindex"`
	Flags   int `json:"flags"`
}

func kernelHotRestartTCMetadata(attachments []kernelAttachment, objectHash string) kernelHotRestartMetadata {
	meta := kernelHotRestartMetadata{
		FormatVersion: kernelHotRestartMetadataFormatVersion,
		Engine:        kernelEngineTC,
		ObjectHash:    strings.TrimSpace(objectHash),
		TCAttachments: make([]kernelHotRestartTCAttachment, 0, len(attachments)),
	}
	for _, att := range attachments {
		if att.filter == nil {
			continue
		}
		meta.TCAttachments = append(meta.TCAttachments, kernelHotRestartTCAttachment{
			LinkIndex: att.filter.LinkIndex,
			Parent:    att.filter.Parent,
			Priority:  att.filter.Priority,
			Handle:    att.filter.Handle,
		})
	}
	return meta
}

func kernelHotRestartXDPMetadata(attachments []xdpAttachment, objectHash string) kernelHotRestartMetadata {
	meta := kernelHotRestartMetadata{
		FormatVersion:  kernelHotRestartMetadataFormatVersion,
		Engine:         kernelEngineXDP,
		ObjectHash:     strings.TrimSpace(objectHash),
		XDPAttachments: make([]kernelHotRestartXDPAttachment, 0, len(attachments)),
	}
	for _, att := range attachments {
		meta.XDPAttachments = append(meta.XDPAttachments, kernelHotRestartXDPAttachment{
			Ifindex: att.ifindex,
			Flags:   att.flags,
		})
	}
	return meta
}

func kernelHotRestartMarkerPath() string {
	return strings.TrimSpace(os.Getenv(forwardHotRestartMarkerEnv))
}

func kernelTCObjectBytes(enableTrafficStats bool) ([]byte, string) {
	objectBytes := embeddedForwardTCObject
	objectName := "internal/app/ebpf/forward-tc-bpf.o"
	if enableTrafficStats {
		objectBytes = embeddedForwardTCStatsObject
		objectName = "internal/app/ebpf/forward-tc-bpf-stats.o"
	}
	return objectBytes, objectName
}

func kernelXDPObjectBytes(enableTrafficStats bool) ([]byte, string) {
	objectBytes := embeddedForwardXDPObject
	objectName := "internal/app/ebpf/forward-xdp-bpf.o"
	if enableTrafficStats {
		objectBytes = embeddedForwardXDPStatsObject
		objectName = "internal/app/ebpf/forward-xdp-bpf-stats.o"
	}
	return objectBytes, objectName
}

func kernelHotRestartObjectHash(objectBytes []byte, objectName string) (string, error) {
	if len(objectBytes) == 0 {
		return "", fmt.Errorf("embedded eBPF object %s is empty", strings.TrimSpace(objectName))
	}
	sum := sha256.Sum256(objectBytes)
	return hex.EncodeToString(sum[:]), nil
}

func kernelTCHotRestartObjectHash(enableTrafficStats bool) (string, error) {
	objectBytes, objectName := kernelTCObjectBytes(enableTrafficStats)
	return kernelHotRestartObjectHash(objectBytes, objectName)
}

func kernelXDPHotRestartObjectHash(enableTrafficStats bool) (string, error) {
	objectBytes, objectName := kernelXDPObjectBytes(enableTrafficStats)
	return kernelHotRestartObjectHash(objectBytes, objectName)
}

func validateKernelHotRestartMetadata(meta kernelHotRestartMetadata, engine string, objectHash string) error {
	engine = strings.TrimSpace(engine)
	if strings.TrimSpace(meta.Engine) != engine {
		return newKernelHotRestartIncompatibleError("metadata engine=%q but current runtime expects %q", meta.Engine, engine)
	}
	if meta.FormatVersion != kernelHotRestartMetadataFormatVersion {
		return newKernelHotRestartIncompatibleError(
			"metadata format=%d but current runtime expects %d",
			meta.FormatVersion,
			kernelHotRestartMetadataFormatVersion,
		)
	}
	if strings.TrimSpace(meta.ObjectHash) == "" {
		return newKernelHotRestartIncompatibleError("metadata object hash is missing")
	}
	if strings.TrimSpace(objectHash) == "" {
		return newKernelHotRestartIncompatibleError("current object hash is missing")
	}
	if strings.TrimSpace(meta.ObjectHash) != strings.TrimSpace(objectHash) {
		return newKernelHotRestartIncompatibleError(
			"metadata object hash=%s but current runtime expects %s",
			meta.ObjectHash,
			objectHash,
		)
	}
	return nil
}

func kernelHotRestartRequested() bool {
	path := kernelHotRestartMarkerPath()
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func kernelHotRestartSkipStatsMarkerPath() string {
	path := kernelHotRestartMarkerPath()
	if path == "" {
		return ""
	}
	return path + hotRestartSkipStatsSuffix
}

func kernelHotRestartSkipStatsRequested() bool {
	path := kernelHotRestartSkipStatsMarkerPath()
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func kernelHotRestartStateRoot() string {
	path := strings.TrimSpace(os.Getenv(forwardBPFStateDirEnv))
	if path == "" {
		path = defaultForwardBPFStateDir
	}
	return path
}

func kernelMetadataStateRoot() string {
	if path := strings.TrimSpace(os.Getenv(forwardRuntimeStateDirEnv)); path != "" {
		return path
	}
	if markerPath := kernelHotRestartMarkerPath(); markerPath != "" {
		return filepath.Join(filepath.Dir(markerPath), ".kernel-state")
	}
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		return filepath.Join(filepath.Dir(exe), ".kernel-state")
	}
	return filepath.Join(os.TempDir(), "forward-kernel-state")
}

func kernelHotRestartEngineDir(engine string) string {
	return filepath.Join(kernelHotRestartStateRoot(), "hot-restart", strings.ToLower(strings.TrimSpace(engine)))
}

func kernelHotRestartStateExists(engine string) bool {
	dir := kernelHotRestartEngineDir(engine)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	return len(entries) > 0
}

func kernelHotRestartPinPath(engine string, mapName string) string {
	return filepath.Join(kernelHotRestartEngineDir(engine), mapName)
}

func kernelHotRestartMetadataPath(engine string) string {
	return filepath.Join(kernelMetadataStateRoot(), "hot-restart", strings.ToLower(strings.TrimSpace(engine)), "meta.json")
}

func kernelHotRestartMetadataDir(engine string) string {
	return filepath.Dir(kernelHotRestartMetadataPath(engine))
}

func kernelRuntimeStateDir(engine string) string {
	return filepath.Join(kernelMetadataStateRoot(), "runtime", strings.ToLower(strings.TrimSpace(engine)))
}

func kernelRuntimeMetadataPath(engine string) string {
	return filepath.Join(kernelRuntimeStateDir(engine), "meta.json")
}

func clearKernelHotRestartState(engine string) {
	if dir := kernelHotRestartEngineDir(engine); dir != "" {
		_ = os.RemoveAll(dir)
	}
	if dir := kernelHotRestartMetadataDir(engine); dir != "" {
		_ = os.RemoveAll(dir)
	}
}

func clearKernelRuntimeMetadata(engine string) {
	dir := kernelRuntimeStateDir(engine)
	if dir == "" {
		return
	}
	_ = os.RemoveAll(dir)
}

func writeKernelHotRestartMetadata(engine string, meta kernelHotRestartMetadata) error {
	dir := kernelHotRestartMetadataDir(engine)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create hot restart metadata dir %q: %w", dir, err)
	}
	meta = populateKernelMetadataOwner(meta)
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal hot restart metadata: %w", err)
	}
	if err := os.WriteFile(kernelHotRestartMetadataPath(engine), data, 0o644); err != nil {
		return fmt.Errorf("write hot restart metadata: %w", err)
	}
	return nil
}

func writeKernelRuntimeMetadata(engine string, meta kernelHotRestartMetadata) error {
	dir := kernelRuntimeStateDir(engine)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create runtime metadata dir %q: %w", dir, err)
	}
	meta = populateKernelMetadataOwner(meta)
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal runtime metadata: %w", err)
	}
	if err := os.WriteFile(kernelRuntimeMetadataPath(engine), data, 0o644); err != nil {
		return fmt.Errorf("write runtime metadata: %w", err)
	}
	return nil
}

func readKernelHotRestartMetadata(engine string) (kernelHotRestartMetadata, error) {
	path := kernelHotRestartMetadataPath(engine)
	data, err := os.ReadFile(path)
	if err != nil {
		return kernelHotRestartMetadata{}, err
	}
	var meta kernelHotRestartMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return kernelHotRestartMetadata{}, err
	}
	return meta, nil
}

func readKernelRuntimeMetadata(engine string) (kernelHotRestartMetadata, error) {
	path := kernelRuntimeMetadataPath(engine)
	data, err := os.ReadFile(path)
	if err != nil {
		return kernelHotRestartMetadata{}, err
	}
	var meta kernelHotRestartMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return kernelHotRestartMetadata{}, err
	}
	return meta, nil
}

func populateKernelMetadataOwner(meta kernelHotRestartMetadata) kernelHotRestartMetadata {
	meta.OwnerPID = os.Getpid()
	if ticks, err := kernelProcessStartTicks(meta.OwnerPID); err == nil {
		meta.OwnerStartTicks = ticks
	}
	return meta
}

func kernelProcessStartTicks(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(string(data))
	end := strings.LastIndex(text, ")")
	if end < 0 || end+2 > len(text) {
		return 0, fmt.Errorf("parse /proc/%d/stat: malformed comm field", pid)
	}
	fields := strings.Fields(text[end+2:])
	if len(fields) <= 19 {
		return 0, fmt.Errorf("parse /proc/%d/stat: missing start time field", pid)
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse /proc/%d/stat start time: %w", pid, err)
	}
	return startTicks, nil
}

func kernelMetadataOwnerAlive(meta kernelHotRestartMetadata) bool {
	if meta.OwnerPID <= 0 {
		return false
	}
	currentTicks, err := kernelProcessStartTicks(meta.OwnerPID)
	if err != nil {
		return false
	}
	if meta.OwnerStartTicks != 0 && currentTicks != meta.OwnerStartTicks {
		return false
	}
	return true
}

func cleanupOrphanTCKernelRuntimeState() error {
	meta, err := readKernelRuntimeMetadata(kernelEngineTC)
	if err != nil {
		if os.IsNotExist(err) {
			clearKernelRuntimeMetadata(kernelEngineTC)
			return nil
		}
		return fmt.Errorf("read tc runtime metadata: %w", err)
	}
	if kernelMetadataOwnerAlive(meta) {
		return nil
	}
	for _, att := range meta.TCAttachments {
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: att.LinkIndex,
				Parent:    att.Parent,
				Priority:  att.Priority,
				Handle:    att.Handle,
				Protocol:  unix.ETH_P_ALL,
			},
		}
		_ = netlink.FilterDel(filter)
	}
	clearKernelRuntimeMetadata(kernelEngineTC)
	return nil
}

func cleanupOrphanXDPKernelRuntimeState() error {
	meta, err := readKernelRuntimeMetadata(kernelEngineXDP)
	if err != nil {
		if os.IsNotExist(err) {
			clearKernelRuntimeMetadata(kernelEngineXDP)
			return nil
		}
		return fmt.Errorf("read xdp runtime metadata: %w", err)
	}
	if kernelMetadataOwnerAlive(meta) {
		return nil
	}
	for _, att := range meta.XDPAttachments {
		_ = detachXDPAttachment(xdpAttachment{ifindex: att.Ifindex, flags: att.Flags})
	}
	clearKernelRuntimeMetadata(kernelEngineXDP)
	return nil
}

func cleanupStaleTCKernelHotRestartState() error {
	meta, err := readKernelHotRestartMetadata(kernelEngineTC)
	if err != nil {
		if os.IsNotExist(err) {
			clearKernelHotRestartState(kernelEngineTC)
			return nil
		}
		return fmt.Errorf("read tc hot restart metadata: %w", err)
	}
	for _, att := range meta.TCAttachments {
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: att.LinkIndex,
				Parent:    att.Parent,
				Priority:  att.Priority,
				Handle:    att.Handle,
				Protocol:  unix.ETH_P_ALL,
			},
		}
		_ = netlink.FilterDel(filter)
	}
	clearKernelHotRestartState(kernelEngineTC)
	return nil
}

func cleanupStaleXDPKernelHotRestartState() error {
	meta, err := readKernelHotRestartMetadata(kernelEngineXDP)
	if err != nil {
		if os.IsNotExist(err) {
			clearKernelHotRestartState(kernelEngineXDP)
			return nil
		}
		return fmt.Errorf("read xdp hot restart metadata: %w", err)
	}
	for _, att := range meta.XDPAttachments {
		_ = detachXDPAttachment(xdpAttachment{ifindex: att.Ifindex, flags: att.Flags})
	}
	clearKernelHotRestartState(kernelEngineXDP)
	return nil
}

func pinKernelHotRestartMaps(engine string, maps map[string]*ebpf.Map) error {
	dir := kernelHotRestartEngineDir(engine)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create hot restart state dir %q: %w", dir, err)
	}

	pinned := make([]string, 0, len(maps))
	for name, m := range maps {
		if m == nil {
			continue
		}
		path := kernelHotRestartPinPath(engine, name)
		_ = os.Remove(path)
		if err := m.Pin(path); err != nil {
			for _, current := range pinned {
				_ = os.Remove(current)
			}
			return fmt.Errorf("pin %s map at %q: %w", name, path, err)
		}
		pinned = append(pinned, path)
	}
	return nil
}

func loadPinnedKernelMap(path string) (*ebpf.Map, bool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, false, nil
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, false, err
	}
	return m, true, nil
}

func kernelHotRestartMapDescriptorFromSpec(spec *ebpf.MapSpec) (kernelHotRestartMapDescriptor, error) {
	if spec == nil {
		return kernelHotRestartMapDescriptor{}, fmt.Errorf("map spec is missing")
	}
	return kernelHotRestartMapDescriptor{
		Type:       spec.Type,
		KeySize:    spec.KeySize,
		ValueSize:  spec.ValueSize,
		MaxEntries: spec.MaxEntries,
		Flags:      spec.Flags,
	}, nil
}

func kernelHotRestartMapDescriptorFromMap(m *ebpf.Map) (kernelHotRestartMapDescriptor, error) {
	if m == nil {
		return kernelHotRestartMapDescriptor{}, fmt.Errorf("map is missing")
	}
	info, err := m.Info()
	if err != nil {
		return kernelHotRestartMapDescriptor{}, err
	}
	if info == nil {
		return kernelHotRestartMapDescriptor{}, fmt.Errorf("map info is unavailable")
	}
	return kernelHotRestartMapDescriptor{
		Type:       info.Type,
		KeySize:    info.KeySize,
		ValueSize:  info.ValueSize,
		MaxEntries: info.MaxEntries,
		Flags:      info.Flags,
	}, nil
}

func validateKernelHotRestartMapCompatibility(name string, actual kernelHotRestartMapDescriptor, desired kernelHotRestartMapDescriptor, allowSmallerCapacity bool) error {
	if actual.Type != desired.Type {
		return newKernelHotRestartIncompatibleError("type=%v but current object expects %v", actual.Type, desired.Type)
	}
	if actual.KeySize != desired.KeySize {
		return newKernelHotRestartIncompatibleError("key_size=%d but current object expects %d", actual.KeySize, desired.KeySize)
	}
	if actual.ValueSize != desired.ValueSize {
		return newKernelHotRestartIncompatibleError("value_size=%d but current object expects %d", actual.ValueSize, desired.ValueSize)
	}
	if actual.Flags != desired.Flags {
		return newKernelHotRestartIncompatibleError("flags=0x%x but current object expects 0x%x", actual.Flags, desired.Flags)
	}
	if actual.MaxEntries < desired.MaxEntries && !allowSmallerCapacity {
		return newKernelHotRestartIncompatibleError(
			"max_entries=%d but current object expects at least %d",
			actual.MaxEntries,
			desired.MaxEntries,
		)
	}
	return nil
}

func validateKernelHotRestartMapReplacements(spec *ebpf.CollectionSpec, replacements map[string]*ebpf.Map, allowSmallerCapacity map[string]bool) error {
	if spec == nil {
		return fmt.Errorf("collection spec is missing")
	}
	if len(replacements) == 0 {
		return nil
	}
	names := make([]string, 0, len(replacements))
	for name := range replacements {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		currentSpec := spec.Maps[name]
		if currentSpec == nil {
			return newKernelHotRestartIncompatibleError("map %q is preserved but missing from current object", name)
		}
		actual, err := kernelHotRestartMapDescriptorFromMap(replacements[name])
		if err != nil {
			return fmt.Errorf("read preserved map %q info: %w", name, err)
		}
		desired, err := kernelHotRestartMapDescriptorFromSpec(currentSpec)
		if err != nil {
			return fmt.Errorf("read current map %q spec: %w", name, err)
		}
		if err := validateKernelHotRestartMapCompatibility(name, actual, desired, allowSmallerCapacity[name]); err != nil {
			return fmt.Errorf("map %q incompatible: %w", name, err)
		}
	}
	return nil
}

func loadTCKernelHotRestartState(desired kernelMapCapacities, objectHash string) (*kernelHotRestartMapState, error) {
	if !kernelHotRestartStateExists(kernelEngineTC) {
		return nil, nil
	}
	meta, err := readKernelHotRestartMetadata(kernelEngineTC)
	if err != nil {
		return nil, fmt.Errorf("read tc hot restart metadata: %w", err)
	}
	if err := validateKernelHotRestartMetadata(meta, kernelEngineTC, objectHash); err != nil {
		return nil, fmt.Errorf("validate tc hot restart metadata: %w", err)
	}
	state := &kernelHotRestartMapState{
		replacements:     make(map[string]*ebpf.Map, 5),
		actualCapacities: desired,
	}
	loadedAny := false
	haveFlows := false
	haveNAT := false
	haveFlowsV6 := false
	haveNATV6 := false
	skipStats := kernelHotRestartSkipStatsRequested()
	preservedFlowsCapacity := 0
	preservedNATCapacity := 0

	flowsMap, ok, err := loadPinnedKernelMap(kernelHotRestartPinPath(kernelEngineTC, kernelFlowsMapName))
	if err != nil {
		state.close()
		return nil, fmt.Errorf("load pinned tc flows map: %w", err)
	}
	if ok {
		loadedAny = true
		haveFlows = true
		state.replacements[kernelFlowsMapName] = flowsMap
		preservedFlowsCapacity += int(flowsMap.MaxEntries())
	}

	flowsMapV6, ok, err := loadPinnedKernelMap(kernelHotRestartPinPath(kernelEngineTC, kernelFlowsMapNameV6))
	if err != nil {
		state.close()
		return nil, fmt.Errorf("load pinned tc IPv6 flows map: %w", err)
	}
	if ok {
		loadedAny = true
		haveFlowsV6 = true
		state.replacements[kernelFlowsMapNameV6] = flowsMapV6
		preservedFlowsCapacity += int(flowsMapV6.MaxEntries())
	}

	natMap, ok, err := loadPinnedKernelMap(kernelHotRestartPinPath(kernelEngineTC, kernelNatPortsMapName))
	if err != nil {
		state.close()
		return nil, fmt.Errorf("load pinned tc nat map: %w", err)
	}
	if ok {
		loadedAny = true
		haveNAT = true
		state.replacements[kernelNatPortsMapName] = natMap
		preservedNATCapacity += int(natMap.MaxEntries())
	}

	natMapV6, ok, err := loadPinnedKernelMap(kernelHotRestartPinPath(kernelEngineTC, kernelNatPortsMapNameV6))
	if err != nil {
		state.close()
		return nil, fmt.Errorf("load pinned tc IPv6 nat map: %w", err)
	}
	if ok {
		loadedAny = true
		haveNATV6 = true
		state.replacements[kernelNatPortsMapNameV6] = natMapV6
		preservedNATCapacity += int(natMapV6.MaxEntries())
	}

	if preservedFlowsCapacity > 0 {
		state.actualCapacities.Flows = preservedFlowsCapacity
	}
	if preservedNATCapacity > 0 {
		state.actualCapacities.NATPorts = preservedNATCapacity
	}

	if !skipStats {
		statsMap, ok, err := loadPinnedKernelMap(kernelHotRestartPinPath(kernelEngineTC, kernelStatsMapName))
		if err != nil {
			state.close()
			return nil, fmt.Errorf("load pinned tc stats map: %w", err)
		}
		if ok {
			loadedAny = true
			if kernelMapReusableWithCapacity(statsMap, desired.Rules) {
				state.replacements[kernelStatsMapName] = statsMap
			} else {
				state.oldStatsMap = statsMap
			}
		}
	} else if _, err := os.Stat(kernelHotRestartPinPath(kernelEngineTC, kernelStatsMapName)); err == nil {
		loadedAny = true
	} else if !os.IsNotExist(err) {
		state.close()
		return nil, fmt.Errorf("stat pinned tc stats map: %w", err)
	}

	if !loadedAny {
		state.close()
		return nil, nil
	}
	if haveFlowsV6 != haveNATV6 {
		state.close()
		return nil, newKernelHotRestartIncompatibleError(
			"preserved tc IPv6 map set is incomplete: flows_v6=%t nat_v6=%t",
			haveFlowsV6,
			haveNATV6,
		)
	}
	haveStats := skipStats || state.oldStatsMap != nil || state.replacements[kernelStatsMapName] != nil
	if !haveFlows || !haveNAT || !haveStats {
		state.close()
		return nil, newKernelHotRestartIncompatibleError(
			"preserved tc map set is incomplete: flows=%t nat=%t stats=%t",
			haveFlows,
			haveNAT,
			haveStats,
		)
	}
	if skipStats {
		log.Printf("kernel dataplane hot restart: skipping preserved %s map for tc; counters will rebuild from live flow state", kernelStatsMapName)
	}
	return state, nil
}

func loadXDPKernelHotRestartState(desired kernelMapCapacities, objectHash string) (*kernelHotRestartMapState, error) {
	if !kernelHotRestartStateExists(kernelEngineXDP) {
		return nil, nil
	}
	meta, err := readKernelHotRestartMetadata(kernelEngineXDP)
	if err != nil {
		return nil, fmt.Errorf("read xdp hot restart metadata: %w", err)
	}
	if err := validateKernelHotRestartMetadata(meta, kernelEngineXDP, objectHash); err != nil {
		return nil, fmt.Errorf("validate xdp hot restart metadata: %w", err)
	}
	state := &kernelHotRestartMapState{
		replacements:     make(map[string]*ebpf.Map, 3),
		actualCapacities: desired,
	}
	loadedAny := false
	haveFlows := false
	skipStats := kernelHotRestartSkipStatsRequested()

	flowsMap, ok, err := loadPinnedKernelMap(kernelHotRestartPinPath(kernelEngineXDP, kernelFlowsMapName))
	if err != nil {
		state.close()
		return nil, fmt.Errorf("load pinned xdp flows map: %w", err)
	}
	if ok {
		loadedAny = true
		haveFlows = true
		state.replacements[kernelFlowsMapName] = flowsMap
		if flowCapacity := int(flowsMap.MaxEntries()); flowCapacity < state.actualCapacities.Flows {
			state.actualCapacities.Flows = flowCapacity
		}
	}

	flowsMapV6, ok, err := loadPinnedKernelMap(kernelHotRestartPinPath(kernelEngineXDP, kernelFlowsMapNameV6))
	if err != nil {
		state.close()
		return nil, fmt.Errorf("load pinned xdp IPv6 flows map: %w", err)
	}
	if ok {
		loadedAny = true
		haveFlows = true
		state.replacements[kernelFlowsMapNameV6] = flowsMapV6
		if flowCapacity := int(flowsMapV6.MaxEntries()); flowCapacity < state.actualCapacities.Flows {
			state.actualCapacities.Flows = flowCapacity
		}
	}

	if !skipStats {
		statsMap, ok, err := loadPinnedKernelMap(kernelHotRestartPinPath(kernelEngineXDP, kernelStatsMapName))
		if err != nil {
			state.close()
			return nil, fmt.Errorf("load pinned xdp stats map: %w", err)
		}
		if ok {
			loadedAny = true
			if kernelMapReusableWithCapacity(statsMap, desired.Rules) {
				state.replacements[kernelStatsMapName] = statsMap
			} else {
				state.oldStatsMap = statsMap
			}
		}
	} else if _, err := os.Stat(kernelHotRestartPinPath(kernelEngineXDP, kernelStatsMapName)); err == nil {
		loadedAny = true
	} else if !os.IsNotExist(err) {
		state.close()
		return nil, fmt.Errorf("stat pinned xdp stats map: %w", err)
	}

	if !loadedAny {
		state.close()
		return nil, nil
	}
	haveStats := skipStats || state.oldStatsMap != nil || state.replacements[kernelStatsMapName] != nil
	if !haveFlows || !haveStats {
		state.close()
		return nil, newKernelHotRestartIncompatibleError(
			"preserved xdp map set is incomplete: flows=%t stats=%t",
			haveFlows,
			haveStats,
		)
	}
	if skipStats {
		log.Printf("xdp dataplane hot restart: skipping preserved %s map; counters will rebuild from live flow state", kernelStatsMapName)
	}
	return state, nil
}

func (state *kernelHotRestartMapState) replacementMapNames() []string {
	if state == nil || len(state.replacements) == 0 {
		return nil
	}
	names := make([]string, 0, len(state.replacements))
	for name := range state.replacements {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (state *kernelHotRestartMapState) close() {
	if state == nil {
		return
	}
	closed := make(map[*ebpf.Map]struct{}, len(state.replacements)+1)
	for _, m := range state.replacements {
		if m == nil {
			continue
		}
		if _, ok := closed[m]; ok {
			continue
		}
		closed[m] = struct{}{}
		_ = m.Close()
	}
	if state.oldStatsMap != nil {
		if _, ok := closed[state.oldStatsMap]; !ok {
			_ = state.oldStatsMap.Close()
		}
	}
}
