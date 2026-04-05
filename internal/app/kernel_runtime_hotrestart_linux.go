//go:build linux

package app

import (
	"encoding/json"
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
	forwardHotRestartMarkerEnv = "FORWARD_HOT_RESTART_MARKER"
	forwardBPFStateDirEnv      = "FORWARD_BPF_STATE_DIR"
	forwardRuntimeStateDirEnv  = "FORWARD_RUNTIME_STATE_DIR"
	defaultForwardBPFStateDir  = "/sys/fs/bpf/forward"
	hotRestartSkipStatsSuffix  = ".skip-stats"
)

type kernelHotRestartMapState struct {
	replacements     map[string]*ebpf.Map
	actualCapacities kernelMapCapacities
	oldStatsMap      *ebpf.Map
}

type kernelHotRestartMetadata struct {
	Engine          string                          `json:"engine"`
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

func kernelHotRestartTCMetadata(attachments []kernelAttachment) kernelHotRestartMetadata {
	meta := kernelHotRestartMetadata{
		Engine:        kernelEngineTC,
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

func kernelHotRestartXDPMetadata(attachments []xdpAttachment) kernelHotRestartMetadata {
	meta := kernelHotRestartMetadata{
		Engine:         kernelEngineXDP,
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

func loadTCKernelHotRestartState(desired kernelMapCapacities) (*kernelHotRestartMapState, error) {
	state := &kernelHotRestartMapState{
		replacements:     make(map[string]*ebpf.Map, 3),
		actualCapacities: desired,
	}
	loadedAny := false
	haveFlows := false
	haveNAT := false
	skipStats := kernelHotRestartSkipStatsRequested()

	flowsMap, ok, err := loadPinnedKernelMap(kernelHotRestartPinPath(kernelEngineTC, kernelFlowsMapName))
	if err != nil {
		state.close()
		return nil, fmt.Errorf("load pinned tc flows map: %w", err)
	}
	if ok {
		loadedAny = true
		haveFlows = true
		state.replacements[kernelFlowsMapName] = flowsMap
		state.actualCapacities.Flows = int(flowsMap.MaxEntries())
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
		state.actualCapacities.NATPorts = int(natMap.MaxEntries())
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
	haveStats := skipStats || state.oldStatsMap != nil || state.replacements[kernelStatsMapName] != nil
	if !haveFlows || !haveNAT || !haveStats {
		state.close()
		return nil, fmt.Errorf(
			"incomplete pinned tc state: flows=%t nat=%t stats=%t",
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

func loadXDPKernelHotRestartState(desired kernelMapCapacities) (*kernelHotRestartMapState, error) {
	state := &kernelHotRestartMapState{
		replacements:     make(map[string]*ebpf.Map, 2),
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
		state.actualCapacities.Flows = int(flowsMap.MaxEntries())
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
		return nil, fmt.Errorf(
			"incomplete pinned xdp state: flows=%t stats=%t",
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
