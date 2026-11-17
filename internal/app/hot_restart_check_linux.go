//go:build linux

package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// A daemon pins its maps only when it stops for a hot restart, so before a
// restart the check reads the maps the running daemon would pin. A handoff
// that is already pinned (the daemon stopped and nothing took over yet) is
// read from its pins. Either way the map set goes through the successor's own
// adoption rules: buildTCKernelHotRestartMapState or
// buildXDPKernelHotRestartMapState, then compareKernelHotRestartMapReplacements.

// bpfObjNameMaxLen is how many bytes of a map name the kernel keeps.
const bpfObjNameMaxLen = 15

// hotRestartCheckMapNames are the maps a tc or xdp runtime can preserve.
var hotRestartCheckMapNames = []string{
	kernelFlowsMapName,
	kernelFlowsMapNameV6,
	kernelNatPortsMapName,
	kernelNatPortsMapNameV6,
	kernelTCFlowsOldMapNameV4,
	kernelTCFlowsOldMapNameV6,
	kernelTCNatPortsOldMapNameV4,
	kernelTCNatPortsOldMapNameV6,
	kernelStatsMapName,
}

func inspectHotRestart(opts hotRestartCheckOptions) (hotRestartCheckReport, error) {
	if os.Geteuid() != 0 {
		return hotRestartCheckReport{}, errors.New("run as root: the check reads the daemon's BPF maps")
	}
	// deploy.sh gives the service its runtime state directory, by default
	// in the install directory.
	if opts.InstallDir != "" && os.Getenv(veerRuntimeStateDirEnv) == "" && os.Getenv(forwardRuntimeStateDirEnv) == "" {
		if err := os.Setenv(veerRuntimeStateDirEnv, filepath.Join(opts.InstallDir, ".kernel-state")); err != nil {
			return hotRestartCheckReport{}, err
		}
	}
	var report hotRestartCheckReport
	trafficStats, found, err := hotRestartCheckTrafficStats(opts.ConfigPath)
	if err != nil {
		return report, err
	}
	if found {
		report.Config = opts.ConfigPath
	} else {
		report.Notes = append(report.Notes, fmt.Sprintf("no config at %s; checking with the default settings", opts.ConfigPath))
	}
	report.TrafficStats = trafficStats
	checks, err := newHotRestartEngineChecks(trafficStats, opts.SkipStats)
	if err != nil {
		return report, err
	}
	var daemons hotRestartLiveDaemons
	defer daemons.close()
	for _, check := range checks {
		report.Engines = append(report.Engines, check.run(daemons.discover))
	}
	report.Verdict = hotRestartOverallVerdict(report.Engines)
	return report, nil
}

// hotRestartCheckTrafficStats reads the setting the next daemon loads its
// objects with. It parses the file itself because loadConfig also tightens
// the file's permissions, and the check changes nothing.
func hotRestartCheckTrafficStats(path string) (enabled bool, found bool, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false, false, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg.ExperimentalFeatureEnabled(experimentalFeatureKernelTraffic), true, nil
}

// hotRestartEngineCheck is what the successor would start one engine with.
type hotRestartEngineCheck struct {
	engine    string
	spec      *ebpf.CollectionSpec
	opts      kernelHotRestartValidationOptions
	skipStats bool
}

func newHotRestartEngineChecks(trafficStats bool, skipStats bool) ([]hotRestartEngineCheck, error) {
	tcSpec, err := loadEmbeddedKernelCollectionSpec(trafficStats)
	if err != nil {
		return nil, err
	}
	tcHash, err := kernelTCHotRestartObjectHash(trafficStats)
	if err != nil {
		return nil, err
	}
	xdpSpec, err := loadEmbeddedXDPCollectionSpec(trafficStats)
	if err != nil {
		return nil, err
	}
	xdpHash, err := kernelXDPHotRestartObjectHash(trafficStats)
	if err != nil {
		return nil, err
	}
	return []hotRestartEngineCheck{
		{engine: kernelEngineTC, spec: tcSpec, opts: kernelTCHotRestartValidationOptions(tcHash, trafficStats), skipStats: skipStats},
		{engine: kernelEngineXDP, spec: xdpSpec, opts: kernelXDPHotRestartValidationOptions(xdpHash, trafficStats), skipStats: skipStats},
	}, nil
}

func (c hotRestartEngineCheck) run(discover func(pid int) (*hotRestartLiveMaps, error)) hotRestartEngineReport {
	report := hotRestartEngineReport{Engine: c.engine, Source: hotRestartSourceNone}
	meta, err := readKernelRuntimeMetadata(c.engine)
	if err == nil && kernelMetadataOwnerAlive(meta) {
		report.Source = hotRestartSourceRunning
		report.PID = meta.OwnerPID
		c.runLive(&report, meta, discover)
		return report
	}
	if kernelHotRestartStateExists(c.engine) {
		report.Source = hotRestartSourcePinned
		report.Path = kernelHotRestartEngineDir(c.engine)
		c.runPinned(&report)
		return report
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		report.Notes = append(report.Notes, "read runtime metadata: "+err.Error())
	}
	report.Verdict = hotRestartVerdictNone
	report.Reason = fmt.Sprintf("no running %s dataplane and no pinned handoff", c.engine)
	return report
}

func (c hotRestartEngineCheck) runLive(report *hotRestartEngineReport, meta kernelHotRestartMetadata, discover func(pid int) (*hotRestartLiveMaps, error)) {
	attached := len(meta.TCAttachments)
	if c.engine == kernelEngineXDP {
		attached = len(meta.XDPAttachments)
	}
	if attached == 0 {
		report.Verdict = hotRestartVerdictNone
		report.Reason = fmt.Sprintf("the running daemon has no %s attachments, so it preserves nothing", c.engine)
		return
	}
	if kernelHotRestartStateExists(c.engine) {
		report.Notes = append(report.Notes, "an earlier handoff is still pinned in "+kernelHotRestartEngineDir(c.engine))
	}
	live, err := discover(meta.OwnerPID)
	if err != nil {
		report.setUnknown(fmt.Errorf("find the daemon's maps: %w", err))
		return
	}
	resolved, err := resolveHotRestartLiveMaps(live.byEngine[c.engine])
	if err != nil {
		report.setUnknown(err)
		return
	}
	maps := make(map[string]*ebpf.Map, len(resolved))
	for name, item := range resolved {
		maps[name] = item.m
	}
	if maps[kernelFlowsMapName] == nil {
		report.setUnknown(fmt.Errorf("found no %s map among the %s programs pid %d holds", kernelFlowsMapName, c.engine, meta.OwnerPID))
		return
	}
	preserved, err := c.livePreservedMapNames(maps)
	if err != nil {
		report.setUnknown(err)
		return
	}
	var metaErr error
	if strings.TrimSpace(meta.CompatToken) == "" {
		report.Notes = append(report.Notes, "the running daemon does not record its compat token (it predates this check); assuming its kernel_traffic_stats setting matches the config")
	} else {
		metaErr = validateKernelHotRestartMetadataWithOptions(meta, c.opts)
	}
	c.evaluate(report, metaErr, liveKernelHotRestartMapSource(maps, preserved), false)
}

// livePreservedMapNames picks the maps the daemon's shutdown would pin, as
// prepareHotRestartLocked does: old banks only while they hold flows, and for
// xdp the NAT maps only while any holds an entry.
func (c hotRestartEngineCheck) livePreservedMapNames(maps map[string]*ebpf.Map) ([]string, error) {
	present := func(name string) bool { return maps[name] != nil }
	oldV4, oldV6 := uint32(tcFlowMigrationFlagV4Old), uint32(tcFlowMigrationFlagV6Old)
	if c.engine == kernelEngineXDP {
		oldV4, oldV6 = uint32(xdpFlowMigrationFlagV4Old), uint32(xdpFlowMigrationFlagV6Old)
	}
	var flags uint32
	for _, bank := range []struct {
		name string
		flag uint32
	}{{kernelTCFlowsOldMapNameV4, oldV4}, {kernelTCFlowsOldMapNameV6, oldV6}} {
		used, err := kernelMapHasEntries(maps[bank.name])
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", bank.name, err)
		}
		if used {
			flags |= bank.flag
		}
	}
	if c.engine == kernelEngineTC {
		return kernelTCHotRestartPreservedMapNames(present, flags, c.skipStats), nil
	}
	keepNAT := false
	for _, name := range []string{kernelNatPortsMapName, kernelNatPortsMapNameV6, kernelTCNatPortsOldMapNameV4, kernelTCNatPortsOldMapNameV6} {
		used, err := kernelMapHasEntries(maps[name])
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		keepNAT = keepNAT || used
	}
	return kernelXDPHotRestartPreservedMapNames(present, flags, keepNAT, c.skipStats), nil
}

func (c hotRestartEngineCheck) runPinned(report *hotRestartEngineReport) {
	var metaErr error
	if meta, err := readKernelHotRestartMetadata(c.engine); err != nil {
		metaErr = fmt.Errorf("read %s hot restart metadata: %w", c.engine, err)
	} else {
		metaErr = validateKernelHotRestartMetadataWithOptions(meta, c.opts)
	}
	c.evaluate(report, metaErr, pinnedKernelHotRestartMapSource(c.engine), true)
}

// evaluate applies the successor's adoption rules to a preserved map set. The
// successor gives up a pinned handoff on any failure, so for one every failure
// means cold; for a running daemon a failure that is not an incompatibility
// leaves the verdict unknown.
func (c hotRestartEngineCheck) evaluate(report *hotRestartEngineReport, metaErr error, source kernelHotRestartMapSource, pinned bool) {
	var coldReasons []string
	if metaErr != nil {
		coldReasons = append(coldReasons, kernelHotRestartIncompatibilityReason(metaErr))
	}
	source, origins := trackKernelHotRestartMapSource(source)
	// Capacity never decides the verdict: flow and NAT banks are adopted at
	// their preserved size, and a stats map smaller than the new rule
	// capacity is copied rather than adopted. Without a desired capacity the
	// stats map counts as adopted, so its layout is checked as well.
	state, err := c.buildState(source)
	switch {
	case err != nil && (pinned || isKernelHotRestartIncompatible(err)):
		coldReasons = append(coldReasons, kernelHotRestartIncompatibilityReason(err))
	case err != nil:
		report.setUnknown(err)
		return
	case state != nil:
		defer state.close()
		incompatible, err := c.compareMaps(report, state, origins)
		if err != nil {
			report.setUnknown(err)
			return
		}
		if len(incompatible) > 0 {
			coldReasons = append(coldReasons, strings.Join(incompatible, ", ")+" cannot be adopted")
		}
	}
	switch {
	case len(coldReasons) > 0:
		report.Verdict = hotRestartVerdictCold
		report.Reason = strings.Join(coldReasons, "; ")
	case state == nil:
		report.Verdict = hotRestartVerdictNone
		report.Reason = "no flow, NAT or stats map is preserved"
	default:
		report.Verdict = hotRestartVerdictHot
	}
}

func (c hotRestartEngineCheck) buildState(source kernelHotRestartMapSource) (*kernelHotRestartMapState, error) {
	if c.engine == kernelEngineXDP {
		return buildXDPKernelHotRestartMapState(kernelMapCapacities{}, source, c.skipStats)
	}
	return buildTCKernelHotRestartMapState(kernelMapCapacities{}, source, c.skipStats)
}

func (c hotRestartEngineCheck) flexibleCapacityMaps() map[string]bool {
	if c.engine == kernelEngineXDP {
		return kernelXDPHotRestartFlexibleCapacityMaps()
	}
	return kernelTCHotRestartFlexibleCapacityMaps()
}

// compareMaps reports every adopted map and returns the ones the successor
// cannot adopt.
func (c hotRestartEngineCheck) compareMaps(report *hotRestartEngineReport, state *kernelHotRestartMapState, origins map[*ebpf.Map]string) ([]string, error) {
	allowSmaller := c.flexibleCapacityMaps()
	allowSmaller[kernelStatsMapName] = true
	comparisons, err := compareKernelHotRestartMapReplacements(c.spec, state.replacements, allowSmaller)
	if err != nil {
		return nil, err
	}
	var incompatible []string
	for _, comparison := range comparisons {
		m := state.replacements[comparison.name]
		item := hotRestartMapReport{
			Name:      comparison.name,
			Preserved: hotRestartMapLayoutOf(comparison.actual),
			Current:   hotRestartMapLayoutOf(comparison.desired),
		}
		if from := origins[m]; from != comparison.name {
			item.From = from
		}
		err := comparison.err
		if err == nil {
			err = hotRestartCollectionLoadCompatible(c.spec.Maps[comparison.name], m)
		}
		item.Compatible = err == nil
		if err != nil {
			item.Reason = kernelHotRestartIncompatibilityReason(err)
			incompatible = append(incompatible, comparison.name)
		}
		report.Maps = append(report.Maps, item)
	}
	return incompatible, nil
}

// hotRestartCollectionLoadCompatible repeats the check the collection load
// makes on a replacement map, with the spec sized to the preserved map as
// kernelCollectionSpecWithReplacementMapCapacities sizes it.
func hotRestartCollectionLoadCompatible(spec *ebpf.MapSpec, m *ebpf.Map) error {
	if spec == nil || m == nil {
		return nil
	}
	sized := spec.Copy()
	sized.MaxEntries = m.MaxEntries()
	if err := sized.Compatible(m); err != nil {
		return newKernelHotRestartIncompatibleError("the collection load would reject it: %v", err)
	}
	return nil
}

func hotRestartMapLayoutOf(descriptor *kernelHotRestartMapDescriptor) *hotRestartMapLayout {
	if descriptor == nil {
		return nil
	}
	return &hotRestartMapLayout{
		Type:       descriptor.Type.String(),
		KeySize:    descriptor.KeySize,
		ValueSize:  descriptor.ValueSize,
		MaxEntries: descriptor.MaxEntries,
		Flags:      descriptor.Flags,
	}
}

func (report *hotRestartEngineReport) setUnknown(err error) {
	report.Verdict = hotRestartVerdictUnknown
	report.Reason = err.Error()
}

// trackKernelHotRestartMapSource remembers the name each map was preserved
// under, since the successor may adopt it under another.
func trackKernelHotRestartMapSource(source kernelHotRestartMapSource) (kernelHotRestartMapSource, map[*ebpf.Map]string) {
	origins := make(map[*ebpf.Map]string)
	return kernelHotRestartMapSource{
		load: func(name string) (*ebpf.Map, bool, error) {
			m, ok, err := source.load(name)
			if m != nil {
				origins[m] = name
			}
			return m, ok, err
		},
		exists: source.exists,
	}, origins
}

// liveKernelHotRestartMapSource gives the maps of a running daemon that its
// shutdown would pin. Each load returns a clone for the state to close.
func liveKernelHotRestartMapSource(maps map[string]*ebpf.Map, preserved []string) kernelHotRestartMapSource {
	keep := make(map[string]bool, len(preserved))
	for _, name := range preserved {
		keep[name] = maps[name] != nil
	}
	return kernelHotRestartMapSource{
		load: func(name string) (*ebpf.Map, bool, error) {
			if !keep[name] {
				return nil, false, nil
			}
			m, err := maps[name].Clone()
			if err != nil {
				return nil, false, fmt.Errorf("open the daemon's %s map: %w", name, err)
			}
			return m, true, nil
		},
		exists: func(name string) (bool, error) {
			return keep[name], nil
		},
	}
}

// kernelMapHasEntries reads one key, so it works whatever the map's value
// layout is.
func kernelMapHasEntries(m *ebpf.Map) (bool, error) {
	if m == nil {
		return false, nil
	}
	key, err := m.NextKeyBytes(nil)
	if err != nil {
		return false, err
	}
	return key != nil, nil
}

// hotRestartLiveDaemons caches what the check found per daemon process; both
// engines normally run in the same one.
type hotRestartLiveDaemons struct {
	maps map[int]*hotRestartLiveMaps
	errs map[int]error
}

func (d *hotRestartLiveDaemons) discover(pid int) (*hotRestartLiveMaps, error) {
	if live, ok := d.maps[pid]; ok {
		return live, nil
	}
	if err, ok := d.errs[pid]; ok {
		return nil, err
	}
	if d.maps == nil {
		d.maps = make(map[int]*hotRestartLiveMaps)
		d.errs = make(map[int]error)
	}
	live, err := discoverHotRestartLiveMaps(pid)
	if err != nil {
		d.errs[pid] = err
		return nil, err
	}
	d.maps[pid] = live
	return live, nil
}

func (d *hotRestartLiveDaemons) close() {
	for _, live := range d.maps {
		live.close()
	}
}

// hotRestartLiveMaps are the maps a daemon's programs use, by engine: tc
// programs are sched_cls, xdp programs are xdp.
type hotRestartLiveMaps struct {
	byEngine map[string][]hotRestartLiveMap
}

type hotRestartLiveMap struct {
	id ebpf.MapID
	// name is what the kernel keeps of the map's name.
	name    string
	keySize uint32
	m       *ebpf.Map
}

func (live *hotRestartLiveMaps) close() {
	for _, maps := range live.byEngine {
		for _, item := range maps {
			if item.m != nil {
				_ = item.m.Close()
			}
		}
	}
}

func bpfObjName(name string) string {
	if len(name) > bpfObjNameMaxLen {
		return name[:bpfObjNameMaxLen]
	}
	return name
}

// discoverHotRestartLiveMaps finds the maps of the programs a process holds.
// Veer keeps every program of a loaded collection open, and the programs list
// the maps they use. It opens only maps whose name a hot restart can preserve.
func discoverHotRestartLiveMaps(pid int) (*hotRestartLiveMaps, error) {
	progIDs, err := processBPFProgramIDs(pid)
	if err != nil {
		return nil, err
	}
	engineMapIDs := make(map[string]map[ebpf.MapID]struct{})
	for _, id := range progIDs {
		engine, mapIDs, err := hotRestartProgramMaps(id)
		if err != nil {
			return nil, err
		}
		if engine == "" {
			continue
		}
		if engineMapIDs[engine] == nil {
			engineMapIDs[engine] = make(map[ebpf.MapID]struct{})
		}
		for _, mapID := range mapIDs {
			engineMapIDs[engine][mapID] = struct{}{}
		}
	}
	wanted := make(map[string]bool, len(hotRestartCheckMapNames))
	for _, name := range hotRestartCheckMapNames {
		wanted[bpfObjName(name)] = true
	}
	live := &hotRestartLiveMaps{byEngine: make(map[string][]hotRestartLiveMap)}
	for engine, ids := range engineMapIDs {
		for id := range ids {
			m, err := ebpf.NewMapFromID(id)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				live.close()
				return nil, fmt.Errorf("open map %d: %w", id, err)
			}
			info, err := m.Info()
			if err != nil {
				_ = m.Close()
				live.close()
				return nil, fmt.Errorf("read map %d info: %w", id, err)
			}
			if !wanted[info.Name] {
				_ = m.Close()
				continue
			}
			live.byEngine[engine] = append(live.byEngine[engine], hotRestartLiveMap{id: id, name: info.Name, keySize: info.KeySize, m: m})
		}
	}
	return live, nil
}

func hotRestartProgramMaps(id ebpf.ProgramID) (string, []ebpf.MapID, error) {
	prog, err := ebpf.NewProgramFromID(id)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("open program %d: %w", id, err)
	}
	defer prog.Close()
	info, err := prog.Info()
	if err != nil {
		return "", nil, fmt.Errorf("read program %d info: %w", id, err)
	}
	var engine string
	switch info.Type {
	case ebpf.SchedCLS:
		engine = kernelEngineTC
	case ebpf.XDP:
		engine = kernelEngineXDP
	default:
		return "", nil, nil
	}
	mapIDs, ok := info.MapIDs()
	if !ok {
		return "", nil, fmt.Errorf("the kernel does not list the maps of program %d", id)
	}
	return engine, mapIDs, nil
}

// processBPFProgramIDs lists the programs a process holds, through program
// and link fds alike: both name their program in fdinfo.
func processBPFProgramIDs(pid int) ([]ebpf.ProgramID, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	seen := make(map[ebpf.ProgramID]struct{})
	var ids []ebpf.ProgramID
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil || !strings.HasPrefix(target, "anon_inode:bpf") {
			continue
		}
		// The fd may close between the two reads.
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", pid, entry.Name()))
		if err != nil {
			continue
		}
		id, ok := parseFDInfoProgramID(string(data))
		if !ok {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func parseFDInfoProgramID(text string) (ebpf.ProgramID, bool) {
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != "prog_id" {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
		if err != nil || id == 0 {
			return 0, false
		}
		return ebpf.ProgramID(id), true
	}
	return 0, false
}

// hotRestartLiveMapBanks pairs each flow and NAT map with the old bank a
// migration drains.
var hotRestartLiveMapBanks = []struct{ active, old string }{
	{kernelFlowsMapNameV4, kernelTCFlowsOldMapNameV4},
	{kernelFlowsMapNameV6, kernelTCFlowsOldMapNameV6},
	{kernelNatPortsMapNameV4, kernelTCNatPortsOldMapNameV4},
	{kernelNatPortsMapNameV6, kernelTCNatPortsOldMapNameV6},
}

// resolveHotRestartLiveMaps tells which of an engine's live maps plays which
// role. A map keeps the name it was created with, and a successor adopts the
// active banks it inherits as its old banks, so after a hot restart both maps
// of a bank pair can carry the active name. The newer map, with the higher
// id, is then the active bank: an old bank is always a former active bank or
// a placeholder named as an old bank. Both old NAT banks reach the kernel as
// "nat_ports_old_v"; each belongs to the pair whose active map has its key
// size, since IPv4 and IPv6 keys differ in size.
func resolveHotRestartLiveMaps(candidates []hotRestartLiveMap) (map[string]hotRestartLiveMap, error) {
	byName := make(map[string][]hotRestartLiveMap)
	for _, item := range candidates {
		byName[item.name] = append(byName[item.name], item)
	}
	resolved := make(map[string]hotRestartLiveMap)
	switch matches := byName[bpfObjName(kernelStatsMapName)]; len(matches) {
	case 0:
	case 1:
		resolved[kernelStatsMapName] = matches[0]
	default:
		return nil, fmt.Errorf("the daemon's programs use %d maps named %q", len(matches), kernelStatsMapName)
	}

	// Assign the maps named as old banks to their pairs.
	oldNamed := make([][]hotRestartLiveMap, len(hotRestartLiveMapBanks))
	pairsByOldName := make(map[string][]int)
	for i, bank := range hotRestartLiveMapBanks {
		pairsByOldName[bpfObjName(bank.old)] = append(pairsByOldName[bpfObjName(bank.old)], i)
	}
	oldNames := make([]string, 0, len(pairsByOldName))
	for name := range pairsByOldName {
		oldNames = append(oldNames, name)
	}
	sort.Strings(oldNames)
	for _, name := range oldNames {
		pairs := pairsByOldName[name]
		for _, item := range byName[name] {
			owners := pairs
			if len(pairs) > 1 {
				owners = nil
				for _, i := range pairs {
					for _, active := range byName[bpfObjName(hotRestartLiveMapBanks[i].active)] {
						if active.keySize == item.keySize {
							owners = append(owners, i)
							break
						}
					}
				}
			}
			if len(owners) != 1 {
				return nil, fmt.Errorf("cannot tell which bank the %q map with %d-byte keys is: it matches %d active banks", name, item.keySize, len(owners))
			}
			oldNamed[owners[0]] = append(oldNamed[owners[0]], item)
		}
	}

	for i, bank := range hotRestartLiveMapBanks {
		activeNamed := append([]hotRestartLiveMap(nil), byName[bpfObjName(bank.active)]...)
		sort.Slice(activeNamed, func(a, b int) bool { return activeNamed[a].id > activeNamed[b].id })
		members := append(activeNamed, oldNamed[i]...)
		if len(members) > 2 || len(oldNamed[i]) > 1 {
			return nil, fmt.Errorf("the daemon's programs use %d maps for the %s bank pair", len(members), bank.active)
		}
		if len(activeNamed) > 0 {
			resolved[bank.active] = activeNamed[0]
		}
		switch {
		case len(oldNamed[i]) == 1:
			if len(activeNamed) > 1 {
				return nil, fmt.Errorf("the daemon's programs use %d active %s maps", len(activeNamed), bank.active)
			}
			resolved[bank.old] = oldNamed[i][0]
		case len(activeNamed) == 2:
			resolved[bank.old] = activeNamed[1]
		}
	}
	return resolved, nil
}
