package app

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Managed processes survive a hot restart through their keepers. The old
// daemon arms each keeper with a one-time abstract socket and token, records
// them in a private file, and moves the processes out of its resource
// cgroups; the successor attaches, reapplies the limits and waits for the
// plugin to claim each process by starting the same specification.
const (
	pluginProcessHandoffFormatVersion = 1
	pluginProcessHandoffMaxBytes      = 1 << 20
	pluginProcessHandoffLeaf          = "veer-handoff"
)

// pluginProcessClaimDeadline bounds how long an adopted process waits for its
// plugin; tests shorten it.
var pluginProcessClaimDeadline = 2 * time.Minute

var pluginProcessHandoffTokenPattern = regexp.MustCompile(`^[0-9a-f]{32,64}$`)

type pluginProcessHandoffRecord struct {
	Owner            string `json:"owner"`
	ID               string `json:"id"`
	Fingerprint      string `json:"fingerprint"`
	Command          string `json:"command"`
	Restart          string `json:"restart"`
	MaxRestarts      int    `json:"max_restarts"`
	StopTimeoutMS    int    `json:"stop_timeout_ms"`
	Starts           int    `json:"starts"`
	StartedAt        int64  `json:"started_at"`
	KeeperPID        int    `json:"keeper_pid"`
	KeeperStartTicks uint64 `json:"keeper_start_ticks"`
	Socket           string `json:"socket"`
	Token            string `json:"token"`
	LimitOwner       string `json:"limit_owner"`
}

type pluginProcessHandoffState struct {
	FormatVersion int                          `json:"format_version"`
	OwnerPID      int                          `json:"owner_pid"`
	CreatedAt     time.Time                    `json:"created_at"`
	Processes     []pluginProcessHandoffRecord `json:"processes"`
}

type pluginProcessHandoff struct {
	registry *pluginProcessRegistry
	records  []pluginProcessHandoffRecord
}

func pluginProcessHandoffPath() string {
	return filepath.Join(kernelMetadataStateRoot(), "plugin-processes", "handoff.json")
}

func randomPluginProcessHandoffHex(bytes int) (string, error) {
	data := make([]byte, bytes)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

// handOffPluginProcesses arms every running managed process for the successor.
// It runs before the plugin control runtime closes, which would stop them.
func handOffPluginProcesses(rt pluginControlRuntime) *pluginProcessHandoff {
	goja, ok := rt.(*gojaPluginControlRuntime)
	if !ok || goja.processRegistry == nil {
		return nil
	}
	records := goja.processRegistry.handOff(pluginKeeperAdoptWait)
	if len(records) == 0 {
		return nil
	}
	if err := writePluginProcessHandoff(records); err != nil {
		log.Printf("plugin processes: handoff unavailable, stopping them: %v", err)
		goja.processRegistry.cancelHandOff(records)
		return nil
	}
	log.Printf("plugin processes: handed %d process(es) to the successor", len(records))
	return &pluginProcessHandoff{registry: goja.processRegistry, records: records}
}

func (r *pluginProcessRegistry) handOff(wait time.Duration) []pluginProcessHandoffRecord {
	r.mu.Lock()
	keys := make([]string, 0, len(r.entries))
	for key := range r.entries {
		keys = append(keys, key)
	}
	entries := make(map[string]*pluginManagedProcess, len(keys))
	for _, key := range keys {
		entries[key] = r.entries[key]
	}
	r.mu.Unlock()
	sort.Strings(keys)
	records := make([]pluginProcessHandoffRecord, 0, len(keys))
	for _, key := range keys {
		p := entries[key]
		owner, _, _ := strings.Cut(key, "/")
		p.mu.Lock()
		run, status := p.run, p.status
		restart, stopTimeout := p.restartPolicy, p.stopTimeout
		p.mu.Unlock()
		if run == nil || status.State != "running" {
			continue
		}
		ticks, err := kernelProcessStartTicks(run.keeperPID)
		if err != nil {
			continue
		}
		name, err := randomPluginProcessHandoffHex(16)
		if err != nil {
			continue
		}
		token, err := randomPluginProcessHandoffHex(32)
		if err != nil {
			continue
		}
		if err := run.detach("veer-keeper-"+name, token, wait); err != nil {
			log.Printf("plugin processes: %s stays with this daemon: %v", key, err)
			continue
		}
		p.mu.Lock()
		p.handedOff = true
		p.mu.Unlock()
		records = append(records, pluginProcessHandoffRecord{
			Owner: owner, ID: status.ID, Fingerprint: hex.EncodeToString(p.fingerprint[:]), Command: p.command,
			Restart: restart, MaxRestarts: p.maxRestarts, StopTimeoutMS: int(stopTimeout / time.Millisecond),
			Starts: status.Starts, StartedAt: status.StartedAt, KeeperPID: run.keeperPID, KeeperStartTicks: ticks,
			Socket: "veer-keeper-" + name, Token: token, LimitOwner: p.limitOwner,
		})
	}
	return records
}

// cancelHandOff returns armed processes to normal supervision. Their keepers
// are still connected, so closing the runtime stops them as before.
func (r *pluginProcessRegistry) cancelHandOff(records []pluginProcessHandoffRecord) {
	for _, record := range records {
		if p := r.get(record.Owner, record.ID); p != nil {
			p.mu.Lock()
			p.handedOff = false
			p.mu.Unlock()
		}
	}
}

func writePluginProcessHandoff(records []pluginProcessHandoffRecord) error {
	path := pluginProcessHandoffPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(pluginProcessHandoffState{
		FormatVersion: pluginProcessHandoffFormatVersion, OwnerPID: os.Getpid(), CreatedAt: time.Now().UTC(), Processes: records,
	})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".handoff-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// finalize runs after the plugin hosts have stopped. A delegated cgroup with
// controllers enabled cannot take the successor's main process while any
// child still holds processes, so the handed-off processes move into
// controller-free leaves and the root gives up its controllers. If that is
// impossible the processes are killed instead: the service must restart.
func (h *pluginProcessHandoff) finalize() error {
	if h == nil || len(h.records) == 0 {
		return nil
	}
	if err := releasePluginProcessHandoffCgroups(h.records); err != nil {
		for _, record := range h.records {
			run := &pluginKeeperRun{keeperPID: record.KeeperPID, keeperTicks: record.KeeperStartTicks}
			run.kill()
		}
		_ = os.Remove(pluginProcessHandoffPath())
		return fmt.Errorf("release cgroups for handed-off processes, stopped them instead: %w", err)
	}
	return nil
}

// preparedPluginHostCgroupRoot reports the delegated root whose controllers
// this daemon enabled. Any other cgroup is not ours to change.
func preparedPluginHostCgroupRoot() (string, bool) {
	pluginHostCgroupPreparation.Lock()
	defer pluginHostCgroupPreparation.Unlock()
	prep := &pluginHostCgroupPreparation
	return prep.root, prep.ready && prep.err == nil && prep.root != ""
}

func releasePluginProcessHandoffCgroups(records []pluginProcessHandoffRecord) error {
	root, prepared := preparedPluginHostCgroupRoot()
	if !prepared {
		return nil // This daemon never enabled delegated controllers.
	}
	enabled, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
	if err != nil {
		return nil
	}
	controllers := strings.Fields(string(enabled))
	if len(controllers) == 0 {
		return nil // The successor can join the root as it is.
	}
	for _, record := range records {
		source, err := pluginProcessCgroupPath(record.KeeperPID)
		if err != nil || !pluginCgroupWithin(root, source) {
			continue
		}
		target := filepath.Join(root, pluginProcessHandoffLeaf, record.LimitOwner)
		if source == target {
			continue
		}
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		if err := movePluginProcessTree(source, target, record.KeeperPID); err != nil {
			return err
		}
		if strings.HasPrefix(filepath.Base(filepath.Dir(source)), "veer-plugins-") {
			_ = os.Remove(source)
		}
	}
	base := filepath.Join(root, fmt.Sprintf("veer-plugins-%d", os.Getpid()))
	if children, err := os.ReadDir(base); err == nil {
		for _, child := range children {
			if child.IsDir() {
				if err := os.Remove(filepath.Join(base, child.Name())); err != nil && !os.IsNotExist(err) {
					return err
				}
			}
		}
		if err := os.Remove(base); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	disable := make([]string, 0, len(controllers))
	for _, controller := range controllers {
		disable = append(disable, "-"+controller)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte(strings.Join(disable, " ")), 0o644); err != nil {
		return fmt.Errorf("disable delegated controllers: %w", err)
	}
	if remaining, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control")); err != nil || strings.TrimSpace(string(remaining)) != "" {
		return fmt.Errorf("delegated controllers remain enabled: %q", strings.TrimSpace(string(remaining)))
	}
	return nil
}

func pluginProcessCgroupPath(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	return resolvePluginHostCgroupRoot(pluginHostCgroupMountRoot, data)
}

func pluginCgroupWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// movePluginProcessTree moves a keeper and its descendants, which may share a
// cgroup with unrelated processes, into target.
func movePluginProcessTree(source, target string, keeperPID int) error {
	data, err := os.ReadFile(filepath.Join(source, "cgroup.procs"))
	if err != nil {
		return err
	}
	for _, field := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 0 {
			continue
		}
		if descends, err := pluginHostProcessDescendsFrom(pid, keeperPID); err != nil || !descends {
			continue
		}
		if err := os.WriteFile(filepath.Join(target, "cgroup.procs"), []byte(field), 0o644); err != nil && !pluginHostProcessUnavailable(err) {
			return fmt.Errorf("move process %d: %w", pid, err)
		}
	}
	return nil
}

// adoptHandedOffProcesses attaches to the keepers the previous daemon handed
// off. The file is consumed either way; keepers nobody attaches to stop their
// processes on their own once their wait expires.
func (r *pluginProcessRegistry) adoptHandedOffProcesses() {
	path := pluginProcessHandoffPath()
	state, err := readPluginProcessHandoff(path)
	_ = os.Remove(path)
	if err != nil {
		log.Printf("plugin processes: ignore handoff: %v", err)
		return
	}
	if state == nil {
		return
	}
	adopted := 0
	for _, record := range state.Processes {
		if err := r.adoptHandedOffProcess(record); err != nil {
			log.Printf("plugin processes: %s/%s not adopted: %v", record.Owner, record.ID, err)
			continue
		}
		adopted++
	}
	if adopted > 0 {
		log.Printf("plugin processes: adopted %d process(es) from the previous daemon", adopted)
	}
}

func readPluginProcessHandoff(path string) (*pluginProcessHandoffState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ok || int(stat.Uid) != os.Geteuid() || info.Size() > pluginProcessHandoffMaxBytes {
		return nil, fmt.Errorf("handoff file must be a private regular file owned by the service user")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state pluginProcessHandoffState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.FormatVersion != pluginProcessHandoffFormatVersion || len(state.Processes) > 32 {
		return nil, fmt.Errorf("unsupported handoff format")
	}
	return &state, nil
}

func (r *pluginProcessRegistry) adoptHandedOffProcess(record pluginProcessHandoffRecord) error {
	if !pluginIDPattern.MatchString(record.Owner) || !pluginProcessIDPattern.MatchString(record.ID) ||
		!pluginProcessHandoffTokenPattern.MatchString(record.Token) || !strings.HasPrefix(record.Socket, "veer-keeper-") ||
		record.KeeperPID <= 0 || record.LimitOwner != pluginManagedProcessLimitOwner(record.Owner+"/"+record.ID) {
		return fmt.Errorf("invalid record")
	}
	fingerprint, err := hex.DecodeString(record.Fingerprint)
	if err != nil || len(fingerprint) != 32 {
		return fmt.Errorf("invalid fingerprint")
	}
	if ticks, err := kernelProcessStartTicks(record.KeeperPID); err != nil || ticks != record.KeeperStartTicks {
		return fmt.Errorf("keeper is gone")
	}
	run, attached, scanner, err := dialPluginKeeper(record.Socket, record.Token, record.KeeperPID, record.KeeperStartTicks)
	if err != nil {
		return err
	}
	if !attached.Running {
		run.release()
		return fmt.Errorf("process exited during the restart")
	}
	key := record.Owner + "/" + record.ID
	p := &pluginManagedProcess{
		command: record.Command, restartPolicy: record.Restart, stopTimeout: time.Duration(record.StopTimeoutMS) * time.Millisecond,
		stop: make(chan struct{}), done: make(chan struct{}), restart: make(chan struct{}, 1), claims: make(chan pluginProcessClaim),
		maxRestarts: record.MaxRestarts, limitOwner: record.LimitOwner, limitConfig: r.cfg, run: run, adopted: true,
		status: pluginProcessStatus{ID: record.ID, State: "running", PID: attached.PID, Starts: record.Starts, ExitCode: -1, StartedAt: record.StartedAt},
	}
	copy(p.fingerprint[:], fingerprint)
	_, _ = p.stdout.Write(attached.Stdout)
	_, _ = p.stderr.Write(attached.Stderr)
	go run.read(scanner, &p.stdout, &p.stderr)
	limitCleanup := adoptPluginManagedProcessLimits(record.KeeperPID, record.LimitOwner, r.cfg)
	cleanup := func() {
		run.kill()
		run.awaitGone(pluginKeeperStopGrace)
		limitCleanup()
	}
	r.mu.Lock()
	if r.closed || r.entries[key] != nil {
		r.mu.Unlock()
		run.stop(p.stopTimeout)
		cleanup()
		return fmt.Errorf("process id is already in use")
	}
	if r.entries == nil {
		r.entries = make(map[string]*pluginManagedProcess)
	}
	r.entries[key] = p
	r.mu.Unlock()
	go r.awaitClaim(key, p, cleanup, pluginProcessClaimDeadline)
	return nil
}

// adoptPluginManagedProcessLimits moves an adopted keeper and its descendants
// into this daemon's resource cgroup. Without limits they stay where the
// previous daemon left them, and that leaf goes once they have exited.
func adoptPluginManagedProcessLimits(keeperPID int, owner string, cfg *Config) func() {
	source, sourceErr := pluginProcessCgroupPath(keeperPID)
	removeHandoffLeaf := func() {
		if sourceErr == nil && filepath.Base(filepath.Dir(source)) == pluginProcessHandoffLeaf {
			_ = os.Remove(source)
			_ = os.Remove(filepath.Dir(source))
		}
	}
	cleanup, err := limitPluginManagedProcess(keeperPID, owner, cfg)
	if err != nil {
		log.Printf("plugin processes: adopted process keeps its previous cgroup: %v", err)
		return removeHandoffLeaf
	}
	if sourceErr == nil {
		if target, err := pluginProcessCgroupPath(keeperPID); err == nil && target != source {
			if err := movePluginProcessTree(source, target, keeperPID); err != nil {
				log.Printf("plugin processes: move adopted process tree: %v", err)
			}
		}
	}
	removeHandoffLeaf()
	return func() {
		cleanup()
		removeHandoffLeaf()
	}
}
