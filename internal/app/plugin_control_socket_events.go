package app

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pluginControlSocketWatchDefaultBytes = 64 << 10
	pluginControlSocketWatchPollTimeout  = 250 * time.Millisecond
)

var errPluginControlSocketEventRejected = errors.New("plugin socket event endpoint rejected")

type pluginControlSocketWatchSpec struct {
	Worker   string
	Handler  string
	MaxBytes int
}

type pluginControlSocketWatchInfo struct {
	Worker      string
	Handler     string
	MaxBytes    int
	Events      uint64
	Rejected    uint64
	LastEventAt time.Time
	LastError   string
}

type pluginControlSocketEvent struct {
	Type       string
	OccurredAt time.Time
	Socket     pluginControlSocketInfo
	Accepted   *pluginControlSocketInfo
	Payload    []byte
	RemoteAddr net.Addr
	Error      string
}

type pluginControlSocketEventHandler func(pluginControlSocketOwner, pluginControlSocketWatchSpec, pluginControlSocketEvent) error

type pluginControlSocketWatchRuntime struct {
	spec     pluginControlSocketWatchSpec
	handler  pluginControlSocketEventHandler
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	events   atomic.Uint64
	rejected atomic.Uint64
	metaMu   sync.Mutex
	lastAt   time.Time
	lastErr  string
}

func (r *pluginControlSocketRegistry) Watch(pluginID, generation, handle string, spec pluginControlSocketWatchSpec, handler pluginControlSocketEventHandler) (pluginControlSocketWatchInfo, error) {
	if handler == nil {
		return pluginControlSocketWatchInfo{}, fmt.Errorf("plugin socket event handler is unavailable")
	}
	if strings.TrimSpace(spec.Worker) == "" || strings.TrimSpace(spec.Handler) == "" {
		return pluginControlSocketWatchInfo{}, fmt.Errorf("socket watcher worker and handler are required")
	}
	if spec.MaxBytes == 0 {
		spec.MaxBytes = pluginControlSocketWatchDefaultBytes
	}
	if spec.MaxBytes < 1 || spec.MaxBytes > pluginControlSocketMaxPayload {
		return pluginControlSocketWatchInfo{}, fmt.Errorf("socket watcher max_bytes must be between 1 and %d", pluginControlSocketMaxPayload)
	}
	entry, err := r.entry(pluginID, generation, handle)
	if err != nil {
		return pluginControlSocketWatchInfo{}, err
	}
	watch := &pluginControlSocketWatchRuntime{
		spec: spec, handler: handler, stop: make(chan struct{}), done: make(chan struct{}),
	}
	entry.watchMu.Lock()
	if current := entry.watch; current != nil {
		info := current.info()
		entry.watchMu.Unlock()
		if current.spec == spec {
			return info, nil
		}
		return pluginControlSocketWatchInfo{}, fmt.Errorf("socket %s already has a watcher", handle)
	}
	entry.watch = watch
	entry.watchMu.Unlock()
	go r.runSocketWatch(entry, watch)
	return watch.info(), nil
}

func (r *pluginControlSocketRegistry) Unwatch(pluginID, generation, handle string) (bool, error) {
	entry, err := r.entry(pluginID, generation, handle)
	if err != nil {
		if errors.Is(err, errPluginControlSocketNotFound) {
			return false, nil
		}
		return false, err
	}
	return entry.stopWatch(), nil
}

func (r *pluginControlSocketRegistry) runSocketWatch(entry *pluginControlSocketEntry, watch *pluginControlSocketWatchRuntime) {
	defer close(watch.done)
	defer entry.clearWatch(watch)
	for {
		if watch.stopped() || !r.socketEntryCurrent(entry) {
			return
		}
		event, timedOut, err := r.nextSocketWatchEvent(entry, watch.spec.MaxBytes)
		if timedOut {
			continue
		}
		if watch.stopped() {
			return
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, errPluginControlSocketNotFound) || !r.socketEntryCurrent(entry) {
				return
			}
			entry.markError(err)
			event = pluginControlSocketEvent{Type: "error", OccurredAt: time.Now(), Socket: entry.info(), Error: err.Error()}
		}
		deliveryErr := r.deliverSocketWatchEvent(entry, watch, event)
		if errors.Is(deliveryErr, errPluginControlSocketEventRejected) {
			watch.noteRejected()
			if event.Accepted != nil {
				owner, current := r.socketEntryOwner(entry)
				if current {
					_, _ = r.Close(owner.pluginID, owner.generation, event.Accepted.Handle)
				}
			}
			continue
		}
		if deliveryErr != nil {
			watch.noteError(deliveryErr)
			entry.markError(fmt.Errorf("socket watch handler: %w", deliveryErr))
			return
		}
		watch.noteEvent(event.OccurredAt)
		if event.Type == "eof" || event.Type == "error" {
			return
		}
	}
}

func (r *pluginControlSocketRegistry) nextSocketWatchEvent(entry *pluginControlSocketEntry, maxBytes int) (pluginControlSocketEvent, bool, error) {
	if entry.listener != nil {
		accepted, timedOut, err := r.acceptWatched(entry, pluginControlSocketWatchPollTimeout)
		if err != nil || timedOut {
			return pluginControlSocketEvent{}, timedOut, err
		}
		return pluginControlSocketEvent{
			Type: "accept", OccurredAt: time.Now(), Socket: entry.info(), Accepted: &accepted,
		}, false, nil
	}
	owner, current := r.socketEntryOwner(entry)
	if !current {
		return pluginControlSocketEvent{}, false, errPluginControlSocketNotFound
	}
	result, err := r.read(owner.pluginID, owner.generation, entry.handle, maxBytes, pluginControlSocketWatchPollTimeout, true)
	if err != nil || result.Timeout {
		return pluginControlSocketEvent{}, result.Timeout, err
	}
	eventType := "data"
	if result.EOF {
		eventType = "eof"
	}
	return pluginControlSocketEvent{
		Type: eventType, OccurredAt: time.Now(), Socket: entry.info(), Payload: result.Payload, RemoteAddr: result.RemoteAddr,
	}, false, nil
}

func (r *pluginControlSocketRegistry) acceptWatched(parent *pluginControlSocketEntry, timeout time.Duration) (pluginControlSocketInfo, bool, error) {
	parent.readMu.Lock()
	defer parent.readMu.Unlock()
	if err := parent.listener.SetDeadline(time.Now().Add(timeout)); err != nil {
		return pluginControlSocketInfo{}, false, err
	}
	conn, err := parent.listener.Accept()
	_ = parent.listener.SetDeadline(time.Time{})
	if err != nil {
		if pluginControlSocketErrorIsTimeout(err) {
			return pluginControlSocketInfo{}, true, nil
		}
		parent.markError(err)
		return pluginControlSocketInfo{}, false, err
	}
	if err := configurePluginControlTCPConn(conn, parent.noDelay, parent.keepAlive); err != nil {
		_ = conn.Close()
		return pluginControlSocketInfo{}, false, err
	}
	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		_ = conn.Close()
		return pluginControlSocketInfo{}, false, fmt.Errorf("accepted socket returned no remote endpoint")
	}
	if _, _, ok := pluginControlSocketRemoteEndpoint(remoteAddr.String()); !ok {
		_ = conn.Close()
		return pluginControlSocketInfo{}, false, fmt.Errorf("accepted socket returned an invalid remote endpoint")
	}
	accepted := &pluginControlSocketEntry{
		network: parent.network, kind: "connection", namespace: parent.namespace, interfaceName: parent.interfaceName,
		parentHandle: parent.handle, conn: conn, keepAlive: parent.keepAlive, noDelay: parent.noDelay, createdAt: time.Now(),
	}
	info, err := r.commitWatchedAccept(parent, accepted)
	if err != nil {
		_ = conn.Close()
		return pluginControlSocketInfo{}, false, err
	}
	return info, false, nil
}

func (r *pluginControlSocketRegistry) commitWatchedAccept(parent, accepted *pluginControlSocketEntry) (pluginControlSocketInfo, error) {
	handle, err := newPluginControlSocketHandle()
	if err != nil {
		return pluginControlSocketInfo{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.entries[parent.handle] != parent {
		return pluginControlSocketInfo{}, errPluginRuntimeTargetNotLoaded
	}
	count := 0
	for owner, pending := range r.pending {
		if owner.pluginID == parent.owner.pluginID {
			count += pending
		}
	}
	for _, entry := range r.entries {
		if entry.owner.pluginID == parent.owner.pluginID {
			count++
		}
	}
	if count >= pluginControlSocketMaxPerPlugin {
		return pluginControlSocketInfo{}, fmt.Errorf("plugin socket limit reached: %d", pluginControlSocketMaxPerPlugin)
	}
	for r.entries[handle] != nil {
		handle, err = newPluginControlSocketHandle()
		if err != nil {
			return pluginControlSocketInfo{}, err
		}
	}
	accepted.owner = parent.owner
	accepted.handle = handle
	r.entries[handle] = accepted
	return accepted.info(), nil
}

func (r *pluginControlSocketRegistry) deliverSocketWatchEvent(entry *pluginControlSocketEntry, watch *pluginControlSocketWatchRuntime, event pluginControlSocketEvent) error {
	for attempt := 0; attempt < 2; attempt++ {
		owner, current := r.socketEntryOwner(entry)
		if !current {
			return errPluginRuntimeTargetNotLoaded
		}
		err := watch.handler(owner, watch.spec, event)
		if !errors.Is(err, errPluginRuntimeTargetNotLoaded) {
			return err
		}
		currentOwner, stillCurrent := r.socketEntryOwner(entry)
		if !stillCurrent || currentOwner == owner {
			return err
		}
	}
	return errPluginRuntimeTargetNotLoaded
}

func (r *pluginControlSocketRegistry) socketEntryOwner(entry *pluginControlSocketEntry) (pluginControlSocketOwner, bool) {
	if r == nil || entry == nil {
		return pluginControlSocketOwner{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.entries[entry.handle] != entry {
		return pluginControlSocketOwner{}, false
	}
	return entry.owner, true
}

func (r *pluginControlSocketRegistry) socketEntryCurrent(entry *pluginControlSocketEntry) bool {
	_, current := r.socketEntryOwner(entry)
	return current
}

func (entry *pluginControlSocketEntry) watching() bool {
	if entry == nil {
		return false
	}
	entry.watchMu.Lock()
	watching := entry.watch != nil
	entry.watchMu.Unlock()
	return watching
}

func (entry *pluginControlSocketEntry) watchInfo() *pluginControlSocketWatchInfo {
	if entry == nil {
		return nil
	}
	entry.watchMu.Lock()
	watch := entry.watch
	entry.watchMu.Unlock()
	if watch == nil {
		return nil
	}
	info := watch.info()
	return &info
}

func (entry *pluginControlSocketEntry) stopWatch() bool {
	if entry == nil {
		return false
	}
	entry.watchMu.Lock()
	watch := entry.watch
	entry.watch = nil
	entry.watchMu.Unlock()
	if watch == nil {
		return false
	}
	watch.stopOnce.Do(func() { close(watch.stop) })
	return true
}

func (entry *pluginControlSocketEntry) clearWatch(watch *pluginControlSocketWatchRuntime) {
	entry.watchMu.Lock()
	if entry.watch == watch {
		entry.watch = nil
	}
	entry.watchMu.Unlock()
}

func (watch *pluginControlSocketWatchRuntime) stopped() bool {
	select {
	case <-watch.stop:
		return true
	default:
		return false
	}
}

func (watch *pluginControlSocketWatchRuntime) noteEvent(at time.Time) {
	watch.events.Add(1)
	watch.metaMu.Lock()
	watch.lastAt = at
	watch.lastErr = ""
	watch.metaMu.Unlock()
}

func (watch *pluginControlSocketWatchRuntime) noteRejected() {
	watch.rejected.Add(1)
}

func (watch *pluginControlSocketWatchRuntime) noteError(err error) {
	watch.metaMu.Lock()
	watch.lastErr = err.Error()
	watch.metaMu.Unlock()
}

func (watch *pluginControlSocketWatchRuntime) info() pluginControlSocketWatchInfo {
	watch.metaMu.Lock()
	lastAt, lastErr := watch.lastAt, watch.lastErr
	watch.metaMu.Unlock()
	return pluginControlSocketWatchInfo{
		Worker: watch.spec.Worker, Handler: watch.spec.Handler, MaxBytes: watch.spec.MaxBytes,
		Events: watch.events.Load(), Rejected: watch.rejected.Load(), LastEventAt: lastAt, LastError: lastErr,
	}
}

func (rt *gojaPluginControlRuntime) deliverPluginControlSocketEvent(owner pluginControlSocketOwner, spec pluginControlSocketWatchSpec, event pluginControlSocketEvent) error {
	if rt == nil {
		return errPluginRuntimeTargetNotLoaded
	}
	deadline := time.Now().Add(pluginControlExecutionLockTimeout)
	lease, err := rt.acquirePluginControlUpgradeLease(owner.pluginID, deadline, false)
	if err != nil {
		return err
	}
	defer lease.release()

	rt.mu.Lock()
	plugin := rt.plugins[owner.pluginID]
	control := rt.controlVMs[owner.pluginID]
	closed := rt.closed
	rt.mu.Unlock()
	if closed || plugin.ID == "" || control == nil || control.key != owner.generation {
		return errPluginRuntimeTargetNotLoaded
	}
	if !pluginControlHasPermission(plugin, "worker") {
		return fmt.Errorf("socket watcher requires worker permission")
	}
	if err := validatePluginControlSocketEventAccess(plugin, event); err != nil {
		return err
	}
	vm, err := rt.getPluginControlVM(plugin, "worker", spec.Worker)
	if err != nil {
		return err
	}
	_, err = vm.run(plugin, pluginControlEvent{
		Kind: "socket", Worker: &pluginControlWorkerEvent{Name: spec.Worker, Handler: spec.Handler},
		SocketEvent: &event, bypassUpgradeGate: true,
	}, false)
	return err
}

func validatePluginControlSocketEventAccess(plugin LoadedPlugin, event pluginControlSocketEvent) error {
	info := event.Socket
	permission, operation := pluginControlSocketPermission(info.Network)
	if !pluginControlHasPermission(plugin, permission) || !pluginControlHasNetAccess(plugin, operation, info.Interface) {
		return fmt.Errorf("socket event is no longer authorized for %s on interface %s", operation, info.Interface)
	}
	if info.Namespace != "host" && (!pluginControlHasPermission(plugin, "net.namespace") || !pluginControlHasNamespaceAccess(plugin, info.Namespace)) {
		return fmt.Errorf("socket event namespace %s is no longer authorized", info.Namespace)
	}
	remote := info.RemoteAddr
	if event.Accepted != nil {
		remote = event.Accepted.RemoteAddr
	} else if event.RemoteAddr != nil {
		remote = event.RemoteAddr.String()
	}
	if strings.TrimSpace(remote) == "" {
		return nil
	}
	ip, port, ok := pluginControlSocketRemoteEndpoint(remote)
	if !ok {
		return fmt.Errorf("%w: invalid remote endpoint", errPluginControlSocketEventRejected)
	}
	if _, err := pluginControlNetEndpointPolicyFor(plugin, operation, info.Interface, "", ip, port); err != nil {
		return fmt.Errorf("%w: %v", errPluginControlSocketEventRejected, err)
	}
	return nil
}

func pluginControlSocketEventObject(event pluginControlSocketEvent) map[string]any {
	out := map[string]any{
		"type": event.Type, "occurred_at": event.OccurredAt.UTC().Format(time.RFC3339Nano),
		"socket": pluginControlSocketInfoObject(event.Socket),
	}
	if event.Accepted != nil {
		out["accepted"] = pluginControlSocketInfoObject(*event.Accepted)
	}
	if event.Payload != nil {
		out["payload_hex"] = hex.EncodeToString(event.Payload)
		out["bytes"] = len(event.Payload)
	}
	if event.RemoteAddr != nil {
		pluginControlSocketAddrObject(out, "remote", event.RemoteAddr)
	}
	if event.Error != "" {
		out["error"] = event.Error
	}
	return out
}
