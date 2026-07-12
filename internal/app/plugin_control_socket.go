package app

import (
	context "context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	pluginControlSocketMaxPerPlugin   = 32
	pluginControlSocketMaxPayload     = 1 << 20
	pluginControlSocketDefaultTimeout = time.Second
	pluginControlSocketMaxTimeout     = 15 * time.Second
	pluginControlSocketHandleBytes    = 16
)

var (
	errPluginControlSocketNotFound = errors.New("plugin socket handle not found")
	errPluginControlSocketTimeout  = errors.New("plugin socket operation timed out")
)

type pluginControlSocketTransport interface {
	Dial(context.Context, pluginControlSocketOpenRequest) (net.Conn, error)
	Listen(context.Context, pluginControlSocketListenRequest) (pluginControlDeadlineListener, error)
	ListenPacket(context.Context, pluginControlSocketListenRequest) (net.PacketConn, error)
}

type pluginControlDeadlineListener interface {
	net.Listener
	SetDeadline(time.Time) error
}

type pluginControlSocketOpenRequest struct {
	Network    string
	Interface  string
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	Timeout    time.Duration
	KeepAlive  time.Duration
	NoDelay    bool
}

type pluginControlSocketListenRequest struct {
	Network   string
	Interface string
	LocalIP   net.IP
	LocalPort int
	KeepAlive time.Duration
	NoDelay   bool
}

type pluginControlSocketWriteRequest struct {
	Payload    []byte
	RemoteAddr net.Addr
	Timeout    time.Duration
}

type pluginControlSocketReadResult struct {
	Payload    []byte
	RemoteAddr net.Addr
	Timeout    bool
	EOF        bool
}

type pluginControlSocketWriteResult struct {
	Bytes int
}

type pluginControlSocketInfo struct {
	Handle       string
	Network      string
	Kind         string
	Interface    string
	LocalAddr    string
	RemoteAddr   string
	ParentHandle string
	State        string
	CreatedAt    time.Time
	LastReadAt   time.Time
	LastWriteAt  time.Time
	BytesRead    uint64
	BytesWritten uint64
	LastError    string
}

type pluginControlSocketOwner struct {
	pluginID   string
	generation string
}

type pluginControlSocketRegistry struct {
	mu              sync.Mutex
	transport       pluginControlSocketTransport
	entries         map[string]*pluginControlSocketEntry
	pending         map[pluginControlSocketOwner]int
	pluginEpoch     map[string]uint64
	generationEpoch map[pluginControlSocketOwner]uint64
	closed          bool
}

type pluginControlSocketReservation struct {
	owner           pluginControlSocketOwner
	pluginEpoch     uint64
	generationEpoch uint64
}

type pluginControlSocketEntry struct {
	readMu  sync.Mutex
	writeMu sync.Mutex
	metaMu  sync.Mutex

	owner         pluginControlSocketOwner
	handle        string
	network       string
	kind          string
	interfaceName string
	parentHandle  string
	conn          net.Conn
	packet        net.PacketConn
	listener      pluginControlDeadlineListener
	keepAlive     time.Duration
	noDelay       bool
	createdAt     time.Time
	lastReadAt    time.Time
	lastWriteAt   time.Time
	bytesRead     uint64
	bytesWritten  uint64
	lastError     string
	eof           bool
	closeOnce     sync.Once
}

func newPluginControlSocketRegistry(transport pluginControlSocketTransport) *pluginControlSocketRegistry {
	return &pluginControlSocketRegistry{
		transport:       transport,
		entries:         make(map[string]*pluginControlSocketEntry),
		pending:         make(map[pluginControlSocketOwner]int),
		pluginEpoch:     make(map[string]uint64),
		generationEpoch: make(map[pluginControlSocketOwner]uint64),
	}
}

func normalizePluginControlSocketNetwork(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		return value, nil
	default:
		return "", fmt.Errorf("network must be one of tcp, tcp4, tcp6, udp, udp4, udp6")
	}
}

func pluginControlSocketIsTCP(network string) bool {
	return strings.HasPrefix(network, "tcp")
}

func pluginControlSocketIsUDP(network string) bool {
	return strings.HasPrefix(network, "udp")
}

func pluginControlSocketResolveNetwork(network string, localIP net.IP, remoteIP net.IP) (string, error) {
	normalized, err := normalizePluginControlSocketNetwork(network)
	if err != nil {
		return "", err
	}
	wantV6 := pluginControlSocketIPIsIPv6(remoteIP) || pluginControlSocketIPIsIPv6(localIP)
	if strings.HasSuffix(normalized, "4") && wantV6 {
		return "", fmt.Errorf("network %s does not accept IPv6 addresses", normalized)
	}
	if strings.HasSuffix(normalized, "6") {
		for _, ip := range []net.IP{localIP, remoteIP} {
			if ip != nil && !pluginControlSocketIPIsIPv6(ip) {
				return "", fmt.Errorf("network %s does not accept IPv4 addresses", normalized)
			}
		}
	}
	if normalized == "tcp" {
		if wantV6 {
			return "tcp6", nil
		}
		return "tcp4", nil
	}
	if normalized == "udp" {
		if wantV6 {
			return "udp6", nil
		}
		return "udp4", nil
	}
	return normalized, nil
}

func pluginControlSocketIPIsIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil
}

func pluginControlSocketAddress(ip net.IP, port int) string {
	host := ""
	if ip != nil {
		host = ip.String()
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

func (r *pluginControlSocketRegistry) Open(pluginID string, generation string, req pluginControlSocketOpenRequest) (pluginControlSocketInfo, error) {
	if r == nil || r.transport == nil {
		return pluginControlSocketInfo{}, fmt.Errorf("persistent socket transport is unavailable")
	}
	reservation, err := r.reserve(pluginID, generation)
	if err != nil {
		return pluginControlSocketInfo{}, err
	}
	committed := false
	defer func() {
		if !committed {
			r.release(reservation)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), req.Timeout)
	defer cancel()
	conn, err := r.transport.Dial(ctx, req)
	if err != nil {
		return pluginControlSocketInfo{}, err
	}
	entry := &pluginControlSocketEntry{
		owner:         reservation.owner,
		network:       req.Network,
		kind:          "connection",
		interfaceName: req.Interface,
		conn:          conn,
		keepAlive:     req.KeepAlive,
		noDelay:       req.NoDelay,
		createdAt:     time.Now(),
	}
	if pluginControlSocketIsUDP(req.Network) {
		entry.kind = "datagram"
	}
	committed = true
	info, err := r.commit(reservation, entry)
	if err != nil {
		_ = conn.Close()
		return pluginControlSocketInfo{}, err
	}
	return info, nil
}

func (r *pluginControlSocketRegistry) Listen(pluginID string, generation string, req pluginControlSocketListenRequest) (pluginControlSocketInfo, error) {
	if r == nil || r.transport == nil {
		return pluginControlSocketInfo{}, fmt.Errorf("persistent socket transport is unavailable")
	}
	reservation, err := r.reserve(pluginID, generation)
	if err != nil {
		return pluginControlSocketInfo{}, err
	}
	committed := false
	defer func() {
		if !committed {
			r.release(reservation)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), pluginControlSocketDefaultTimeout)
	defer cancel()
	entry := &pluginControlSocketEntry{
		owner:         reservation.owner,
		network:       req.Network,
		interfaceName: req.Interface,
		keepAlive:     req.KeepAlive,
		noDelay:       req.NoDelay,
		createdAt:     time.Now(),
	}
	if pluginControlSocketIsTCP(req.Network) {
		listener, listenErr := r.transport.Listen(ctx, req)
		if listenErr != nil {
			return pluginControlSocketInfo{}, listenErr
		}
		entry.kind = "listener"
		entry.listener = listener
	} else {
		packet, listenErr := r.transport.ListenPacket(ctx, req)
		if listenErr != nil {
			return pluginControlSocketInfo{}, listenErr
		}
		entry.kind = "datagram"
		entry.packet = packet
	}
	committed = true
	info, err := r.commit(reservation, entry)
	if err != nil {
		_ = entry.close()
		return pluginControlSocketInfo{}, err
	}
	return info, nil
}

func (r *pluginControlSocketRegistry) Accept(pluginID string, generation string, handle string, timeout time.Duration) (pluginControlSocketInfo, bool, error) {
	entry, err := r.entry(pluginID, generation, handle)
	if err != nil {
		return pluginControlSocketInfo{}, false, err
	}
	if entry.listener == nil {
		return pluginControlSocketInfo{}, false, fmt.Errorf("socket %s is not a TCP listener", handle)
	}
	reservation, err := r.reserve(pluginID, generation)
	if err != nil {
		return pluginControlSocketInfo{}, false, err
	}
	committed := false
	defer func() {
		if !committed {
			r.release(reservation)
		}
	}()

	entry.readMu.Lock()
	defer entry.readMu.Unlock()
	if err := entry.listener.SetDeadline(time.Now().Add(timeout)); err != nil {
		return pluginControlSocketInfo{}, false, err
	}
	conn, err := entry.listener.Accept()
	_ = entry.listener.SetDeadline(time.Time{})
	if err != nil {
		if pluginControlSocketErrorIsTimeout(err) {
			return pluginControlSocketInfo{}, true, nil
		}
		entry.markError(err)
		return pluginControlSocketInfo{}, false, err
	}
	if err := configurePluginControlTCPConn(conn, entry.noDelay, entry.keepAlive); err != nil {
		_ = conn.Close()
		return pluginControlSocketInfo{}, false, err
	}
	accepted := &pluginControlSocketEntry{
		owner:         reservation.owner,
		network:       entry.network,
		kind:          "connection",
		interfaceName: entry.interfaceName,
		parentHandle:  entry.handle,
		conn:          conn,
		keepAlive:     entry.keepAlive,
		noDelay:       entry.noDelay,
		createdAt:     time.Now(),
	}
	committed = true
	info, err := r.commit(reservation, accepted)
	if err != nil {
		_ = conn.Close()
		return pluginControlSocketInfo{}, false, err
	}
	return info, false, nil
}

func (r *pluginControlSocketRegistry) Read(pluginID string, generation string, handle string, maxBytes int, timeout time.Duration) (pluginControlSocketReadResult, error) {
	entry, err := r.entry(pluginID, generation, handle)
	if err != nil {
		return pluginControlSocketReadResult{}, err
	}
	if entry.listener != nil {
		return pluginControlSocketReadResult{}, fmt.Errorf("socket %s is a listener", handle)
	}
	entry.readMu.Lock()
	defer entry.readMu.Unlock()

	buf := make([]byte, maxBytes)
	deadline := time.Now().Add(timeout)
	var n int
	var remote net.Addr
	if entry.conn != nil {
		if err := entry.conn.SetReadDeadline(deadline); err != nil {
			return pluginControlSocketReadResult{}, err
		}
		n, err = entry.conn.Read(buf)
		_ = entry.conn.SetReadDeadline(time.Time{})
	} else if entry.packet != nil {
		if err := entry.packet.SetReadDeadline(deadline); err != nil {
			return pluginControlSocketReadResult{}, err
		}
		n, remote, err = entry.packet.ReadFrom(buf)
		_ = entry.packet.SetReadDeadline(time.Time{})
	} else {
		return pluginControlSocketReadResult{}, fmt.Errorf("socket %s has no readable endpoint", handle)
	}
	if err != nil {
		if pluginControlSocketErrorIsTimeout(err) {
			return pluginControlSocketReadResult{Timeout: true}, nil
		}
		if errors.Is(err, io.EOF) {
			entry.markEOF()
			return pluginControlSocketReadResult{EOF: true}, nil
		}
		entry.markError(err)
		return pluginControlSocketReadResult{}, err
	}
	payload := append([]byte(nil), buf[:n]...)
	entry.markRead(n)
	return pluginControlSocketReadResult{Payload: payload, RemoteAddr: remote}, nil
}

func (r *pluginControlSocketRegistry) Write(pluginID string, generation string, handle string, req pluginControlSocketWriteRequest) (pluginControlSocketWriteResult, error) {
	entry, err := r.entry(pluginID, generation, handle)
	if err != nil {
		return pluginControlSocketWriteResult{}, err
	}
	if entry.listener != nil {
		return pluginControlSocketWriteResult{}, fmt.Errorf("socket %s is a listener", handle)
	}
	entry.writeMu.Lock()
	defer entry.writeMu.Unlock()

	deadline := time.Now().Add(req.Timeout)
	var n int
	if entry.conn != nil {
		if req.RemoteAddr != nil {
			return pluginControlSocketWriteResult{}, fmt.Errorf("connected socket %s does not accept remote_addr", handle)
		}
		if err := entry.conn.SetWriteDeadline(deadline); err != nil {
			return pluginControlSocketWriteResult{}, err
		}
		n, err = entry.conn.Write(req.Payload)
		_ = entry.conn.SetWriteDeadline(time.Time{})
	} else if entry.packet != nil {
		if req.RemoteAddr == nil {
			return pluginControlSocketWriteResult{}, fmt.Errorf("datagram socket %s requires remote_ip and remote_port", handle)
		}
		if err := entry.packet.SetWriteDeadline(deadline); err != nil {
			return pluginControlSocketWriteResult{}, err
		}
		n, err = entry.packet.WriteTo(req.Payload, req.RemoteAddr)
		_ = entry.packet.SetWriteDeadline(time.Time{})
	} else {
		return pluginControlSocketWriteResult{}, fmt.Errorf("socket %s has no writable endpoint", handle)
	}
	if err != nil {
		if pluginControlSocketErrorIsTimeout(err) {
			return pluginControlSocketWriteResult{}, errPluginControlSocketTimeout
		}
		entry.markError(err)
		return pluginControlSocketWriteResult{}, err
	}
	entry.markWrite(n)
	return pluginControlSocketWriteResult{Bytes: n}, nil
}

func (r *pluginControlSocketRegistry) Info(pluginID string, generation string, handle string) (pluginControlSocketInfo, error) {
	entry, err := r.entry(pluginID, generation, handle)
	if err != nil {
		return pluginControlSocketInfo{}, err
	}
	return entry.info(), nil
}

func (r *pluginControlSocketRegistry) List(pluginID string, generation string) []pluginControlSocketInfo {
	if r == nil {
		return nil
	}
	owner := pluginControlSocketOwner{pluginID: pluginID, generation: generation}
	r.mu.Lock()
	entries := make([]*pluginControlSocketEntry, 0)
	for _, entry := range r.entries {
		if entry.owner == owner {
			entries = append(entries, entry)
		}
	}
	r.mu.Unlock()
	out := make([]pluginControlSocketInfo, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Handle < out[j].Handle })
	return out
}

func (r *pluginControlSocketRegistry) Close(pluginID string, generation string, handle string) (bool, error) {
	if r == nil {
		return false, nil
	}
	owner := pluginControlSocketOwner{pluginID: pluginID, generation: generation}
	r.mu.Lock()
	entry := r.entries[handle]
	if entry == nil || entry.owner != owner {
		r.mu.Unlock()
		return false, nil
	}
	delete(r.entries, handle)
	r.mu.Unlock()
	return true, entry.close()
}

func (r *pluginControlSocketRegistry) ClosePluginGeneration(pluginID string, generation string) int {
	if r == nil {
		return 0
	}
	owner := pluginControlSocketOwner{pluginID: pluginID, generation: generation}
	r.mu.Lock()
	r.generationEpoch[owner]++
	entries := r.removeEntriesLocked(func(entry *pluginControlSocketEntry) bool { return entry.owner == owner })
	r.mu.Unlock()
	closePluginControlSocketEntries(entries)
	return len(entries)
}

func (r *pluginControlSocketRegistry) TransferPluginGeneration(plugin LoadedPlugin, oldGeneration string, newGeneration string) (int, error) {
	if r == nil {
		return 0, nil
	}
	pluginID := strings.TrimSpace(strings.ToLower(plugin.ID))
	oldGeneration = strings.TrimSpace(oldGeneration)
	newGeneration = strings.TrimSpace(newGeneration)
	if pluginID == "" || oldGeneration == "" || newGeneration == "" {
		return 0, fmt.Errorf("plugin socket transfer owner is invalid")
	}
	if oldGeneration == newGeneration {
		return 0, nil
	}
	oldOwner := pluginControlSocketOwner{pluginID: pluginID, generation: oldGeneration}
	newOwner := pluginControlSocketOwner{pluginID: pluginID, generation: newGeneration}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, errPluginRuntimeTargetNotLoaded
	}
	if pending := r.pending[oldOwner]; pending > 0 {
		return 0, fmt.Errorf("old plugin generation still has %d pending socket operation(s)", pending)
	}
	if pending := r.pending[newOwner]; pending > 0 {
		return 0, fmt.Errorf("new plugin generation already has %d pending socket operation(s)", pending)
	}
	entries := make([]*pluginControlSocketEntry, 0)
	for _, entry := range r.entries {
		if entry.owner == newOwner {
			return 0, fmt.Errorf("new plugin generation already owns socket %s", entry.handle)
		}
		if entry.owner != oldOwner {
			continue
		}
		info := entry.info()
		permission, operation := pluginControlSocketPermission(info.Network)
		if !pluginControlHasPermission(plugin, permission) {
			return 0, fmt.Errorf("socket %s requires retained %s permission", info.Handle, permission)
		}
		if !pluginControlHasNetAccess(plugin, operation, info.Interface) {
			return 0, fmt.Errorf("socket %s is no longer allowed on interface %s for %s", info.Handle, info.Interface, operation)
		}
		entries = append(entries, entry)
	}
	r.generationEpoch[oldOwner]++
	for _, entry := range entries {
		entry.owner = newOwner
	}
	return len(entries), nil
}

func (r *pluginControlSocketRegistry) ClosePlugin(pluginID string) int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	r.pluginEpoch[pluginID]++
	for owner := range r.generationEpoch {
		if owner.pluginID == pluginID {
			r.generationEpoch[owner]++
		}
	}
	entries := r.removeEntriesLocked(func(entry *pluginControlSocketEntry) bool { return entry.owner.pluginID == pluginID })
	r.mu.Unlock()
	closePluginControlSocketEntries(entries)
	return len(entries)
}

func (r *pluginControlSocketRegistry) CloseInactive(active map[string]LoadedPlugin) int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	invalidated := make(map[string]struct{})
	for owner := range r.pending {
		if _, ok := active[owner.pluginID]; ok {
			continue
		}
		if _, done := invalidated[owner.pluginID]; !done {
			r.pluginEpoch[owner.pluginID]++
			invalidated[owner.pluginID] = struct{}{}
		}
	}
	entries := r.removeEntriesLocked(func(entry *pluginControlSocketEntry) bool {
		_, ok := active[entry.owner.pluginID]
		if !ok {
			if _, done := invalidated[entry.owner.pluginID]; done {
				return true
			}
			r.pluginEpoch[entry.owner.pluginID]++
			invalidated[entry.owner.pluginID] = struct{}{}
		}
		return !ok
	})
	r.mu.Unlock()
	closePluginControlSocketEntries(entries)
	return len(entries)
}

func (r *pluginControlSocketRegistry) CloseAll() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	r.closed = true
	entries := r.removeEntriesLocked(func(*pluginControlSocketEntry) bool { return true })
	r.mu.Unlock()
	closePluginControlSocketEntries(entries)
	return len(entries)
}

func (r *pluginControlSocketRegistry) reserve(pluginID string, generation string) (pluginControlSocketReservation, error) {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	generation = strings.TrimSpace(generation)
	if pluginID == "" || generation == "" {
		return pluginControlSocketReservation{}, fmt.Errorf("plugin socket owner is invalid")
	}
	owner := pluginControlSocketOwner{pluginID: pluginID, generation: generation}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return pluginControlSocketReservation{}, errPluginRuntimeTargetNotLoaded
	}
	count := 0
	for pendingOwner, pendingCount := range r.pending {
		if pendingOwner.pluginID == pluginID {
			count += pendingCount
		}
	}
	for _, entry := range r.entries {
		if entry.owner.pluginID == pluginID {
			count++
		}
	}
	if count >= pluginControlSocketMaxPerPlugin {
		return pluginControlSocketReservation{}, fmt.Errorf("plugin socket limit reached: %d", pluginControlSocketMaxPerPlugin)
	}
	r.pending[owner]++
	return pluginControlSocketReservation{
		owner:           owner,
		pluginEpoch:     r.pluginEpoch[pluginID],
		generationEpoch: r.generationEpoch[owner],
	}, nil
}

func (r *pluginControlSocketRegistry) release(reservation pluginControlSocketReservation) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.releaseLocked(reservation.owner)
	r.mu.Unlock()
}

func (r *pluginControlSocketRegistry) releaseLocked(owner pluginControlSocketOwner) {
	if r.pending[owner] <= 1 {
		delete(r.pending, owner)
		return
	}
	r.pending[owner]--
}

func (r *pluginControlSocketRegistry) commit(reservation pluginControlSocketReservation, entry *pluginControlSocketEntry) (pluginControlSocketInfo, error) {
	handle, err := newPluginControlSocketHandle()
	if err != nil {
		r.release(reservation)
		return pluginControlSocketInfo{}, err
	}
	r.mu.Lock()
	r.releaseLocked(reservation.owner)
	if r.closed || r.pluginEpoch[reservation.owner.pluginID] != reservation.pluginEpoch || r.generationEpoch[reservation.owner] != reservation.generationEpoch {
		r.mu.Unlock()
		return pluginControlSocketInfo{}, errPluginRuntimeTargetNotLoaded
	}
	for r.entries[handle] != nil {
		handle, err = newPluginControlSocketHandle()
		if err != nil {
			r.mu.Unlock()
			return pluginControlSocketInfo{}, err
		}
	}
	entry.handle = handle
	r.entries[handle] = entry
	r.mu.Unlock()
	return entry.info(), nil
}

func (r *pluginControlSocketRegistry) entry(pluginID string, generation string, handle string) (*pluginControlSocketEntry, error) {
	if r == nil {
		return nil, errPluginControlSocketNotFound
	}
	owner := pluginControlSocketOwner{pluginID: strings.TrimSpace(strings.ToLower(pluginID)), generation: strings.TrimSpace(generation)}
	handle = strings.TrimSpace(handle)
	r.mu.Lock()
	entry := r.entries[handle]
	r.mu.Unlock()
	if entry == nil || entry.owner != owner {
		return nil, errPluginControlSocketNotFound
	}
	return entry, nil
}

func (r *pluginControlSocketRegistry) removeEntriesLocked(match func(*pluginControlSocketEntry) bool) []*pluginControlSocketEntry {
	entries := make([]*pluginControlSocketEntry, 0)
	for handle, entry := range r.entries {
		if !match(entry) {
			continue
		}
		entries = append(entries, entry)
		delete(r.entries, handle)
	}
	return entries
}

func newPluginControlSocketHandle() (string, error) {
	raw := make([]byte, pluginControlSocketHandleBytes)
	if _, err := cryptorand.Read(raw); err != nil {
		return "", fmt.Errorf("generate plugin socket handle: %w", err)
	}
	return "sock_" + hex.EncodeToString(raw), nil
}

func (entry *pluginControlSocketEntry) info() pluginControlSocketInfo {
	entry.metaMu.Lock()
	defer entry.metaMu.Unlock()
	state := "open"
	if entry.listener != nil {
		state = "listening"
	} else if entry.eof {
		state = "eof"
	}
	info := pluginControlSocketInfo{
		Handle:       entry.handle,
		Network:      entry.network,
		Kind:         entry.kind,
		Interface:    entry.interfaceName,
		ParentHandle: entry.parentHandle,
		State:        state,
		CreatedAt:    entry.createdAt,
		LastReadAt:   entry.lastReadAt,
		LastWriteAt:  entry.lastWriteAt,
		BytesRead:    entry.bytesRead,
		BytesWritten: entry.bytesWritten,
		LastError:    entry.lastError,
	}
	if entry.conn != nil {
		if addr := entry.conn.LocalAddr(); addr != nil {
			info.LocalAddr = addr.String()
		}
		if addr := entry.conn.RemoteAddr(); addr != nil {
			info.RemoteAddr = addr.String()
		}
	} else if entry.packet != nil {
		if addr := entry.packet.LocalAddr(); addr != nil {
			info.LocalAddr = addr.String()
		}
	} else if entry.listener != nil {
		if addr := entry.listener.Addr(); addr != nil {
			info.LocalAddr = addr.String()
		}
	}
	return info
}

func (entry *pluginControlSocketEntry) markRead(n int) {
	entry.metaMu.Lock()
	entry.bytesRead += uint64(n)
	entry.lastReadAt = time.Now()
	entry.lastError = ""
	entry.metaMu.Unlock()
}

func (entry *pluginControlSocketEntry) markWrite(n int) {
	entry.metaMu.Lock()
	entry.bytesWritten += uint64(n)
	entry.lastWriteAt = time.Now()
	entry.lastError = ""
	entry.metaMu.Unlock()
}

func (entry *pluginControlSocketEntry) markError(err error) {
	if err == nil {
		return
	}
	entry.metaMu.Lock()
	entry.lastError = err.Error()
	entry.metaMu.Unlock()
}

func (entry *pluginControlSocketEntry) markEOF() {
	entry.metaMu.Lock()
	entry.eof = true
	entry.lastReadAt = time.Now()
	entry.metaMu.Unlock()
}

func (entry *pluginControlSocketEntry) close() error {
	var closeErr error
	entry.closeOnce.Do(func() {
		switch {
		case entry.conn != nil:
			closeErr = entry.conn.Close()
		case entry.packet != nil:
			closeErr = entry.packet.Close()
		case entry.listener != nil:
			closeErr = entry.listener.Close()
		}
	})
	return closeErr
}

func closePluginControlSocketEntries(entries []*pluginControlSocketEntry) {
	for _, entry := range entries {
		if entry != nil {
			_ = entry.close()
		}
	}
}

func pluginControlSocketErrorIsTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errPluginControlSocketTimeout) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func configurePluginControlTCPConn(conn net.Conn, noDelay bool, keepAlive time.Duration) error {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	if err := tcp.SetNoDelay(noDelay); err != nil {
		return fmt.Errorf("set TCP_NODELAY: %w", err)
	}
	if keepAlive > 0 {
		if err := tcp.SetKeepAlive(true); err != nil {
			return fmt.Errorf("enable TCP keepalive: %w", err)
		}
		if err := tcp.SetKeepAlivePeriod(keepAlive); err != nil {
			return fmt.Errorf("set TCP keepalive period: %w", err)
		}
	}
	return nil
}
