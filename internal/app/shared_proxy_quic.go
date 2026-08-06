package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sharedQUICHandshakeTimeout     = 15 * time.Second
	sharedQUICMaxPendingHandshakes = 256
	sharedQUICMaxPendingDatagrams  = 64
	sharedQUICMaxPendingBytes      = 128 * 1024
	sharedQUICTotalPendingBytes    = 8 * 1024 * 1024
	sharedQUICMaxSessionCIDs       = 16
)

type sharedQUICPending struct {
	aliases      map[string]struct{}
	crypto       *sharedQUICCryptoAccumulator
	datagrams    [][]byte
	buffered     int
	lastActivity time.Time
}

type sharedQUICSession struct {
	endpointKey  string
	aliases      map[string]struct{}
	client       *net.UDPAddr
	reply        udpReplyInfo
	backend      string
	domain       string
	conn         *net.UDPConn
	stats        *siteStats
	lastActivity time.Time
}

type sharedQUICRelay struct {
	proxy *sharedProxyEngine
	conn  *net.UDPConn

	mu                 sync.Mutex
	pending            map[*sharedQUICPending]struct{}
	pendingByAlias     map[string]*sharedQUICPending
	pendingBytes       int
	sessions           map[*sharedQUICSession]struct{}
	sessionsByAlias    map[string]*sharedQUICSession
	sessionsByEndpoint map[string]map[*sharedQUICSession]struct{}
}

func listenSharedProxyQUIC(ctx context.Context, iface, addr string) (*net.UDPConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse QUIC listen address %s: %w", addr, err)
	}
	lc := net.ListenConfig{}
	if ctrl := controlBindToDevice(iface); ctrl != nil {
		lc.Control = ctrl
	}
	packetConn, err := lc.ListenPacket(ctx, udpListenNetworkForIP(host), addr)
	if err != nil {
		return nil, fmt.Errorf("QUIC listen %s: %w", addr, err)
	}
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		packetConn.Close()
		return nil, fmt.Errorf("QUIC listen %s returned unsupported packet conn %T", addr, packetConn)
	}
	if err := enableUDPReplyPacketInfo(udpConn); err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("QUIC listen %s enable packet info: %w", addr, err)
	}
	_ = configureUDPConnBuffers(udpConn)
	return udpConn, nil
}

func (sp *sharedProxyEngine) serveQUIC(ctx context.Context, conn *net.UDPConn, addr string) {
	relay := &sharedQUICRelay{
		proxy:              sp,
		conn:               conn,
		pending:            make(map[*sharedQUICPending]struct{}),
		pendingByAlias:     make(map[string]*sharedQUICPending),
		sessions:           make(map[*sharedQUICSession]struct{}),
		sessionsByAlias:    make(map[string]*sharedQUICSession),
		sessionsByEndpoint: make(map[string]map[*sharedQUICSession]struct{}),
	}
	if err := relay.run(ctx); err != nil && ctx.Err() == nil {
		log.Printf("shared proxy QUIC %s: %v", addr, err)
	}
}

func (relay *sharedQUICRelay) run(ctx context.Context) error {
	defer relay.closeAll()

	nextCleanup := time.Now().Add(udpCleanupInterval)
	if err := relay.conn.SetReadDeadline(nextCleanup); err != nil {
		return err
	}
	buf := getUDPPacketBuffer()
	defer putUDPPacketBuffer(buf)
	oobBuf := make([]byte, udpReplyPacketInfoBufferSize())

	for {
		n, client, reply, err := readUDPWithReplyInfo(relay.conn, buf, oobBuf)
		now := time.Now()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if ctx.Err() != nil {
					return nil
				}
				relay.cleanup(now)
				nextCleanup = now.Add(udpCleanupInterval)
				if err := relay.conn.SetReadDeadline(nextCleanup); err != nil {
					return err
				}
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !now.Before(nextCleanup) {
			relay.cleanup(now)
			nextCleanup = now.Add(udpCleanupInterval)
			if err := relay.conn.SetReadDeadline(nextCleanup); err != nil {
				return err
			}
		}
		if n == 0 {
			continue
		}
		client = cloneSharedQUICUDPAddr(client)
		reply = cloneSharedQUICReplyInfo(reply)
		packet := buf[:n]
		endpointKey := udpReplyKey(client, reply)
		if session := relay.findSession(endpointKey, packet); session != nil {
			relay.forwardToBackend(session, packet, now)
			continue
		}
		relay.handleInitial(ctx, endpointKey, client, reply, packet, now)
	}
}

func (relay *sharedQUICRelay) handleInitial(ctx context.Context, endpointKey string, client *net.UDPAddr, reply udpReplyInfo, packet []byte, now time.Time) {
	header, err := parseSharedQUICLongHeader(packet)
	if err != nil || header.typ != sharedQUICPacketInitial ||
		(header.version != sharedQUICVersion1 && header.version != sharedQUICVersion2) {
		return
	}

	aliasCandidates := sharedQUICAliases(endpointKey, header.dcid)
	relay.mu.Lock()
	var pending *sharedQUICPending
	for _, alias := range aliasCandidates {
		candidate := relay.pendingByAlias[alias]
		if candidate == nil {
			continue
		}
		if pending != nil && pending != candidate {
			relay.mu.Unlock()
			return
		}
		pending = candidate
	}
	if pending == nil {
		if len(relay.pending) >= sharedQUICMaxPendingHandshakes {
			relay.mu.Unlock()
			return
		}
		pending = &sharedQUICPending{
			aliases:      make(map[string]struct{}),
			crypto:       newSharedQUICCryptoAccumulator(),
			lastActivity: now,
		}
		relay.pending[pending] = struct{}{}
	}
	for _, alias := range aliasCandidates {
		if existing := relay.pendingByAlias[alias]; existing != nil && existing != pending {
			relay.mu.Unlock()
			return
		}
		pending.aliases[alias] = struct{}{}
		relay.pendingByAlias[alias] = pending
	}
	if len(pending.datagrams) >= sharedQUICMaxPendingDatagrams ||
		pending.buffered+len(packet) > sharedQUICMaxPendingBytes ||
		relay.pendingBytes+len(packet) > sharedQUICTotalPendingBytes {
		relay.removePendingLocked(pending)
		relay.mu.Unlock()
		return
	}
	packetCopy := append([]byte(nil), packet...)
	pending.datagrams = append(pending.datagrams, packetCopy)
	pending.buffered += len(packetCopy)
	pending.lastActivity = now
	relay.pendingBytes += len(packetCopy)
	domain, complete, parseErr := pending.crypto.feed(packetCopy)
	if parseErr != nil {
		relay.removePendingLocked(pending)
		relay.mu.Unlock()
		return
	}
	if !complete {
		relay.mu.Unlock()
		return
	}
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	datagrams := pending.datagrams
	aliases := make([]string, 0, len(pending.aliases))
	for alias := range pending.aliases {
		aliases = append(aliases, alias)
	}
	relay.removePendingLocked(pending)
	relay.mu.Unlock()

	relay.proxy.mu.RLock()
	backend, ok := relay.proxy.quicRoutes[domain]
	stats := relay.proxy.domainStats[domain]
	sourceIP := relay.proxy.domainSourceIP[domain]
	transparent := relay.proxy.domainTransparent[domain]
	relay.proxy.mu.RUnlock()
	if !ok {
		return
	}
	target, err := net.ResolveUDPAddr("udp", backend)
	if err != nil {
		log.Printf("shared proxy QUIC resolve %s -> %s: %v", domain, backend, err)
		return
	}
	if !userspaceUDPNATBudget.tryAcquire() {
		return
	}
	var outConn *net.UDPConn
	if transparent {
		outConn, err = dialTransparentUDP(client.IP, "", target)
	} else {
		outConn, err = dialOutboundUDP(target, "", sourceIP)
	}
	if err != nil {
		userspaceUDPNATBudget.release()
		log.Printf("shared proxy QUIC dial %s -> %s: %v", domain, backend, err)
		return
	}

	session := &sharedQUICSession{
		endpointKey:  endpointKey,
		aliases:      make(map[string]struct{}, len(aliases)),
		client:       client,
		reply:        reply,
		backend:      backend,
		domain:       domain,
		conn:         outConn,
		stats:        stats,
		lastActivity: now,
	}
	relay.mu.Lock()
	if _, exists := relay.sessionsByEndpoint[endpointKey]; !exists {
		relay.sessionsByEndpoint[endpointKey] = make(map[*sharedQUICSession]struct{})
	}
	for _, alias := range aliases {
		if existing := relay.sessionsByAlias[alias]; existing != nil {
			relay.mu.Unlock()
			userspaceUDPNATBudget.release()
			outConn.Close()
			return
		}
		session.aliases[alias] = struct{}{}
	}
	for alias := range session.aliases {
		relay.sessionsByAlias[alias] = session
	}
	relay.sessions[session] = struct{}{}
	relay.sessionsByEndpoint[endpointKey][session] = struct{}{}
	relay.mu.Unlock()
	if stats != nil {
		atomic.AddInt64(&stats.totalConns, 1)
		atomic.AddInt64(&stats.activeConns, 1)
	}
	go relay.readBackend(ctx, session)
	for _, datagram := range datagrams {
		if !relay.forwardToBackend(session, datagram, time.Now()) {
			return
		}
	}
}

func (relay *sharedQUICRelay) findSession(endpointKey string, packet []byte) *sharedQUICSession {
	if len(packet) < 1 {
		return nil
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if packet[0]&0x80 != 0 {
		header, err := parseSharedQUICLongHeader(packet)
		if err != nil {
			return nil
		}
		return relay.sessionsByAlias[sharedQUICAlias(endpointKey, header.dcid)]
	}

	var matched *sharedQUICSession
	maxCIDLen := len(packet) - 1
	if maxCIDLen > sharedQUICMaxConnectionIDBytes {
		maxCIDLen = sharedQUICMaxConnectionIDBytes
	}
	for cidLen := 1; cidLen <= maxCIDLen; cidLen++ {
		candidate := relay.sessionsByAlias[sharedQUICAlias(endpointKey, packet[1:1+cidLen])]
		if candidate == nil {
			continue
		}
		if matched != nil && matched != candidate {
			return nil
		}
		matched = candidate
	}
	if matched != nil {
		return matched
	}
	// CID rotation is opaque after the handshake. A unique endpoint is still
	// unambiguous; multiplexed endpoints require a known destination CID.
	endpointSessions := relay.sessionsByEndpoint[endpointKey]
	if len(endpointSessions) == 1 {
		for session := range endpointSessions {
			return session
		}
	}
	return nil
}

func (relay *sharedQUICRelay) forwardToBackend(session *sharedQUICSession, packet []byte, now time.Time) bool {
	relay.mu.Lock()
	if _, ok := relay.sessions[session]; !ok {
		relay.mu.Unlock()
		return false
	}
	session.lastActivity = now
	relay.mu.Unlock()
	if _, err := session.conn.Write(packet); err != nil {
		relay.removeSession(session)
		return false
	}
	if session.stats != nil {
		atomic.AddInt64(&session.stats.bytesIn, int64(len(packet)))
	}
	return true
}

func (relay *sharedQUICRelay) readBackend(ctx context.Context, session *sharedQUICSession) {
	buf := getUDPPacketBuffer()
	defer putUDPPacketBuffer(buf)
	for {
		if err := session.conn.SetReadDeadline(time.Now().Add(udpNatIdleTimeout)); err != nil {
			relay.removeSession(session)
			return
		}
		n, err := session.conn.Read(buf)
		if err != nil {
			relay.removeSession(session)
			return
		}
		if ctx.Err() != nil {
			relay.removeSession(session)
			return
		}
		now := time.Now()
		if header, err := parseSharedQUICLongHeader(buf[:n]); err == nil && len(header.scid) > 0 {
			relay.addSessionCID(session, header.scid)
		}
		relay.mu.Lock()
		if _, ok := relay.sessions[session]; !ok {
			relay.mu.Unlock()
			return
		}
		session.lastActivity = now
		relay.mu.Unlock()
		if session.stats != nil {
			atomic.AddInt64(&session.stats.bytesOut, int64(n))
		}
		if _, err := writeUDPWithReplyInfo(relay.conn, buf[:n], session.client, session.reply); err != nil {
			log.Printf("shared proxy QUIC reply %s <- %s: %v", session.domain, session.backend, err)
			relay.removeSession(session)
			return
		}
	}
}

func (relay *sharedQUICRelay) addSessionCID(session *sharedQUICSession, cid []byte) {
	alias := sharedQUICAlias(session.endpointKey, cid)
	if alias == "" {
		return
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if _, ok := relay.sessions[session]; !ok {
		return
	}
	if existing := relay.sessionsByAlias[alias]; existing != nil && existing != session {
		return
	}
	if _, exists := session.aliases[alias]; !exists && len(session.aliases) >= sharedQUICMaxSessionCIDs {
		return
	}
	session.aliases[alias] = struct{}{}
	relay.sessionsByAlias[alias] = session
}

func (relay *sharedQUICRelay) cleanup(now time.Time) {
	relay.mu.Lock()
	for pending := range relay.pending {
		if now.Sub(pending.lastActivity) > sharedQUICHandshakeTimeout {
			relay.removePendingLocked(pending)
		}
	}
	var stale []*sharedQUICSession
	for session := range relay.sessions {
		if now.Sub(session.lastActivity) > udpNatIdleTimeout {
			stale = append(stale, session)
		}
	}
	relay.mu.Unlock()
	for _, session := range stale {
		relay.removeSession(session)
	}
}

func (relay *sharedQUICRelay) removePendingLocked(pending *sharedQUICPending) {
	if _, ok := relay.pending[pending]; !ok {
		return
	}
	delete(relay.pending, pending)
	for alias := range pending.aliases {
		if relay.pendingByAlias[alias] == pending {
			delete(relay.pendingByAlias, alias)
		}
	}
	relay.pendingBytes -= pending.buffered
	if relay.pendingBytes < 0 {
		relay.pendingBytes = 0
	}
}

func (relay *sharedQUICRelay) removeSession(session *sharedQUICSession) {
	relay.mu.Lock()
	if _, ok := relay.sessions[session]; !ok {
		relay.mu.Unlock()
		return
	}
	delete(relay.sessions, session)
	for alias := range session.aliases {
		if relay.sessionsByAlias[alias] == session {
			delete(relay.sessionsByAlias, alias)
		}
	}
	if endpointSessions := relay.sessionsByEndpoint[session.endpointKey]; endpointSessions != nil {
		delete(endpointSessions, session)
		if len(endpointSessions) == 0 {
			delete(relay.sessionsByEndpoint, session.endpointKey)
		}
	}
	relay.mu.Unlock()
	if session.stats != nil {
		atomic.AddInt64(&session.stats.activeConns, -1)
	}
	userspaceUDPNATBudget.release()
	session.conn.Close()
}

func (relay *sharedQUICRelay) closeAll() {
	relay.mu.Lock()
	for pending := range relay.pending {
		relay.removePendingLocked(pending)
	}
	sessions := make([]*sharedQUICSession, 0, len(relay.sessions))
	for session := range relay.sessions {
		sessions = append(sessions, session)
	}
	relay.mu.Unlock()
	for _, session := range sessions {
		relay.removeSession(session)
	}
}

func sharedQUICAliases(endpointKey string, cids ...[]byte) []string {
	aliases := make([]string, 0, len(cids))
	seen := make(map[string]struct{}, len(cids))
	for _, cid := range cids {
		alias := sharedQUICAlias(endpointKey, cid)
		if alias == "" {
			continue
		}
		if _, ok := seen[alias]; ok {
			continue
		}
		seen[alias] = struct{}{}
		aliases = append(aliases, alias)
	}
	return aliases
}

func sharedQUICAlias(endpointKey string, cid []byte) string {
	if endpointKey == "" || len(cid) == 0 || len(cid) > sharedQUICMaxConnectionIDBytes {
		return ""
	}
	return endpointKey + "\x00" + strconv.Itoa(len(cid)) + "\x00" + string(cid)
}

func cloneSharedQUICUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	clone := *addr
	clone.IP = append(net.IP(nil), addr.IP...)
	return &clone
}

func cloneSharedQUICReplyInfo(info udpReplyInfo) udpReplyInfo {
	info.SourceIP = append(net.IP(nil), info.SourceIP...)
	return info
}
