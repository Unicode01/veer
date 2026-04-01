package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func runSharedProxy(sockPath string) {
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM)
	myHash := computeBinaryHash()

	var (
		connMu         sync.Mutex
		ipcConn        net.Conn
		pendingUpgrade int32
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sp := &sharedProxyEngine{
		httpRoutes:        make(map[string]string),
		httpsRoutes:       make(map[string]string),
		listeners:         make(map[string]*managedListener),
		domainSiteID:      make(map[string]int64),
		domainStats:       make(map[string]*siteStats),
		domainSourceIP:    make(map[string]string),
		domainTransparent: make(map[string]bool),
	}

	sendIPC := func(msg IPCMessage) {
		connMu.Lock()
		c := ipcConn
		connMu.Unlock()
		if c == nil {
			return
		}
		data, _ := json.Marshal(msg)
		data = append(data, '\n')
		c.Write(data)
	}

	sendStatus := func(status, errMsg string) {
		sendIPC(IPCMessage{Type: "status", Status: status, Error: errMsg})
	}

	sendSiteStats := func() {
		sp.mu.RLock()
		reports := make([]SiteStatsReport, 0, len(sp.domainStats))
		for domain, ss := range sp.domainStats {
			reports = append(reports, SiteStatsReport{
				SiteID:      sp.domainSiteID[domain],
				Domain:      domain,
				ActiveConns: atomic.LoadInt64(&ss.activeConns),
				TotalConns:  atomic.LoadInt64(&ss.totalConns),
				BytesIn:     atomic.LoadInt64(&ss.bytesIn),
				BytesOut:    atomic.LoadInt64(&ss.bytesOut),
				SpeedIn:     atomic.LoadInt64(&ss.speedIn),
				SpeedOut:    atomic.LoadInt64(&ss.speedOut),
			})
		}
		sp.mu.RUnlock()
		sendIPC(IPCMessage{Type: "site_stats", SiteStats: reports})
	}

	// Periodic stats reporting
	go func() {
		speedTicker := time.NewTicker(1 * time.Second)
		sendTicker := time.NewTicker(2 * time.Second)
		defer speedTicker.Stop()
		defer sendTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-speedTicker.C:
				sp.mu.RLock()
				for _, ss := range sp.domainStats {
					ss.updateSpeed()
				}
				sp.mu.RUnlock()
			case <-sendTicker.C:
				sendSiteStats()
			}
		}
	}()

	// Drain checker for pending binary upgrade
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if atomic.LoadInt32(&pendingUpgrade) == 0 {
				continue
			}
			sp.mu.RLock()
			total := int64(0)
			for _, ss := range sp.domainStats {
				total += atomic.LoadInt64(&ss.activeConns)
			}
			sp.mu.RUnlock()
			if total == 0 {
				log.Println("shared proxy: binary upgraded and connections drained, exiting")
				os.Exit(0)
			}
		}
	}()

	// Reconnect loop
	for {
		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		connMu.Lock()
		ipcConn = conn
		connMu.Unlock()

		regMsg := IPCMessage{Type: "register_proxy", BinaryHash: myHash}
		data, _ := json.Marshal(regMsg)
		data = append(data, '\n')
		conn.Write(data)

		scanner := bufio.NewScanner(conn)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

		for scanner.Scan() {
			var msg IPCMessage
			if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
				continue
			}
			switch msg.Type {
			case "sites_config":
				if msg.BinaryHash != "" && msg.BinaryHash != myHash {
					if atomic.CompareAndSwapInt32(&pendingUpgrade, 0, 1) {
						log.Println("shared proxy: binary update detected, closing listeners for new proxy")
						sp.closeAll()
					}
				}
				if atomic.LoadInt32(&pendingUpgrade) != 0 {
					log.Println("shared proxy: pending upgrade, ignoring config update")
					sendStatus("draining", "")
					continue
				}
				log.Printf("shared proxy: updating %d sites", len(msg.Sites))
				sp.applySites(ctx, msg.Sites)
				sendStatus("running", "")
			case "stop":
				log.Println("shared proxy: received stop")
				cancel()
				sp.closeAll()
				return
			}
		}

		// Disconnected from master - keep serving, will reconnect
		connMu.Lock()
		ipcConn = nil
		connMu.Unlock()
		conn.Close()
		log.Println("shared proxy: disconnected from master, reconnecting...")
		time.Sleep(2 * time.Second)
	}
}

type managedListener struct {
	iface    string
	addr     string
	listener net.Listener
	cancel   context.CancelFunc
}

func listenerKey(iface, addr string) string {
	return iface + "\x00" + addr
}

type siteStats struct {
	activeConns  int64
	totalConns   int64
	bytesIn      int64
	bytesOut     int64
	speedIn      int64
	speedOut     int64
	lastBytesIn  int64
	lastBytesOut int64
}

func (ss *siteStats) updateSpeed() {
	curIn := atomic.LoadInt64(&ss.bytesIn)
	curOut := atomic.LoadInt64(&ss.bytesOut)
	sIn := curIn - ss.lastBytesIn
	sOut := curOut - ss.lastBytesOut
	if sIn < 0 {
		sIn = 0
	}
	if sOut < 0 {
		sOut = 0
	}
	ss.lastBytesIn = curIn
	ss.lastBytesOut = curOut
	atomic.StoreInt64(&ss.speedIn, sIn)
	atomic.StoreInt64(&ss.speedOut, sOut)
}

type sharedProxyEngine struct {
	mu                sync.RWMutex
	httpRoutes        map[string]string // domain -> ip:port
	httpsRoutes       map[string]string // domain -> ip:port
	listeners         map[string]*managedListener
	domainSiteID      map[string]int64      // domain -> site ID
	domainStats       map[string]*siteStats // domain -> stats
	domainSourceIP    map[string]string     // domain -> backend source IPv4
	domainTransparent map[string]bool       // domain -> transparent flag
}

func (sp *sharedProxyEngine) applySites(parentCtx context.Context, sites []Site) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	// Build new route tables
	newHTTP := make(map[string]string)
	newHTTPS := make(map[string]string)
	neededListeners := make(map[string]managedListener)

	newSiteID := make(map[string]int64)
	newStats := make(map[string]*siteStats)
	newSourceIP := make(map[string]string)
	newTransparent := make(map[string]bool)

	for _, s := range sites {
		domain := strings.ToLower(s.Domain)
		newSiteID[domain] = s.ID
		newSourceIP[domain] = s.BackendSourceIP
		newTransparent[domain] = s.Transparent
		if old, ok := sp.domainStats[domain]; ok {
			newStats[domain] = old
		} else {
			newStats[domain] = &siteStats{}
		}
		if s.BackendHTTP > 0 {
			newHTTP[domain] = net.JoinHostPort(s.BackendIP, fmt.Sprintf("%d", s.BackendHTTP))
			addr := net.JoinHostPort(s.ListenIP, "80")
			neededListeners[listenerKey(s.ListenIface, addr)] = managedListener{iface: s.ListenIface, addr: addr}
		}
		if s.BackendHTTPS > 0 {
			newHTTPS[domain] = net.JoinHostPort(s.BackendIP, fmt.Sprintf("%d", s.BackendHTTPS))
			addr := net.JoinHostPort(s.ListenIP, "443")
			neededListeners[listenerKey(s.ListenIface, addr)] = managedListener{iface: s.ListenIface, addr: addr}
		}
	}

	sp.httpRoutes = newHTTP
	sp.httpsRoutes = newHTTPS
	sp.domainSiteID = newSiteID
	sp.domainStats = newStats
	sp.domainSourceIP = newSourceIP
	sp.domainTransparent = newTransparent

	// Stop unneeded listeners
	for key, ml := range sp.listeners {
		if _, ok := neededListeners[key]; !ok {
			ml.cancel()
			ml.listener.Close()
			delete(sp.listeners, key)
			if ml.iface != "" {
				log.Printf("shared proxy: stopped listener %s on %s", ml.addr, ml.iface)
			} else {
				log.Printf("shared proxy: stopped listener %s", ml.addr)
			}
		}
	}

	// Start new listeners
	for key, spec := range neededListeners {
		if _, exists := sp.listeners[key]; exists {
			continue
		}
		lc := net.ListenConfig{}
		if ctrl := controlBindToDevice(spec.iface); ctrl != nil {
			lc.Control = ctrl
		}
		ln, err := lc.Listen(parentCtx, "tcp", spec.addr)
		if err != nil {
			if spec.iface != "" {
				log.Printf("shared proxy: listen %s on %s: %v", spec.addr, spec.iface, err)
			} else {
				log.Printf("shared proxy: listen %s: %v", spec.addr, err)
			}
			continue
		}
		ctx, cancel := context.WithCancel(parentCtx)
		sp.listeners[key] = &managedListener{iface: spec.iface, addr: spec.addr, listener: ln, cancel: cancel}

		_, port, _ := net.SplitHostPort(spec.addr)
		if port == "80" {
			go sp.serveHTTP(ctx, ln, spec.addr)
		} else {
			go sp.serveHTTPS(ctx, ln, spec.addr)
		}
		if spec.iface != "" {
			log.Printf("shared proxy: listening on %s via %s", spec.addr, spec.iface)
		} else {
			log.Printf("shared proxy: listening on %s", spec.addr)
		}
	}
}

func (sp *sharedProxyEngine) closeAll() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	for key, ml := range sp.listeners {
		ml.cancel()
		ml.listener.Close()
		delete(sp.listeners, key)
	}
}

func (sp *sharedProxyEngine) serveHTTP(ctx context.Context, ln net.Listener, addr string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go sp.handleHTTPConn(ctx, conn)
	}
}

func (sp *sharedProxyEngine) serveHTTPS(ctx context.Context, ln net.Listener, addr string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go sp.handleHTTPSConn(ctx, conn)
	}
}

func (sp *sharedProxyEngine) handleHTTPConn(ctx context.Context, src net.Conn) {
	defer src.Close()

	clientIP, _, _ := net.SplitHostPort(src.RemoteAddr().String())

	br := bufio.NewReader(src)
	var headerLines []string
	host := ""
	hasXFF := false

	// Read HTTP headers to extract Host
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "host:") {
			h := strings.TrimSpace(trimmed[5:])
			if colonIdx := strings.LastIndex(h, ":"); colonIdx > 0 {
				h = h[:colonIdx]
			}
			host = strings.ToLower(h)
		}
		if strings.HasPrefix(lower, "x-forwarded-for:") {
			hasXFF = true
			existing := strings.TrimSpace(trimmed[16:])
			trimmed = "X-Forwarded-For: " + existing + ", " + clientIP
		}
		headerLines = append(headerLines, trimmed)
	}

	if host == "" {
		return
	}

	// Inject X-Forwarded-For if not present
	if !hasXFF && clientIP != "" {
		headerLines = append(headerLines, "X-Forwarded-For: "+clientIP)
	}

	sp.mu.RLock()
	backend, ok := sp.httpRoutes[host]
	ss := sp.domainStats[host]
	sourceIP := sp.domainSourceIP[host]
	transparent := sp.domainTransparent[host]
	sp.mu.RUnlock()
	if !ok {
		return
	}

	var dst net.Conn
	var err error
	if transparent {
		clientAddr := src.RemoteAddr().(*net.TCPAddr)
		ip4 := clientAddr.IP.To4()
		if ip4 == nil {
			ip4 = clientAddr.IP
		}
		dialer := net.Dialer{
			Timeout:   10 * time.Second,
			LocalAddr: &net.TCPAddr{IP: ip4, Port: 0},
			Control:   controlTransparent(ip4, ""),
		}
		dst, err = dialer.DialContext(ctx, "tcp4", backend)
	} else {
		dialer := net.Dialer{Timeout: 10 * time.Second}
		if err = configureOutboundTCPDialer(&dialer, "", sourceIP); err != nil {
			log.Printf("shared proxy http dial %s -> %s: %v", host, backend, err)
			return
		}
		dst, err = dialer.DialContext(ctx, "tcp", backend)
	}
	if err != nil {
		log.Printf("shared proxy http dial %s -> %s: %v", host, backend, err)
		return
	}
	defer dst.Close()

	if ss != nil {
		atomic.AddInt64(&ss.totalConns, 1)
		atomic.AddInt64(&ss.activeConns, 1)
		defer atomic.AddInt64(&ss.activeConns, -1)
	}

	// Write buffered headers (count as bytes in)
	var headerBuf bytes.Buffer
	for _, h := range headerLines {
		headerBuf.WriteString(h)
		headerBuf.WriteString("\r\n")
	}
	headerBuf.WriteString("\r\n")
	if err := writeAllCounting(dst, headerBuf.Bytes(), func() *int64 {
		if ss == nil {
			return nil
		}
		return &ss.bytesIn
	}()); err != nil {
		log.Printf("shared proxy http write buffered headers %s -> %s: %v", host, backend, err)
		return
	}

	// Bridge remaining data
	var inCounter, outCounter *int64
	if ss != nil {
		inCounter = &ss.bytesIn
		outCounter = &ss.bytesOut
	}
	proxyTCPBidirectional(dst, src, br, inCounter, outCounter)
}

func (sp *sharedProxyEngine) handleHTTPSConn(ctx context.Context, src net.Conn) {
	defer src.Close()

	br := bufio.NewReader(src)

	// Peek TLS record header (5 bytes)
	header, err := br.Peek(5)
	if err != nil || header[0] != 0x16 {
		return
	}

	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 16384 {
		return
	}

	// Peek full TLS record
	record, err := br.Peek(5 + recordLen)
	if err != nil {
		return
	}

	sni := extractSNI(record)
	if sni == "" {
		return
	}
	sni = strings.ToLower(sni)

	sp.mu.RLock()
	backend, ok := sp.httpsRoutes[sni]
	ss := sp.domainStats[sni]
	sourceIP := sp.domainSourceIP[sni]
	transparent := sp.domainTransparent[sni]
	sp.mu.RUnlock()
	if !ok {
		return
	}

	var dst net.Conn
	var err2 error
	if transparent {
		clientAddr := src.RemoteAddr().(*net.TCPAddr)
		ip4 := clientAddr.IP.To4()
		if ip4 == nil {
			ip4 = clientAddr.IP
		}
		dialer := net.Dialer{
			Timeout:   10 * time.Second,
			LocalAddr: &net.TCPAddr{IP: ip4, Port: 0},
			Control:   controlTransparent(ip4, ""),
		}
		dst, err2 = dialer.DialContext(ctx, "tcp4", backend)
	} else {
		dialer := net.Dialer{Timeout: 10 * time.Second}
		if err2 = configureOutboundTCPDialer(&dialer, "", sourceIP); err2 != nil {
			log.Printf("shared proxy https dial %s -> %s: %v", sni, backend, err2)
			return
		}
		dst, err2 = dialer.DialContext(ctx, "tcp", backend)
	}
	if err2 != nil {
		log.Printf("shared proxy https dial %s -> %s: %v", sni, backend, err2)
		return
	}
	defer dst.Close()

	if ss != nil {
		atomic.AddInt64(&ss.totalConns, 1)
		atomic.AddInt64(&ss.activeConns, 1)
		defer atomic.AddInt64(&ss.activeConns, -1)
	}

	var inCounter, outCounter *int64
	if ss != nil {
		inCounter = &ss.bytesIn
		outCounter = &ss.bytesOut
	}
	proxyTCPBidirectional(dst, src, br, inCounter, outCounter)
}

// extractSNI parses a TLS ClientHello to extract the SNI server name.
func extractSNI(data []byte) string {
	// TLS record: type(1) + version(2) + length(2) = 5 bytes header
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	pos := 5

	// Handshake: type(1) + length(3)
	if pos+4 > len(data) || data[pos] != 0x01 {
		return ""
	}
	pos += 4

	// ClientHello: version(2) + random(32)
	if pos+34 > len(data) {
		return ""
	}
	pos += 34

	// Session ID
	if pos >= len(data) {
		return ""
	}
	sessionLen := int(data[pos])
	pos += 1 + sessionLen

	// Cipher suites
	if pos+2 > len(data) {
		return ""
	}
	cipherLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherLen

	// Compression methods
	if pos >= len(data) {
		return ""
	}
	compLen := int(data[pos])
	pos += 1 + compLen

	// Extensions
	if pos+2 > len(data) {
		return ""
	}
	extLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for pos+4 <= extEnd {
		extType := int(data[pos])<<8 | int(data[pos+1])
		eLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0x0000 { // server_name
			if pos+5 > extEnd {
				break
			}
			// SNI list: length(2) + name_type(1) + name_length(2) + name
			sniPos := pos + 2 // skip list length
			if sniPos >= extEnd {
				break
			}
			nameType := data[sniPos]
			sniPos++
			if nameType != 0 { // must be host_name
				pos += eLen
				continue
			}
			if sniPos+2 > extEnd {
				break
			}
			nameLen := int(data[sniPos])<<8 | int(data[sniPos+1])
			sniPos += 2
			if sniPos+nameLen > extEnd {
				break
			}
			return string(data[sniPos : sniPos+nameLen])
		}

		pos += eLen
	}

	return ""
}
