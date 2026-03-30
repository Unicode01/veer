package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type ruleStats struct {
	activeConns   int64
	totalConns    int64
	rejectedConns int64
	bytesIn       int64
	bytesOut      int64
	speedIn       int64
	speedOut      int64
	natTableSize  int64
	lastBytesIn   int64
	lastBytesOut  int64
}

func (st *ruleStats) updateSpeed() {
	curIn := atomic.LoadInt64(&st.bytesIn)
	curOut := atomic.LoadInt64(&st.bytesOut)
	speedIn := curIn - st.lastBytesIn
	speedOut := curOut - st.lastBytesOut
	if speedIn < 0 {
		speedIn = 0
	}
	if speedOut < 0 {
		speedOut = 0
	}
	st.lastBytesIn = curIn
	st.lastBytesOut = curOut
	atomic.StoreInt64(&st.speedIn, speedIn)
	atomic.StoreInt64(&st.speedOut, speedOut)
}

func (st *ruleStats) snapshot(ruleID int64) RuleStatsReport {
	return RuleStatsReport{
		RuleID:        ruleID,
		ActiveConns:   atomic.LoadInt64(&st.activeConns),
		TotalConns:    atomic.LoadInt64(&st.totalConns),
		RejectedConns: atomic.LoadInt64(&st.rejectedConns),
		BytesIn:       atomic.LoadInt64(&st.bytesIn),
		BytesOut:      atomic.LoadInt64(&st.bytesOut),
		SpeedIn:       atomic.LoadInt64(&st.speedIn),
		SpeedOut:      atomic.LoadInt64(&st.speedOut),
		NatTableSize:  int(atomic.LoadInt64(&st.natTableSize)),
	}
}

type countingWriter struct {
	w     io.Writer
	count *int64
}

func (cw countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if cw.count != nil && n > 0 {
		atomic.AddInt64(cw.count, int64(n))
	}
	return n, err
}

// runWorker handles a worker process that can forward multiple rules.
// workerIndex identifies the logical worker slot; the master sends rule configs over the socket.
func runWorker(workerIndex int, sockPath string) {
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM)
	myHash := computeBinaryHash()

	var (
		connMu         sync.Mutex
		ipcConn        net.Conn
		currentCancel  context.CancelFunc
		currentDone    chan struct{}
		currentStats   map[int64]*ruleStats
		pendingUpgrade int32 // atomic flag
	)

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

	sendStatus := func(status, errMsg string, failedIDs []int64) {
		sendIPC(IPCMessage{Type: "status", Status: status, Error: errMsg, FailedRuleIDs: failedIDs})
	}

	sendStats := func(stats []RuleStatsReport) {
		sendIPC(IPCMessage{Type: "stats", Stats: stats})
	}

	startRules := func(rules []Rule) {
		if currentCancel != nil {
			currentCancel()
			<-currentDone
		}
		sm := make(map[int64]*ruleStats, len(rules))
		for _, r := range rules {
			sm[r.ID] = &ruleStats{}
		}
		connMu.Lock()
		currentStats = sm
		connMu.Unlock()

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		currentCancel = cancel
		currentDone = done
		go func() {
			defer close(done)
			runRuleForwarder(ctx, workerIndex, rules, sm, sendStatus, sendStats)
		}()
	}

	// Drain checker for pending binary upgrade
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if atomic.LoadInt32(&pendingUpgrade) == 0 {
				continue
			}
			connMu.Lock()
			sm := currentStats
			connMu.Unlock()
			if sm == nil {
				log.Printf("worker[%d]: binary upgraded, no rules, exiting", workerIndex)
				os.Exit(0)
			}
			total := int64(0)
			for _, st := range sm {
				total += atomic.LoadInt64(&st.activeConns) + atomic.LoadInt64(&st.natTableSize)
			}
			if total == 0 {
				log.Printf("worker[%d]: binary upgraded and connections drained, exiting", workerIndex)
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

		regMsg := IPCMessage{Type: "register", WorkerIndex: workerIndex, BinaryHash: myHash}
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
			case "config":
				if msg.BinaryHash != "" && msg.BinaryHash != myHash {
					if atomic.CompareAndSwapInt32(&pendingUpgrade, 0, 1) {
						log.Printf("worker[%d]: binary update detected, closing listeners for new worker", workerIndex)
						// Close listeners to free ports; existing TCP connections keep running
						if currentCancel != nil {
							currentCancel()
							<-currentDone
							currentCancel = nil
							currentDone = nil
						}
						// Start drain-mode stats reporter (the one in runRuleForwarder stopped with ctx)
						go func() {
							speedTicker := time.NewTicker(1 * time.Second)
							sendTicker := time.NewTicker(2 * time.Second)
							defer speedTicker.Stop()
							defer sendTicker.Stop()
							for {
								select {
								case <-speedTicker.C:
									connMu.Lock()
									sm := currentStats
									connMu.Unlock()
									if sm != nil {
										for _, st := range sm {
											st.updateSpeed()
										}
									}
								case <-sendTicker.C:
									connMu.Lock()
									sm := currentStats
									connMu.Unlock()
									if sm == nil {
										continue
									}
									reports := make([]RuleStatsReport, 0, len(sm))
									for id, st := range sm {
										reports = append(reports, st.snapshot(id))
									}
									sendStats(reports)
								}
							}
						}()
					}
				}
				if atomic.LoadInt32(&pendingUpgrade) != 0 {
					log.Printf("worker[%d]: pending upgrade, ignoring config update", workerIndex)
					connMu.Lock()
					sm := currentStats
					connMu.Unlock()
					var activeIDs []int64
					if sm != nil {
						for id, st := range sm {
							if atomic.LoadInt64(&st.activeConns) > 0 || atomic.LoadInt64(&st.natTableSize) > 0 {
								activeIDs = append(activeIDs, id)
							}
						}
					}
					sendIPC(IPCMessage{Type: "status", Status: "draining", ActiveRuleIDs: activeIDs})
					continue
				}
				if len(msg.Rules) == 0 {
					if currentCancel != nil {
						currentCancel()
						<-currentDone
						currentCancel = nil
						currentDone = nil
						connMu.Lock()
						currentStats = nil
						connMu.Unlock()
					}
					sendStatus("idle", "", nil)
					continue
				}
				log.Printf("worker[%d]: received %d rule(s)", workerIndex, len(msg.Rules))
				startRules(msg.Rules)
			case "stop":
				log.Printf("worker[%d]: received stop", workerIndex)
				if currentCancel != nil {
					currentCancel()
					<-currentDone
				}
				return
			}
		}

		// Disconnected from master - keep forwarding, will reconnect
		connMu.Lock()
		ipcConn = nil
		connMu.Unlock()
		conn.Close()
		log.Printf("worker[%d]: disconnected from master, reconnecting...", workerIndex)
		time.Sleep(2 * time.Second)
	}
}

func runRuleForwarder(ctx context.Context, workerIndex int, rules []Rule, statsMap map[int64]*ruleStats, sendStatus func(string, string, []int64), sendStats func([]RuleStatsReport)) {
	type ruleListeners struct {
		rule  Rule
		tcpLn net.Listener
		udpPC net.PacketConn
		stats *ruleStats
	}

	var listeners []ruleListeners
	failed := 0
	var failedRuleIDs []int64
	for _, rule := range rules {
		r := rule
		var tcpLn net.Listener
		var udpPC net.PacketConn
		ok := false
		st := statsMap[r.ID]

		if r.Protocol == "tcp" || r.Protocol == "tcp+udp" {
			ln, err := listenTCP(ctx, &r)
			if err != nil {
				log.Printf("worker[%d] rule %d tcp: %v", workerIndex, r.ID, err)
			} else {
				tcpLn = ln
				ok = true
			}
		}
		if r.Protocol == "udp" || r.Protocol == "tcp+udp" {
			pc, err := listenUDP(ctx, &r)
			if err != nil {
				log.Printf("worker[%d] rule %d udp: %v", workerIndex, r.ID, err)
			} else {
				udpPC = pc
				ok = true
			}
		}

		if !ok {
			failed++
			failedRuleIDs = append(failedRuleIDs, r.ID)
			if tcpLn != nil {
				tcpLn.Close()
			}
			if udpPC != nil {
				udpPC.Close()
			}
			continue
		}

		log.Printf("worker[%d]: rule %d: %s:%d -> %s:%d [%s]",
			workerIndex, r.ID, r.InIP, r.InPort, r.OutIP, r.OutPort, r.Protocol)
		listeners = append(listeners, ruleListeners{rule: r, tcpLn: tcpLn, udpPC: udpPC, stats: st})
	}

	if len(listeners) == 0 {
		sendStatus("error", fmt.Sprintf("all %d rule bindings failed", failed), failedRuleIDs)
		return
	}

	if failed > 0 {
		log.Printf("worker[%d]: %d/%d rules bound, %d failed", workerIndex, len(listeners), len(listeners)+failed, failed)
	}

	sendStatus("running", "", failedRuleIDs)

	closeSet := &closerSet{}
	for _, l := range listeners {
		if l.tcpLn != nil {
			closeSet.Add(l.tcpLn)
		}
		if l.udpPC != nil {
			closeSet.Add(l.udpPC)
		}
	}
	closeDone := make(chan struct{})
	defer close(closeDone)
	go func() {
		select {
		case <-ctx.Done():
			closeSet.CloseAll()
		case <-closeDone:
		}
	}()

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
				for _, st := range statsMap {
					st.updateSpeed()
				}
			case <-sendTicker.C:
				if len(statsMap) == 0 {
					continue
				}
				reports := make([]RuleStatsReport, 0, len(statsMap))
				for id, st := range statsMap {
					reports = append(reports, st.snapshot(id))
				}
				sendStats(reports)
			}
		}
	}()

	var wg sync.WaitGroup
	for _, l := range listeners {
		l := l
		if l.tcpLn != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := serveTCP(ctx, l.tcpLn, &l.rule, l.stats); err != nil && ctx.Err() == nil {
					log.Printf("worker[%d] rule %d tcp: %v", workerIndex, l.rule.ID, err)
				}
			}()
		}
		if l.udpPC != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := serveUDP(ctx, l.udpPC, &l.rule, l.stats); err != nil && ctx.Err() == nil {
					log.Printf("worker[%d] rule %d udp: %v", workerIndex, l.rule.ID, err)
				}
			}()
		}
	}

	wg.Wait()
}

func listenTCP(ctx context.Context, rule *Rule) (net.Listener, error) {
	lc := net.ListenConfig{}
	ctrl := controlBindToDevice(rule.InInterface)
	if ctrl != nil {
		lc.Control = ctrl
	}
	addr := net.JoinHostPort(rule.InIP, strconv.Itoa(rule.InPort))
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp listen %s: %w", addr, err)
	}
	return ln, nil
}

func serveTCP(ctx context.Context, ln net.Listener, rule *Rule, st *ruleStats) error {
	target := net.JoinHostPort(rule.OutIP, strconv.Itoa(rule.OutPort))
	for {
		src, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handleTCPConn(ctx, src, target, rule.OutInterface, rule.Transparent, st)
	}
}
func handleTCPConn(ctx context.Context, src net.Conn, target, outIface string, transparent bool, st *ruleStats) {
	defer src.Close()

	dialer := net.Dialer{Timeout: 10 * time.Second}

	dialNetwork := "tcp"
	if transparent {
		clientAddr := src.RemoteAddr().(*net.TCPAddr)
		ip4 := clientAddr.IP.To4()
		if ip4 == nil {
			ip4 = clientAddr.IP
		}
		dialer.LocalAddr = &net.TCPAddr{IP: ip4, Port: 0}
		dialer.Control = controlTransparent(ip4, outIface)
		dialNetwork = "tcp4"
	} else {
		ctrl := controlBindToDevice(outIface)
		if ctrl != nil {
			dialer.Control = ctrl
		}
	}

	dst, err := dialer.DialContext(ctx, dialNetwork, target)
	if err != nil {
		if st != nil {
			atomic.AddInt64(&st.rejectedConns, 1)
		}
		log.Printf("tcp dial %s: %v", target, err)
		return
	}
	defer dst.Close()

	if st != nil {
		atomic.AddInt64(&st.totalConns, 1)
		atomic.AddInt64(&st.activeConns, 1)
		defer atomic.AddInt64(&st.activeConns, -1)
	}

	var inCounter *int64
	var outCounter *int64
	if st != nil {
		inCounter = &st.bytesIn
		outCounter = &st.bytesOut
	}

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(countingWriter{w: dst, count: inCounter}, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(countingWriter{w: src, count: outCounter}, dst)
		if tc, ok := src.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}

func listenUDP(ctx context.Context, rule *Rule) (net.PacketConn, error) {
	lc := net.ListenConfig{}
	ctrl := controlBindToDevice(rule.InInterface)
	if ctrl != nil {
		lc.Control = ctrl
	}
	addr := net.JoinHostPort(rule.InIP, strconv.Itoa(rule.InPort))
	pc, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("udp listen %s: %w", addr, err)
	}
	return pc, nil
}

func dialTransparentUDP(localIP net.IP, outIface string, targetAddr *net.UDPAddr) (*net.UDPConn, error) {
	ip4 := localIP.To4()
	if ip4 == nil {
		ip4 = localIP
	}
	dialer := net.Dialer{
		LocalAddr: &net.UDPAddr{IP: ip4, Port: 0},
		Control:   controlTransparent(ip4, outIface),
	}
	conn, err := dialer.Dial("udp4", targetAddr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

func serveUDP(ctx context.Context, pc net.PacketConn, rule *Rule, st *ruleStats) error {
	targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(rule.OutIP, strconv.Itoa(rule.OutPort)))
	if err != nil {
		return err
	}

	type natEntry struct {
		conn       *net.UDPConn
		lastActive time.Time
	}

	natTable := make(map[string]*natEntry)
	var mu sync.Mutex
	removeEntryLocked := func(key string) {
		entry, ok := natTable[key]
		if !ok {
			return
		}
		delete(natTable, key)
		if st != nil {
			atomic.AddInt64(&st.natTableSize, -1)
		}
		entry.conn.Close()
	}
	cleanupStaleEntries := func(now time.Time) {
		mu.Lock()
		for key, entry := range natTable {
			if now.Sub(entry.lastActive) > udpNatIdleTimeout {
				removeEntryLocked(key)
			}
		}
		mu.Unlock()
	}

	nextCleanup := time.Now().Add(udpCleanupInterval)
	if err := pc.SetReadDeadline(nextCleanup); err != nil {
		return err
	}

	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := pc.ReadFrom(buf)
		now := time.Now()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return nil
				}
				cleanupStaleEntries(now)
				nextCleanup = now.Add(udpCleanupInterval)
				if err := pc.SetReadDeadline(nextCleanup); err != nil {
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
			cleanupStaleEntries(now)
			nextCleanup = now.Add(udpCleanupInterval)
			if err := pc.SetReadDeadline(nextCleanup); err != nil {
				return err
			}
		}
		if st != nil && n > 0 {
			atomic.AddInt64(&st.bytesIn, int64(n))
		}

		key := srcAddr.String()
		mu.Lock()
		entry, exists := natTable[key]
		if !exists {
			var outConn *net.UDPConn
			if rule.Transparent {
				srcUDP := srcAddr.(*net.UDPAddr)
				outConn, err = dialTransparentUDP(srcUDP.IP, rule.OutInterface, targetAddr)
			} else {
				outConn, err = dialOutboundUDP(targetAddr, rule.OutInterface)
			}
			if err != nil {
				mu.Unlock()
				if st != nil {
					atomic.AddInt64(&st.rejectedConns, 1)
				}
				log.Printf("udp dial: %v", err)
				continue
			}
			entry = &natEntry{conn: outConn, lastActive: now}
			natTable[key] = entry
			if st != nil {
				atomic.AddInt64(&st.totalConns, 1)
				atomic.AddInt64(&st.natTableSize, 1)
			}

			go func(src net.Addr, out *net.UDPConn, natKey string) {
				retBuf := make([]byte, 65535)
				for {
					out.SetReadDeadline(time.Now().Add(udpNatIdleTimeout))
					rn, err := out.Read(retBuf)
					if err != nil {
						mu.Lock()
						removeEntryLocked(natKey)
						mu.Unlock()
						return
					}
					if st != nil && rn > 0 {
						atomic.AddInt64(&st.bytesOut, int64(rn))
					}
					pc.WriteTo(retBuf[:rn], src)
					mu.Lock()
					if e, ok := natTable[natKey]; ok {
						e.lastActive = time.Now()
					}
					mu.Unlock()
				}
			}(srcAddr, outConn, key)
		}
		entry.lastActive = now
		mu.Unlock()

		entry.conn.Write(buf[:n])
	}
}
