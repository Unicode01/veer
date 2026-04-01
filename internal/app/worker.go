package app

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
	"sort"
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

func reuseLiveRuleStats(current map[int64]*ruleStats, ids []int64) map[int64]*ruleStats {
	next := make(map[int64]*ruleStats, len(ids))
	for _, id := range ids {
		if current != nil {
			if st, ok := current[id]; ok && st != nil {
				next[id] = st
				continue
			}
		}
		next[id] = &ruleStats{}
	}
	return next
}

func buildRuleStatsReports(statsMap map[int64]*ruleStats) []RuleStatsReport {
	if len(statsMap) == 0 {
		return nil
	}
	reports := make([]RuleStatsReport, 0, len(statsMap))
	for id, st := range statsMap {
		reports = append(reports, st.snapshot(id))
	}
	return reports
}

func buildRangeStatsReports(statsMap map[int64]*ruleStats) []RangeStatsReport {
	if len(statsMap) == 0 {
		return nil
	}
	reports := make([]RangeStatsReport, 0, len(statsMap))
	for id, st := range statsMap {
		snap := st.snapshot(id)
		reports = append(reports, RangeStatsReport{
			RangeID:       id,
			ActiveConns:   snap.ActiveConns,
			TotalConns:    snap.TotalConns,
			RejectedConns: snap.RejectedConns,
			BytesIn:       snap.BytesIn,
			BytesOut:      snap.BytesOut,
			SpeedIn:       snap.SpeedIn,
			SpeedOut:      snap.SpeedOut,
			NatTableSize:  snap.NatTableSize,
		})
	}
	return reports
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

func writeAllCounting(w io.Writer, data []byte, count *int64) error {
	for len(data) > 0 {
		n, err := countingWriter{w: w, count: count}.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func closeWriteIfPossible(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if conn == nil {
		return
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func proxyTCPBidirectional(dst net.Conn, src net.Conn, srcReader io.Reader, inCounter *int64, outCounter *int64) {
	if srcReader == nil {
		srcReader = src
	}
	done := make(chan struct{}, 2)

	go func() {
		_, _ = io.Copy(countingWriter{w: dst, count: inCounter}, srcReader)
		closeWriteIfPossible(dst)
		done <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(countingWriter{w: src, count: outCounter}, dst)
		closeWriteIfPossible(src)
		done <- struct{}{}
	}()

	<-done
	<-done
}

type ruleBinding struct {
	rule     Rule
	stats    *ruleStats
	cancel   context.CancelFunc
	tcpLn    net.Listener
	udpPC    *net.UDPConn
	done     chan struct{}
	stopOnce sync.Once
}

func startRuleBinding(workerIndex int, rule Rule, st *ruleStats) (*ruleBinding, error) {
	ctx, cancel := context.WithCancel(context.Background())
	binding := &ruleBinding{
		rule:   rule,
		stats:  st,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	ok := false
	var wg sync.WaitGroup

	if rule.Protocol == "tcp" || rule.Protocol == "tcp+udp" {
		ln, err := listenTCP(ctx, &rule)
		if err != nil {
			log.Printf("worker[%d] rule %d tcp: %v", workerIndex, rule.ID, err)
		} else {
			binding.tcpLn = ln
			ok = true
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := serveTCP(ctx, ln, &rule, st); err != nil && ctx.Err() == nil {
					log.Printf("worker[%d] rule %d tcp: %v", workerIndex, rule.ID, err)
				}
			}()
		}
	}
	if rule.Protocol == "udp" || rule.Protocol == "tcp+udp" {
		pc, err := listenUDP(ctx, &rule)
		if err != nil {
			log.Printf("worker[%d] rule %d udp: %v", workerIndex, rule.ID, err)
		} else {
			binding.udpPC = pc
			ok = true
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := serveUDP(ctx, pc, &rule, st); err != nil && ctx.Err() == nil {
					log.Printf("worker[%d] rule %d udp: %v", workerIndex, rule.ID, err)
				}
			}()
		}
	}

	if !ok {
		cancel()
		if binding.tcpLn != nil {
			_ = binding.tcpLn.Close()
		}
		if binding.udpPC != nil {
			_ = binding.udpPC.Close()
		}
		close(binding.done)
		return nil, fmt.Errorf("all bindings failed")
	}

	go func() {
		defer close(binding.done)
		wg.Wait()
	}()
	return binding, nil
}

func (b *ruleBinding) Stop() {
	if b == nil {
		return
	}
	b.stopOnce.Do(func() {
		if b.cancel != nil {
			b.cancel()
		}
		if b.tcpLn != nil {
			_ = b.tcpLn.Close()
		}
		if b.udpPC != nil {
			_ = b.udpPC.Close()
		}
		if b.done != nil {
			<-b.done
		}
	})
}

func stopRuleBindings(bindings map[int64]*ruleBinding) {
	for _, binding := range bindings {
		binding.Stop()
	}
}

func snapshotRuleStatsMap(statsMap map[int64]*ruleStats) map[int64]*ruleStats {
	if len(statsMap) == 0 {
		return nil
	}
	out := make(map[int64]*ruleStats, len(statsMap))
	for id, st := range statsMap {
		out[id] = st
	}
	return out
}

func buildRuleConfigMap(rules []Rule) map[int64]Rule {
	if len(rules) == 0 {
		return nil
	}
	out := make(map[int64]Rule, len(rules))
	for _, rule := range rules {
		out[rule.ID] = rule
	}
	return out
}

func diffRuleConfigs(current map[int64]Rule, desired []Rule) (map[int64]struct{}, []Rule, []int64, map[int64]Rule) {
	desiredMap := buildRuleConfigMap(desired)
	keepIDs := make(map[int64]struct{})
	startRules := make([]Rule, 0, len(desired))
	stopIDs := make([]int64, 0)

	for id, currentRule := range current {
		nextRule, ok := desiredMap[id]
		if ok && sameUserspaceRuleConfig(currentRule, nextRule) {
			keepIDs[id] = struct{}{}
			continue
		}
		stopIDs = append(stopIDs, id)
	}

	for _, rule := range desired {
		if _, ok := keepIDs[rule.ID]; ok {
			continue
		}
		startRules = append(startRules, rule)
	}

	sort.Slice(stopIDs, func(i, j int) bool { return stopIDs[i] < stopIDs[j] })
	return keepIDs, startRules, stopIDs, desiredMap
}

func sortedRuleActiveIDs(statsMap map[int64]*ruleStats) []int64 {
	if len(statsMap) == 0 {
		return nil
	}
	activeIDs := make([]int64, 0, len(statsMap))
	for id, st := range statsMap {
		if st == nil {
			continue
		}
		if atomic.LoadInt64(&st.activeConns) > 0 || atomic.LoadInt64(&st.natTableSize) > 0 {
			activeIDs = append(activeIDs, id)
		}
	}
	sort.Slice(activeIDs, func(i, j int) bool { return activeIDs[i] < activeIDs[j] })
	return activeIDs
}

func sortedInt64SetKeys(values map[int64]struct{}) []int64 {
	if len(values) == 0 {
		return nil
	}
	out := make([]int64, 0, len(values))
	for id := range values {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// runWorker handles a worker process that can forward multiple rules.
// workerIndex identifies the logical worker slot; the master sends rule configs over the socket.
func runWorker(workerIndex int, sockPath string) {
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM)
	myHash := computeBinaryHash()

	var (
		connMu         sync.Mutex
		stateMu        sync.Mutex
		ipcConn        net.Conn
		currentStats   map[int64]*ruleStats
		currentRules   map[int64]Rule
		currentBinds   map[int64]*ruleBinding
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

	stopBindings := func(clearStats bool) {
		stateMu.Lock()
		bindings := currentBinds
		currentBinds = nil
		currentRules = nil
		if clearStats {
			currentStats = nil
		}
		stateMu.Unlock()
		stopRuleBindings(bindings)
	}

	applyRules := func(rules []Rule) {
		ids := make([]int64, 0, len(rules))
		for _, r := range rules {
			ids = append(ids, r.ID)
		}

		stateMu.Lock()
		prevStats := currentStats
		prevRules := currentRules
		prevBindings := currentBinds
		stateMu.Unlock()

		keepIDs, startList, stopIDs, nextRules := diffRuleConfigs(prevRules, rules)
		sm := reuseLiveRuleStats(prevStats, ids)
		nextBindings := make(map[int64]*ruleBinding, len(rules))
		for id := range keepIDs {
			if binding := prevBindings[id]; binding != nil {
				nextBindings[id] = binding
			}
		}
		for _, id := range stopIDs {
			if binding := prevBindings[id]; binding != nil {
				binding.Stop()
			}
		}

		nextFailed := make(map[int64]struct{})
		for _, rule := range startList {
			binding, err := startRuleBinding(workerIndex, rule, sm[rule.ID])
			if err != nil {
				nextFailed[rule.ID] = struct{}{}
				continue
			}
			nextBindings[rule.ID] = binding
		}

		stateMu.Lock()
		currentStats = sm
		currentRules = nextRules
		currentBinds = nextBindings
		stateMu.Unlock()

		if len(rules) == 0 {
			sendStatus("idle", "", nil)
			return
		}

		failedIDs := sortedInt64SetKeys(nextFailed)
		if len(nextBindings) == 0 {
			sendStatus("error", fmt.Sprintf("all %d rule bindings failed", len(rules)), failedIDs)
			return
		}
		sendStatus("running", "", failedIDs)
		if reports := buildRuleStatsReports(snapshotRuleStatsMap(sm)); len(reports) > 0 {
			sendStats(reports)
		}
	}

	go func() {
		speedTicker := time.NewTicker(1 * time.Second)
		sendTicker := time.NewTicker(2 * time.Second)
		defer speedTicker.Stop()
		defer sendTicker.Stop()
		for {
			select {
			case <-speedTicker.C:
				stateMu.Lock()
				statsSnapshot := snapshotRuleStatsMap(currentStats)
				stateMu.Unlock()
				for _, st := range statsSnapshot {
					st.updateSpeed()
				}
			case <-sendTicker.C:
				stateMu.Lock()
				statsSnapshot := snapshotRuleStatsMap(currentStats)
				stateMu.Unlock()
				reports := buildRuleStatsReports(statsSnapshot)
				if len(reports) > 0 {
					sendStats(reports)
				}
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if atomic.LoadInt32(&pendingUpgrade) == 0 {
				continue
			}
			stateMu.Lock()
			sm := snapshotRuleStatsMap(currentStats)
			stateMu.Unlock()
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
						stopBindings(false)
					}
				}
				if atomic.LoadInt32(&pendingUpgrade) != 0 {
					log.Printf("worker[%d]: pending upgrade, ignoring config update", workerIndex)
					stateMu.Lock()
					activeIDs := sortedRuleActiveIDs(currentStats)
					stateMu.Unlock()
					sendIPC(IPCMessage{Type: "status", Status: "draining", ActiveRuleIDs: activeIDs})
					continue
				}
				if len(msg.Rules) == 0 {
					stopBindings(true)
					sendStatus("idle", "", nil)
					continue
				}
				applyRules(msg.Rules)
			case "stop":
				stopBindings(true)
				return
			}
		}

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
		udpPC *net.UDPConn
		stats *ruleStats
	}

	var listeners []ruleListeners
	failed := 0
	var failedRuleIDs []int64
	for _, rule := range rules {
		r := rule
		var tcpLn net.Listener
		var udpPC *net.UDPConn
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
	if reports := buildRuleStatsReports(statsMap); len(reports) > 0 {
		sendStats(reports)
	}

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
				reports := buildRuleStatsReports(statsMap)
				if len(reports) == 0 {
					continue
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
		go handleTCPConn(ctx, src, target, rule.OutInterface, rule.OutSourceIP, rule.Transparent, st)
	}
}
func handleTCPConn(ctx context.Context, src net.Conn, target, outIface, outSourceIP string, transparent bool, st *ruleStats) {
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
		if err := configureOutboundTCPDialer(&dialer, outIface, outSourceIP); err != nil {
			if st != nil {
				atomic.AddInt64(&st.rejectedConns, 1)
			}
			log.Printf("tcp dial %s: %v", target, err)
			return
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

	proxyTCPBidirectional(dst, src, src, inCounter, outCounter)
}

func listenUDP(ctx context.Context, rule *Rule) (*net.UDPConn, error) {
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
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("udp listen %s returned unsupported packet conn %T", addr, pc)
	}
	if err := enableUDPReplyPacketInfo(udpConn); err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("udp listen %s enable packet info: %w", addr, err)
	}
	return udpConn, nil
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

func serveUDP(ctx context.Context, pc *net.UDPConn, rule *Rule, st *ruleStats) error {
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
	oobBuf := make([]byte, udpReplyPacketInfoBufferSize())
	for {
		n, srcAddr, replyInfo, err := readUDPWithReplyInfo(pc, buf, oobBuf)
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

		key := udpReplyKey(srcAddr, replyInfo)
		mu.Lock()
		entry, exists := natTable[key]
		if !exists {
			var outConn *net.UDPConn
			if rule.Transparent {
				outConn, err = dialTransparentUDP(srcAddr.IP, rule.OutInterface, targetAddr)
			} else {
				outConn, err = dialOutboundUDP(targetAddr, rule.OutInterface, rule.OutSourceIP)
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

			go func(src *net.UDPAddr, reply udpReplyInfo, out *net.UDPConn, natKey string) {
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
					if _, err := writeUDPWithReplyInfo(pc, retBuf[:rn], src, reply); err != nil {
						log.Printf("rule %d: udp reply write: %v", rule.ID, err)
						mu.Lock()
						removeEntryLocked(natKey)
						mu.Unlock()
						return
					}
					mu.Lock()
					if e, ok := natTable[natKey]; ok {
						e.lastActive = time.Now()
					}
					mu.Unlock()
				}
			}(srcAddr, replyInfo, outConn, key)
		}
		entry.lastActive = now
		mu.Unlock()

		if _, err := entry.conn.Write(buf[:n]); err != nil {
			if st != nil {
				atomic.AddInt64(&st.rejectedConns, 1)
			}
			log.Printf("rule %d: udp backend write: %v", rule.ID, err)
			mu.Lock()
			removeEntryLocked(key)
			mu.Unlock()
		}
	}
}
