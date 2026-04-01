package app

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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

type rangeBinding struct {
	pr       PortRange
	cancel   context.CancelFunc
	closeSet *closerSet
	done     chan struct{}
	stopOnce sync.Once
}

func startRangeBinding(workerIndex int, pr PortRange, st *ruleStats) (*rangeBinding, error) {
	ctx, cancel := context.WithCancel(context.Background())
	closeSet := &closerSet{}
	bound, failed, wg := startRangeForwarder(ctx, &pr, st, closeSet)
	if bound == 0 {
		cancel()
		closeSet.CloseAll()
		wg.Wait()
		return nil, fmt.Errorf("all %d port bindings failed", failed)
	}
	if failed > 0 {
		log.Printf("range worker[%d] range %d: %d/%d ports bound, %d failed", workerIndex, pr.ID, bound, bound+failed, failed)
	}

	binding := &rangeBinding{
		pr:       pr,
		cancel:   cancel,
		closeSet: closeSet,
		done:     make(chan struct{}),
	}
	go func() {
		defer close(binding.done)
		wg.Wait()
	}()
	return binding, nil
}

func (b *rangeBinding) Stop() {
	if b == nil {
		return
	}
	b.stopOnce.Do(func() {
		if b.cancel != nil {
			b.cancel()
		}
		if b.closeSet != nil {
			b.closeSet.CloseAll()
		}
		if b.done != nil {
			<-b.done
		}
	})
}

func stopRangeBindings(bindings map[int64]*rangeBinding) {
	for _, binding := range bindings {
		binding.Stop()
	}
}

func buildRangeConfigMap(ranges []PortRange) map[int64]PortRange {
	if len(ranges) == 0 {
		return nil
	}
	out := make(map[int64]PortRange, len(ranges))
	for _, pr := range ranges {
		out[pr.ID] = pr
	}
	return out
}

func diffRangeConfigs(current map[int64]PortRange, desired []PortRange) (map[int64]struct{}, []PortRange, []int64, map[int64]PortRange) {
	desiredMap := buildRangeConfigMap(desired)
	keepIDs := make(map[int64]struct{})
	startRanges := make([]PortRange, 0, len(desired))
	stopIDs := make([]int64, 0)

	for id, currentRange := range current {
		nextRange, ok := desiredMap[id]
		if ok && sameUserspaceRangeConfig(currentRange, nextRange) {
			keepIDs[id] = struct{}{}
			continue
		}
		stopIDs = append(stopIDs, id)
	}

	for _, pr := range desired {
		if _, ok := keepIDs[pr.ID]; ok {
			continue
		}
		startRanges = append(startRanges, pr)
	}

	sort.Slice(stopIDs, func(i, j int) bool { return stopIDs[i] < stopIDs[j] })
	return keepIDs, startRanges, stopIDs, desiredMap
}

// runRangeWorker handles a worker process that can forward multiple port ranges.
func runRangeWorker(workerIndex int, sockPath string) {
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM)
	myHash := computeBinaryHash()

	var (
		connMu         sync.Mutex
		stateMu        sync.Mutex
		ipcConn        net.Conn
		currentStats   map[int64]*ruleStats
		currentRanges  map[int64]PortRange
		currentBinds   map[int64]*rangeBinding
		pendingUpgrade int32
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
		sendIPC(IPCMessage{Type: "status", Status: status, Error: errMsg, FailedRangeIDs: failedIDs})
	}

	sendStats := func(stats []RangeStatsReport) {
		sendIPC(IPCMessage{Type: "range_stats", RangeStats: stats})
	}

	stopBindings := func(clearStats bool) {
		stateMu.Lock()
		bindings := currentBinds
		currentBinds = nil
		currentRanges = nil
		if clearStats {
			currentStats = nil
		}
		stateMu.Unlock()
		stopRangeBindings(bindings)
	}

	applyRanges := func(ranges []PortRange) {
		ids := make([]int64, 0, len(ranges))
		for _, pr := range ranges {
			ids = append(ids, pr.ID)
		}

		stateMu.Lock()
		prevStats := currentStats
		prevRanges := currentRanges
		prevBindings := currentBinds
		stateMu.Unlock()

		keepIDs, startList, stopIDs, nextRanges := diffRangeConfigs(prevRanges, ranges)
		sm := reuseLiveRuleStats(prevStats, ids)
		nextBindings := make(map[int64]*rangeBinding, len(ranges))
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
		for _, pr := range startList {
			binding, err := startRangeBinding(workerIndex, pr, sm[pr.ID])
			if err != nil {
				nextFailed[pr.ID] = struct{}{}
				continue
			}
			nextBindings[pr.ID] = binding
		}

		stateMu.Lock()
		currentStats = sm
		currentRanges = nextRanges
		currentBinds = nextBindings
		stateMu.Unlock()

		if len(ranges) == 0 {
			sendStatus("idle", "", nil)
			return
		}

		failedIDs := sortedInt64SetKeys(nextFailed)
		if len(nextBindings) == 0 {
			sendStatus("error", fmt.Sprintf("all %d port range bindings failed", len(ranges)), failedIDs)
			return
		}
		sendStatus("running", "", failedIDs)
		if reports := buildRangeStatsReports(snapshotRuleStatsMap(sm)); len(reports) > 0 {
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
				reports := buildRangeStatsReports(statsSnapshot)
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
				log.Printf("range worker[%d]: binary upgraded, no ranges, exiting", workerIndex)
				os.Exit(0)
			}
			total := int64(0)
			for _, st := range sm {
				total += atomic.LoadInt64(&st.activeConns) + atomic.LoadInt64(&st.natTableSize)
			}
			if total == 0 {
				log.Printf("range worker[%d]: binary upgraded and connections drained, exiting", workerIndex)
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

		regMsg := IPCMessage{Type: "register_range", WorkerIndex: workerIndex, BinaryHash: myHash}
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
			case "range_config":
				if msg.BinaryHash != "" && msg.BinaryHash != myHash {
					if atomic.CompareAndSwapInt32(&pendingUpgrade, 0, 1) {
						log.Printf("range worker[%d]: binary update detected, closing listeners for new worker", workerIndex)
						stopBindings(false)
					}
				}
				if atomic.LoadInt32(&pendingUpgrade) != 0 {
					log.Printf("range worker[%d]: pending upgrade, ignoring config update", workerIndex)
					stateMu.Lock()
					activeIDs := sortedRuleActiveIDs(currentStats)
					stateMu.Unlock()
					sendIPC(IPCMessage{Type: "status", Status: "draining", ActiveRangeIDs: activeIDs})
					continue
				}
				if len(msg.PortRanges) == 0 {
					stopBindings(true)
					sendStatus("idle", "", nil)
					continue
				}
				applyRanges(msg.PortRanges)
			case "stop":
				stopBindings(true)
				return
			}
		}

		connMu.Lock()
		ipcConn = nil
		connMu.Unlock()
		conn.Close()
		log.Printf("range worker[%d]: disconnected from master, reconnecting...", workerIndex)
		time.Sleep(2 * time.Second)
	}
}

func runRangeForwarder(ctx context.Context, workerIndex int, ranges []PortRange, statsMap map[int64]*ruleStats, sendStatus func(string, string, []int64), sendStats func([]RangeStatsReport)) {
	totalBound := 0
	totalFailed := 0
	var allWg sync.WaitGroup
	var failedRangeIDs []int64

	closeSet := &closerSet{}
	closeDone := make(chan struct{})
	defer close(closeDone)
	go func() {
		select {
		case <-ctx.Done():
			closeSet.CloseAll()
		case <-closeDone:
		}
	}()

	for i := range ranges {
		pr := &ranges[i]
		st := statsMap[pr.ID]
		bound, failed, wg := startRangeForwarder(ctx, pr, st, closeSet)
		totalBound += bound
		totalFailed += failed
		if bound == 0 {
			failedRangeIDs = append(failedRangeIDs, pr.ID)
		}
		allWg.Add(1)
		go func() {
			defer allWg.Done()
			wg.Wait()
		}()
	}

	if totalBound == 0 {
		sendStatus("error", fmt.Sprintf("all %d port bindings failed", totalFailed), failedRangeIDs)
		log.Printf("range worker[%d]: all %d port bindings failed", workerIndex, totalFailed)
		return
	}

	if totalFailed > 0 {
		log.Printf("range worker[%d]: %d/%d ports bound, %d failed", workerIndex, totalBound, totalBound+totalFailed, totalFailed)
	}

	sendStatus("running", "", failedRangeIDs)
	if reports := buildRangeStatsReports(statsMap); len(reports) > 0 {
		sendStats(reports)
	}

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
				reports := buildRangeStatsReports(statsMap)
				if len(reports) == 0 {
					continue
				}
				sendStats(reports)
			}
		}
	}()

	allWg.Wait()
}

// startRangeForwarder binds all ports in the range, counts successes/failures,
// and returns the counts plus a WaitGroup that completes when all serve goroutines exit.
func startRangeForwarder(ctx context.Context, pr *PortRange, st *ruleStats, closeSet *closerSet) (bound int, failed int, wg *sync.WaitGroup) {
	wg = &sync.WaitGroup{}

	ports := pr.EndPort - pr.StartPort + 1
	perPort := 0
	if pr.Protocol == "tcp" || pr.Protocol == "tcp+udp" {
		perPort++
	}
	if pr.Protocol == "udp" || pr.Protocol == "tcp+udp" {
		perPort++
	}
	totalBinds := ports * perPort
	if totalBinds == 0 {
		return 0, 0, wg
	}

	bindCh := make(chan error, totalBinds)
	for port := pr.StartPort; port <= pr.EndPort; port++ {
		p := port
		if pr.Protocol == "tcp" || pr.Protocol == "tcp+udp" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				runRangeTCPPort(ctx, pr, p, bindCh, st, closeSet)
			}()
		}
		if pr.Protocol == "udp" || pr.Protocol == "tcp+udp" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				runRangeUDPPort(ctx, pr, p, bindCh, st, closeSet)
			}()
		}
	}

	for i := 0; i < totalBinds; i++ {
		if err := <-bindCh; err != nil {
			failed++
		} else {
			bound++
		}
	}

	return bound, failed, wg
}
func runRangeTCPPort(ctx context.Context, pr *PortRange, port int, bindCh chan<- error, st *ruleStats, closeSet *closerSet) {
	lc := net.ListenConfig{}
	ctrl := controlBindToDevice(pr.InInterface)
	if ctrl != nil {
		lc.Control = ctrl
	}

	addr := net.JoinHostPort(pr.InIP, strconv.Itoa(port))
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		err = fmt.Errorf("tcp listen %s: %w", addr, err)
		log.Printf("range %d: %v", pr.ID, err)
		bindCh <- err
		return
	}
	if !closeSet.Add(ln) {
		bindCh <- context.Canceled
		return
	}
	bindCh <- nil
	defer ln.Close()

	outPort := port - pr.StartPort + pr.OutStartPort
	target := net.JoinHostPort(pr.OutIP, strconv.Itoa(outPort))

	for {
		src, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("range %d: tcp accept port %d: %v", pr.ID, port, err)
			return
		}
		go handleTCPConn(ctx, src, target, pr.OutInterface, pr.OutSourceIP, pr.Transparent, st)
	}
}
func runRangeUDPPort(ctx context.Context, pr *PortRange, port int, bindCh chan<- error, st *ruleStats, closeSet *closerSet) {
	lc := net.ListenConfig{}
	ctrl := controlBindToDevice(pr.InInterface)
	if ctrl != nil {
		lc.Control = ctrl
	}

	addr := net.JoinHostPort(pr.InIP, strconv.Itoa(port))
	pc, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		err = fmt.Errorf("udp listen %s: %w", addr, err)
		log.Printf("range %d: %v", pr.ID, err)
		bindCh <- err
		return
	}
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		err = fmt.Errorf("udp listen %s returned unsupported packet conn %T", addr, pc)
		log.Printf("range %d: %v", pr.ID, err)
		bindCh <- err
		return
	}
	if err := enableUDPReplyPacketInfo(udpConn); err != nil {
		udpConn.Close()
		err = fmt.Errorf("udp listen %s enable packet info: %w", addr, err)
		log.Printf("range %d: %v", pr.ID, err)
		bindCh <- err
		return
	}
	if !closeSet.Add(udpConn) {
		bindCh <- context.Canceled
		return
	}
	bindCh <- nil
	defer udpConn.Close()

	outPort := port - pr.StartPort + pr.OutStartPort
	targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(pr.OutIP, strconv.Itoa(outPort)))
	if err != nil {
		log.Printf("range %d: udp resolve port %d: %v", pr.ID, port, err)
		return
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
	if err := udpConn.SetReadDeadline(nextCleanup); err != nil {
		log.Printf("range %d: udp deadline port %d: %v", pr.ID, port, err)
		return
	}

	buf := make([]byte, 65535)
	oobBuf := make([]byte, udpReplyPacketInfoBufferSize())
	for {
		n, srcAddr, replyInfo, err := readUDPWithReplyInfo(udpConn, buf, oobBuf)
		now := time.Now()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return
				}
				cleanupStaleEntries(now)
				nextCleanup = now.Add(udpCleanupInterval)
				if err := udpConn.SetReadDeadline(nextCleanup); err != nil {
					log.Printf("range %d: udp deadline port %d: %v", pr.ID, port, err)
					return
				}
				continue
			}
			if ctx.Err() != nil {
				return
			}
			log.Printf("range %d: udp read port %d: %v", pr.ID, port, err)
			return
		}
		if !now.Before(nextCleanup) {
			cleanupStaleEntries(now)
			nextCleanup = now.Add(udpCleanupInterval)
			if err := udpConn.SetReadDeadline(nextCleanup); err != nil {
				log.Printf("range %d: udp deadline port %d: %v", pr.ID, port, err)
				return
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
			if pr.Transparent {
				outConn, err = dialTransparentUDP(srcAddr.IP, pr.OutInterface, targetAddr)
			} else {
				outConn, err = dialOutboundUDP(targetAddr, pr.OutInterface, pr.OutSourceIP)
			}
			if err != nil {
				mu.Unlock()
				if st != nil {
					atomic.AddInt64(&st.rejectedConns, 1)
				}
				log.Printf("range %d: udp dial port %d: %v", pr.ID, port, err)
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
					if _, err := writeUDPWithReplyInfo(udpConn, retBuf[:rn], src, reply); err != nil {
						log.Printf("range %d: udp reply write port %d: %v", pr.ID, port, err)
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

		entry.conn.Write(buf[:n])
	}
}
