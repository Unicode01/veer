package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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

// runRangeWorker handles a worker process that can forward multiple port ranges.
func runRangeWorker(workerIndex int, sockPath string) {
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM)
	myHash := computeBinaryHash()

	var (
		connMu         sync.Mutex
		ipcConn        net.Conn
		currentCancel  context.CancelFunc
		currentDone    chan struct{}
		currentStats   map[int64]*ruleStats
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

	startRanges := func(ranges []PortRange) {
		if currentCancel != nil {
			currentCancel()
			<-currentDone
		}
		sm := make(map[int64]*ruleStats, len(ranges))
		for _, pr := range ranges {
			sm[pr.ID] = &ruleStats{}
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
			runRangeForwarder(ctx, workerIndex, ranges, sm, sendStatus, sendStats)
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
						if currentCancel != nil {
							currentCancel()
							<-currentDone
							currentCancel = nil
							currentDone = nil
						}
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
									reports := make([]RangeStatsReport, 0, len(sm))
									for id, st := range sm {
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
									sendStats(reports)
								}
							}
						}()
					}
				}
				if atomic.LoadInt32(&pendingUpgrade) != 0 {
					log.Printf("range worker[%d]: pending upgrade, ignoring config update", workerIndex)
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
					sendIPC(IPCMessage{Type: "status", Status: "draining", ActiveRangeIDs: activeIDs})
					continue
				}
				if len(msg.PortRanges) == 0 {
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
				log.Printf("range worker[%d]: received %d range(s)", workerIndex, len(msg.PortRanges))
				startRanges(msg.PortRanges)
			case "stop":
				log.Printf("range worker[%d]: received stop", workerIndex)
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
		log.Printf("range worker[%d]: range %d: %s:[%d-%d] -> %s:[%d-%d] [%s]",
			workerIndex, pr.ID, pr.InIP, pr.StartPort, pr.EndPort,
			pr.OutIP, pr.OutStartPort, pr.OutStartPort+(pr.EndPort-pr.StartPort), pr.Protocol)

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
		go handleTCPConn(ctx, src, target, pr.OutInterface, pr.Transparent, st)
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
	if !closeSet.Add(pc) {
		bindCh <- context.Canceled
		return
	}
	bindCh <- nil
	defer pc.Close()

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
	if err := pc.SetReadDeadline(nextCleanup); err != nil {
		log.Printf("range %d: udp deadline port %d: %v", pr.ID, port, err)
		return
	}

	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := pc.ReadFrom(buf)
		now := time.Now()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return
				}
				cleanupStaleEntries(now)
				nextCleanup = now.Add(udpCleanupInterval)
				if err := pc.SetReadDeadline(nextCleanup); err != nil {
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
			if err := pc.SetReadDeadline(nextCleanup); err != nil {
				log.Printf("range %d: udp deadline port %d: %v", pr.ID, port, err)
				return
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
			if pr.Transparent {
				srcUDP := srcAddr.(*net.UDPAddr)
				outConn, err = dialTransparentUDP(srcUDP.IP, pr.OutInterface, targetAddr)
			} else {
				outConn, err = dialOutboundUDP(targetAddr, pr.OutInterface)
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
