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
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type rangeBinding struct {
	pr    PortRange
	group *userspaceBindingGroup
}

func startRangeBinding(workerIndex int, pr PortRange, st *ruleStats) (*rangeBinding, error) {
	binding, _, err := startRangeBindingWithDegradedState(workerIndex, pr, st)
	return binding, err
}

func startRangeBindingWithDegradedState(workerIndex int, pr PortRange, st *ruleStats) (*rangeBinding, error, error) {
	if msg := validatePortRangePorts(pr); msg != "" {
		return nil, nil, fmt.Errorf("invalid port range: %s", msg)
	}
	protocols := userspaceRuleProtocols(Rule{Protocol: pr.Protocol})
	count := (pr.EndPort - pr.StartPort + 1) * len(protocols)
	if int64(count) > userspaceListenerBudget.limit {
		return nil, nil, fmt.Errorf("userspace listener budget exceeded: requested %d, process limit %d; use the kernel dataplane or a smaller range", count, userspaceListenerBudget.limit)
	}
	rules := make([]Rule, 0, count)
	for port := pr.StartPort; port <= pr.EndPort; port++ {
		for _, protocol := range protocols {
			rules = append(rules, Rule{ID: pr.ID, InInterface: pr.InInterface, InIP: pr.InIP, InPort: port,
				OutInterface: pr.OutInterface, OutIP: pr.OutIP, OutPort: pr.OutStartPort + port - pr.StartPort,
				OutSourceIP: pr.OutSourceIP, Transparent: pr.Transparent, Protocol: protocol.Protocol})
		}
	}
	group, err := newUserspaceBindingGroup(rules, st)
	if err != nil {
		return nil, nil, err
	}
	bound, degraded := group.Status()
	if bound == 0 {
		group.Stop()
		return nil, nil, degraded
	}
	return &rangeBinding{pr: pr, group: group}, degraded, nil
}

func (b *rangeBinding) Stop() {
	if b != nil {
		b.group.Stop()
	}
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
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	myHash := computeBinaryHash()

	var (
		connMu            sync.Mutex
		writeMu           sync.Mutex
		stateMu           sync.Mutex
		ipcConn           net.Conn
		currentStats      map[int64]*ruleStats
		currentRanges     map[int64]PortRange
		currentBinds      map[int64]*rangeBinding
		currentGeneration uint64
		pendingUpgrade    int32
	)

	sendIPC := func(msg IPCMessage) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		connMu.Lock()
		c := ipcConn
		connMu.Unlock()
		if c == nil {
			return net.ErrClosed
		}
		if err := writeIPC(c, msg); err != nil {
			_ = c.Close()
			return err
		}
		return nil
	}

	sendStatus := func(generation uint64, status, errMsg string, failedIDs []int64, rangeErrors map[int64]string) {
		_ = sendIPC(IPCMessage{Type: "status", Generation: generation, Status: status, Error: errMsg, FailedRangeIDs: failedIDs, RangeErrors: rangeErrors})
	}

	sendStats := func(stats []RangeStatsReport) {
		_ = sendIPC(IPCMessage{Type: "range_stats", RangeStats: stats})
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

	go func() {
		<-ctx.Done()
		connMu.Lock()
		conn := ipcConn
		ipcConn = nil
		connMu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		stopBindings(true)
	}()

	applyRanges := func(generation uint64, ranges []PortRange) {
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
		startList, stopIDs = retryUnavailableRangeBindings(keepIDs, startList, stopIDs, ranges, prevBindings)
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
		rangeErrors := make(map[int64]string)
		for _, pr := range startList {
			binding, degradedErr, err := startRangeBindingWithDegradedState(workerIndex, pr, sm[pr.ID])
			if err != nil {
				nextFailed[pr.ID] = struct{}{}
				rangeErrors[pr.ID] = err.Error()
				continue
			}
			nextBindings[pr.ID] = binding
			if degradedErr != nil {
				nextFailed[pr.ID] = struct{}{}
				rangeErrors[pr.ID] = degradedErr.Error()
			}
		}

		stateMu.Lock()
		currentStats = sm
		currentRanges = nextRanges
		currentBinds = nextBindings
		currentGeneration = generation
		stateMu.Unlock()

		if len(ranges) == 0 {
			sendStatus(generation, "idle", "", nil, nil)
			return
		}

		for id, binding := range nextBindings {
			if _, err := binding.group.Status(); err != nil {
				nextFailed[id] = struct{}{}
				rangeErrors[id] = err.Error()
			}
		}
		failedIDs := sortedInt64SetKeys(nextFailed)
		if len(nextBindings) == 0 {
			sendStatus(generation, "error", fmt.Sprintf("all %d port range bindings failed", len(ranges)), failedIDs, rangeErrors)
			return
		}
		sendStatus(generation, "running", "", failedIDs, rangeErrors)
		if reports := buildRangeStatsReports(snapshotRuleStatsMap(sm)); len(reports) > 0 {
			sendStats(reports)
		}
	}

	go func() {
		speedTimer := time.NewTimer(workerStatsIdleUpdateInterval)
		sendTimer := time.NewTimer(workerStatsIdleSendInterval)
		defer stopTimer(speedTimer)
		defer stopTimer(sendTimer)
		for {
			select {
			case <-ctx.Done():
				return
			case <-speedTimer.C:
				stateMu.Lock()
				statsSnapshot := snapshotRuleStatsMap(currentStats)
				active := ruleStatsMapHasActivity(currentStats)
				stateMu.Unlock()
				for _, st := range statsSnapshot {
					st.updateSpeed()
				}
				speedTimer.Reset(statsUpdateInterval(active))
			case <-sendTimer.C:
				stateMu.Lock()
				statsSnapshot := snapshotRuleStatsMap(currentStats)
				active := ruleStatsMapHasActivity(currentStats)
				generation := currentGeneration
				failures := make(map[int64]struct{})
				bindingErrors := make(map[int64]string)
				for id := range currentRanges {
					var group *userspaceBindingGroup
					if b := currentBinds[id]; b != nil {
						group = b.group
					}
					if _, err := group.Status(); err != nil {
						failures[id] = struct{}{}
						bindingErrors[id] = err.Error()
					}
				}
				hasRanges := len(currentRanges) > 0
				stateMu.Unlock()
				connMu.Lock()
				hasIPC := ipcConn != nil
				connMu.Unlock()
				if hasIPC {
					if hasRanges && atomic.LoadInt32(&pendingUpgrade) == 0 {
						sendStatus(generation, "running", "", sortedInt64SetKeys(failures), bindingErrors)
					}
					reports := buildRangeStatsReports(statsSnapshot)
					if len(reports) > 0 {
						sendStats(reports)
					}
				}
				sendTimer.Reset(statsSendInterval(active))
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
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
		if ctx.Err() != nil {
			stopBindings(true)
			return
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
		if err != nil {
			if ctx.Err() != nil {
				stopBindings(true)
				return
			}
			select {
			case <-ctx.Done():
				stopBindings(true)
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}

		if err := registerIPCConnection(conn, IPCMessage{Type: "register_range", WorkerIndex: workerIndex, BinaryHash: myHash}, &connMu, &ipcConn); err != nil {
			_ = conn.Close()
			continue
		}

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
					_ = sendIPC(IPCMessage{Type: "status", Generation: msg.Generation, Status: "draining", ActiveRangeIDs: activeIDs})
					continue
				}
				if len(msg.PortRanges) == 0 {
					stopBindings(true)
					sendStatus(msg.Generation, "idle", "", nil, nil)
					continue
				}
				applyRanges(msg.Generation, msg.PortRanges)
			case "stop":
				stopBindings(true)
				return
			}
		}

		connMu.Lock()
		ipcConn = nil
		connMu.Unlock()
		conn.Close()
		if ctx.Err() != nil {
			stopBindings(true)
			return
		}
		log.Printf("range worker[%d]: disconnected from master, reconnecting...", workerIndex)
		select {
		case <-ctx.Done():
			stopBindings(true)
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func retryUnavailableRangeBindings(keepIDs map[int64]struct{}, startList []PortRange, stopIDs []int64, desired []PortRange, bindings map[int64]*rangeBinding) ([]PortRange, []int64) {
	for _, pr := range desired {
		if _, keep := keepIDs[pr.ID]; !keep {
			continue
		}
		binding := bindings[pr.ID]
		if binding != nil && binding.group != nil {
			binding.group.Repair()
			continue
		}
		delete(keepIDs, pr.ID)
		startList = append(startList, pr)
		if binding != nil {
			stopIDs = append(stopIDs, pr.ID)
		}
	}
	return startList, stopIDs
}
