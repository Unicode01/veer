//go:build linux

package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	egressNATSoakEnableEnv   = "FORWARD_RUN_EGRESS_NAT_SOAK"
	egressNATSoakSecondsEnv  = "FORWARD_EGRESS_NAT_SOAK_SECONDS"
	egressNATSoakHelperEnv   = "FORWARD_EGRESS_NAT_SOAK_HELPER"
	egressNATSoakRoleEnv     = "FORWARD_EGRESS_NAT_SOAK_ROLE"
	egressNATSoakListenEnv   = "FORWARD_EGRESS_NAT_SOAK_LISTEN"
	egressNATSoakPlanEnv     = "FORWARD_EGRESS_NAT_SOAK_PLAN"
	egressNATSoakDeadlineEnv = "FORWARD_EGRESS_NAT_SOAK_DEADLINE"
	egressNATSoakPort        = 24101
	// A connection that waits longer than this for its echo counts as broken.
	egressNATSoakStall = 5 * time.Second
)

// egressNATSoakConn is one long-lived connection a soak client keeps up.
type egressNATSoakConn struct {
	Label   string `json:"label"`
	Proto   string `json:"proto"`   // tcp or udp
	Pattern string `json:"pattern"` // stream, chat or idle
	Target  string `json:"target"`
	GapSecs int    `json:"gap_secs,omitempty"`
}

type egressNATSoakResult struct {
	Label      string  `json:"label"`
	OK         bool    `json:"ok"`
	Error      string  `json:"error,omitempty"`
	Exchanges  int     `json:"exchanges"`
	Bytes      int64   `json:"bytes"`
	MaxRTTms   float64 `json:"max_rtt_ms"`
	Retries    int     `json:"retries,omitempty"`
	SeenSource string  `json:"seen_source,omitempty"`
}

// TestEgressNATLongConnectionSoak keeps long TCP and UDP connections up
// through egress NAT for a while (FORWARD_EGRESS_NAT_SOAK_SECONDS, default
// 900) with the flow cache and traffic stats on, across two hot restarts and
// a change of rules and local networks in between: streams, a message every
// second, and connections idle for minutes, by the default exit, by a child
// override to another exit, routed between bridges and within one. Every
// connection must keep its echo flowing with no stall over 5 s, and every UDP
// flow must keep its NAT mapping.
func TestEgressNATLongConnectionSoak(t *testing.T) {
	if os.Getenv(egressNATSoakEnableEnv) != "1" {
		t.Skipf("set %s=1 to run the egress NAT long connection soak", egressNATSoakEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	duration := time.Duration(envInt(egressNATSoakSecondsEnv, 900)) * time.Second

	h := startEgressNATIntegrationHarness(t, "soak")
	top := h.Topology
	suffix := strconv.Itoa(os.Getpid() % 100000)
	nsB, nsC, nsV := "skb"+suffix, "skc"+suffix, "skv"+suffix
	tapB, peerB := truncateIfName("skpb"+suffix), truncateIfName("sknb"+suffix)
	br2, tapC, peerC := truncateIfName("skbr"+suffix), truncateIfName("skpc"+suffix), truncateIfName("sknc"+suffix)
	exitV, peerV := truncateIfName("skvx"+suffix), truncateIfName("skvn"+suffix)
	extra := truncateIfName("skdm" + suffix)
	const (
		addrA     = egressNATClientAddr
		addrB     = "198.18.0.3"
		br2Addr   = "198.21.0.1"
		addrC     = "198.21.0.2"
		exitVAddr = "198.20.0.1"
		addrV     = "198.20.0.2"
	)
	cleanupLateralLinks(t, []string{tapB, tapC, exitV, br2, extra}, []string{nsB, nsC, nsV})
	addLateralGuest(t, nsB, tapB, peerB, top.BridgeIF, addrB, egressNATBridgeAddr)
	mustRunDataplanePerfCmd(t, "ip", "link", "add", br2, "type", "bridge")
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", br2Addr+"/24", "dev", br2)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", br2, "up")
	addLateralGuest(t, nsC, tapC, peerC, br2, addrC, br2Addr)
	addLateralGuest(t, nsV, exitV, peerV, "", addrV, exitVAddr)
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", exitVAddr+"/24", "dev", exitV)

	createEgressNATIntegrationEntryForScopeWithOptions(t, h.APIBase, top, "", "tcp+udp+icmp", egressNATTypeFullCone)
	postLateralEgressNAT(t, h.APIBase, `{"parent_interface":"`+top.BridgeIF+`","child_interface":"`+tapB+`","out_interface":"`+exitV+`","out_source_ip":"`+exitVAddr+`","protocol":"tcp+udp","nat_type":"full_cone"}`)
	postLateralEgressNAT(t, h.APIBase, `{"parent_interface":"`+br2+`","out_interface":"`+top.UplinkHostIF+`","out_source_ip":"`+egressNATUplinkAddr+`","protocol":"tcp+udp+icmp","nat_type":"full_cone"}`)
	waitForLateralEgressNATs(t, h.APIBase, h.LogPath, 3, kernelEngineTC)

	for _, server := range []struct{ ns, addr string }{
		{top.BackendNS, egressNATBackendAddr}, {nsV, addrV}, {nsC, addrC}, {nsB, addrB},
	} {
		startEgressNATSoakServer(t, server.ns, net.JoinHostPort(server.addr, strconv.Itoa(egressNATSoakPort)))
	}
	at := func(addr string) string { return net.JoinHostPort(addr, strconv.Itoa(egressNATSoakPort)) }
	plans := map[string][]egressNATSoakConn{
		top.ClientNS: {
			{Label: "A_uplink_tcp_stream", Proto: "tcp", Pattern: "stream", Target: at(egressNATBackendAddr)},
			{Label: "A_uplink_tcp_chat", Proto: "tcp", Pattern: "chat", Target: at(egressNATBackendAddr)},
			{Label: "A_uplink_tcp_idle70", Proto: "tcp", Pattern: "idle", Target: at(egressNATBackendAddr), GapSecs: 70},
			{Label: "A_uplink_tcp_idle250", Proto: "tcp", Pattern: "idle", Target: at(egressNATBackendAddr), GapSecs: 250},
			{Label: "A_uplink_udp_chat", Proto: "udp", Pattern: "chat", Target: at(egressNATBackendAddr)},
			{Label: "A_uplink_udp_idle120", Proto: "udp", Pattern: "idle", Target: at(egressNATBackendAddr), GapSecs: 120},
			{Label: "A_otherbridge_tcp_chat", Proto: "tcp", Pattern: "chat", Target: at(addrC)},
			{Label: "A_otherbridge_tcp_stream", Proto: "tcp", Pattern: "stream", Target: at(addrC)},
			{Label: "A_samebridge_tcp_chat", Proto: "tcp", Pattern: "chat", Target: at(addrB)},
		},
		nsB: {
			{Label: "B_exit_tcp_stream", Proto: "tcp", Pattern: "stream", Target: at(addrV)},
			{Label: "B_exit_tcp_chat", Proto: "tcp", Pattern: "chat", Target: at(addrV)},
			{Label: "B_exit_tcp_idle250", Proto: "tcp", Pattern: "idle", Target: at(addrV), GapSecs: 250},
			{Label: "B_exit_udp_chat", Proto: "udp", Pattern: "chat", Target: at(addrV)},
			{Label: "B_otherbridge_udp_chat", Proto: "udp", Pattern: "chat", Target: at(addrC)},
		},
		nsC: {
			{Label: "C_uplink_tcp_chat", Proto: "tcp", Pattern: "chat", Target: at(egressNATBackendAddr)},
			{Label: "C_uplink_udp_chat", Proto: "udp", Pattern: "chat", Target: at(egressNATBackendAddr)},
		},
	}
	deadline := time.Now().Add(duration)
	type clientRun struct {
		ns     string
		cmd    *exec.Cmd
		stdout bytes.Buffer
		stderr bytes.Buffer
		done   chan error
	}
	var clients []*clientRun
	for ns, plan := range plans {
		data, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		run := &clientRun{ns: ns, done: make(chan error, 1)}
		run.cmd = exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run", "^TestEgressNATSoakHelperProcess$", "-test.v=false")
		run.cmd.Env = append(os.Environ(),
			egressNATSoakHelperEnv+"=1",
			egressNATSoakRoleEnv+"=client",
			egressNATSoakPlanEnv+"="+string(data),
			egressNATSoakDeadlineEnv+"="+strconv.FormatInt(deadline.UnixNano(), 10),
		)
		run.cmd.Stdout = &run.stdout
		run.cmd.Stderr = &run.stderr
		if err := run.cmd.Start(); err != nil {
			t.Fatalf("start soak client in %s: %v", ns, err)
		}
		go func() { run.done <- run.cmd.Wait() }()
		clients = append(clients, run)
	}
	t.Cleanup(func() {
		for _, run := range clients {
			if run.cmd.ProcessState == nil && run.cmd.Process != nil {
				_ = run.cmd.Process.Kill()
			}
		}
	})

	start := time.Now()
	sleepUntil := func(at time.Duration) {
		if wait := time.Until(start.Add(at)); wait > 0 {
			time.Sleep(wait)
		}
	}
	nats := 3
	hotRestart := func(label string) {
		t.Logf("%s: hot restart at %s", label, time.Since(start).Round(time.Second))
		if err := os.WriteFile(h.HotRestartMarkerPath, []byte("1"), 0o644); err != nil {
			t.Fatalf("write hot restart marker: %v", err)
		}
		restartManagedNetworkIntegrationForward(t, &h)
		waitForLateralEgressNATs(t, h.APIBase, h.LogPath, nats, kernelEngineTC)
		t.Logf("%s: back up at %s", label, time.Since(start).Round(time.Second))
	}
	sleepUntil(duration / 4)
	hotRestart("first")
	sleepUntil(duration / 2)
	// A rule change flushes the flow cache records, and a new local network
	// rewrites the local network map.
	t.Logf("rule and network change at %s", time.Since(start).Round(time.Second))
	mustRunDataplanePerfCmd(t, "ip", "link", "add", extra, "type", "dummy")
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", "198.22.0.1/24", "dev", extra)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", extra, "up")
	postLateralEgressNAT(t, h.APIBase, `{"parent_interface":"`+extra+`","out_interface":"`+top.UplinkHostIF+`","out_source_ip":"`+egressNATUplinkAddr+`","protocol":"udp","nat_type":"symmetric"}`)
	nats++
	waitForLateralEgressNATs(t, h.APIBase, h.LogPath, nats, kernelEngineTC)
	sleepUntil(duration * 3 / 4)
	hotRestart("second")

	failed := false
	for _, run := range clients {
		var err error
		select {
		case err = <-run.done:
		case <-time.After(time.Until(deadline) + 2*time.Minute):
			_ = run.cmd.Process.Kill()
			err = errors.New("client did not finish")
		}
		for _, line := range strings.Split(strings.TrimSpace(run.stdout.String()), "\n") {
			var result egressNATSoakResult
			if json.Unmarshal([]byte(line), &result) != nil || result.Label == "" {
				continue
			}
			t.Logf("%-26s ok=%v exchanges=%d bytes=%d max_rtt=%.1fms retries=%d source=%s %s",
				result.Label, result.OK, result.Exchanges, result.Bytes, result.MaxRTTms, result.Retries, result.SeenSource, result.Error)
			if !result.OK {
				failed = true
			}
		}
		if err != nil {
			failed = true
			t.Errorf("soak client in %s: %v\n%s", run.ns, err, run.stderr.String())
		}
	}
	if failed {
		logKernelRuntimeOnFailure(t, h.APIBase)
		logForwardLogOnFailure(t, h.LogPath)
		t.Fatal("a long connection broke")
	}
}

func startEgressNATSoakServer(t *testing.T, ns, listen string) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run", "^TestEgressNATSoakHelperProcess$", "-test.v=false")
	cmd.Env = append(os.Environ(), egressNATSoakHelperEnv+"=1", egressNATSoakRoleEnv+"=server", egressNATSoakListenEnv+"="+listen)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start soak server in %s: %v", ns, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == egressNATHelperReadyLine {
				ready <- true
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatalf("soak server in %s exited: %s", ns, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("soak server in %s not ready: %s", ns, stderr.String())
	}
}

// TestEgressNATSoakHelperProcess runs a soak server or client inside a test
// namespace.
func TestEgressNATSoakHelperProcess(t *testing.T) {
	if os.Getenv(egressNATSoakHelperEnv) != "1" {
		t.Skip("helper process")
	}
	var err error
	switch os.Getenv(egressNATSoakRoleEnv) {
	case "server":
		err = runEgressNATSoakServer(os.Getenv(egressNATSoakListenEnv))
	case "client":
		err = runEgressNATSoakClient()
	case "hold":
		err = runEgressNATSoakHold()
	default:
		err = errors.New("unknown soak role")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

// runEgressNATSoakServer echoes TCP streams, and answers each UDP datagram
// with the sender's address followed by the datagram.
func runEgressNATSoakServer(listen string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return err
	}
	fmt.Println(egressNATHelperReadyLine)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			reply := append([]byte(from.String()+"|"), buf[:n]...)
			_, _ = pc.WriteTo(reply, from)
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

// runEgressNATSoakHold opens a TCP connection to the target from every local
// port of FORWARD_EGRESS_NAT_SOAK_PLAN ("first-last"), checks one echo on
// each, prints READY and keeps them open until stdin closes. Each "check"
// line on stdin echoes on every connection again and prints
// "CHECK ok=N broken=M".
func runEgressNATSoakHold() error {
	var first, last int
	if _, err := fmt.Sscanf(os.Getenv(egressNATSoakPlanEnv), "%d-%d", &first, &last); err != nil {
		return err
	}
	target := os.Getenv(egressNATSoakListenEnv)
	var conns []net.Conn
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for port := first; port <= last; port++ {
		dialer := net.Dialer{Timeout: egressNATSoakStall, LocalAddr: &net.TCPAddr{Port: port}}
		conn, err := dialer.Dial("tcp", target)
		if err != nil {
			return fmt.Errorf("dial from port %d: %w", port, err)
		}
		conns = append(conns, conn)
		_ = conn.SetDeadline(time.Now().Add(egressNATSoakStall))
		msg := []byte(fmt.Sprintf("hold-%d", port))
		buf := make([]byte, len(msg))
		if _, err := conn.Write(msg); err != nil {
			return fmt.Errorf("write from port %d: %w", port, err)
		}
		if _, err := io.ReadFull(conn, buf); err != nil || !bytes.Equal(buf, msg) {
			return fmt.Errorf("echo from port %d: %v", port, err)
		}
		_ = conn.SetDeadline(time.Time{})
	}
	fmt.Println(egressNATHelperReadyLine)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "check" {
			continue
		}
		ok, broken := 0, 0
		for i, conn := range conns {
			msg := []byte(fmt.Sprintf("check-%d", i))
			buf := make([]byte, len(msg))
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(msg); err == nil {
				if _, err := io.ReadFull(conn, buf); err == nil && bytes.Equal(buf, msg) {
					ok++
					continue
				}
			}
			broken++
		}
		fmt.Printf("CHECK ok=%d broken=%d\n", ok, broken)
	}
	return nil
}

func runEgressNATSoakClient() error {
	var plan []egressNATSoakConn
	if err := json.Unmarshal([]byte(os.Getenv(egressNATSoakPlanEnv)), &plan); err != nil {
		return err
	}
	nanos, err := strconv.ParseInt(os.Getenv(egressNATSoakDeadlineEnv), 10, 64)
	if err != nil {
		return err
	}
	deadline := time.Unix(0, nanos)
	results := make([]egressNATSoakResult, len(plan))
	var wg sync.WaitGroup
	for i, conn := range plan {
		wg.Add(1)
		go func(i int, conn egressNATSoakConn) {
			defer wg.Done()
			result := egressNATSoakResult{Label: conn.Label}
			err := runEgressNATSoakConn(conn, deadline, &result)
			result.OK = err == nil
			if err != nil {
				result.Error = err.Error()
			}
			results[i] = result
		}(i, conn)
	}
	wg.Wait()
	failed := 0
	for _, result := range results {
		data, _ := json.Marshal(result)
		fmt.Println(string(data))
		if !result.OK {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d connections broke", failed, len(results))
	}
	return nil
}

func runEgressNATSoakConn(spec egressNATSoakConn, deadline time.Time, result *egressNATSoakResult) error {
	if spec.Proto == "udp" {
		return runEgressNATSoakUDP(spec, deadline, result)
	}
	dialer := net.Dialer{Timeout: egressNATSoakStall}
	conn, err := dialer.DialContext(context.Background(), "tcp", spec.Target)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	size, every := 64, time.Second
	switch spec.Pattern {
	case "stream":
		// About 4 MB/s: steady enough to stay on the fast path without
		// starving the other connections of the CPU.
		size, every = 32*1024, 8*time.Millisecond
	case "idle":
		every = time.Duration(spec.GapSecs) * time.Second
	}
	out := make([]byte, size)
	in := make([]byte, size)
	var seq uint64
	for {
		seq++
		for i := 0; i+8 <= len(out); i += 8 {
			binary.BigEndian.PutUint64(out[i:], seq*0x9e3779b97f4a7c15+uint64(i))
		}
		sent := time.Now()
		if err := conn.SetDeadline(sent.Add(egressNATSoakStall)); err != nil {
			return err
		}
		if _, err := conn.Write(out); err != nil {
			return fmt.Errorf("exchange %d write after %s: %w", seq, time.Since(sent), err)
		}
		if _, err := io.ReadFull(conn, in); err != nil {
			return fmt.Errorf("exchange %d echo after %s: %w", seq, time.Since(sent), err)
		}
		if !bytes.Equal(in, out) {
			return fmt.Errorf("exchange %d: echo differs", seq)
		}
		recordEgressNATSoakRTT(result, time.Since(sent), int64(2*size))
		next := sent.Add(every)
		if !next.Before(deadline) {
			return nil
		}
		time.Sleep(time.Until(next))
	}
}

// runEgressNATSoakUDP sends a datagram per period and wants its echo; a lost
// one is resent once. The source the server saw must not change: a new NAT
// mapping would break a real UDP session.
func runEgressNATSoakUDP(spec egressNATSoakConn, deadline time.Time, result *egressNATSoakResult) error {
	conn, err := net.Dial("udp", spec.Target)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	every := time.Second
	if spec.Pattern == "idle" {
		every = time.Duration(spec.GapSecs) * time.Second
	}
	buf := make([]byte, 2048)
	for seq := 1; ; seq++ {
		msg := []byte(fmt.Sprintf("%s-%d", spec.Label, seq))
		sent := time.Now()
		answered := false
		for attempt := 0; attempt < 2 && !answered; attempt++ {
			if attempt > 0 {
				result.Retries++
			}
			if _, err := conn.Write(msg); err != nil {
				return fmt.Errorf("datagram %d write: %w", seq, err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(egressNATSoakStall / 2))
			for {
				n, err := conn.Read(buf)
				if err != nil {
					break
				}
				source, payload, ok := strings.Cut(string(buf[:n]), "|")
				if !ok || payload != string(msg) {
					continue
				}
				if result.SeenSource == "" {
					result.SeenSource = source
				} else if source != result.SeenSource {
					return fmt.Errorf("datagram %d: server saw %s, earlier %s", seq, source, result.SeenSource)
				}
				answered = true
				break
			}
		}
		if !answered {
			return fmt.Errorf("datagram %d: no echo after a resend", seq)
		}
		recordEgressNATSoakRTT(result, time.Since(sent), int64(2*len(msg)))
		next := sent.Add(every)
		if !next.Before(deadline) {
			return nil
		}
		time.Sleep(time.Until(next))
	}
}

func recordEgressNATSoakRTT(result *egressNATSoakResult, rtt time.Duration, bytes int64) {
	result.Exchanges++
	result.Bytes += bytes
	if ms := float64(rtt) / float64(time.Millisecond); ms > result.MaxRTTms {
		result.MaxRTTms = ms
	}
}
