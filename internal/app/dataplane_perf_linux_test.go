//go:build linux

package app

// Linux usage:
//   1. Prepare embedded eBPF objects first:
//      bash release.sh
//   2. Run the benchmark test as root:
//      FORWARD_RUN_PERF_TEST=1 go test ./internal/app -run TestDataplanePerfMatrix -count=1 -v
//
// Optional environment variables:
//   FORWARD_PERF_CONNECTIONS
//   FORWARD_PERF_CONNECTION_SERIES
//   FORWARD_PERF_CONCURRENCY
//   FORWARD_PERF_CONCURRENCY_SERIES
//   FORWARD_PERF_MODES
//   FORWARD_PERF_PROTOCOL
//   FORWARD_PERF_TCP_MODE
//   FORWARD_PERF_BYTES_PER_CONN
//   FORWARD_PERF_IO_CHUNK_BYTES
//   FORWARD_PERF_TOTAL_PAYLOAD_BYTES
//   FORWARD_PERF_STEADY_SECONDS
//   FORWARD_PERF_WARMUP_CONNECTIONS
//   FORWARD_PERF_WARMUP_BYTES_PER_CONN
//   FORWARD_PERF_BACKEND_WORKERS
//   FORWARD_PERF_DISABLE_OFFLOADS
//
// The test builds a temporary forward binary, creates two network namespaces plus
// two veth pairs, then benchmarks userspace, tc, and xdp sequentially with the
// same transparent TCP echo workload.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	dataplanePerfEnableEnv      = "FORWARD_RUN_PERF_TEST"
	dataplanePerfConnEnv        = "FORWARD_PERF_CONNECTIONS"
	dataplanePerfConnSeriesEnv  = "FORWARD_PERF_CONNECTION_SERIES"
	dataplanePerfConcurrencyEnv = "FORWARD_PERF_CONCURRENCY"
	dataplanePerfConcSeriesEnv  = "FORWARD_PERF_CONCURRENCY_SERIES"
	dataplanePerfModesEnv       = "FORWARD_PERF_MODES"
	dataplanePerfProtocolEnv    = "FORWARD_PERF_PROTOCOL"
	dataplanePerfTCPModeEnv     = "FORWARD_PERF_TCP_MODE"
	dataplanePerfBytesEnv       = "FORWARD_PERF_BYTES_PER_CONN"
	dataplanePerfIOChunkEnv     = "FORWARD_PERF_IO_CHUNK_BYTES"
	dataplanePerfTotalBytesEnv  = "FORWARD_PERF_TOTAL_PAYLOAD_BYTES"
	dataplanePerfSteadyEnv      = "FORWARD_PERF_STEADY_SECONDS"
	dataplanePerfWarmupConnEnv  = "FORWARD_PERF_WARMUP_CONNECTIONS"
	dataplanePerfWarmupBytesEnv = "FORWARD_PERF_WARMUP_BYTES_PER_CONN"
	dataplanePerfDeadlineEnv    = "FORWARD_PERF_CONN_DEADLINE_MS"
	dataplanePerfIdleEnv        = "FORWARD_PERF_CONN_IDLE_MS"
	dataplanePerfBackendWorkEnv = "FORWARD_PERF_BACKEND_WORKERS"
	dataplanePerfOffloadsEnv    = "FORWARD_PERF_DISABLE_OFFLOADS"
	dataplanePerfHelperEnv      = "FORWARD_PERF_HELPER"
	dataplanePerfHelperRoleEnv  = "FORWARD_PERF_HELPER_ROLE"
	dataplanePerfTargetEnv      = "FORWARD_PERF_TARGET_ADDR"
	dataplanePerfBackendEnv     = "FORWARD_PERF_BACKEND_ADDR"
	dataplanePerfToken          = "forward-perf-token"
	dataplanePerfFrontAddr      = "198.18.0.1"
	dataplanePerfClientAddr     = "198.18.0.2"
	dataplanePerfBackendHost    = "198.19.0.1"
	dataplanePerfBackendAddr    = "198.19.0.2"
	dataplanePerfFrontPort      = 10000
	dataplanePerfBackendPort    = 20000
)

const (
	dataplanePerfTCPEchoMode     = "echo"
	dataplanePerfTCPUploadMode   = "upload"
	dataplanePerfTCPDownloadMode = "download"
)

type dataplanePerfMode struct {
	Name         string
	Default      string
	Order        []string
	Expected     string
	ExpectedKern string
}

type dataplanePerfScenario struct {
	Label              string
	Connections        int
	Concurrency        int
	BytesPerConnection int64
	IOChunkBytes       int64
	WarmupConnections  int
	WarmupBytesPerConn int64
}

type dataplanePerfResult struct {
	Scenario           string  `json:"scenario,omitempty"`
	Mode               string  `json:"mode"`
	Connections        int     `json:"connections"`
	Concurrency        int     `json:"concurrency"`
	BytesPerConnection int64   `json:"bytes_per_connection"`
	IOChunkBytes       int64   `json:"io_chunk_bytes"`
	PayloadBytes       int64   `json:"payload_bytes"`
	PayloadPackets     int64   `json:"payload_packets"`
	WirePackets        int64   `json:"wire_packets"`
	ElapsedSeconds     float64 `json:"elapsed_seconds"`
	PayloadMiBPerSec   float64 `json:"payload_mib_per_sec"`
	WireMiBPerSec      float64 `json:"wire_mib_per_sec"`
	PayloadPPS         float64 `json:"payload_packets_per_sec"`
	WirePPS            float64 `json:"wire_packets_per_sec"`
	ConnPerSec         float64 `json:"conn_per_sec"`
	ForwardCPUSeconds  float64 `json:"forward_cpu_seconds"`
	PayloadMiBPerCPU   float64 `json:"payload_mib_per_cpu_second"`
	EffectiveEngine    string  `json:"effective_engine"`
	KernelEngine       string  `json:"effective_kernel_engine,omitempty"`
}

type dataplanePerfClientResult struct {
	Connections    int           `json:"connections"`
	PayloadBytes   int64         `json:"payload_bytes"`
	Elapsed        time.Duration `json:"elapsed"`
	ElapsedSeconds float64       `json:"elapsed_seconds"`
}

type dataplanePerfRuleStatus struct {
	ID                    int64  `json:"id"`
	Status                string `json:"status"`
	EffectiveEngine       string `json:"effective_engine"`
	EffectiveKernelEngine string `json:"effective_kernel_engine"`
	KernelReason          string `json:"kernel_reason"`
	FallbackReason        string `json:"fallback_reason"`
}

type dataplanePerfTopology struct {
	ClientNS      string
	BackendNS     string
	ClientHostIF  string
	ClientNSIF    string
	BackendHostIF string
	BackendNSIF   string
}

func TestDataplanePerfHelperProcess(t *testing.T) {
	if os.Getenv(dataplanePerfHelperEnv) != "1" {
		return
	}

	role := strings.TrimSpace(os.Getenv(dataplanePerfHelperRoleEnv))
	var err error
	switch role {
	case "backend":
		err = runDataplanePerfBackend()
	case "client":
		err = runDataplanePerfClient()
	default:
		err = fmt.Errorf("unknown helper role %q", role)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func dataplanePerfProtocol() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(dataplanePerfProtocolEnv))) {
	case "udp":
		return "udp"
	default:
		return "tcp"
	}
}

func dataplanePerfTCPMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(dataplanePerfTCPModeEnv))) {
	case dataplanePerfTCPUploadMode, "stream", "stream_upload":
		return dataplanePerfTCPUploadMode
	case dataplanePerfTCPDownloadMode, "stream_download":
		return dataplanePerfTCPDownloadMode
	default:
		return dataplanePerfTCPEchoMode
	}
}

func TestDataplanePerfMatrix(t *testing.T) {
	if os.Getenv(dataplanePerfEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux dataplane performance test", dataplanePerfEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	repoRoot := findRepoRoot(t)
	requireEmbeddedEBPFObjects(t, repoRoot)

	baseBinary := buildDataplanePerfBinary(t, repoRoot)
	topology := setupDataplanePerfTopology(t)
	defer cleanupTransparentRouting()

	backendCmd, backendLogs := startDataplanePerfBackend(t, topology)
	defer stopDataplanePerfHelper(t, backendCmd)

	connections := envInt(dataplanePerfConnEnv, 256)
	concurrency := envInt(dataplanePerfConcurrencyEnv, 32)
	bytesPerConn := envInt64(dataplanePerfBytesEnv, 1<<20)
	ioChunkBytes := envInt64(dataplanePerfIOChunkEnv, 16<<10)
	warmupConnections := envInt(dataplanePerfWarmupConnEnv, 8)
	warmupBytesPerConn := envInt64(dataplanePerfWarmupBytesEnv, 64<<10)
	scenarios := dataplanePerfScenarios(connections, concurrency, bytesPerConn, ioChunkBytes, warmupConnections, warmupBytesPerConn)

	modes := []dataplanePerfMode{
		{Name: "userspace", Default: ruleEngineUserspace, Expected: ruleEngineUserspace},
		{Name: "tc", Default: ruleEngineKernel, Order: []string{kernelEngineTC}, Expected: ruleEngineKernel, ExpectedKern: kernelEngineTC},
		{Name: "xdp", Default: ruleEngineKernel, Order: []string{kernelEngineXDP}, Expected: ruleEngineKernel, ExpectedKern: kernelEngineXDP},
	}
	modes = selectDataplanePerfModes(t, modes)

	results := make([]dataplanePerfResult, 0, len(modes)*len(scenarios))
	for _, scenario := range scenarios {
		scenario := scenario
		runScenario := func(t *testing.T) {
			for _, mode := range modes {
				mode := mode
				t.Run(mode.Name, func(t *testing.T) {
					result := runDataplanePerfMode(t, baseBinary, topology, mode, scenario)
					results = append(results, result)
					t.Logf("%s payload=%.2f MiB/s wire=%.2f MiB/s payload_pps=%.0f wire_pps=%.0f conn=%.2f/s cpu=%.2fs payload/cpu=%.2f MiB/s",
						mode.Name,
						result.PayloadMiBPerSec,
						result.WireMiBPerSec,
						result.PayloadPPS,
						result.WirePPS,
						result.ConnPerSec,
						result.ForwardCPUSeconds,
						result.PayloadMiBPerCPU,
					)
				})
			}
		}
		if len(scenarios) == 1 {
			runScenario(t)
			continue
		}
		t.Run(scenario.Label, runScenario)
	}

	if len(results) > 0 {
		payload, _ := json.MarshalIndent(results, "", "  ")
		t.Logf("dataplane perf summary:\n%s", payload)
	}

	if t.Failed() {
		t.Logf("backend helper logs:\n%s", backendLogs.String())
	}
}

func runDataplanePerfMode(t *testing.T, baseBinary string, topology dataplanePerfTopology, mode dataplanePerfMode, scenario dataplanePerfScenario) dataplanePerfResult {
	t.Helper()
	cleanupTransparentRouting()
	defer cleanupTransparentRouting()
	steadySeconds := envInt(dataplanePerfSteadyEnv, 0)

	modeDir := t.TempDir()
	forwardBinary := filepath.Join(modeDir, "forward-perf")
	copyFile(t, baseBinary, forwardBinary)
	workDir := filepath.Join(modeDir, "work")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}

	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, mode, webPort)

	forwardLogs := filepath.Join(workDir, "forward.log")
	logFile, err := os.Create(forwardLogs)
	if err != nil {
		t.Fatalf("create forward log file: %v", err)
	}
	defer logFile.Close()

	cmd := exec.Command(forwardBinary, "--config", configPath)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), forwardKernelMaintenanceIntervalEnv+"="+strconv.Itoa(envInt(forwardKernelMaintenanceIntervalEnv, 600000)))
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start forward: %v", err)
	}
	defer stopForwardProcessTree(t, cmd)

	apiBase := fmt.Sprintf("http://127.0.0.1:%d", webPort)
	waitForDataplanePerfAPI(t, apiBase)
	seedDataplanePerfNeighbors(t, topology)
	createDataplanePerfRule(t, apiBase, topology, mode)
	rule := waitForDataplanePerfRule(t, apiBase, mode)

	if _, err := runDataplanePerfClientBenchmarkRaw(topology.ClientNS, scenario.WarmupConnections, minInt(scenario.Concurrency, maxInt(1, scenario.WarmupConnections)), scenario.WarmupBytesPerConn, scenario.IOChunkBytes, 0); err != nil {
		if data, readErr := os.ReadFile(forwardLogs); readErr == nil {
			t.Logf("%s forward logs before warmup failure:\n%s", mode.Name, string(data))
		}
		t.Fatalf("warmup client benchmark failed: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	hz := procClockTicks(t)
	startCPU := sampleProcessTreeJiffies(t, cmd.Process.Pid)
	clientResult, err := runDataplanePerfClientBenchmarkRaw(topology.ClientNS, scenario.Connections, scenario.Concurrency, scenario.BytesPerConnection, scenario.IOChunkBytes, steadySeconds)
	if err != nil {
		if data, readErr := os.ReadFile(forwardLogs); readErr == nil {
			t.Logf("%s forward logs before client failure:\n%s", mode.Name, string(data))
		}
		t.Fatalf("client benchmark failed: %v", err)
	}
	endCPU := sampleProcessTreeJiffies(t, cmd.Process.Pid)

	cpuSeconds := float64(endCPU-startCPU) / float64(hz)
	if cpuSeconds < 0 {
		cpuSeconds = 0
	}

	payloadMiB := float64(clientResult.PayloadBytes) / (1024.0 * 1024.0)
	elapsedSeconds := clientResult.Elapsed.Seconds()
	payloadPackets := dataplanePerfPacketCount(clientResult.PayloadBytes, scenario.IOChunkBytes)
	wireMultiplier := dataplanePerfWireMultiplier()
	wireMiB := payloadMiB * wireMultiplier
	wirePackets := int64(math.Round(float64(payloadPackets) * wireMultiplier))
	result := dataplanePerfResult{
		Scenario:           scenario.Label,
		Mode:               mode.Name,
		Connections:        scenario.Connections,
		Concurrency:        scenario.Concurrency,
		BytesPerConnection: scenario.BytesPerConnection,
		IOChunkBytes:       scenario.IOChunkBytes,
		PayloadBytes:       clientResult.PayloadBytes,
		PayloadPackets:     payloadPackets,
		WirePackets:        wirePackets,
		ElapsedSeconds:     elapsedSeconds,
		PayloadMiBPerSec:   safeRate(payloadMiB, elapsedSeconds),
		WireMiBPerSec:      safeRate(wireMiB, elapsedSeconds),
		PayloadPPS:         safeRate(float64(payloadPackets), elapsedSeconds),
		WirePPS:            safeRate(float64(wirePackets), elapsedSeconds),
		ConnPerSec:         safeRate(float64(scenario.Connections), elapsedSeconds),
		ForwardCPUSeconds:  cpuSeconds,
		PayloadMiBPerCPU:   safeRate(payloadMiB, cpuSeconds),
		EffectiveEngine:    rule.EffectiveEngine,
		KernelEngine:       rule.EffectiveKernelEngine,
	}

	if t.Failed() {
		if data, err := os.ReadFile(forwardLogs); err == nil {
			t.Logf("%s forward logs:\n%s", mode.Name, string(data))
		}
	}

	return result
}

func dataplanePerfWireMultiplier() float64 {
	if dataplanePerfProtocol() == "tcp" {
		switch dataplanePerfTCPMode() {
		case dataplanePerfTCPUploadMode, dataplanePerfTCPDownloadMode:
			return 1
		}
	}
	return 2
}

func runDataplanePerfBackend() error {
	if dataplanePerfProtocol() == "udp" {
		return runDataplanePerfBackendUDP()
	}
	return runDataplanePerfBackendTCP()
}

func runDataplanePerfBackendTCP() error {
	addr := strings.TrimSpace(os.Getenv(dataplanePerfBackendEnv))
	if addr == "" {
		return errors.New("missing backend address")
	}
	tcpMode := dataplanePerfTCPMode()
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	fmt.Println("READY")
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			if tcpConn, ok := c.(*net.TCPConn); ok {
				_ = tcpConn.SetNoDelay(true)
			}
			var serveErr error
			switch tcpMode {
			case dataplanePerfTCPUploadMode:
				serveErr = runDataplanePerfBackendTCPUpload(c)
			case dataplanePerfTCPDownloadMode:
				serveErr = runDataplanePerfBackendTCPDownload(c)
			default:
				serveErr = runDataplanePerfBackendTCPEcho(c)
			}
			if serveErr != nil {
				return
			}
		}(conn)
	}
}

func runDataplanePerfBackendTCPEcho(c net.Conn) error {
	buf := make([]byte, 4<<10)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if writeErr := writeAll(c, buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func runDataplanePerfBackendTCPUpload(c net.Conn) error {
	payloadBytes, err := readDataplanePerfTCPTransferHeader(c, dataplanePerfTCPUploadMode)
	if err != nil {
		return err
	}
	buf := make([]byte, 64<<10)
	for remaining := payloadBytes; remaining > 0; {
		step := len(buf)
		if int64(step) > remaining {
			step = int(remaining)
		}
		if _, err := io.ReadFull(c, buf[:step]); err != nil {
			return err
		}
		remaining -= int64(step)
	}
	_, err = c.Write([]byte{1})
	return err
}

func runDataplanePerfBackendTCPDownload(c net.Conn) error {
	payloadBytes, err := readDataplanePerfTCPTransferHeader(c, dataplanePerfTCPDownloadMode)
	if err != nil {
		return err
	}
	buf := bytes.Repeat([]byte("forward-perf-"), int(math.Ceil(float64(64<<10)/13.0)))
	buf = buf[:64<<10]
	for remaining := payloadBytes; remaining > 0; {
		step := len(buf)
		if int64(step) > remaining {
			step = int(remaining)
		}
		if err := writeAll(c, buf[:step]); err != nil {
			return err
		}
		remaining -= int64(step)
	}
	return nil
}

func runDataplanePerfBackendUDP() error {
	addr := strings.TrimSpace(os.Getenv(dataplanePerfBackendEnv))
	if addr == "" {
		return errors.New("missing backend address")
	}

	workers := envInt(dataplanePerfBackendWorkEnv, 1)
	if workers <= 0 {
		workers = 1
	}

	listeners := make([]net.PacketConn, 0, workers)
	for i := 0; i < workers; i++ {
		pc, err := listenDataplanePerfBackendUDP(addr, workers > 1)
		if err != nil {
			for _, item := range listeners {
				_ = item.Close()
			}
			return err
		}
		listeners = append(listeners, pc)
	}

	defer func() {
		for _, item := range listeners {
			_ = item.Close()
		}
	}()

	fmt.Println("READY")
	errCh := make(chan error, len(listeners))
	for _, pc := range listeners {
		current := pc
		go func() {
			buf := make([]byte, 64<<10)
			for {
				n, peer, err := current.ReadFrom(buf)
				if err != nil {
					errCh <- err
					return
				}
				if n > 0 {
					if _, err := current.WriteTo(buf[:n], peer); err != nil {
						errCh <- err
						return
					}
				}
			}
		}()
	}
	return <-errCh
}

func listenDataplanePerfBackendUDP(addr string, reusePort bool) (net.PacketConn, error) {
	if !reusePort {
		return net.ListenPacket("udp4", addr)
	}

	lc := net.ListenConfig{
		Control: func(network string, address string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					sockErr = err
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					sockErr = err
				}
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.ListenPacket(context.Background(), "udp4", addr)
}

func runDataplanePerfClient() error {
	if dataplanePerfProtocol() == "udp" {
		return runDataplanePerfClientUDP()
	}
	return runDataplanePerfClientTCP()
}

func runDataplanePerfClientTCP() error {
	target := strings.TrimSpace(os.Getenv(dataplanePerfTargetEnv))
	if target == "" {
		return errors.New("missing target address")
	}
	tcpMode := dataplanePerfTCPMode()
	connections := envInt(dataplanePerfConnEnv, 1)
	concurrency := envInt(dataplanePerfConcurrencyEnv, 1)
	bytesPerConn := envInt64(dataplanePerfBytesEnv, 64<<10)
	ioChunkBytes := envInt64(dataplanePerfIOChunkEnv, 16<<10)
	steadySeconds := envInt(dataplanePerfSteadyEnv, 0)
	deadlineMs := envInt(dataplanePerfDeadlineEnv, 120000)
	idleMs := envInt(dataplanePerfIdleEnv, 10000)

	if connections <= 0 {
		return errors.New("connections must be greater than 0")
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	if bytesPerConn <= 0 {
		return errors.New("bytes per connection must be greater than 0")
	}
	if ioChunkBytes <= 0 {
		ioChunkBytes = 16 << 10
	}
	if steadySeconds > 0 {
		if tcpMode != dataplanePerfTCPEchoMode {
			return fmt.Errorf("steady TCP benchmark currently supports only %q mode; got %q", dataplanePerfTCPEchoMode, tcpMode)
		}
		result, err := runDataplanePerfSteadyClient(target, connections, concurrency, bytesPerConn, ioChunkBytes, time.Duration(steadySeconds)*time.Second, time.Duration(deadlineMs)*time.Millisecond, time.Duration(idleMs)*time.Millisecond)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	start := time.Now()
	workCh := make(chan int, connections)
	errCh := make(chan error, concurrency)
	for i := 0; i < connections; i++ {
		workCh <- i
	}
	close(workCh)

	for i := 0; i < concurrency; i++ {
		go func() {
			for range workCh {
				if err := runDataplanePerfConnection(target, tcpMode, bytesPerConn, ioChunkBytes, time.Duration(deadlineMs)*time.Millisecond, time.Duration(idleMs)*time.Millisecond); err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
		}()
	}

	for i := 0; i < concurrency; i++ {
		if err := <-errCh; err != nil {
			return err
		}
	}

	elapsed := time.Since(start)
	resp := dataplanePerfClientResult{
		Connections:    connections,
		PayloadBytes:   int64(connections) * bytesPerConn,
		Elapsed:        elapsed,
		ElapsedSeconds: elapsed.Seconds(),
	}
	return json.NewEncoder(os.Stdout).Encode(resp)
}

func runDataplanePerfClientUDP() error {
	target := strings.TrimSpace(os.Getenv(dataplanePerfTargetEnv))
	if target == "" {
		return errors.New("missing target address")
	}
	connections := envInt(dataplanePerfConnEnv, 1)
	concurrency := envInt(dataplanePerfConcurrencyEnv, 1)
	bytesPerConn := envInt64(dataplanePerfBytesEnv, 64<<10)
	ioChunkBytes := envInt64(dataplanePerfIOChunkEnv, 16<<10)
	steadySeconds := envInt(dataplanePerfSteadyEnv, 0)
	deadlineMs := envInt(dataplanePerfDeadlineEnv, 120000)
	idleMs := envInt(dataplanePerfIdleEnv, 10000)

	if connections <= 0 {
		return errors.New("connections must be greater than 0")
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	if bytesPerConn <= 0 {
		return errors.New("bytes per connection must be greater than 0")
	}
	if ioChunkBytes <= 0 {
		ioChunkBytes = 1472
	}
	if steadySeconds > 0 {
		result, err := runDataplanePerfSteadyClientUDP(target, connections, concurrency, bytesPerConn, ioChunkBytes, time.Duration(steadySeconds)*time.Second, time.Duration(deadlineMs)*time.Millisecond, time.Duration(idleMs)*time.Millisecond)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	start := time.Now()
	workCh := make(chan int, connections)
	errCh := make(chan error, concurrency)
	var totalBytes atomic.Int64
	for i := 0; i < connections; i++ {
		workCh <- i
	}
	close(workCh)

	for i := 0; i < concurrency; i++ {
		go func() {
			for range workCh {
				successBytes, err := runDataplanePerfUDPConnection(target, bytesPerConn, ioChunkBytes, time.Duration(deadlineMs)*time.Millisecond, time.Duration(idleMs)*time.Millisecond)
				if err != nil {
					errCh <- err
					return
				}
				totalBytes.Add(successBytes)
			}
			errCh <- nil
		}()
	}

	for i := 0; i < concurrency; i++ {
		if err := <-errCh; err != nil {
			return err
		}
	}

	elapsed := time.Since(start)
	resp := dataplanePerfClientResult{
		Connections:    connections,
		PayloadBytes:   totalBytes.Load(),
		Elapsed:        elapsed,
		ElapsedSeconds: elapsed.Seconds(),
	}
	return json.NewEncoder(os.Stdout).Encode(resp)
}

func runDataplanePerfSteadyClient(target string, totalConnections int, activeConnections int, chunkBytes int64, ioChunkBytes int64, duration time.Duration, deadline time.Duration, idle time.Duration) (dataplanePerfClientResult, error) {
	if totalConnections <= 0 {
		return dataplanePerfClientResult{}, errors.New("steady connections must be greater than 0")
	}
	if activeConnections <= 0 {
		activeConnections = 1
	}
	if activeConnections > totalConnections {
		activeConnections = totalConnections
	}
	if chunkBytes <= 0 {
		return dataplanePerfClientResult{}, errors.New("steady chunk bytes must be greater than 0")
	}
	if duration <= 0 {
		return dataplanePerfClientResult{}, errors.New("steady duration must be greater than 0")
	}
	if deadline <= 0 {
		deadline = 120 * time.Second
	}
	if idle <= 0 {
		idle = 10 * time.Second
	}

	bufferChunkBytes := minInt64(ioChunkBytes, chunkBytes)
	if bufferChunkBytes > 4<<10 {
		bufferChunkBytes = 4 << 10
	}
	bufferChunkLen := int(bufferChunkBytes)
	payload := bytes.Repeat([]byte("forward-perf-"), int(math.Ceil(float64(bufferChunkLen)/13.0)))
	payload = payload[:bufferChunkLen]
	conns, err := openDataplanePerfConnections(target, totalConnections, dataplanePerfDialParallelism(totalConnections, activeConnections))
	if err != nil {
		closeDataplanePerfConnections(conns)
		return dataplanePerfClientResult{}, err
	}
	defer closeDataplanePerfConnections(conns)

	start := time.Now()
	stopAt := start.Add(duration)
	var totalBytes atomic.Int64
	errCh := make(chan error, len(conns))
	done := make(chan struct{})
	var stopOnce sync.Once
	stopAll := func() {
		stopOnce.Do(func() {
			close(done)
			closeDataplanePerfConnections(conns)
		})
	}

	for _, conn := range conns[:activeConnections] {
		currentConn := conn
		go func() {
			readBuf := make([]byte, len(payload))
			for {
				select {
				case <-done:
					errCh <- nil
					return
				default:
				}
				now := time.Now()
				if !now.Before(stopAt) {
					errCh <- nil
					return
				}
				stepDeadline := idle
				if remaining := time.Until(stopAt); remaining < stepDeadline {
					stepDeadline = remaining
				}
				if stepDeadline < time.Second {
					stepDeadline = time.Second
				}
				if stepDeadline > deadline {
					stepDeadline = deadline
				}
				if err := currentConn.SetDeadline(now.Add(stepDeadline)); err != nil {
					stopAll()
					errCh <- err
					return
				}
				for remaining := chunkBytes; remaining > 0; {
					step := minInt64(ioChunkBytes, remaining)
					for step > int64(len(payload)) {
						if err := writeAllChunked(currentConn, payload, len(payload), nil); err != nil {
							stopAll()
							errCh <- err
							return
						}
						if _, err := io.ReadFull(currentConn, readBuf); err != nil {
							stopAll()
							errCh <- err
							return
						}
						if !bytes.Equal(readBuf, payload) {
							stopAll()
							errCh <- errors.New("steady echo payload mismatch")
							return
						}
						remaining -= int64(len(payload))
						step = minInt64(ioChunkBytes, remaining)
						if remaining <= 0 {
							break
						}
					}
					if remaining <= 0 {
						break
					}
					stepLen := int(step)
					if err := writeAllChunked(currentConn, payload[:stepLen], stepLen, nil); err != nil {
						stopAll()
						errCh <- err
						return
					}
					if _, err := io.ReadFull(currentConn, readBuf[:stepLen]); err != nil {
						stopAll()
						errCh <- err
						return
					}
					if !bytes.Equal(readBuf[:stepLen], payload[:stepLen]) {
						stopAll()
						errCh <- errors.New("steady echo payload mismatch")
						return
					}
					remaining -= step
				}
				totalBytes.Add(chunkBytes)
			}
		}()
	}

	var firstErr error
	for i := 0; i < activeConnections; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	elapsed := time.Since(start)
	if firstErr != nil {
		return dataplanePerfClientResult{}, firstErr
	}
	return dataplanePerfClientResult{
		Connections:    totalConnections,
		PayloadBytes:   totalBytes.Load(),
		Elapsed:        elapsed,
		ElapsedSeconds: elapsed.Seconds(),
	}, nil
}

func runDataplanePerfSteadyClientUDP(target string, totalConnections int, activeConnections int, chunkBytes int64, ioChunkBytes int64, duration time.Duration, deadline time.Duration, idle time.Duration) (dataplanePerfClientResult, error) {
	if totalConnections <= 0 {
		return dataplanePerfClientResult{}, errors.New("steady connections must be greater than 0")
	}
	if activeConnections <= 0 {
		activeConnections = 1
	}
	if activeConnections > totalConnections {
		activeConnections = totalConnections
	}
	if chunkBytes <= 0 {
		return dataplanePerfClientResult{}, errors.New("steady chunk bytes must be greater than 0")
	}
	if ioChunkBytes <= 0 {
		ioChunkBytes = 1472
	}
	if duration <= 0 {
		return dataplanePerfClientResult{}, errors.New("steady duration must be greater than 0")
	}
	if deadline <= 0 {
		deadline = 120 * time.Second
	}
	if idle <= 0 {
		idle = 10 * time.Second
	}

	sockets, err := openDataplanePerfUDPConnections(target, totalConnections, dataplanePerfDialParallelism(totalConnections, activeConnections))
	if err != nil {
		closeDataplanePerfUDPConnections(sockets)
		return dataplanePerfClientResult{}, err
	}
	defer closeDataplanePerfUDPConnections(sockets)

	packetSize := dataplanePerfUDPPacketSize(chunkBytes, ioChunkBytes)
	payload := bytes.Repeat([]byte("forward-perf-"), int(math.Ceil(float64(packetSize)/13.0)))
	payload = payload[:packetSize]

	start := time.Now()
	stopAt := start.Add(duration)
	var totalBytes atomic.Int64
	errCh := make(chan error, activeConnections)
	done := make(chan struct{})
	var stopOnce sync.Once
	stopAll := func() {
		stopOnce.Do(func() {
			close(done)
			closeDataplanePerfUDPConnections(sockets)
		})
	}

	for _, conn := range sockets[:activeConnections] {
		currentConn := conn
		go func() {
			readBuf := make([]byte, len(payload))
			consecutiveLosses := 0
			for {
				select {
				case <-done:
					errCh <- nil
					return
				default:
				}
				now := time.Now()
				if !now.Before(stopAt) {
					errCh <- nil
					return
				}
				for remaining := chunkBytes; remaining > 0; {
					step := dataplanePerfUDPPacketSize(remaining, ioChunkBytes)
					stepDeadline, ok := dataplanePerfUDPDeadline(time.Now(), stopAt, deadline, idle)
					if !ok {
						errCh <- nil
						return
					}
					if err := currentConn.SetDeadline(stepDeadline); err != nil {
						stopAll()
						errCh <- err
						return
					}
					if _, err := currentConn.Write(payload[:step]); err != nil {
						if isDataplanePerfTimeout(err) {
							consecutiveLosses++
							remaining -= int64(step)
							if !sleepDataplanePerfUDPBackoff(dataplanePerfUDPLossBackoff(consecutiveLosses, idle), done) {
								errCh <- nil
								return
							}
							continue
						}
						stopAll()
						errCh <- err
						return
					}
					n, err := currentConn.Read(readBuf[:step])
					if err != nil {
						if isDataplanePerfTimeout(err) {
							consecutiveLosses++
							remaining -= int64(step)
							if !sleepDataplanePerfUDPBackoff(dataplanePerfUDPLossBackoff(consecutiveLosses, idle), done) {
								errCh <- nil
								return
							}
							continue
						}
						stopAll()
						errCh <- err
						return
					}
					if n != step || !bytes.Equal(readBuf[:step], payload[:step]) {
						consecutiveLosses++
						remaining -= int64(step)
						if !sleepDataplanePerfUDPBackoff(dataplanePerfUDPLossBackoff(consecutiveLosses, idle), done) {
							errCh <- nil
							return
						}
						continue
					}
					consecutiveLosses = 0
					remaining -= int64(step)
					totalBytes.Add(int64(step))
				}
			}
		}()
	}

	var firstErr error
	for i := 0; i < activeConnections; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	elapsed := time.Since(start)
	if firstErr != nil {
		return dataplanePerfClientResult{}, firstErr
	}
	if totalBytes.Load() == 0 {
		return dataplanePerfClientResult{}, errors.New("steady udp benchmark produced no successful echoed payload")
	}
	return dataplanePerfClientResult{
		Connections:    totalConnections,
		PayloadBytes:   totalBytes.Load(),
		Elapsed:        elapsed,
		ElapsedSeconds: elapsed.Seconds(),
	}, nil
}

func dataplanePerfDialParallelism(totalConnections int, activeConnections int) int {
	parallelism := activeConnections
	if parallelism < 128 {
		parallelism = 128
	}
	if parallelism > 512 {
		parallelism = 512
	}
	if parallelism > totalConnections {
		parallelism = totalConnections
	}
	if parallelism <= 0 {
		return 1
	}
	return parallelism
}

func openDataplanePerfUDPConnections(target string, count int, parallelism int) ([]*net.UDPConn, error) {
	type dialResult struct {
		index int
		conn  *net.UDPConn
		err   error
	}

	if count <= 0 {
		return nil, nil
	}
	if parallelism <= 0 {
		parallelism = 1
	}
	if parallelism > count {
		parallelism = count
	}
	raddr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return nil, err
	}

	workCh := make(chan int, count)
	resultCh := make(chan dialResult, count)
	for i := 0; i < count; i++ {
		workCh <- i
	}
	close(workCh)

	for i := 0; i < parallelism; i++ {
		go func() {
			for idx := range workCh {
				conn, err := net.DialUDP("udp4", nil, raddr)
				resultCh <- dialResult{index: idx, conn: conn, err: err}
			}
		}()
	}

	conns := make([]*net.UDPConn, count)
	var firstErr error
	for i := 0; i < count; i++ {
		result := <-resultCh
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
			}
			continue
		}
		conns[result.index] = result.conn
	}
	if firstErr != nil {
		closeDataplanePerfUDPConnections(conns)
		return nil, firstErr
	}
	return conns, nil
}

func closeDataplanePerfUDPConnections(conns []*net.UDPConn) {
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func openDataplanePerfConnections(target string, count int, parallelism int) ([]net.Conn, error) {
	type dialResult struct {
		index int
		conn  net.Conn
		err   error
	}

	if count <= 0 {
		return nil, nil
	}
	if parallelism <= 0 {
		parallelism = 1
	}
	if parallelism > count {
		parallelism = count
	}

	workCh := make(chan int, count)
	resultCh := make(chan dialResult, count)
	for i := 0; i < count; i++ {
		workCh <- i
	}
	close(workCh)

	for i := 0; i < parallelism; i++ {
		go func() {
			for idx := range workCh {
				conn, err := net.DialTimeout("tcp4", target, 5*time.Second)
				if err == nil {
					if tcpConn, ok := conn.(*net.TCPConn); ok {
						_ = tcpConn.SetNoDelay(true)
					}
				}
				resultCh <- dialResult{index: idx, conn: conn, err: err}
			}
		}()
	}

	conns := make([]net.Conn, count)
	var firstErr error
	for i := 0; i < count; i++ {
		result := <-resultCh
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
			}
			continue
		}
		conns[result.index] = result.conn
	}
	if firstErr != nil {
		closeDataplanePerfConnections(conns)
		return nil, firstErr
	}
	return conns, nil
}

func closeDataplanePerfConnections(conns []net.Conn) {
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func runDataplanePerfConnection(target string, tcpMode string, payloadBytes int64, ioChunkBytes int64, deadline time.Duration, idle time.Duration) error {
	conn, err := net.DialTimeout("tcp4", target, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	if deadline <= 0 {
		deadline = 120 * time.Second
	}
	if idle <= 0 {
		idle = 10 * time.Second
	}
	start := time.Now()
	refreshDeadline := func() error {
		remaining := deadline - time.Since(start)
		if remaining <= 0 {
			return conn.SetDeadline(time.Now())
		}
		next := idle
		if remaining < next {
			next = remaining
		}
		return conn.SetDeadline(time.Now().Add(next))
	}

	chunkSize := int(ioChunkBytes)
	if chunkSize <= 0 {
		chunkSize = 16 << 10
	}
	if payloadBytes > 0 && int64(chunkSize) > payloadBytes {
		chunkSize = int(payloadBytes)
	}
	if chunkSize <= 0 {
		chunkSize = 1
	}

	payload := bytes.Repeat([]byte("forward-perf-"), int(math.Ceil(float64(chunkSize)/13.0)))
	payload = payload[:chunkSize]
	readBuf := make([]byte, chunkSize)

	switch tcpMode {
	case dataplanePerfTCPUploadMode:
		if err := writeDataplanePerfTCPTransferHeader(conn, tcpMode, payloadBytes, refreshDeadline); err != nil {
			return err
		}
		for remaining := payloadBytes; remaining > 0; {
			step := chunkSize
			if int64(step) > remaining {
				step = int(remaining)
			}
			if err := writeAllChunked(conn, payload[:step], step, refreshDeadline); err != nil {
				return err
			}
			remaining -= int64(step)
		}
		var ack [1]byte
		if _, err := readFullWithDeadline(conn, ack[:], refreshDeadline); err != nil {
			return err
		}
		if ack[0] != 1 {
			return errors.New("upload completion ack mismatch")
		}
		return nil
	case dataplanePerfTCPDownloadMode:
		if err := writeDataplanePerfTCPTransferHeader(conn, tcpMode, payloadBytes, refreshDeadline); err != nil {
			return err
		}
		for remaining := payloadBytes; remaining > 0; {
			step := chunkSize
			if int64(step) > remaining {
				step = int(remaining)
			}
			if _, err := readFullWithDeadline(conn, readBuf[:step], refreshDeadline); err != nil {
				return err
			}
			remaining -= int64(step)
		}
		return nil
	}

	for remaining := payloadBytes; remaining > 0; {
		step := chunkSize
		if int64(step) > remaining {
			step = int(remaining)
		}
		if err := writeAllChunked(conn, payload[:step], step, refreshDeadline); err != nil {
			return err
		}
		if _, err := readFullWithDeadline(conn, readBuf[:step], refreshDeadline); err != nil {
			return err
		}
		if !bytes.Equal(readBuf[:step], payload[:step]) {
			return errors.New("echo payload mismatch")
		}
		remaining -= int64(step)
	}
	return nil
}

func writeDataplanePerfTCPTransferHeader(conn net.Conn, tcpMode string, payloadBytes int64, refreshDeadline func() error) error {
	var modeByte byte
	switch tcpMode {
	case dataplanePerfTCPUploadMode:
		modeByte = 'U'
	case dataplanePerfTCPDownloadMode:
		modeByte = 'D'
	default:
		return fmt.Errorf("unsupported tcp transfer mode %q", tcpMode)
	}
	var header [9]byte
	header[0] = modeByte
	binary.BigEndian.PutUint64(header[1:], uint64(payloadBytes))
	if refreshDeadline != nil {
		if err := refreshDeadline(); err != nil {
			return err
		}
	}
	return writeAll(conn, header[:])
}

func readDataplanePerfTCPTransferHeader(conn net.Conn, expectedMode string) (int64, error) {
	var header [9]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, err
	}
	var expected byte
	switch expectedMode {
	case dataplanePerfTCPUploadMode:
		expected = 'U'
	case dataplanePerfTCPDownloadMode:
		expected = 'D'
	default:
		return 0, fmt.Errorf("unsupported tcp transfer mode %q", expectedMode)
	}
	if header[0] != expected {
		return 0, fmt.Errorf("unexpected tcp transfer mode %q", string([]byte{header[0]}))
	}
	payloadBytes := int64(binary.BigEndian.Uint64(header[1:]))
	if payloadBytes < 0 {
		return 0, errors.New("negative tcp transfer payload")
	}
	return payloadBytes, nil
}

func runDataplanePerfUDPConnection(target string, payloadBytes int64, ioChunkBytes int64, deadline time.Duration, idle time.Duration) (int64, error) {
	raddr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return 0, err
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if deadline <= 0 {
		deadline = 120 * time.Second
	}
	if idle <= 0 {
		idle = 10 * time.Second
	}
	packetSize := dataplanePerfUDPPacketSize(payloadBytes, ioChunkBytes)
	payload := bytes.Repeat([]byte("forward-perf-"), int(math.Ceil(float64(packetSize)/13.0)))
	payload = payload[:packetSize]
	readBuf := make([]byte, len(payload))
	stopAt := time.Now().Add(deadline)
	var successBytes int64
	consecutiveLosses := 0

	for remaining := payloadBytes; remaining > 0; {
		step := dataplanePerfUDPPacketSize(remaining, ioChunkBytes)
		stepDeadline, ok := dataplanePerfUDPDeadline(time.Now(), stopAt, deadline, idle)
		if !ok {
			break
		}
		if err := conn.SetDeadline(stepDeadline); err != nil {
			return successBytes, err
		}
		if _, err := conn.Write(payload[:step]); err != nil {
			if isDataplanePerfTimeout(err) {
				consecutiveLosses++
				remaining -= int64(step)
				sleepDataplanePerfUDPBackoff(dataplanePerfUDPLossBackoff(consecutiveLosses, idle), nil)
				continue
			}
			return successBytes, err
		}
		n, err := conn.Read(readBuf[:step])
		if err != nil {
			if isDataplanePerfTimeout(err) {
				consecutiveLosses++
				remaining -= int64(step)
				sleepDataplanePerfUDPBackoff(dataplanePerfUDPLossBackoff(consecutiveLosses, idle), nil)
				continue
			}
			return successBytes, err
		}
		if n != step || !bytes.Equal(readBuf[:step], payload[:step]) {
			consecutiveLosses++
			remaining -= int64(step)
			sleepDataplanePerfUDPBackoff(dataplanePerfUDPLossBackoff(consecutiveLosses, idle), nil)
			continue
		}
		consecutiveLosses = 0
		remaining -= int64(step)
		successBytes += int64(step)
	}
	if successBytes == 0 {
		return 0, errors.New("udp benchmark produced no successful echoed payload")
	}
	return successBytes, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
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

func writeAllChunked(w io.Writer, data []byte, chunkSize int, refreshDeadline func() error) error {
	if chunkSize <= 0 {
		if refreshDeadline != nil {
			if err := refreshDeadline(); err != nil {
				return err
			}
		}
		return writeAll(w, data)
	}
	for len(data) > 0 {
		n := chunkSize
		if n > len(data) {
			n = len(data)
		}
		if refreshDeadline != nil {
			if err := refreshDeadline(); err != nil {
				return err
			}
		}
		if err := writeAll(w, data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func readFullWithDeadline(conn net.Conn, buf []byte, refreshDeadline func() error) (int, error) {
	read := 0
	for read < len(buf) {
		if refreshDeadline != nil {
			if err := refreshDeadline(); err != nil {
				return read, err
			}
		}
		n, err := conn.Read(buf[read:])
		if n > 0 {
			read += n
		}
		if err != nil {
			if err == io.EOF && read == len(buf) {
				return read, nil
			}
			return read, err
		}
		if n <= 0 {
			return read, io.ErrNoProgress
		}
	}
	return read, nil
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatal("repo root not found")
		}
		dir = next
	}
}

func requireEmbeddedEBPFObjects(t *testing.T, repoRoot string) {
	t.Helper()
	required := []string{
		filepath.Join(repoRoot, "internal", "app", "ebpf", "forward-tc-bpf.o"),
		filepath.Join(repoRoot, "internal", "app", "ebpf", "forward-tc-bpf-stats.o"),
		filepath.Join(repoRoot, "internal", "app", "ebpf", "forward-xdp-bpf.o"),
		filepath.Join(repoRoot, "internal", "app", "ebpf", "forward-xdp-bpf-stats.o"),
	}
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing embedded eBPF object %s; run `bash release.sh` first", path)
		}
	}
}

func buildDataplanePerfBinary(t *testing.T, repoRoot string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "forward-perf")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build forward binary: %v\n%s", err, string(output))
	}
	return out
}

func setupDataplanePerfTopology(t *testing.T) dataplanePerfTopology {
	t.Helper()

	suffix := strconv.Itoa(os.Getpid() % 100000)
	topology := dataplanePerfTopology{
		ClientNS:      "fwpc" + suffix,
		BackendNS:     "fwpb" + suffix,
		ClientHostIF:  truncateIfName("fwch" + suffix),
		ClientNSIF:    truncateIfName("fwcn" + suffix),
		BackendHostIF: truncateIfName("fwbh" + suffix),
		BackendNSIF:   truncateIfName("fwbn" + suffix),
	}

	cleanup := func() {
		runDataplanePerfCmd("ip", "link", "del", topology.ClientHostIF)
		runDataplanePerfCmd("ip", "link", "del", topology.BackendHostIF)
		runDataplanePerfCmd("ip", "netns", "del", topology.ClientNS)
		runDataplanePerfCmd("ip", "netns", "del", topology.BackendNS)
	}
	cleanup()
	t.Cleanup(cleanup)

	mustRunDataplanePerfCmd(t, "ip", "netns", "add", topology.ClientNS)
	mustRunDataplanePerfCmd(t, "ip", "netns", "add", topology.BackendNS)
	mustRunDataplanePerfCmd(t, "ip", "link", "add", topology.ClientHostIF, "type", "veth", "peer", "name", topology.ClientNSIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "add", topology.BackendHostIF, "type", "veth", "peer", "name", topology.BackendNSIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.ClientNSIF, "netns", topology.ClientNS)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.BackendNSIF, "netns", topology.BackendNS)

	mustRunDataplanePerfCmd(t, "ip", "addr", "add", dataplanePerfFrontAddr+"/24", "dev", topology.ClientHostIF)
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", dataplanePerfBackendHost+"/24", "dev", topology.BackendHostIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.ClientHostIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.BackendHostIF, "up")

	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "link", "set", "lo", "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "addr", "add", dataplanePerfClientAddr+"/24", "dev", topology.ClientNSIF)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "link", "set", topology.ClientNSIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "route", "replace", "default", "via", dataplanePerfFrontAddr, "dev", topology.ClientNSIF)

	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "link", "set", "lo", "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "addr", "add", dataplanePerfBackendAddr+"/24", "dev", topology.BackendNSIF)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "link", "set", topology.BackendNSIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "route", "replace", "default", "via", dataplanePerfBackendHost, "dev", topology.BackendNSIF)
	if dataplanePerfDisableOffloads() {
		bestEffortDisableDataplanePerfOffloads(t, topology)
	} else {
		t.Log("dataplane perf: keeping veth offloads enabled")
	}

	return topology
}

func seedDataplanePerfNeighbors(t *testing.T, topology dataplanePerfTopology) {
	t.Helper()

	mustRunDataplanePerfCmd(t, "ip", "route", "replace", dataplanePerfBackendAddr+"/32", "dev", topology.BackendHostIF, "src", dataplanePerfBackendHost)
	mustRunDataplanePerfCmd(t, "ip", "route", "replace", dataplanePerfClientAddr+"/32", "dev", topology.ClientHostIF, "src", dataplanePerfFrontAddr)

	runDataplanePerfCmd("ip", "neigh", "del", dataplanePerfBackendAddr, "dev", topology.BackendHostIF)
	runDataplanePerfCmd("ip", "neigh", "del", dataplanePerfClientAddr, "dev", topology.ClientHostIF)

	mustRunDataplanePerfCmd(t, "ip", "neigh", "replace", dataplanePerfBackendAddr, "lladdr", mustReadDataplanePerfNetnsMAC(t, topology.BackendNS, topology.BackendNSIF), "dev", topology.BackendHostIF, "nud", "permanent")
	mustRunDataplanePerfCmd(t, "ip", "neigh", "replace", dataplanePerfClientAddr, "lladdr", mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF), "dev", topology.ClientHostIF, "nud", "permanent")
}

func mustReadDataplanePerfNetnsMAC(t *testing.T, netns string, ifName string) string {
	t.Helper()

	cmd := exec.Command("ip", "netns", "exec", netns, "cat", "/sys/class/net/"+ifName+"/address")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("read MAC for %s/%s: %v", netns, ifName, err)
	}
	mac := strings.TrimSpace(string(output))
	if mac == "" {
		t.Fatalf("read MAC for %s/%s: empty address", netns, ifName)
	}
	return mac
}

func bestEffortDisableDataplanePerfOffloads(t *testing.T, topology dataplanePerfTopology) {
	t.Helper()

	if _, err := exec.LookPath("ethtool"); err != nil {
		t.Logf("dataplane perf: ethtool not found, skipping veth offload disable")
		return
	}

	features := []string{"rx", "tx", "sg", "tso", "ufo", "gso", "gro", "lro"}
	disable := func(prefix []string, ifName string) {
		for _, feature := range features {
			args := append(append([]string{}, prefix...), "-K", ifName, feature, "off")
			if output, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
				text := strings.TrimSpace(string(output))
				if text == "" {
					text = err.Error()
				}
				t.Logf("dataplane perf: ethtool %s %s off skipped: %s", ifName, feature, text)
			}
		}
	}

	disable([]string{"ethtool"}, topology.ClientHostIF)
	disable([]string{"ethtool"}, topology.BackendHostIF)
	disable([]string{"ip", "netns", "exec", topology.ClientNS, "ethtool"}, topology.ClientNSIF)
	disable([]string{"ip", "netns", "exec", topology.BackendNS, "ethtool"}, topology.BackendNSIF)
}

func dataplanePerfDisableOffloads() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(dataplanePerfOffloadsEnv)))
	switch raw {
	case "", "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func truncateIfName(name string) string {
	if len(name) <= 15 {
		return name
	}
	return name[:15]
}

func startDataplanePerfBackend(t *testing.T, topology dataplanePerfTopology) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()

	cmd := exec.Command("ip", "netns", "exec", topology.BackendNS, os.Args[0], "-test.run", "TestDataplanePerfHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(),
		dataplanePerfHelperEnv+"=1",
		dataplanePerfHelperRoleEnv+"=backend",
		dataplanePerfBackendEnv+"="+net.JoinHostPort(dataplanePerfBackendAddr, strconv.Itoa(dataplanePerfBackendPort)),
	)
	var stderr bytes.Buffer
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("backend stdout pipe: %v", err)
	}
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start backend helper: %v", err)
	}

	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "READY" {
				ready <- nil
				return
			}
		}
		if err := scanner.Err(); err != nil {
			ready <- err
			return
		}
		ready <- errors.New("backend helper exited before ready")
	}()

	select {
	case err := <-ready:
		if err != nil {
			stopDataplanePerfHelper(t, cmd)
			t.Fatalf("backend helper ready: %v\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		stopDataplanePerfHelper(t, cmd)
		t.Fatalf("backend helper ready timeout\n%s", stderr.String())
	}

	return cmd, &stderr
}

func stopDataplanePerfHelper(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	case <-done:
	}
}

func writeDataplanePerfConfig(t *testing.T, path string, mode dataplanePerfMode, webPort int) {
	t.Helper()

	cfg := Config{
		WebPort:           webPort,
		WebToken:          dataplanePerfToken,
		MaxWorkers:        1,
		DrainTimeoutHours: 1,
		DefaultEngine:     mode.Default,
		KernelEngineOrder: mode.Order,
		Experimental: map[string]bool{
			experimentalFeatureBridgeXDP:     false,
			experimentalFeatureKernelTraffic: false,
		},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func waitForDataplanePerfAPI(t *testing.T, apiBase string) {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, apiBase+"/api/tags", nil)
		if err != nil {
			t.Fatalf("build api request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("api %s not ready in time", apiBase)
}

func createDataplanePerfRule(t *testing.T, apiBase string, topology dataplanePerfTopology, mode dataplanePerfMode) {
	t.Helper()

	payload := map[string]any{
		"in_interface":      topology.ClientHostIF,
		"in_ip":             dataplanePerfFrontAddr,
		"in_port":           dataplanePerfFrontPort,
		"out_interface":     topology.BackendHostIF,
		"out_ip":            dataplanePerfBackendAddr,
		"out_port":          dataplanePerfBackendPort,
		"protocol":          dataplanePerfProtocol(),
		"transparent":       true,
		"engine_preference": mode.Default,
		"remark":            "dataplane-perf",
		"tag":               "perf",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal rule: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/rules", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build create rule request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create rule unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

func waitForDataplanePerfRule(t *testing.T, apiBase string, mode dataplanePerfMode) dataplanePerfRuleStatus {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, apiBase+"/api/rules", nil)
		if err != nil {
			t.Fatalf("build list rules request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		var rules []dataplanePerfRuleStatus
		err = json.NewDecoder(resp.Body).Decode(&rules)
		resp.Body.Close()
		if err != nil || len(rules) == 0 {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		rule := rules[0]
		if rule.Status != "running" {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if rule.EffectiveEngine != mode.Expected {
			t.Fatalf("%s benchmark requested %s but effective engine is %s (kernel=%s kernel_reason=%q fallback=%q)",
				mode.Name,
				mode.Expected,
				rule.EffectiveEngine,
				rule.EffectiveKernelEngine,
				rule.KernelReason,
				rule.FallbackReason,
			)
		}
		if mode.ExpectedKern != "" && rule.EffectiveKernelEngine != mode.ExpectedKern {
			t.Fatalf("%s benchmark requested kernel engine %s but effective kernel engine is %s (kernel_reason=%q fallback=%q)",
				mode.Name,
				mode.ExpectedKern,
				rule.EffectiveKernelEngine,
				rule.KernelReason,
				rule.FallbackReason,
			)
		}
		return rule
	}
	t.Fatalf("%s rule did not enter running/%s state in time", mode.Name, mode.Expected)
	return dataplanePerfRuleStatus{}
}

func runDataplanePerfClientBenchmark(t *testing.T, clientNS string, connections int, concurrency int, bytesPerConn int64, ioChunkBytes int64, steadySeconds int) dataplanePerfClientResult {
	t.Helper()

	result, err := runDataplanePerfClientBenchmarkRaw(clientNS, connections, concurrency, bytesPerConn, ioChunkBytes, steadySeconds)
	if err != nil {
		t.Fatalf("client benchmark failed: %v", err)
	}
	return result
}

func runDataplanePerfClientBenchmarkRaw(clientNS string, connections int, concurrency int, bytesPerConn int64, ioChunkBytes int64, steadySeconds int) (dataplanePerfClientResult, error) {
	cmd := exec.Command("ip", "netns", "exec", clientNS, os.Args[0], "-test.run", "TestDataplanePerfHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(),
		dataplanePerfHelperEnv+"=1",
		dataplanePerfHelperRoleEnv+"=client",
		dataplanePerfTargetEnv+"="+net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(dataplanePerfFrontPort)),
		dataplanePerfConnEnv+"="+strconv.Itoa(connections),
		dataplanePerfConcurrencyEnv+"="+strconv.Itoa(concurrency),
		dataplanePerfBytesEnv+"="+strconv.FormatInt(bytesPerConn, 10),
		dataplanePerfIOChunkEnv+"="+strconv.FormatInt(ioChunkBytes, 10),
		dataplanePerfSteadyEnv+"="+strconv.Itoa(steadySeconds),
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return dataplanePerfClientResult{}, fmt.Errorf("%w\n%s", err, strings.TrimSpace(stderr.String()))
	}

	var result dataplanePerfClientResult
	if err := json.Unmarshal(bytes.TrimSpace(output), &result); err != nil {
		return dataplanePerfClientResult{}, fmt.Errorf("decode client benchmark output: %w\nstdout=%s\nstderr=%s", err, string(output), stderr.String())
	}
	result.Elapsed = time.Duration(result.ElapsedSeconds * float64(time.Second))
	return result, nil
}

func stopForwardProcessTree(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return
	}
	rootPID := cmd.Process.Pid
	pids := listProcessTreePIDs(t, rootPID)

	_ = syscall.Kill(rootPID, syscall.SIGTERM)
	for _, pid := range pids {
		if pid == rootPID {
			continue
		}
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}

	for _, pid := range pids {
		if pid != rootPID && processExists(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	if processExists(rootPID) {
		_ = syscall.Kill(rootPID, syscall.SIGKILL)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil
}

func sampleProcessTreeJiffies(t *testing.T, rootPID int) int64 {
	t.Helper()
	var total int64
	for _, pid := range listProcessTreePIDs(t, rootPID) {
		jiffies, err := readProcJiffies(pid)
		if err != nil {
			continue
		}
		total += jiffies
	}
	return total
}

func listProcessTreePIDs(t *testing.T, rootPID int) []int {
	t.Helper()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("read /proc: %v", err)
	}
	children := make(map[int][]int)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		ppid, err := readProcPPID(pid)
		if err != nil {
			continue
		}
		children[ppid] = append(children[ppid], pid)
	}

	seen := map[int]struct{}{rootPID: {}}
	queue := []int{rootPID}
	out := []int{rootPID}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, child := range children[pid] {
			if _, ok := seen[child]; ok {
				continue
			}
			seen[child] = struct{}{}
			out = append(out, child)
			queue = append(queue, child)
		}
	}
	return out
}

func readProcPPID(pid int) (int, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	return parseProcStatPPID(string(data))
}

func readProcJiffies(pid int) (int64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	return parseProcStatJiffies(string(data))
}

func parseProcStatPPID(line string) (int, error) {
	after, err := procStatFieldsAfterComm(line)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(after)
	if len(fields) < 2 {
		return 0, errors.New("proc stat too short for ppid")
	}
	return strconv.Atoi(fields[1])
}

func parseProcStatJiffies(line string) (int64, error) {
	after, err := procStatFieldsAfterComm(line)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(after)
	if len(fields) < 15 {
		return 0, errors.New("proc stat too short for jiffies")
	}
	utime, err := strconv.ParseInt(fields[11], 10, 64)
	if err != nil {
		return 0, err
	}
	stime, err := strconv.ParseInt(fields[12], 10, 64)
	if err != nil {
		return 0, err
	}
	return utime + stime, nil
}

func procStatFieldsAfterComm(line string) (string, error) {
	end := strings.LastIndexByte(line, ')')
	if end < 0 || end+2 >= len(line) {
		return "", errors.New("malformed proc stat line")
	}
	return line[end+2:], nil
}

func procClockTicks(t *testing.T) int64 {
	t.Helper()
	out, err := exec.Command("getconf", "CLK_TCK").Output()
	if err != nil {
		t.Fatalf("getconf CLK_TCK: %v", err)
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		t.Fatalf("parse CLK_TCK: %v", err)
	}
	return value
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate tcp port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func copyFile(t *testing.T, src string, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open %s: %v", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatalf("create %s: %v", dst, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatalf("copy %s -> %s: %v", src, dst, err)
	}
}

func mustRunDataplanePerfCmd(t *testing.T, name string, args ...string) {
	t.Helper()
	if output, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, string(output))
	}
}

func runDataplanePerfCmd(name string, args ...string) {
	_ = exec.Command(name, args...).Run()
}

func dataplanePerfScenarios(defaultConnections int, defaultConcurrency int, defaultBytesPerConn int64, defaultIOChunkBytes int64, defaultWarmupConnections int, defaultWarmupBytesPerConn int64) []dataplanePerfScenario {
	connectionSeries := envIntList(dataplanePerfConnSeriesEnv)
	concurrencySeries := envIntList(dataplanePerfConcSeriesEnv)
	totalPayloadBytes := envInt64(dataplanePerfTotalBytesEnv, 0)
	if len(connectionSeries) == 0 {
		bytesPerConn := dataplanePerfBytesPerConn(defaultConnections, defaultBytesPerConn, totalPayloadBytes)
		ioChunkBytes := dataplanePerfIOChunkBytes(bytesPerConn, defaultIOChunkBytes)
		return []dataplanePerfScenario{{
			Label:              "default",
			Connections:        defaultConnections,
			Concurrency:        defaultConcurrency,
			BytesPerConnection: bytesPerConn,
			IOChunkBytes:       ioChunkBytes,
			WarmupConnections:  defaultWarmupConnections,
			WarmupBytesPerConn: minInt64(defaultWarmupBytesPerConn, bytesPerConn),
		}}
	}

	scenarios := make([]dataplanePerfScenario, 0, len(connectionSeries))
	for i, connections := range connectionSeries {
		concurrency := defaultConcurrency
		if len(concurrencySeries) > 0 {
			if i < len(concurrencySeries) {
				concurrency = concurrencySeries[i]
			} else {
				concurrency = concurrencySeries[len(concurrencySeries)-1]
			}
		}
		bytesPerConn := dataplanePerfBytesPerConn(connections, defaultBytesPerConn, totalPayloadBytes)
		ioChunkBytes := dataplanePerfIOChunkBytes(bytesPerConn, defaultIOChunkBytes)
		scenarios = append(scenarios, dataplanePerfScenario{
			Label:              fmt.Sprintf("conn-%d-conc-%d", connections, concurrency),
			Connections:        connections,
			Concurrency:        concurrency,
			BytesPerConnection: bytesPerConn,
			IOChunkBytes:       ioChunkBytes,
			WarmupConnections:  minInt(defaultWarmupConnections, maxInt(1, connections)),
			WarmupBytesPerConn: minInt64(defaultWarmupBytesPerConn, bytesPerConn),
		})
	}
	return scenarios
}

func selectDataplanePerfModes(t *testing.T, modes []dataplanePerfMode) []dataplanePerfMode {
	t.Helper()
	selected := strings.TrimSpace(os.Getenv(dataplanePerfModesEnv))
	if selected == "" {
		return modes
	}
	allowed := make(map[string]struct{})
	for _, item := range strings.Split(selected, ",") {
		name := strings.ToLower(strings.TrimSpace(item))
		if name == "" {
			continue
		}
		allowed[name] = struct{}{}
	}
	filtered := make([]dataplanePerfMode, 0, len(modes))
	for _, mode := range modes {
		if _, ok := allowed[strings.ToLower(mode.Name)]; ok {
			filtered = append(filtered, mode)
		}
	}
	if len(filtered) == 0 {
		t.Fatalf("no perf modes matched %q", selected)
	}
	return filtered
}

func dataplanePerfIOChunkBytes(bytesPerConn int64, configured int64) int64 {
	if configured <= 0 {
		configured = 16 << 10
	}
	if bytesPerConn > 0 && configured > bytesPerConn {
		return bytesPerConn
	}
	return configured
}

func dataplanePerfBytesPerConn(connections int, fallbackBytesPerConn int64, totalPayloadBytes int64) int64 {
	if connections <= 0 {
		return fallbackBytesPerConn
	}
	if totalPayloadBytes <= 0 {
		return fallbackBytesPerConn
	}
	bytesPerConn := (totalPayloadBytes + int64(connections) - 1) / int64(connections)
	if bytesPerConn < 4<<10 {
		return 4 << 10
	}
	return bytesPerConn
}

func dataplanePerfPacketCount(payloadBytes int64, ioChunkBytes int64) int64 {
	if payloadBytes <= 0 {
		return 0
	}
	if ioChunkBytes <= 0 {
		ioChunkBytes = 1
	}
	return (payloadBytes + ioChunkBytes - 1) / ioChunkBytes
}

func dataplanePerfUDPPacketSize(remaining int64, ioChunkBytes int64) int {
	if ioChunkBytes <= 0 {
		ioChunkBytes = 1472
	}
	if ioChunkBytes > 64<<10 {
		ioChunkBytes = 64 << 10
	}
	if remaining <= 0 {
		return int(ioChunkBytes)
	}
	if remaining < ioChunkBytes {
		return int(remaining)
	}
	return int(ioChunkBytes)
}

func dataplanePerfUDPDeadline(now time.Time, stopAt time.Time, deadline time.Duration, idle time.Duration) (time.Time, bool) {
	remaining := time.Until(stopAt)
	if !stopAt.IsZero() && remaining <= 0 {
		return time.Time{}, false
	}

	stepDeadline := deadline
	if stepDeadline <= 0 || (idle > 0 && idle < stepDeadline) {
		stepDeadline = idle
	}
	if !stopAt.IsZero() && (stepDeadline <= 0 || remaining < stepDeadline) {
		stepDeadline = remaining
	}
	if stepDeadline <= 0 {
		return time.Time{}, false
	}
	if now.IsZero() {
		now = time.Now()
	}
	return now.Add(stepDeadline), true
}

func dataplanePerfUDPLossBackoff(consecutiveLosses int, idle time.Duration) time.Duration {
	if consecutiveLosses < 4 {
		return 0
	}
	backoff := 250 * time.Microsecond
	shift := (consecutiveLosses - 4) / 4
	if shift > 4 {
		shift = 4
	}
	backoff <<= shift

	maxBackoff := 5 * time.Millisecond
	if idle > 0 {
		idleCap := idle / 4
		if idleCap > 0 && idleCap < maxBackoff {
			maxBackoff = idleCap
		}
	}
	if maxBackoff <= 0 {
		maxBackoff = 250 * time.Microsecond
	}
	if backoff > maxBackoff {
		return maxBackoff
	}
	return backoff
}

func sleepDataplanePerfUDPBackoff(backoff time.Duration, done <-chan struct{}) bool {
	if backoff <= 0 {
		return true
	}
	timer := time.NewTimer(backoff)
	defer timer.Stop()
	if done == nil {
		<-timer.C
		return true
	}
	select {
	case <-done:
		return false
	case <-timer.C:
		return true
	}
}

func isDataplanePerfTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envInt64(name string, fallback int64) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envIntList(name string) []int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || value <= 0 {
			continue
		}
		out = append(out, value)
	}
	return out
}

func safeRate(value float64, seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}
	return value / seconds
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func minInt64(a int64, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
