//go:build linux

package app

// Dataplane cost of the bundled XDP firewall plugin (docs/plugins/firewall/
// DESIGN.md §8, 性能): Veer TC port forwarding through the firewall next to
// the same forwarding without it, and a SYN flood dropped by the firewall, by
// an nftables netdev ingress rule, or by nothing.
//
// Both tests reuse TestDataplanePerfMatrix's topology (client namespace, veth
// pair, host, veth pair, backend namespace) and start the daemon given by
// FORWARD_PERF_BINARY with a transparent TC forward 198.18.0.1:10000 ->
// 198.19.0.2:20000. The firewall binds to the client-facing host veth.
//
// Run as root, with the daemon and the plugin directory (firewall.o built):
//
//	VEER_RUN_FIREWALL_PERF=1 FORWARD_PERF_BINARY=/path/veer \
//	VEER_FIREWALL_PERF_PLUGIN_DIR=/path/plugins/firewall \
//	go test ./internal/app -run '^TestFirewallPluginThroughput$' -count=1 -v -timeout=60m
//
// and -run '^TestFirewallPluginSYNFlood$' for the flood. Optional settings:
//
//	VEER_FIREWALL_PERF_PLUGIN_DIR   plugin directory (default <repo>/plugins/firewall)
//	VEER_FIREWALL_PERF_ROUNDS       paired rounds, medians over them (default 3)
//	VEER_FIREWALL_PERF_SECONDS      UDP steady seconds (default 6)
//	VEER_FIREWALL_PERF_CASES        throughput cases, comma-separated, or "all"
//	                                (default: every case marked default below)
//	VEER_FIREWALL_PERF_MIN_RATIOS   case=ratio,...: fail when a case's median
//	                                paired ratio (with / without) is lower
//	VEER_FIREWALL_PERF_TCP_BYTES    bulk TCP bytes per sample (default 4 GiB)
//	VEER_FIREWALL_PERF_TCP_CONNECTIONS (default 8)
//	VEER_FIREWALL_PERF_UDP_CONNECTIONS (default 64, all active)
//	VEER_FIREWALL_FLOOD_SECONDS     flood length per sample (default 5)
//	VEER_FIREWALL_FLOOD_SENDERS     sender threads, one CPU each (default 1)
//	VEER_FIREWALL_FLOOD_GENERATORS  xdp,packet (default both, see below)
//	VEER_FIREWALL_FLOOD_VARIANTS    none,xdp_native,tc_fallback,nft_ingress, or xdp_generic
//	                                instead of tc_fallback (one daemon cannot run both)
//	VEER_FIREWALL_FLOOD_TARGETS     forwarded (port 10000), host (port 10022)
//
// Every throughput sample starts its own daemon. A baseline sample runs the
// same forward without the plugin (not installed, plugins disabled), or, for
// the _vs_noop cases, with a bare XDP_PASS program in native mode instead;
// each case's sample sits next to its baseline, their order alternating by
// round and position like scripts/verify-plugin-release.sh's TC profiles,
// because the KVM test box drifts. The tc and generic cases raise the client
// veth's MTU to 9000 so native XDP cannot attach to the host veth (veth
// refuses native XDP when the peer MTU exceeds a page): the firewall then runs
// its tc_fallback ahead of the core, or, with the daemon's
// xdp_plugin_no_tc_fallback set, the dispatcher in generic mode. Their
// baselines use the same MTU. On veth, any native XDP
// program turns off the peer's TSO and makes veth copy each skb into an XDP
// buffer, which a physical NIC does not do: the noop_xdp_native cases measure
// that artifact, the _vs_noop cases the firewall's own cost on top of it.
//
// The flood has two generators in the client namespace. packet sends from
// AF_PACKET sockets: every frame is an skb from the start, which veth copies
// into an XDP buffer in native mode, so it understates what native XDP saves.
// xdp runs an XDP program that redirects into the client veth with
// BPF_PROG_RUN's live frame mode: the frames reach the host veth as XDP
// frames with no skb, as from a NIC driver, and veth builds an skb only for
// what XDP passes (GRO is turned on on the host veth so its NAPI takes frames
// without an XDP program). Either way the receive side runs in softirq on the
// sender's CPU, so the sender's rate is bounded by what a packet costs there.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	firewallPerfEnableEnv        = "VEER_RUN_FIREWALL_PERF"
	firewallPerfPluginDirEnv     = "VEER_FIREWALL_PERF_PLUGIN_DIR"
	firewallPerfRoundsEnv        = "VEER_FIREWALL_PERF_ROUNDS"
	firewallPerfSecondsEnv       = "VEER_FIREWALL_PERF_SECONDS"
	firewallPerfCasesEnv         = "VEER_FIREWALL_PERF_CASES"
	firewallPerfMinRatiosEnv     = "VEER_FIREWALL_PERF_MIN_RATIOS"
	firewallPerfTCPBytesEnv      = "VEER_FIREWALL_PERF_TCP_BYTES"
	firewallPerfTCPConnEnv       = "VEER_FIREWALL_PERF_TCP_CONNECTIONS"
	firewallPerfUDPConnEnv       = "VEER_FIREWALL_PERF_UDP_CONNECTIONS"
	firewallPerfFloodSecondsEnv  = "VEER_FIREWALL_FLOOD_SECONDS"
	firewallPerfFloodSendersEnv  = "VEER_FIREWALL_FLOOD_SENDERS"
	firewallPerfFloodVariantsEnv = "VEER_FIREWALL_FLOOD_VARIANTS"
	firewallPerfFloodTargetsEnv  = "VEER_FIREWALL_FLOOD_TARGETS"
	firewallPerfFloodGensEnv     = "VEER_FIREWALL_FLOOD_GENERATORS"

	firewallPerfHelperEnv       = "VEER_FIREWALL_PERF_HELPER"
	firewallPerfFloodIfaceEnv   = "VEER_FIREWALL_FLOOD_IFACE"
	firewallPerfFloodSrcMACEnv  = "VEER_FIREWALL_FLOOD_SRC_MAC"
	firewallPerfFloodDstMACEnv  = "VEER_FIREWALL_FLOOD_DST_MAC"
	firewallPerfFloodSrcIPEnv   = "VEER_FIREWALL_FLOOD_SRC_IP"
	firewallPerfFloodDstIPEnv   = "VEER_FIREWALL_FLOOD_DST_IP"
	firewallPerfFloodDstPortEnv = "VEER_FIREWALL_FLOOD_DST_PORT"
	firewallPerfFloodGenEnv     = "VEER_FIREWALL_FLOOD_GENERATOR"
	// udp_reply: the packet generator sends one UDP datagram over and over,
	// from firewallPerfReplySourcePort: the replies of a flow the host opened
	// (TestFirewallPluginEstablishedFlood).
	firewallPerfFloodFrameEnv = "VEER_FIREWALL_FLOOD_FRAME"

	// BPF_F_TEST_XDP_LIVE_FRAMES: BPF_PROG_RUN transmits what the program
	// redirects (Linux 5.18).
	firewallPerfXDPLiveFrames = 1 << 1

	firewallPerfAdminToken  = "firewall-perf-plugin-admin-token"
	firewallPerfFloodSource = "198.18.0.3"
	firewallPerfHostPort    = 10022
	firewallPerfJumboMTU    = 9000
	firewallPerfNFTTable    = "veer_fwperf"
	firewallPerfPolicyKey   = "svc"
)

type firewallPerfSetup struct {
	firewall  bool // install the plugin and bind it to the client-facing veth
	protected bool // the forwarded port is in a policy; the client is an allowed source
	jumbo     bool // client veth MTU 9000: no native XDP, the firewall runs its tc fallback
	// noTCFallback sets xdp_plugin_no_tc_fallback: on the jumbo veth the
	// dispatcher runs in generic mode instead.
	noTCFallback bool
	noopXDP      bool // no plugin: a bare XDP_PASS program in native mode
	// noopGeneric attaches the bare XDP_PASS program in generic mode.
	noopGeneric bool
	// noOffloads turns TSO, GSO and GRO off on both ends of the client veth
	// pair, as the core XDP engine's generic-mode guard does: generic XDP
	// then sees MTU-sized packets instead of linearizing 64 KB GSO ones.
	noOffloads bool
}

type firewallPerfCase struct {
	name      string
	workload  string // tcp: bulk upload; udp: 64-byte echo
	setup     firewallPerfSetup
	base      firewallPerfSetup // the adjacent baseline sample
	byDefault bool
}

var (
	firewallPerfPlain    = firewallPerfSetup{}
	firewallPerfJumbo    = firewallPerfSetup{jumbo: true}
	firewallPerfNoop     = firewallPerfSetup{noopXDP: true}
	firewallPerfNative   = firewallPerfSetup{firewall: true}
	firewallPerfNativeP  = firewallPerfSetup{firewall: true, protected: true}
	firewallPerfTC       = firewallPerfSetup{firewall: true, jumbo: true}
	firewallPerfTCP      = firewallPerfSetup{firewall: true, protected: true, jumbo: true}
	firewallPerfGeneric  = firewallPerfSetup{firewall: true, jumbo: true, noTCFallback: true}
	firewallPerfGenericP = firewallPerfSetup{firewall: true, protected: true, jumbo: true, noTCFallback: true}
)

// Cases against a plain baseline give what a user sees on this host. The
// _vs_noop cases pair the firewall with a bare native XDP program instead:
// on veth, attaching any native XDP program turns off the peer's TSO and
// makes veth copy every skb into an XDP buffer, which a physical NIC does not
// do, so these isolate the firewall's own cost (the design's native target).
// noop_xdp_native measures that veth artifact by itself.
var firewallPerfCases = []firewallPerfCase{
	{"tcp_native_unprotected", "tcp", firewallPerfNative, firewallPerfPlain, true},
	{"tcp_native_protected", "tcp", firewallPerfNativeP, firewallPerfPlain, false},
	{"tcp_native_unprotected_vs_noop", "tcp", firewallPerfNative, firewallPerfNoop, true},
	{"tcp_native_protected_vs_noop", "tcp", firewallPerfNativeP, firewallPerfNoop, true},
	{"tcp_tc_unprotected", "tcp", firewallPerfTC, firewallPerfJumbo, true},
	{"tcp_tc_protected", "tcp", firewallPerfTCP, firewallPerfJumbo, true},
	{"tcp_generic_unprotected", "tcp", firewallPerfGeneric, firewallPerfJumbo, true},
	{"tcp_generic_protected", "tcp", firewallPerfGenericP, firewallPerfJumbo, false},
	{"tcp_noop_xdp_native", "tcp", firewallPerfNoop, firewallPerfPlain, true},
	{"udp_native_unprotected", "udp", firewallPerfNative, firewallPerfPlain, true},
	{"udp_native_protected", "udp", firewallPerfNativeP, firewallPerfPlain, true},
	{"udp_native_unprotected_vs_noop", "udp", firewallPerfNative, firewallPerfNoop, false},
	{"udp_native_protected_vs_noop", "udp", firewallPerfNativeP, firewallPerfNoop, false},
	{"udp_tc_unprotected", "udp", firewallPerfTC, firewallPerfJumbo, true},
	{"udp_tc_protected", "udp", firewallPerfTCP, firewallPerfJumbo, false},
	{"udp_generic_unprotected", "udp", firewallPerfGeneric, firewallPerfJumbo, false},
	{"udp_noop_xdp_native", "udp", firewallPerfNoop, firewallPerfPlain, true},
	// Where generic mode's cost comes from: a bare generic program, and the
	// same with the client veth's offloads off.
	{"tcp_noop_xdp_generic", "tcp", firewallPerfSetup{jumbo: true, noopGeneric: true}, firewallPerfJumbo, false},
	{"tcp_jumbo_nooffload", "tcp", firewallPerfSetup{jumbo: true, noOffloads: true}, firewallPerfJumbo, false},
	{"tcp_noop_xdp_generic_nooffload", "tcp", firewallPerfSetup{jumbo: true, noopGeneric: true, noOffloads: true}, firewallPerfSetup{jumbo: true, noOffloads: true}, false},
	{"tcp_generic_unprotected_nooffload", "tcp", firewallPerfSetup{firewall: true, jumbo: true, noTCFallback: true, noOffloads: true}, firewallPerfSetup{jumbo: true, noOffloads: true}, false},
}

type firewallPerfWorkload struct {
	protocol string
	tcpMode  string
	scenario dataplanePerfScenario
	unit     string
}

func firewallPerfWorkloads(t *testing.T) map[string]firewallPerfWorkload {
	t.Helper()
	tcpConns := envInt(firewallPerfTCPConnEnv, 8)
	tcpBytes := envInt64(firewallPerfTCPBytesEnv, 4<<30)
	udpConns := envInt(firewallPerfUDPConnEnv, 64)
	seconds := envInt(firewallPerfSecondsEnv, 6)
	if tcpConns < 1 || tcpBytes < int64(tcpConns)<<20 || udpConns < 1 || seconds < 1 {
		t.Fatalf("invalid workload settings: %s=%d %s=%d %s=%d %s=%d", firewallPerfTCPConnEnv, tcpConns,
			firewallPerfTCPBytesEnv, tcpBytes, firewallPerfUDPConnEnv, udpConns, firewallPerfSecondsEnv, seconds)
	}
	return map[string]firewallPerfWorkload{
		"tcp": {
			protocol: "tcp",
			tcpMode:  dataplanePerfTCPUploadMode,
			scenario: dataplanePerfScenario{
				Label:              "bulk-tcp-upload",
				Connections:        tcpConns,
				Concurrency:        tcpConns,
				BytesPerConnection: tcpBytes / int64(tcpConns),
				IOChunkBytes:       128 << 10,
				WarmupConnections:  2,
				WarmupBytesPerConn: 16 << 20,
			},
			unit: "MiB/s",
		},
		"udp": {
			protocol: "udp",
			tcpMode:  dataplanePerfTCPEchoMode,
			scenario: dataplanePerfScenario{
				Label:              "udp-64-echo",
				Connections:        udpConns,
				Concurrency:        udpConns,
				BytesPerConnection: 64,
				IOChunkBytes:       64,
				WarmupConnections:  8,
				WarmupBytesPerConn: 64,
				SteadySeconds:      seconds,
			},
			unit: "pps",
		},
	}
}

type firewallPerfHarness struct {
	binary    string
	pluginDir string
	topology  dataplanePerfTopology
	mode      dataplanePerfMode
}

func newFirewallPerfHarness(t *testing.T) *firewallPerfHarness {
	t.Helper()
	if os.Getenv(firewallPerfEnableEnv) != "1" {
		t.Skipf("set %s=1 to run the firewall plugin dataplane performance test", firewallPerfEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
	pluginDir := strings.TrimSpace(os.Getenv(firewallPerfPluginDirEnv))
	if pluginDir == "" {
		pluginDir = filepath.Join(findRepoRoot(t), "plugins", "firewall")
	}
	for _, name := range []string{"plugin.json", "control.js", "firewall.o"} {
		if _, err := os.Stat(filepath.Join(pluginDir, name)); err != nil {
			t.Fatalf("firewall plugin directory %s is incomplete (build firewall.o with scripts/build-plugin-ebpf.sh): %v", pluginDir, err)
		}
	}
	binary := strings.TrimSpace(os.Getenv(dataplanePerfBinaryEnv))
	if binary == "" {
		repoRoot := findRepoRoot(t)
		requireEmbeddedEBPFObjects(t, repoRoot)
		binary = buildDataplanePerfBinary(t, repoRoot)
	} else if _, err := os.Stat(binary); err != nil {
		t.Fatalf("%s=%q is not usable: %v", dataplanePerfBinaryEnv, binary, err)
	}
	_ = rlimit.RemoveMemlock()
	h := &firewallPerfHarness{
		binary:    binary,
		pluginDir: pluginDir,
		topology:  setupDataplanePerfTopology(t),
		mode: dataplanePerfMode{
			Name:         "tc",
			Default:      ruleEngineKernel,
			Order:        []string{kernelEngineTC},
			Expected:     ruleEngineKernel,
			ExpectedKern: kernelEngineTC,
		},
	}
	t.Cleanup(cleanupTransparentRouting)
	t.Logf("firewall perf: kernel %s, %d CPUs, load %s, plugin %s", kernelRelease(), runtime.NumCPU(), firewallPerfLoadAverage(), pluginDir)
	return h
}

func firewallPerfRounds(t *testing.T) int {
	t.Helper()
	rounds := envInt(firewallPerfRoundsEnv, 3)
	if rounds < 1 {
		t.Fatalf("%s must be at least 1", firewallPerfRoundsEnv)
	}
	if rounds < 3 {
		t.Logf("firewall perf: %d round(s); medians are meaningful from 3", rounds)
	}
	return rounds
}

func firewallPerfLoadAverage() string {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "unknown"
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return strings.TrimSpace(string(data))
	}
	return strings.Join(fields[:3], " ")
}

func (h *firewallPerfHarness) setClientMTU(t *testing.T, mtu int) {
	t.Helper()
	mustRunDataplanePerfCmd(t, "ip", "-n", h.topology.ClientNS, "link", "set", "dev", h.topology.ClientNSIF, "mtu", strconv.Itoa(mtu))
}

// TestFirewallPluginThroughput measures bulk TCP (MiB/s) and 64-byte UDP
// echo (pps) through the forward with the firewall bound in native mode on
// traffic to an unprotected and to a protected port, through its tc fallback
// and in generic mode on a veth without native XDP, and
// with a bare native XDP program, each against an adjacent baseline sample
// without the plugin.
func TestFirewallPluginThroughput(t *testing.T) {
	h := newFirewallPerfHarness(t)
	rounds := firewallPerfRounds(t)
	cases := selectFirewallPerfCases(t)
	minRatios := firewallPerfMinRatios(t, cases)
	workloads := firewallPerfWorkloads(t)

	type pairs struct {
		unit                      string
		baselines, values, ratios []float64
		baseSoftirq, valueSoftirq []float64
		baseBusy, valueBusy       []float64
		attach, baseAttach        string
	}
	results := map[string]*pairs{}
	for _, workloadName := range []string{"tcp", "udp"} {
		var selected []firewallPerfCase
		for _, c := range cases {
			if c.workload == workloadName {
				selected = append(selected, c)
			}
		}
		if len(selected) == 0 {
			continue
		}
		workload := workloads[workloadName]
		t.Setenv(dataplanePerfProtocolEnv, workload.protocol)
		t.Setenv(dataplanePerfTCPModeEnv, workload.tcpMode)
		backend, backendLogs := startDataplanePerfBackend(t, h.topology)
		for round := 1; round <= rounds; round++ {
			t.Logf("firewall perf: %s round %d/%d, load %s", workloadName, round, rounds, firewallPerfLoadAverage())
			order := append([]firewallPerfCase(nil), selected...)
			if round%2 == 0 {
				for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
					order[i], order[j] = order[j], order[i]
				}
			}
			for index, c := range order {
				var base, value firewallPerfSample
				if (round+index)%2 == 0 {
					base = h.throughputSample(t, c, workload, true)
					value = h.throughputSample(t, c, workload, false)
				} else {
					value = h.throughputSample(t, c, workload, false)
					base = h.throughputSample(t, c, workload, true)
				}
				p := results[c.name]
				if p == nil {
					p = &pairs{unit: workload.unit}
					results[c.name] = p
				}
				ratio := value.value / base.value
				p.baselines = append(p.baselines, base.value)
				p.values = append(p.values, value.value)
				p.ratios = append(p.ratios, ratio)
				p.baseSoftirq = append(p.baseSoftirq, base.softirqCores)
				p.valueSoftirq = append(p.valueSoftirq, value.softirqCores)
				p.baseBusy = append(p.baseBusy, base.busyCores)
				p.valueBusy = append(p.valueBusy, value.busyCores)
				p.attach, p.baseAttach = value.attach, base.attach
				t.Logf("firewall perf pair case=%s round=%d attach=%s base_attach=%s baseline=%.2f value=%.2f ratio=%.4f unit=%s busy_cores=%.2f/%.2f softirq_cores=%.2f/%.2f",
					c.name, round, value.attach, base.attach, base.value, value.value, ratio, workload.unit,
					base.busyCores, value.busyCores, base.softirqCores, value.softirqCores)
			}
		}
		stopDataplanePerfHelper(t, backend)
		if t.Failed() {
			t.Logf("backend helper logs:\n%s", backendLogs.String())
		}
	}

	type summary struct {
		Case         string  `json:"case"`
		Attach       string  `json:"attach"`
		BaseAttach   string  `json:"baseline_attach"`
		Unit         string  `json:"unit"`
		Rounds       int     `json:"rounds"`
		Baseline     float64 `json:"baseline_median"`
		Value        float64 `json:"value_median"`
		Ratio        float64 `json:"paired_ratio_median"`
		BaseBusy     float64 `json:"baseline_busy_cores"`
		ValueBusy    float64 `json:"value_busy_cores"`
		BaseSoftirq  float64 `json:"baseline_softirq_cores"`
		ValueSoftirq float64 `json:"value_softirq_cores"`
		MinimumRatio float64 `json:"minimum_ratio,omitempty"`
	}
	var summaries []summary
	for _, c := range cases {
		p := results[c.name]
		if p == nil {
			continue
		}
		s := summary{
			Case: c.name, Attach: p.attach, BaseAttach: p.baseAttach, Unit: p.unit, Rounds: len(p.ratios),
			Baseline: firewallPerfMedian(p.baselines), Value: firewallPerfMedian(p.values), Ratio: firewallPerfMedian(p.ratios),
			BaseBusy: firewallPerfMedian(p.baseBusy), ValueBusy: firewallPerfMedian(p.valueBusy),
			BaseSoftirq: firewallPerfMedian(p.baseSoftirq), ValueSoftirq: firewallPerfMedian(p.valueSoftirq),
			MinimumRatio: minRatios[c.name],
		}
		summaries = append(summaries, s)
		t.Logf("firewall perf median case=%s attach=%s base_attach=%s baseline=%.2f value=%.2f paired_ratio=%.4f loss=%.2f%% unit=%s rounds=%d",
			s.Case, s.Attach, s.BaseAttach, s.Baseline, s.Value, s.Ratio, (1-s.Ratio)*100, s.Unit, s.Rounds)
	}
	data, _ := json.MarshalIndent(summaries, "", "  ")
	t.Logf("firewall perf summary:\n%s", data)
	for _, s := range summaries {
		if s.MinimumRatio > 0 && s.Ratio < s.MinimumRatio {
			t.Errorf("%s median paired ratio %.4f is below %.4f", s.Case, s.Ratio, s.MinimumRatio)
		}
	}
}

func selectFirewallPerfCases(t *testing.T) []firewallPerfCase {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(firewallPerfCasesEnv))
	if raw == "" || raw == "all" {
		var out []firewallPerfCase
		for _, c := range firewallPerfCases {
			if raw == "all" || c.byDefault {
				out = append(out, c)
			}
		}
		return out
	}
	wanted := map[string]bool{}
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			wanted[name] = true
		}
	}
	var out []firewallPerfCase
	for _, c := range firewallPerfCases {
		if wanted[c.name] {
			out = append(out, c)
			delete(wanted, c.name)
		}
	}
	if len(wanted) > 0 || len(out) == 0 {
		var names []string
		for _, c := range firewallPerfCases {
			names = append(names, c.name)
		}
		t.Fatalf("%s=%q: unknown or no cases; known: %s", firewallPerfCasesEnv, raw, strings.Join(names, ", "))
	}
	return out
}

func firewallPerfMinRatios(t *testing.T, cases []firewallPerfCase) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	raw := strings.TrimSpace(os.Getenv(firewallPerfMinRatiosEnv))
	if raw == "" {
		return out
	}
	known := map[string]bool{}
	for _, c := range cases {
		known[c.name] = true
	}
	for _, item := range strings.Split(raw, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(item), "=")
		ratio, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if !ok || err != nil || ratio <= 0 || ratio > 1 {
			t.Fatalf("%s: %q is not case=ratio with 0 < ratio <= 1", firewallPerfMinRatiosEnv, item)
		}
		if !known[strings.TrimSpace(name)] {
			t.Fatalf("%s names %q, which this run does not measure", firewallPerfMinRatiosEnv, name)
		}
		out[strings.TrimSpace(name)] = ratio
	}
	return out
}

type firewallPerfSample struct {
	value        float64
	attach       string
	busyCores    float64
	softirqCores float64
}

// throughputSample runs one sample with a daemon of its own: the case's setup,
// or with baseline the case's baseline setup.
func (h *firewallPerfHarness) throughputSample(t *testing.T, c firewallPerfCase, workload firewallPerfWorkload, baseline bool) firewallPerfSample {
	t.Helper()
	setup := c.setup
	if baseline {
		setup = c.base
	}
	cleanupTransparentRouting()
	clearFirewallPerfXDP(t, h.topology.ClientHostIF)
	mtu := 1500
	if setup.jumbo {
		mtu = firewallPerfJumboMTU
	}
	h.setClientMTU(t, mtu)
	if setup.noOffloads {
		restore := setFirewallPerfOffloads(t, h.topology, "off")
		defer restore()
	}

	pluginDir := ""
	if setup.firewall {
		pluginDir = h.pluginDir
	}
	d := startFirewallPerfDaemon(t, h.binary, pluginDir, setup.noTCFallback)
	defer d.stop()
	seedDataplanePerfNeighbors(t, h.topology)
	createDataplanePerfRule(t, d.base, h.topology, h.mode)
	waitForDataplanePerfRule(t, d.base, h.mode)

	attach := "none"
	if setup.firewall {
		d.applyFirewall([]string{h.topology.ClientHostIF}, firewallPerfRules(setup.protected))
		want := uint32(nl.XDP_ATTACHED_DRV)
		if setup.jumbo && setup.noTCFallback {
			want = nl.XDP_ATTACHED_SKB
		}
		if setup.jumbo && !setup.noTCFallback {
			waitFirewallPerfTCFallback(t, h.topology.ClientHostIF)
			attach = "firewall-tc"
		} else {
			waitFirewallPerfXDP(t, h.topology.ClientHostIF, want)
			attach = "firewall-" + firewallPerfAttachLabel(want)
		}
	}
	if setup.noopXDP || setup.noopGeneric {
		detach := attachFirewallPerfNoopXDP(t, h.topology.ClientHostIF, setup.noopGeneric)
		defer detach()
		attach = "noop-native"
		if setup.noopGeneric {
			attach = "noop-generic"
		}
	}

	s := workload.scenario
	if _, err := runDataplanePerfClientBenchmarkRaw(h.topology.ClientNS, s.WarmupConnections, minInt(s.Concurrency, maxInt(1, s.WarmupConnections)), s.WarmupBytesPerConn, s.IOChunkBytes, 0); err != nil {
		d.logTail(t)
		logDataplanePerfInterfaceStats(t, h.topology, c.name+" interface stats after warmup failure")
		t.Fatalf("%s warmup failed (baseline=%t): %v", c.name, baseline, err)
	}
	time.Sleep(500 * time.Millisecond)

	var passBefore float64
	if setup.firewall {
		passBefore, _ = d.policyCounters(firewallPerfPolicyKey)
	}
	hz := procClockTicks(t)
	cpuStart := readDataplanePerfCPUStat(t)
	client, err := runDataplanePerfClientBenchmarkRaw(h.topology.ClientNS, s.Connections, s.Concurrency, s.BytesPerConnection, s.IOChunkBytes, s.SteadySeconds)
	cpuEnd := readDataplanePerfCPUStat(t)
	if err != nil {
		d.logTail(t)
		logDataplanePerfInterfaceStats(t, h.topology, c.name+" interface stats after client failure")
		t.Fatalf("%s client failed (baseline=%t): %v", c.name, baseline, err)
	}
	result := dataplanePerfBuildResult(c.name, s, client, 0, ruleEngineKernel, kernelEngineTC)
	sample := firewallPerfSample{
		value:     result.PayloadMiBPerSec,
		attach:    attach,
		busyCores: dataplanePerfBusyCores(cpuStart, cpuEnd, hz, client.Elapsed),
	}
	if workload.unit == "pps" {
		sample.value = result.PayloadPPS
	}
	if client.Elapsed > 0 {
		sample.softirqCores = float64(cpuEnd.SoftIRQ-cpuStart.SoftIRQ) / float64(hz) / client.Elapsed.Seconds()
	}
	if sample.value <= 0 {
		t.Fatalf("%s measured no throughput (baseline=%t): %+v", c.name, baseline, client)
	}
	// The policy's pass counter tells which path the packets took: the
	// protected port's source lookups, or the port bitmap's early pass.
	if setup.firewall {
		passAfter, _ := d.policyCounters(firewallPerfPolicyKey)
		passed := passAfter - passBefore
		if setup.protected && passed <= 0 {
			t.Fatalf("%s: the %s policy passed no packets; traffic did not take the protected path", c.name, firewallPerfPolicyKey)
		}
		if !setup.protected && passed != 0 {
			t.Fatalf("%s: the %s policy passed %.0f packets to an unprotected port", c.name, firewallPerfPolicyKey, passed)
		}
	}
	return sample
}

// --- daemon and plugin API ---

type firewallPerfDaemon struct {
	t       *testing.T
	cmd     *exec.Cmd
	dir     string
	base    string
	logPath string
	logFile *os.File
	created map[string]bool
}

// startFirewallPerfDaemon starts the daemon in a fresh work directory; with
// pluginDir set, the firewall plugin is installed and plugins are enabled,
// otherwise plugins stay off as in a plain installation.
func startFirewallPerfDaemon(t *testing.T, binary, pluginDir string, noTCFallback bool) *firewallPerfDaemon {
	t.Helper()
	dir, err := os.MkdirTemp("", "veer-fwperf-")
	if err != nil {
		t.Fatalf("create daemon work dir: %v", err)
	}
	cfg := Config{
		WebBind:           "127.0.0.1",
		WebPort:           freeTCPPort(t),
		WebToken:          dataplanePerfToken,
		MaxWorkers:        1,
		DrainTimeoutHours: 1,
		DefaultEngine:     ruleEngineKernel,
		KernelEngineOrder: []string{kernelEngineTC},
		Experimental: map[string]bool{
			experimentalFeatureBridgeXDP:     false,
			experimentalFeatureKernelTraffic: false,
		},
	}
	if noTCFallback {
		cfg.Experimental[experimentalFeatureXDPPluginNoTCFallback] = true
	}
	if pluginDir != "" {
		copyDirForTest(t, pluginDir, filepath.Join(dir, "plugins", "firewall"))
		enabled, disabled := true, false
		cfg.PluginAdminToken = firewallPerfAdminToken
		cfg.PluginsDir = filepath.Join(dir, "plugins")
		cfg.PluginsEnabledSetting = &enabled
		cfg.PluginsDataplaneSetting = &enabled
		cfg.PluginsMinSandboxLevel = pluginSandboxLevelNone
		cfg.PluginsRequireSigned = &disabled
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	d := &firewallPerfDaemon{
		t:       t,
		dir:     dir,
		base:    fmt.Sprintf("http://127.0.0.1:%d", cfg.WebPort),
		logPath: filepath.Join(dir, "veer.log"),
		created: map[string]bool{},
	}
	if d.logFile, err = os.Create(d.logPath); err != nil {
		t.Fatalf("create daemon log: %v", err)
	}
	d.cmd = exec.Command(binary, "--config", configPath)
	d.cmd.Dir = dir
	d.cmd.Env = append(os.Environ(), forwardKernelMaintenanceIntervalEnv+"="+strconv.Itoa(envInt(forwardKernelMaintenanceIntervalEnv, 600000)))
	d.cmd.Stdout, d.cmd.Stderr = d.logFile, d.logFile
	d.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := d.cmd.Start(); err != nil {
		d.logFile.Close()
		_ = os.RemoveAll(dir)
		t.Fatalf("start daemon: %v", err)
	}
	// A failed wait below ends the test before the caller can defer stop; a
	// daemon left behind would hold its interfaces and the caller's flock.
	t.Cleanup(d.stop)
	waitForEgressNATIntegrationAPIWithTimeout(t, d.base, d.cmd, d.logPath, 45*time.Second)
	if pluginDir != "" {
		waitForEgressNATIntegrationPluginAction(t, d.base, d.cmd, d.logPath, "firewall", "apply")
	}
	return d
}

func (d *firewallPerfDaemon) stop() {
	if d.cmd != nil {
		stopForwardProcessTree(d.t, d.cmd)
		d.cmd = nil
	}
	if d.t.Failed() {
		d.logTail(d.t)
	}
	if d.logFile != nil {
		d.logFile.Close()
		d.logFile = nil
	}
	_ = os.RemoveAll(d.dir)
}

func (d *firewallPerfDaemon) logTail(t *testing.T) {
	data, err := os.ReadFile(d.logPath)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > 120 {
		lines = lines[len(lines)-120:]
	}
	t.Logf("daemon log (tail):\n%s", strings.Join(lines, "\n"))
}

func (d *firewallPerfDaemon) request(method, path string, payload any) []byte {
	d.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		d.t.Fatalf("marshal %s %s: %v", method, path, err)
	}
	req, err := http.NewRequest(method, d.base+path, bytes.NewReader(body))
	if err != nil {
		d.t.Fatalf("build %s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	req.Header.Set(pluginAdminTokenHeader, firewallPerfAdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		d.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		d.logTail(d.t)
		d.t.Fatalf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, out)
	}
	return out
}

func (d *firewallPerfDaemon) action(id string, payload map[string]any) map[string]any {
	d.t.Helper()
	if payload == nil {
		payload = map[string]any{}
	}
	var response struct {
		Result map[string]any `json:"result"`
	}
	out := d.request(http.MethodPost, "/api/plugins/firewall/actions/"+id, map[string]any{"payload": payload})
	if err := json.Unmarshal(out, &response); err != nil {
		d.t.Fatalf("decode firewall %s: %v: %s", id, err, out)
	}
	return response.Result
}

func (d *firewallPerfDaemon) save(resource, key string, data map[string]any) {
	d.t.Helper()
	id := resource + "/" + key
	if d.created[id] {
		d.request(http.MethodPut, "/api/plugins/firewall/resources/"+id, map[string]any{"enabled": true, "data": data})
		return
	}
	d.request(http.MethodPost, "/api/plugins/firewall/resources/"+resource, map[string]any{"key": key, "enabled": true, "data": data})
	d.created[id] = true
}

// applyFirewall writes the draft (interfaces, trusted sources, policies),
// applies it with its warnings accepted, as the page does once the user
// agrees, and confirms it.
func (d *firewallPerfDaemon) applyFirewall(interfaces []string, rules firewallPerfRuleSet) {
	d.t.Helper()
	if interfaces == nil {
		interfaces = []string{}
	}
	d.save("settings", "default", map[string]any{
		"interfaces":              interfaces,
		"trusted_sources":         rules.trusted,
		"confirm_timeout_seconds": 120,
	})
	for _, policy := range rules.policies {
		d.save("policies", policy.key, policy.data)
	}
	check := d.action("check", nil)
	if errs, _ := check["errors"].([]any); len(errs) > 0 {
		d.t.Fatalf("firewall check: %v", errs)
	}
	payload := map[string]any{}
	if token, _ := check["token"].(string); token != "" {
		payload["accept_warnings"] = token
	}
	d.action("apply", payload)
	d.action("confirm", nil)
}

// policyCounters reads a policy's pass and drop counters from the status action.
func (d *firewallPerfDaemon) policyCounters(key string) (pass, drop float64) {
	d.t.Helper()
	status := d.action("status", nil)
	policies, _ := status["policies"].([]any)
	for _, item := range policies {
		policy, _ := item.(map[string]any)
		if policy["key"] != key {
			continue
		}
		counters, _ := policy["counters"].(map[string]any)
		if counters == nil {
			d.t.Fatalf("firewall policy %s has no counters: %v", key, policy)
		}
		pass, _ = counters["pass"].(float64)
		drop, _ = counters["drop"].(float64)
		return pass, drop
	}
	d.t.Fatalf("firewall status has no policy %s: %v", key, status["policies"])
	return 0, 0
}

// --- rule set ---

type firewallPerfPolicy struct {
	key  string
	data map[string]any
}

type firewallPerfRuleSet struct {
	policies []firewallPerfPolicy
	trusted  []string
	allow4   []string // what lets an IPv4 source to the protected ports through: the nftables set
}

// firewallPerfRules builds a mid-sized deployment: the policy svc (tcp+udp,
// default drop) with the client 198.18.0.2 and 287 other IPv4 and 32 IPv6
// source prefixes (about a tenth of them dropped), three more policies on
// other ports, and four trusted sources. protected puts the forwarded port
// 10000 into svc; otherwise svc covers only the host port 10022 and the
// forwarded traffic passes at the port bitmap.
func firewallPerfRules(protected bool) firewallPerfRuleSet {
	rng := rand.New(rand.NewSource(11))
	seen := map[string]bool{}
	sources := func(count4, count6 int, allowed *[]string) []map[string]string {
		var out []map[string]string
		for added := 0; added < count4+count6; {
			cidr := firewallPerfRandomPrefix(rng, added >= count4)
			if seen[cidr] {
				continue
			}
			seen[cidr] = true
			action := "allow"
			if rng.Intn(10) == 0 {
				action = "drop"
			} else if allowed != nil && added < count4 {
				*allowed = append(*allowed, cidr)
			}
			out = append(out, map[string]string{"cidr": cidr, "action": action})
			added++
		}
		return out
	}
	rules := firewallPerfRuleSet{
		trusted: []string{"192.0.2.10/32", "198.51.100.0/29", "100.64.0.0/26", "2001:db8:ffff::1/128"},
		allow4:  []string{"198.18.0.2/32", "192.0.2.10/32", "198.51.100.0/29", "100.64.0.0/26"},
	}
	ports := []string{strconv.Itoa(firewallPerfHostPort)}
	if protected {
		ports = []string{strconv.Itoa(dataplanePerfFrontPort), strconv.Itoa(firewallPerfHostPort)}
	}
	svcSources := append([]map[string]string{{"cidr": dataplanePerfClientAddr + "/32", "action": "allow"}}, sources(287, 32, &rules.allow4)...)
	rules.policies = []firewallPerfPolicy{
		{firewallPerfPolicyKey, map[string]any{"name": firewallPerfPolicyKey, "protocol": "tcp+udp", "ports": ports, "default_action": "drop", "sources": svcSources}},
		{"ssh", map[string]any{"name": "ssh", "protocol": "tcp", "ports": []string{"22"}, "default_action": "drop", "sources": sources(64, 8, nil)}},
		{"db", map[string]any{"name": "db", "protocol": "tcp", "ports": []string{"3306", "5432", "6379"}, "default_action": "drop", "sources": sources(48, 0, nil)}},
		{"apps", map[string]any{"name": "apps", "protocol": "tcp", "ports": []string{"9000-9099"}, "default_action": "drop", "sources": sources(32, 0, nil)}},
	}
	return rules
}

// firewallPerfRandomPrefix returns a public-looking prefix outside the
// benchmark (198.18.0.0/15), documentation and trusted ranges.
func firewallPerfRandomPrefix(rng *rand.Rand, v6 bool) string {
	if v6 {
		ip := make(net.IP, 16)
		binary.BigEndian.PutUint64(ip, rng.Uint64())
		binary.BigEndian.PutUint64(ip[8:], rng.Uint64())
		ip[0] = 0x20 | ip[0]&0x0f // 2000::/4, clear of 2001:db8::/32 often enough; duplicates are skipped
		lengths := []int{32, 40, 48, 48, 56, 64, 64, 128}
		mask := net.CIDRMask(lengths[rng.Intn(len(lengths))], 128)
		return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, rng.Uint32())
	for {
		ip[0] = 1 + byte(rng.Intn(223))
		switch ip[0] {
		case 10, 100, 127, 192, 198:
			continue
		}
		break
	}
	lengths := []int{16, 18, 20, 22, 24, 24, 24, 24, 26, 28, 32, 32, 32}
	mask := net.CIDRMask(lengths[rng.Intn(len(lengths))], 32)
	return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
}

// --- XDP state ---

func firewallPerfAttachLabel(mode uint32) string {
	switch mode {
	case nl.XDP_ATTACHED_DRV:
		return "native"
	case nl.XDP_ATTACHED_SKB:
		return "generic"
	case nl.XDP_ATTACHED_HW:
		return "offload"
	case 0:
		return "detached"
	}
	return "mode-" + strconv.Itoa(int(mode))
}

func firewallPerfXDPState(ifName string) (uint32, error) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return 0, err
	}
	if xdp := link.Attrs().Xdp; xdp != nil && xdp.Attached {
		return uint32(xdp.AttachMode), nil
	}
	return 0, nil
}

// waitFirewallPerfXDP waits until ifName has an XDP program attached in mode
// want (nl.XDP_ATTACHED_*), or none with want 0.
func waitFirewallPerfXDP(t *testing.T, ifName string, want uint32) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		got, err := firewallPerfXDPState(ifName)
		if err == nil && got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s XDP is %s (err %v), want %s", ifName, firewallPerfAttachLabel(got), err, firewallPerfAttachLabel(want))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitFirewallPerfTCFallback waits until the firewall's tc_fallback runs at
// the head of ifName's TC ingress, with no XDP program on it.
func waitFirewallPerfTCFallback(t *testing.T, ifName string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		first, err := firewallPerfFirstTCProgram(ifName)
		xdp, xdpErr := firewallPerfXDPState(ifName)
		if err == nil && xdpErr == nil && xdp == 0 && first == "tc_firewall" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: first TC ingress program %q (err %v), XDP %s; want the firewall's tc fallback and no XDP", ifName, first, err, firewallPerfAttachLabel(xdp))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func waitFirewallPerfNoTCFallback(t *testing.T, ifName string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		first, err := firewallPerfFirstTCProgram(ifName)
		if err == nil && first != "tc_firewall" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the firewall's tc fallback is still attached (err %v)", ifName, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// firewallPerfFirstTCProgram names the program that runs first at ifName's
// TC ingress: the head of the tcx list, else the lowest-priority cls_bpf filter.
func firewallPerfFirstTCProgram(ifName string) (string, error) {
	l, err := netlink.LinkByName(ifName)
	if err != nil {
		return "", err
	}
	if kernelTCXSupported() {
		result, err := link.QueryPrograms(link.QueryOptions{Target: l.Attrs().Index, Attach: ebpf.AttachTCXIngress})
		if err == nil && len(result.Programs) > 0 {
			prog, err := ebpf.NewProgramFromID(result.Programs[0].ID)
			if err != nil {
				return "", err
			}
			defer prog.Close()
			info, err := prog.Info()
			if err != nil {
				return "", err
			}
			return info.Name, nil
		}
	}
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return "", err
	}
	name, lowest := "", uint16(0xffff)
	for _, filter := range filters {
		if bpf, ok := filter.(*netlink.BpfFilter); ok && bpf.Priority < lowest {
			name, lowest = bpf.Name, bpf.Priority
			if prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(bpf.Id)); err == nil {
				if info, err := prog.Info(); err == nil {
					name = info.Name
				}
				prog.Close()
			}
		}
	}
	return name, nil
}

// clearFirewallPerfXDP detaches whatever a stopped daemon left behind, so the
// next sample does not run through it.
func clearFirewallPerfXDP(t *testing.T, ifName string) {
	t.Helper()
	mode, err := firewallPerfXDPState(ifName)
	if err != nil || mode == 0 {
		return
	}
	t.Logf("firewall perf: %s still had a %s XDP program; detaching it", ifName, firewallPerfAttachLabel(mode))
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		t.Fatalf("link %s: %v", ifName, err)
	}
	for _, flags := range []int{nl.XDP_FLAGS_DRV_MODE, nl.XDP_FLAGS_SKB_MODE} {
		_ = netlink.LinkSetXdpFdWithFlags(link, -1, flags)
	}
	waitFirewallPerfXDP(t, ifName, 0)
}

// attachFirewallPerfNoopXDP attaches "return XDP_PASS" in native mode and
// returns its detach.
// setFirewallPerfOffloads switches TSO, GSO and GRO on both ends of the
// client veth pair and returns what puts the previous values back.
func setFirewallPerfOffloads(t *testing.T, topo dataplanePerfTopology, state string) func() {
	t.Helper()
	features := []string{"tso", "gso", "gro"}
	long := map[string]string{"tso": "tcp-segmentation-offload", "gso": "generic-segmentation-offload", "gro": "generic-receive-offload"}
	type end struct{ ns, ifName string }
	ends := []end{{"", topo.ClientHostIF}, {topo.ClientNS, topo.ClientNSIF}}
	ethtool := func(e end, args ...string) ([]byte, error) {
		if e.ns == "" {
			return exec.Command("ethtool", args...).CombinedOutput()
		}
		return exec.Command("ip", append([]string{"netns", "exec", e.ns, "ethtool"}, args...)...).CombinedOutput()
	}
	previous := make([][]string, len(ends))
	for i, e := range ends {
		out, err := ethtool(e, "-k", e.ifName)
		if err != nil {
			t.Fatalf("ethtool -k %s: %v: %s", e.ifName, err, out)
		}
		for _, f := range features {
			value := "on"
			if strings.Contains(string(out), long[f]+": off") {
				value = "off"
			}
			previous[i] = append(previous[i], f, value)
		}
		args := []string{"-K", e.ifName}
		for _, f := range features {
			args = append(args, f, state)
		}
		if out, err := ethtool(e, args...); err != nil {
			t.Fatalf("ethtool %v: %v: %s", args, err, out)
		}
	}
	return func() {
		for i, e := range ends {
			_, _ = ethtool(e, append([]string{"-K", e.ifName}, previous[i]...)...)
		}
	}
}

func attachFirewallPerfNoopXDP(t *testing.T, ifName string, generic bool) func() {
	t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "fwperf_noop",
		Type:         ebpf.XDP,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()},
	})
	if err != nil {
		t.Fatalf("load no-op XDP program: %v", err)
	}
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		prog.Close()
		t.Fatalf("link %s: %v", ifName, err)
	}
	flags, attached := nl.XDP_FLAGS_DRV_MODE, uint32(nl.XDP_ATTACHED_DRV)
	if generic {
		flags, attached = nl.XDP_FLAGS_SKB_MODE, uint32(nl.XDP_ATTACHED_SKB)
	}
	if err := netlink.LinkSetXdpFdWithFlags(link, prog.FD(), flags); err != nil {
		prog.Close()
		t.Fatalf("attach no-op XDP to %s (flags %d): %v", ifName, flags, err)
	}
	waitFirewallPerfXDP(t, ifName, attached)
	return func() {
		_ = netlink.LinkSetXdpFdWithFlags(link, -1, flags)
		prog.Close()
	}
}

// --- SYN flood ---

type firewallPerfFloodTarget struct {
	name string
	port int
}

type firewallPerfFloodResult struct {
	Generator       string  `json:"generator"`
	Target          string  `json:"target"`
	Variant         string  `json:"variant"`
	Round           int     `json:"round"`
	Attach          string  `json:"attach"`
	SentPPS         float64 `json:"sent_pps"`      // into the host veth
	GeneratedPPS    float64 `json:"generated_pps"` // as the generator counts them
	DroppedPPS      float64 `json:"dropped_pps"`
	ReachedPPS      float64 `json:"reached_tcp_segments_pps"` // the target's TCP stack
	HostInSegsPPS   float64 `json:"host_tcp_segments_pps"`    // the host's, for either target
	VethDropPPS     float64 `json:"veth_drop_pps"`
	SoftIRQCores    float64 `json:"softirq_cores"`
	SystemCores     float64 `json:"system_cores"`
	BusyCores       float64 `json:"busy_cores"`
	SoftIRQNsPerPkt float64 `json:"softirq_ns_per_packet"`
	BusyNsPerPkt    float64 `json:"busy_ns_per_packet"`
}

// TestFirewallPluginSYNFlood floods SYNs from 198.18.0.3, a source no policy
// allows, at the forwarded port 10000 and at a host listener on 10022, both
// in the firewall's svc policy, and compares what dropping them costs: the
// firewall in native mode and through its tc fallback (or, selected instead,
// in generic mode), an nftables netdev ingress rule with
// the same ports and allowed sources, and no filter (the TC forward takes the
// SYNs to the forwarded port, the host's listener answers the others with SYN
// cookies). The netdev ingress hook runs after TC ingress, so the nftables
// rule never sees what Veer's TC forward redirects. It reports the rate into
// the host veth, the drop rate from the filter's own counters, the TCP
// segments that still reached the target's stack and the host's, and the CPU
// spent (softirq and all busy time, per packet). The legitimate client must
// connect through every variant.
func TestFirewallPluginSYNFlood(t *testing.T) {
	h := newFirewallPerfHarness(t)
	rounds := firewallPerfRounds(t)
	seconds := envInt(firewallPerfFloodSecondsEnv, 5)
	senders := envInt(firewallPerfFloodSendersEnv, 1)
	if seconds < 3 || senders < 1 || senders > runtime.NumCPU() {
		t.Fatalf("invalid flood settings: %s=%d (min 3) %s=%d (1..%d)", firewallPerfFloodSecondsEnv, seconds, firewallPerfFloodSendersEnv, senders, runtime.NumCPU())
	}
	generators := firewallPerfSelect(t, firewallPerfFloodGensEnv, []string{"xdp", "packet"})
	variants := firewallPerfSelect(t, firewallPerfFloodVariantsEnv, []string{"none", "xdp_native", "tc_fallback", "nft_ingress", "xdp_generic"}, "none", "xdp_native", "tc_fallback", "nft_ingress")
	floodGeneric := slices.Contains(variants, "xdp_generic")
	if floodGeneric && slices.Contains(variants, "tc_fallback") {
		t.Fatalf("%s: tc_fallback and xdp_generic need differently configured daemons; select one", firewallPerfFloodVariantsEnv)
	}
	var targets []firewallPerfFloodTarget
	for _, name := range firewallPerfSelect(t, firewallPerfFloodTargetsEnv, []string{"forwarded", "host"}) {
		port := dataplanePerfFrontPort
		if name == "host" {
			port = firewallPerfHostPort
		}
		targets = append(targets, firewallPerfFloodTarget{name, port})
	}
	for _, variant := range variants {
		if variant == "nft_ingress" {
			if _, err := exec.LookPath("nft"); err != nil {
				t.Skip("nft command is required for the nft_ingress variant")
			}
		}
	}
	if _, err := exec.LookPath("ethtool"); err != nil {
		t.Skip("ethtool is required to switch GRO on the host veth")
	}

	t.Setenv(dataplanePerfProtocolEnv, "tcp")
	t.Setenv(dataplanePerfTCPModeEnv, dataplanePerfTCPEchoMode)
	backend, backendLogs := startDataplanePerfBackend(t, h.topology)
	defer func() {
		stopDataplanePerfHelper(t, backend)
		if t.Failed() {
			t.Logf("backend helper logs:\n%s", backendLogs.String())
		}
	}()
	mustRunDataplanePerfCmd(t, "ip", "-n", h.topology.ClientNS, "address", "add", firewallPerfFloodSource+"/24", "dev", h.topology.ClientNSIF)
	listener, err := net.Listen("tcp4", net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(firewallPerfHostPort)))
	if err != nil {
		t.Fatalf("listen on the host port: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { runDataplanePerfCmd("nft", "delete", "table", "netdev", firewallPerfNFTTable) })

	d := startFirewallPerfDaemon(t, h.binary, h.pluginDir, floodGeneric)
	defer d.stop()
	seedDataplanePerfNeighbors(t, h.topology)
	createDataplanePerfRule(t, d.base, h.topology, h.mode)
	waitForDataplanePerfRule(t, d.base, h.mode)
	rules := firewallPerfRules(true)
	d.applyFirewall(nil, rules)

	srcMAC := mustReadDataplanePerfNetnsMAC(t, h.topology.ClientNS, h.topology.ClientNSIF)
	hostIface, err := net.InterfaceByName(h.topology.ClientHostIF)
	if err != nil {
		t.Fatalf("interface %s: %v", h.topology.ClientHostIF, err)
	}
	dstMAC := hostIface.HardwareAddr.String()
	t.Cleanup(func() { runDataplanePerfCmd("ethtool", "-K", h.topology.ClientHostIF, "gro", "off") })

	var all []firewallPerfFloodResult
	for round := 1; round <= rounds; round++ {
		t.Logf("firewall flood: round %d/%d, load %s", round, rounds, firewallPerfLoadAverage())
		for gi, generator := range generators {
			// veth hands redirected XDP frames only to a peer with NAPI on;
			// GRO turns NAPI on without an XDP program.
			gro := "off"
			if generator == "xdp" {
				gro = "on"
			}
			mustRunDataplanePerfCmd(t, "ethtool", "-K", h.topology.ClientHostIF, "gro", gro)
			for ti, target := range targets {
				shift := (round + gi + ti) % len(variants)
				order := append(append([]string(nil), variants[shift:]...), variants[:shift]...)
				for _, variant := range order {
					attach := h.setFloodVariant(t, d, variant, rules)
					if !firewallPerfLegitConnects(h.topology.ClientNS) {
						d.logTail(t)
						t.Fatalf("%s: the allowed client cannot reach the forward", variant)
					}
					result := h.flood(t, d, generator, target, variant, seconds, senders, srcMAC, dstMAC)
					h.resetFloodVariant(t, d, variant, rules)
					result.Round, result.Attach = round, attach
					all = append(all, result)
					t.Logf("firewall flood generator=%s target=%s variant=%s round=%d attach=%s sent_pps=%.0f generated_pps=%.0f dropped_pps=%.0f reached_pps=%.0f host_insegs_pps=%.0f veth_drop_pps=%.0f softirq_cores=%.2f system_cores=%.2f busy_cores=%.2f softirq_ns/pkt=%.1f busy_ns/pkt=%.1f",
						generator, target.name, variant, round, attach, result.SentPPS, result.GeneratedPPS, result.DroppedPPS, result.ReachedPPS, result.HostInSegsPPS, result.VethDropPPS,
						result.SoftIRQCores, result.SystemCores, result.BusyCores, result.SoftIRQNsPerPkt, result.BusyNsPerPkt)
					if (strings.HasPrefix(variant, "xdp_") || variant == "tc_fallback") && result.DroppedPPS < 0.9*result.SentPPS {
						t.Errorf("%s/%s/%s dropped %.0f of %.0f pps", generator, target.name, variant, result.DroppedPPS, result.SentPPS)
					}
				}
			}
		}
	}

	var medians []firewallPerfFloodResult
	for _, generator := range generators {
		for _, target := range targets {
			for _, variant := range variants {
				var picked []firewallPerfFloodResult
				for _, r := range all {
					if r.Generator == generator && r.Target == target.name && r.Variant == variant {
						picked = append(picked, r)
					}
				}
				m := firewallPerfFloodMedian(picked)
				medians = append(medians, m)
				t.Logf("firewall flood median generator=%s target=%s variant=%s attach=%s sent_pps=%.0f generated_pps=%.0f dropped_pps=%.0f reached_pps=%.0f host_insegs_pps=%.0f softirq_cores=%.2f busy_cores=%.2f softirq_ns/pkt=%.1f busy_ns/pkt=%.1f rounds=%d",
					m.Generator, m.Target, m.Variant, m.Attach, m.SentPPS, m.GeneratedPPS, m.DroppedPPS, m.ReachedPPS, m.HostInSegsPPS, m.SoftIRQCores, m.BusyCores, m.SoftIRQNsPerPkt, m.BusyNsPerPkt, m.Round)
			}
		}
	}
	data, _ := json.MarshalIndent(medians, "", "  ")
	t.Logf("firewall flood summary (medians; round = samples):\n%s", data)
}

// firewallPerfFloodMedian takes each metric's median over one
// generator/target/variant's rounds; Round holds the number of rounds.
func firewallPerfFloodMedian(picked []firewallPerfFloodResult) firewallPerfFloodResult {
	median := func(get func(firewallPerfFloodResult) float64) float64 {
		values := make([]float64, len(picked))
		for i, r := range picked {
			values[i] = get(r)
		}
		return firewallPerfMedian(values)
	}
	return firewallPerfFloodResult{
		Generator: picked[0].Generator, Target: picked[0].Target, Variant: picked[0].Variant,
		Round: len(picked), Attach: picked[0].Attach,
		SentPPS:         median(func(r firewallPerfFloodResult) float64 { return r.SentPPS }),
		GeneratedPPS:    median(func(r firewallPerfFloodResult) float64 { return r.GeneratedPPS }),
		DroppedPPS:      median(func(r firewallPerfFloodResult) float64 { return r.DroppedPPS }),
		ReachedPPS:      median(func(r firewallPerfFloodResult) float64 { return r.ReachedPPS }),
		HostInSegsPPS:   median(func(r firewallPerfFloodResult) float64 { return r.HostInSegsPPS }),
		VethDropPPS:     median(func(r firewallPerfFloodResult) float64 { return r.VethDropPPS }),
		SoftIRQCores:    median(func(r firewallPerfFloodResult) float64 { return r.SoftIRQCores }),
		SystemCores:     median(func(r firewallPerfFloodResult) float64 { return r.SystemCores }),
		BusyCores:       median(func(r firewallPerfFloodResult) float64 { return r.BusyCores }),
		SoftIRQNsPerPkt: median(func(r firewallPerfFloodResult) float64 { return r.SoftIRQNsPerPkt }),
		BusyNsPerPkt:    median(func(r firewallPerfFloodResult) float64 { return r.BusyNsPerPkt }),
	}
}

// firewallPerfSelect returns the names env lists, each one of known; without
// env it returns defaults, or all of known when there are none.
func firewallPerfSelect(t *testing.T, env string, known []string, defaults ...string) []string {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(env))
	if raw == "" {
		if len(defaults) > 0 {
			return defaults
		}
		return known
	}
	var out []string
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		found := false
		for _, k := range known {
			if k == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: unknown %q; known: %s", env, name, strings.Join(known, ", "))
		}
		out = append(out, name)
	}
	return out
}

// setFloodVariant puts the filter in place, starting from no filter, the
// client MTU at 1500 and the firewall unbound; it returns the attachment.
func (h *firewallPerfHarness) setFloodVariant(t *testing.T, d *firewallPerfDaemon, variant string, rules firewallPerfRuleSet) string {
	t.Helper()
	ifName := h.topology.ClientHostIF
	switch variant {
	case "xdp_native":
		d.applyFirewall([]string{ifName}, rules)
		waitFirewallPerfXDP(t, ifName, nl.XDP_ATTACHED_DRV)
		return "firewall-native"
	case "xdp_generic":
		h.setClientMTU(t, firewallPerfJumboMTU)
		d.applyFirewall([]string{ifName}, rules)
		waitFirewallPerfXDP(t, ifName, nl.XDP_ATTACHED_SKB)
		return "firewall-generic"
	case "tc_fallback":
		h.setClientMTU(t, firewallPerfJumboMTU)
		d.applyFirewall([]string{ifName}, rules)
		waitFirewallPerfTCFallback(t, ifName)
		return "firewall-tc"
	case "nft_ingress":
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(firewallPerfNFTRuleset(ifName, rules.allow4, []int{dataplanePerfFrontPort, firewallPerfHostPort}))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("load nftables ruleset: %v\n%s", err, out)
		}
		return "nft-netdev-ingress"
	}
	return "none"
}

func (h *firewallPerfHarness) resetFloodVariant(t *testing.T, d *firewallPerfDaemon, variant string, rules firewallPerfRuleSet) {
	t.Helper()
	switch variant {
	case "xdp_native", "xdp_generic", "tc_fallback":
		d.applyFirewall(nil, rules)
		waitFirewallPerfXDP(t, h.topology.ClientHostIF, 0)
		if variant != "xdp_native" {
			waitFirewallPerfNoTCFallback(t, h.topology.ClientHostIF)
			h.setClientMTU(t, 1500)
		}
	case "nft_ingress":
		mustRunDataplanePerfCmd(t, "nft", "delete", "table", "netdev", firewallPerfNFTTable)
	}
}

// firewallPerfNFTRuleset drops what the svc policy drops at the same place
// in the packet's path as far as nftables gets: TCP to the ports from any
// IPv4 source outside the allowed prefixes and trusted sources.
func firewallPerfNFTRuleset(ifName string, allow4 []string, ports []int) string {
	portText := make([]string, len(ports))
	for i, port := range ports {
		portText[i] = strconv.Itoa(port)
	}
	return fmt.Sprintf(`table netdev %s {
	set allow4 {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { %s }
	}
	chain ingress {
		type filter hook ingress device "%s" priority -500; policy accept;
		tcp dport { %s } ip saddr != @allow4 counter drop
	}
}
`, firewallPerfNFTTable, strings.Join(allow4, ", "), ifName, strings.Join(portText, ", "))
}

var firewallPerfNFTCounter = regexp.MustCompile(`counter packets (\d+)`)

func firewallPerfLegitConnects(ns string) bool {
	script := fmt.Sprintf("exec 3<>/dev/tcp/%s/%d", dataplanePerfFrontAddr, dataplanePerfFrontPort)
	return exec.Command("ip", "netns", "exec", ns, "timeout", "3", "bash", "-c", script).Run() == nil
}

// flood runs the sender in the client namespace and measures a window inside
// its run: CPU from /proc/stat, drops from the filter's counter, segments
// that reached the target's TCP stack, and drops on the veth itself.
func (h *firewallPerfHarness) flood(t *testing.T, d *firewallPerfDaemon, generator string, target firewallPerfFloodTarget, variant string, seconds, senders int, srcMAC, dstMAC string) firewallPerfFloodResult {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", h.topology.ClientNS, os.Args[0], "-test.run", "^TestFirewallPerfHelperProcess$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		firewallPerfHelperEnv+"=1",
		// A goroutine preempted by signal inside BPF_PROG_RUN would restart
		// the run and send frames it does not count.
		"GODEBUG=asyncpreemptoff=1",
		firewallPerfFloodGenEnv+"="+generator,
		firewallPerfFloodIfaceEnv+"="+h.topology.ClientNSIF,
		firewallPerfFloodSrcMACEnv+"="+srcMAC,
		firewallPerfFloodDstMACEnv+"="+dstMAC,
		firewallPerfFloodSrcIPEnv+"="+firewallPerfFloodSource,
		firewallPerfFloodDstIPEnv+"="+dataplanePerfFrontAddr,
		firewallPerfFloodDstPortEnv+"="+strconv.Itoa(target.port),
		firewallPerfFloodSecondsEnv+"="+strconv.Itoa(seconds),
		firewallPerfFloodSendersEnv+"="+strconv.Itoa(senders),
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("flood stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start flood helper: %v", err)
	}
	started := make(chan struct{})
	lines := make(chan string, 4)
	go func() {
		scanner := bufio.NewScanner(stdout)
		once := sync.Once{}
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "START" {
				once.Do(func() { close(started) })
				continue
			}
			lines <- line
		}
		close(lines)
	}()
	select {
	case <-started:
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("flood helper did not start: %s", stderr.String())
	}

	drops := func() (float64, time.Time) {
		switch variant {
		case "xdp_native", "xdp_generic", "tc_fallback":
			_, drop := d.policyCounters(firewallPerfPolicyKey)
			return drop, time.Now()
		case "nft_ingress":
			out, err := exec.Command("nft", "list", "chain", "netdev", firewallPerfNFTTable, "ingress").CombinedOutput()
			match := firewallPerfNFTCounter.FindSubmatch(out)
			if err != nil || match == nil {
				t.Fatalf("read the nftables counter: %v\n%s", err, out)
			}
			value, _ := strconv.ParseFloat(string(match[1]), 64)
			return value, time.Now()
		}
		return 0, time.Now()
	}
	reached := func() float64 {
		if target.name == "forwarded" {
			return firewallPerfTCPInSegs(t, h.topology.BackendNS)
		}
		return firewallPerfTCPInSegs(t, "")
	}
	vethDrops := func() float64 {
		return firewallPerfIfaceCounter(t, h.topology.ClientNS, h.topology.ClientNSIF, "tx_dropped") +
			firewallPerfIfaceCounter(t, "", h.topology.ClientHostIF, "rx_dropped")
	}

	time.Sleep(500 * time.Millisecond)
	dropStart, dropStartAt := drops()
	// The xdp generator's own count includes the setup of each BPF_PROG_RUN
	// call (its page pool teardown waits for an RCU grace period); what the
	// host veth's queues took in the window is the rate that counts.
	received := func() (float64, time.Time) {
		return firewallPerfVethXDPPackets(t, h.topology.ClientHostIF), time.Now()
	}
	receivedStart, receivedStartAt := received()
	reachedStart, vethStart, hostStart := reached(), vethDrops(), firewallPerfTCPInSegs(t, "")
	pathStart := h.pathCounters(t, d)
	hz := procClockTicks(t)
	cpuStart, cpuStartAt := readDataplanePerfCPUStat(t), time.Now()
	time.Sleep(time.Duration(seconds)*time.Second - 1500*time.Millisecond)
	cpuEnd, cpuEndAt := readDataplanePerfCPUStat(t), time.Now()
	reachedEnd, vethEnd, hostEnd := reached(), vethDrops(), firewallPerfTCPInSegs(t, "")
	pathEnd := h.pathCounters(t, d)
	receivedEnd, receivedEndAt := received()
	dropEnd, dropEndAt := drops()

	var report struct {
		Sent    uint64  `json:"sent"`
		Failed  uint64  `json:"failed"`
		Elapsed float64 `json:"elapsed_seconds"`
	}
	var last string
	for line := range lines {
		last = line
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("flood helper: %v\n%s", err, stderr.String())
	}
	if err := json.Unmarshal([]byte(last), &report); err != nil || report.Elapsed <= 0 || report.Sent == 0 {
		t.Fatalf("flood helper report %q: %v\n%s", last, err, stderr.String())
	}
	window := cpuEndAt.Sub(cpuStartAt).Seconds()
	cores := func(delta int64) float64 { return float64(delta) / float64(hz) / window }
	logFirewallPerfPathCounters(t, fmt.Sprintf("%s/%s/%s", generator, target.name, variant), pathStart, pathEnd, window)
	result := firewallPerfFloodResult{
		Generator:     generator,
		Target:        target.name,
		Variant:       variant,
		SentPPS:       float64(report.Sent) / report.Elapsed,
		GeneratedPPS:  float64(report.Sent) / report.Elapsed,
		DroppedPPS:    (dropEnd - dropStart) / dropEndAt.Sub(dropStartAt).Seconds(),
		ReachedPPS:    (reachedEnd - reachedStart) / window,
		HostInSegsPPS: (hostEnd - hostStart) / window,
		VethDropPPS:   (vethEnd - vethStart) / window,
		SoftIRQCores:  cores(cpuEnd.SoftIRQ - cpuStart.SoftIRQ),
		SystemCores:   cores(cpuEnd.System - cpuStart.System),
		BusyCores:     dataplanePerfBusyCores(cpuStart, cpuEnd, hz, cpuEndAt.Sub(cpuStartAt)),
	}
	if generator == "xdp" {
		result.SentPPS = (receivedEnd - receivedStart) / receivedEndAt.Sub(receivedStartAt).Seconds()
	}
	if packets := result.SentPPS * window; packets > 0 {
		result.SoftIRQNsPerPkt = result.SoftIRQCores * window / packets * 1e9
		result.BusyNsPerPkt = result.BusyCores * window / packets * 1e9
	}
	if report.Failed > 0 {
		t.Logf("firewall flood %s/%s/%s: %d send calls failed", generator, target.name, variant, report.Failed)
	}
	return result
}

// pathCounters reads the counters along the forward's path, to tell where a
// flood's packets go: what the host sent toward the backend, what the backend
// veth and its IP and TCP layers took, softnet backlog drops, and Veer's own
// TC diag counters.
func (h *firewallPerfHarness) pathCounters(t *testing.T, d *firewallPerfDaemon) map[string]float64 {
	t.Helper()
	c := map[string]float64{
		"host->backend veth tx":         firewallPerfIfaceCounter(t, "", h.topology.BackendHostIF, "tx_packets"),
		"host->backend veth tx_dropped": firewallPerfIfaceCounter(t, "", h.topology.BackendHostIF, "tx_dropped"),
		"backend veth rx":               firewallPerfIfaceCounter(t, h.topology.BackendNS, h.topology.BackendNSIF, "rx_packets"),
		"backend veth rx_dropped":       firewallPerfIfaceCounter(t, h.topology.BackendNS, h.topology.BackendNSIF, "rx_dropped"),
	}
	for _, file := range []string{"snmp", "netstat"} {
		for _, ns := range []string{h.topology.BackendNS, ""} {
			var data []byte
			if ns == "" {
				data, _ = os.ReadFile("/proc/net/" + file)
			} else {
				data, _ = exec.Command("ip", "netns", "exec", ns, "cat", "/proc/net/"+file).Output()
			}
			where := "backend "
			if ns == "" {
				where = "host "
			}
			var header []string
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				if header == nil || header[0] != fields[0] {
					header = fields
					continue
				}
				for i := 1; i < len(fields) && i < len(header); i++ {
					if value, err := strconv.ParseFloat(fields[i], 64); err == nil {
						c[where+strings.TrimSuffix(header[0], ":")+"."+header[i]] = value
					}
				}
				header = nil
			}
		}
	}
	if data, err := os.ReadFile("/proc/net/softnet_stat"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				value, _ := strconv.ParseUint(fields[1], 16, 64)
				c["softnet backlog dropped"] += float64(value)
			}
		}
	}
	var runtime any
	if err := json.Unmarshal(d.request(http.MethodGet, "/api/kernel/runtime?refresh=1", nil), &runtime); err == nil {
		var walk func(prefix string, v any)
		walk = func(prefix string, v any) {
			switch v := v.(type) {
			case map[string]any:
				for k, child := range v {
					walk(prefix+"."+k, child)
				}
			case []any:
				for i, child := range v {
					walk(prefix+"."+strconv.Itoa(i), child)
				}
			case float64:
				c["veer"+prefix] = v
			}
		}
		walk("", runtime)
	}
	return c
}

func logFirewallPerfPathCounters(t *testing.T, label string, start, end map[string]float64, window float64) {
	t.Helper()
	keys := make([]string, 0, len(end))
	for k := range end {
		if end[k] != start[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "\n  %-60s %12.0f/s", k, (end[k]-start[k])/window)
	}
	t.Logf("firewall flood path counters %s:%s", label, b.String())
}

// firewallPerfVethXDPPackets sums a veth's rx_queue_N_xdp_packets: every
// frame and skb its NAPI took off the XDP ring.
func firewallPerfVethXDPPackets(t *testing.T, ifName string) float64 {
	t.Helper()
	out, err := exec.Command("ethtool", "-S", ifName).Output()
	if err != nil {
		t.Fatalf("ethtool -S %s: %v", ifName, err)
	}
	total, found := 0.0, false
	for _, line := range strings.Split(string(out), "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || !strings.HasPrefix(name, "rx_queue_") || !strings.HasSuffix(name, "_xdp_packets") {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			t.Fatalf("ethtool -S %s: %q: %v", ifName, line, err)
		}
		total, found = total+n, true
	}
	if !found {
		t.Fatalf("ethtool -S %s has no rx_queue_*_xdp_packets", ifName)
	}
	return total
}

// firewallPerfTCPInSegs reads Tcp InSegs from /proc/net/snmp in a namespace
// ("" for the host's).
func firewallPerfTCPInSegs(t *testing.T, ns string) float64 {
	t.Helper()
	var data []byte
	var err error
	if ns == "" {
		data, err = os.ReadFile("/proc/net/snmp")
	} else {
		data, err = exec.Command("ip", "netns", "exec", ns, "cat", "/proc/net/snmp").Output()
	}
	if err != nil {
		t.Fatalf("read /proc/net/snmp (%q): %v", ns, err)
	}
	var header []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Tcp:") {
			continue
		}
		fields := strings.Fields(line)
		if header == nil {
			header = fields
			continue
		}
		for i, name := range header {
			if name == "InSegs" && i < len(fields) {
				value, _ := strconv.ParseFloat(fields[i], 64)
				return value
			}
		}
	}
	t.Fatalf("no Tcp InSegs in /proc/net/snmp (%q)", ns)
	return 0
}

func firewallPerfIfaceCounter(t *testing.T, ns, ifName, counter string) float64 {
	t.Helper()
	path := "/sys/class/net/" + ifName + "/statistics/" + counter
	var data []byte
	var err error
	if ns == "" {
		data, err = os.ReadFile(path)
	} else {
		data, err = exec.Command("ip", "netns", "exec", ns, "cat", path).Output()
	}
	if err != nil {
		t.Fatalf("read %s (%q): %v", path, ns, err)
	}
	value, _ := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
	return value
}

// TestFirewallPerfHelperProcess is the SYN flood sender, run by
// TestFirewallPluginSYNFlood inside the client namespace.
func TestFirewallPerfHelperProcess(t *testing.T) {
	if os.Getenv(firewallPerfHelperEnv) != "1" {
		return
	}
	if err := runFirewallPerfFloodHelper(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

// firewallPerfMmsghdr is struct mmsghdr; Go pads it like C does.
type firewallPerfMmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
}

// runFirewallPerfFloodHelper floods prebuilt SYN frames out of the client
// veth from one pinned thread per sender until the deadline. It prints START
// when sending begins and a JSON report at the end.
func runFirewallPerfFloodHelper() error {
	ifName := os.Getenv(firewallPerfFloodIfaceEnv)
	srcMAC, err := net.ParseMAC(os.Getenv(firewallPerfFloodSrcMACEnv))
	if err != nil {
		return fmt.Errorf("source MAC: %w", err)
	}
	dstMAC, err := net.ParseMAC(os.Getenv(firewallPerfFloodDstMACEnv))
	if err != nil {
		return fmt.Errorf("destination MAC: %w", err)
	}
	src := net.ParseIP(os.Getenv(firewallPerfFloodSrcIPEnv)).To4()
	dst := net.ParseIP(os.Getenv(firewallPerfFloodDstIPEnv)).To4()
	port, err := strconv.Atoi(os.Getenv(firewallPerfFloodDstPortEnv))
	if src == nil || dst == nil || err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("flood addresses: src=%v dst=%v port=%d (%v)", src, dst, port, err)
	}
	seconds := envInt(firewallPerfFloodSecondsEnv, 5)
	senders := envInt(firewallPerfFloodSendersEnv, 1)
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return err
	}
	switch generator := os.Getenv(firewallPerfFloodGenEnv); generator {
	case "packet":
		frames := firewallPerfSYNFrames(srcMAC, dstMAC, src, dst, uint16(port), 1024)
		if os.Getenv(firewallPerfFloodFrameEnv) == "udp_reply" {
			frames = [][]byte{firewallPerfUDPFrame(srcMAC, dstMAC, src, dst, firewallPerfReplySourcePort, uint16(port))}
		}
		return firewallPerfDrive(senders, seconds, func(int) (func() (uint64, bool, error), func(), error) {
			return firewallPerfPacketSender(frames, iface.Index, dstMAC)
		})
	case "xdp":
		// One template: live-frame mode recycles its pages without
		// initializing them again, and a forwarder downstream rewrites the
		// headers in place (Veer's forward puts the backend's MAC, address and
		// port there). Sent again unchanged, such frames carry another host's
		// MAC and the host veth drops them before any filter or forwarder sees
		// them. So every run first writes the template's headers back.
		frames := firewallPerfSYNFrames(srcMAC, dstMAC, src, dst, uint16(port), 1)
		// udp_reply keeps one tuple: no random source port.
		fixed := os.Getenv(firewallPerfFloodFrameEnv) == "udp_reply"
		if fixed {
			frames = [][]byte{firewallPerfUDPFrame(srcMAC, dstMAC, src, dst, firewallPerfReplySourcePort, uint16(port))}
		}
		template := frames[0]
		_ = rlimit.RemoveMemlock()
		// Every frame gets a random source port, its TCP checksum updated to
		// match (RFC 1624; 16-bit words read and written in the same byte
		// order keep the ones' complement sum valid), then
		// bpf_redirect(ifindex, 0) sends it out of the client veth into the
		// host veth's XDP ring.
		const sportOff, csumOff = 14 + 20, 14 + 20 + 16
		restore := asm.Instructions{}
		for off := 0; off+4 <= len(template); off += 4 {
			restore = append(restore, asm.StoreImm(asm.R7, int16(off), int64(int32(binary.LittleEndian.Uint32(template[off:]))), asm.Word))
		}
		if rest := len(template) % 4; rest == 2 {
			off := len(template) - 2
			restore = append(restore, asm.StoreImm(asm.R7, int16(off), int64(binary.LittleEndian.Uint16(template[off:])), asm.Half))
		} else if rest != 0 {
			return fmt.Errorf("SYN template of %d bytes is not a whole number of 16-bit words", len(template))
		}
		fold := asm.Instructions{
			asm.Mov.Reg(asm.R1, asm.R9),
			asm.RSh.Imm(asm.R1, 16),
			asm.And.Imm(asm.R9, 0xffff),
			asm.Add.Reg(asm.R9, asm.R1),
		}
		insns := asm.Instructions{
			asm.LoadMem(asm.R7, asm.R1, 0, asm.Word), // xdp_md.data
			asm.LoadMem(asm.R3, asm.R1, 4, asm.Word), // xdp_md.data_end
			asm.Mov.Reg(asm.R4, asm.R7),
			asm.Add.Imm(asm.R4, int32(len(template))),
			asm.JGT.Reg(asm.R4, asm.R3, "redirect"),
		}
		insns = append(insns, restore...)
		random := asm.Instructions{
			asm.FnGetPrandomU32.Call(),
			asm.And.Imm(asm.R0, 0xffff),
			asm.Or.Imm(asm.R0, 0x0400),
			asm.LoadMem(asm.R8, asm.R7, sportOff, asm.Half),
			asm.LoadMem(asm.R9, asm.R7, csumOff, asm.Half),
			asm.StoreMem(asm.R7, sportOff, asm.R0, asm.Half),
			asm.Xor.Imm(asm.R9, 0xffff),
			asm.Xor.Imm(asm.R8, 0xffff),
			asm.Add.Reg(asm.R9, asm.R8),
			asm.Add.Reg(asm.R9, asm.R0),
		}
		if !fixed {
			insns = append(insns, random...)
			insns = append(insns, fold...)
			insns = append(insns, fold...)
			insns = append(insns,
				asm.Xor.Imm(asm.R9, 0xffff),
				asm.StoreMem(asm.R7, csumOff, asm.R9, asm.Half))
		}
		insns = append(insns,
			asm.Mov.Imm(asm.R1, int32(iface.Index)).WithSymbol("redirect"),
			asm.Mov.Imm(asm.R2, 0),
			asm.FnRedirect.Call(),
			asm.Return(),
		)
		prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name:         "fwperf_flood",
			Type:         ebpf.XDP,
			License:      "GPL",
			Instructions: insns,
		})
		if err != nil {
			return fmt.Errorf("load the XDP generator: %w", err)
		}
		defer prog.Close()
		if _, err := prog.Run(&ebpf.RunOptions{Data: frames[0], Repeat: 1, Flags: firewallPerfXDPLiveFrames}); err != nil {
			return fmt.Errorf("BPF_PROG_RUN live frames (Linux 5.18+): %w", err)
		}
		return firewallPerfDrive(senders, seconds, func(id int) (func() (uint64, bool, error), func(), error) {
			// Each call sets up and tears down a page pool; large calls
			// keep that out of the flood.
			const chunk = 1 << 20
			next := id
			return func() (uint64, bool, error) {
				frame := frames[next%len(frames)]
				next++
				if _, err := prog.Run(&ebpf.RunOptions{Data: frame, Repeat: chunk, Flags: firewallPerfXDPLiveFrames, BatchSize: 64}); err != nil {
					return 0, false, err
				}
				return chunk, false, nil
			}, func() {}, nil
		})
	default:
		return fmt.Errorf("%s=%q: want packet or xdp", firewallPerfFloodGenEnv, generator)
	}
}

// firewallPerfPacketSender sends from an AF_PACKET socket, 64 frames per
// sendmmsg call, bypassing the qdisc.
func firewallPerfPacketSender(frames [][]byte, ifindex int, dstMAC net.HardwareAddr) (func() (uint64, bool, error), func(), error) {
	const batch = 64
	// Protocol 0: the socket only sends, it receives nothing.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("AF_PACKET socket: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_QDISC_BYPASS, 1)
	addr := &unix.RawSockaddrLinklayer{
		Family:   unix.AF_PACKET,
		Protocol: firewallPerfHtons(unix.ETH_P_IP),
		Ifindex:  int32(ifindex),
		Halen:    6,
	}
	copy(addr.Addr[:], dstMAC)
	iovs := make([]unix.Iovec, len(frames))
	msgs := make([]firewallPerfMmsghdr, len(frames))
	for i := range frames {
		iovs[i].Base = &frames[i][0]
		iovs[i].SetLen(len(frames[i]))
		msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(addr))
		msgs[i].Hdr.Namelen = unix.SizeofSockaddrLinklayer
		msgs[i].Hdr.Iov = &iovs[i]
		msgs[i].Hdr.SetIovlen(1)
	}
	off := 0
	send := func() (uint64, bool, error) {
		n, _, errno := unix.Syscall(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgs[off])), batch)
		off = (off + batch) % len(msgs)
		if errno == unix.ENOBUFS || errno == unix.EAGAIN || errno == unix.EINTR {
			return 0, true, nil
		}
		if errno != 0 {
			return 0, false, fmt.Errorf("sendmmsg: %w", errno)
		}
		return uint64(n), false, nil
	}
	done := func() {
		runtime.KeepAlive(addr)
		runtime.KeepAlive(iovs)
		runtime.KeepAlive(frames)
		unix.Close(fd)
	}
	return send, done, nil
}

// firewallPerfDrive runs one sender per goroutine, each locked to its own
// thread pinned to a CPU from the last one down. prepare readies a sender on
// that thread and returns its step (packets sent, a transient failure) and
// cleanup. All start together and stop at the deadline.
func firewallPerfDrive(senders, seconds int, prepare func(id int) (func() (uint64, bool, error), func(), error)) error {
	var sent, failed atomic.Uint64
	var deadline time.Time
	start := make(chan struct{})
	ready := make(chan error, senders)
	errs := make(chan error, senders)
	var wg sync.WaitGroup
	for id := 0; id < senders; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			runtime.LockOSThread()
			var set unix.CPUSet
			set.Set((runtime.NumCPU() - 1 - id + runtime.NumCPU()) % runtime.NumCPU())
			_ = unix.SchedSetaffinity(0, &set)
			step, done, err := prepare(id)
			if err != nil {
				ready <- err
				return
			}
			defer done()
			ready <- nil
			<-start
			var local, localFailed uint64
			for time.Now().Before(deadline) {
				n, transient, err := step()
				if err != nil {
					errs <- err
					break
				}
				if transient {
					localFailed++
				}
				local += n
			}
			sent.Add(local)
			failed.Add(localFailed)
		}(id)
	}
	for i := 0; i < senders; i++ {
		if err := <-ready; err != nil {
			return err
		}
	}
	began := time.Now()
	deadline = began.Add(time.Duration(seconds) * time.Second)
	close(start)
	fmt.Println("START")
	wg.Wait()
	elapsed := time.Since(began)
	select {
	case err := <-errs:
		return err
	default:
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"sent":            sent.Load(),
		"failed":          failed.Load(),
		"elapsed_seconds": elapsed.Seconds(),
	})
}

func firewallPerfHtons(value uint16) uint16 {
	return value<<8 | value>>8
}

// firewallPerfSYNFrames builds count SYNs (MSS option, random source ports,
// sequence numbers and IP IDs) with valid checksums, so that a stack that
// gets them handles them as real connection attempts.
func firewallPerfSYNFrames(srcMAC, dstMAC net.HardwareAddr, src, dst net.IP, port uint16, count int) [][]byte {
	rng := rand.New(rand.NewSource(7))
	frames := make([][]byte, count)
	for i := range frames {
		frame := make([]byte, 14+20+24)
		copy(frame[0:6], dstMAC)
		copy(frame[6:12], srcMAC)
		binary.BigEndian.PutUint16(frame[12:], 0x0800)
		ip := frame[14:34]
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], 44)
		binary.BigEndian.PutUint16(ip[4:], uint16(rng.Intn(65536)))
		binary.BigEndian.PutUint16(ip[6:], 0x4000)
		ip[8], ip[9] = 64, 6
		copy(ip[12:16], src)
		copy(ip[16:20], dst)
		binary.BigEndian.PutUint16(ip[10:], firewallPerfChecksum(0, ip))
		tcp := frame[34:]
		binary.BigEndian.PutUint16(tcp[0:], uint16(1024+rng.Intn(64000)))
		binary.BigEndian.PutUint16(tcp[2:], port)
		binary.BigEndian.PutUint32(tcp[4:], rng.Uint32())
		tcp[12] = 6 << 4
		tcp[13] = 0x02
		binary.BigEndian.PutUint16(tcp[14:], 64240)
		copy(tcp[20:], []byte{2, 4, 0x05, 0xb4})
		pseudo := uint32(0)
		for j := 0; j < 4; j += 2 {
			pseudo += uint32(binary.BigEndian.Uint16(src[j:])) + uint32(binary.BigEndian.Uint16(dst[j:]))
		}
		pseudo += 6 + uint32(len(tcp))
		binary.BigEndian.PutUint16(tcp[16:], firewallPerfChecksum(pseudo, tcp))
		frames[i] = frame
	}
	return frames
}

func firewallPerfChecksum(sum uint32, data []byte) uint16 {
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func firewallPerfMedian(values []float64) float64 {
	if len(values) == 0 {
		return math.NaN()
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}
