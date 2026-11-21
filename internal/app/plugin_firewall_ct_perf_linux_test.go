//go:build linux

package app

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
)

// TestFirewallPluginEstablishedFlood compares what accepting the replies of
// a connection costs per packet: the firewall's connection tracking (a
// catch-all policy drops everything, fw_ct lets the replies through, in
// native XDP) against nftables with conntrack ("ct state established
// accept", then drop, on the same interface's input), and against no filter.
// The host opens one UDP flow to the client namespace; the client's packet
// generator then sends that flow's reply over and over to a host socket.
// Both filters accept every packet, so the difference is the cost of
// tracking: an XDP hash lookup before any skb against conntrack in the
// stack. A second set of variants floods a flow the host never opened, which
// both drop.
//
// Two generators, as in the SYN flood: xdp sends XDP frames into the host
// veth (no skb until something passes them, as from a NIC driver); packet
// sends skbs from AF_PACKET, which veth copies into an XDP buffer for any
// native XDP program, a cost no physical NIC has.
//
// The harness is TestFirewallPluginSYNFlood's (topology, daemon, packet
// generator):
//
//	VEER_RUN_FIREWALL_PERF=1 FORWARD_PERF_BINARY=/path/veer \
//	VEER_FIREWALL_PERF_PLUGIN_DIR=/path/plugins/firewall \
//	go test ./internal/app -run '^TestFirewallPluginEstablishedFlood$' -count=1 -v
//
// VEER_FIREWALL_FLOOD_VARIANTS picks from none, fw_ct, nft_ct, fw_ct_new and
// nft_ct_new; VEER_FIREWALL_PERF_ROUNDS and VEER_FIREWALL_FLOOD_SECONDS work
// as for the SYN flood.
const (
	firewallPerfReplySourcePort = 5353
	firewallPerfReplyHostPort   = 10023
	firewallPerfNFTCTTable      = "veer_fwperf_ct"
)

type firewallPerfReplyResult struct {
	Generator       string  `json:"generator"`
	Variant         string  `json:"variant"`
	Round           int     `json:"round"`
	SentPPS         float64 `json:"sent_pps"`
	DeliveredPPS    float64 `json:"delivered_pps"`
	SoftIRQCores    float64 `json:"softirq_cores"`
	SoftIRQNsPerPkt float64 `json:"softirq_ns_per_pkt"`
	BusyNsPerPkt    float64 `json:"busy_ns_per_pkt"`
}

func TestFirewallPluginEstablishedFlood(t *testing.T) {
	h := newFirewallPerfHarness(t)
	rounds := firewallPerfRounds(t)
	seconds := envInt(firewallPerfFloodSecondsEnv, 5)
	variants := firewallPerfSelect(t, firewallPerfFloodVariantsEnv, []string{"none", "fw_ct", "nft_ct", "fw_ct_new", "nft_ct_new"})
	generators := firewallPerfSelect(t, firewallPerfFloodGensEnv, []string{"xdp", "packet"})
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft command is required")
	}
	mustRunDataplanePerfCmd(t, "ip", "-n", h.topology.ClientNS, "address", "add", firewallPerfFloodSource+"/24", "dev", h.topology.ClientNSIF)
	clientMAC := mustReadDataplanePerfNetnsMAC(t, h.topology.ClientNS, h.topology.ClientNSIF)
	mustRunDataplanePerfCmd(t, "ip", "neigh", "replace", firewallPerfFloodSource, "lladdr", clientMAC, "dev", h.topology.ClientHostIF, "nud", "permanent")
	t.Cleanup(func() { runDataplanePerfCmd("nft", "delete", "table", "inet", firewallPerfNFTCTTable) })

	// The host end of the flow: bound, never read, a small buffer. Datagrams
	// past the filters count in Udp InDatagrams or RcvbufErrors.
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(dataplanePerfFrontAddr), Port: firewallPerfReplyHostPort})
	if err != nil {
		t.Fatalf("bind the host end: %v", err)
	}
	defer sock.Close()
	_ = sock.SetReadBuffer(4096)
	open := func() {
		t.Helper()
		if _, err := sock.WriteToUDP([]byte("open"), &net.UDPAddr{IP: net.ParseIP(firewallPerfFloodSource), Port: firewallPerfReplySourcePort}); err != nil {
			t.Fatalf("open the flow: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	d := startFirewallPerfDaemon(t, h.binary, h.pluginDir, false)
	defer d.stop()
	ifName := h.topology.ClientHostIF
	applyCT := func(interfaces []string) {
		t.Helper()
		if interfaces == nil {
			interfaces = []string{}
		}
		d.save("settings", "default", map[string]any{"interfaces": interfaces, "confirm_timeout_seconds": 120, "connection_tracking": true,
			"trusted_sources": []string{"192.0.2.10/32"}})
		d.save("policies", "inbound", map[string]any{"name": "inbound", "protocol": "any", "default_action": "drop"})
		check := d.action("check", nil)
		if errs, _ := check["errors"].([]any); len(errs) > 0 {
			t.Fatalf("firewall check: %v", errs)
		}
		payload := map[string]any{}
		if token, _ := check["token"].(string); token != "" {
			payload["accept_warnings"] = token
		}
		d.action("apply", payload)
		d.action("confirm", nil)
	}
	applyCT(nil)
	t.Cleanup(func() { runDataplanePerfCmd("ethtool", "-K", ifName, "gro", "off") })
	srcMAC := clientMAC
	hostIface, err := net.InterfaceByName(ifName)
	if err != nil {
		t.Fatal(err)
	}
	dstMAC := hostIface.HardwareAddr.String()

	set := func(variant string) {
		t.Helper()
		switch variant {
		case "fw_ct", "fw_ct_new":
			applyCT([]string{ifName})
			waitFirewallPerfXDP(t, ifName, nl.XDP_ATTACHED_DRV)
		case "nft_ct", "nft_ct_new":
			ruleset := fmt.Sprintf(`table inet %s {
	chain input {
		type filter hook input priority 0; policy accept;
		iifname %q ct state established,related counter accept
		iifname %q counter drop
	}
}
`, firewallPerfNFTCTTable, ifName, ifName)
			cmd := exec.Command("nft", "-f", "-")
			cmd.Stdin = strings.NewReader(ruleset)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("load nftables ruleset: %v\n%s", err, out)
			}
		}
		if !strings.HasSuffix(variant, "_new") {
			open()
		}
	}
	reset := func(variant string) {
		t.Helper()
		switch variant {
		case "fw_ct", "fw_ct_new":
			applyCT(nil)
			waitFirewallPerfXDP(t, ifName, 0)
		case "nft_ct", "nft_ct_new":
			mustRunDataplanePerfCmd(t, "nft", "delete", "table", "inet", firewallPerfNFTCTTable)
		}
	}

	var all []firewallPerfReplyResult
	for round := 1; round <= rounds; round++ {
		for gi, generator := range generators {
			// veth hands redirected XDP frames only to a peer with NAPI on;
			// GRO turns NAPI on without an XDP program.
			gro := "off"
			if generator == "xdp" {
				gro = "on"
			}
			mustRunDataplanePerfCmd(t, "ethtool", "-K", ifName, "gro", gro)
			shift := (round + gi) % len(variants)
			order := append(append([]string(nil), variants[shift:]...), variants[:shift]...)
			for _, variant := range order {
				set(variant)
				// _new variants flood a flow the host never opened: another
				// source port.
				port := firewallPerfReplyHostPort
				if strings.HasSuffix(variant, "_new") {
					port = firewallPerfReplyHostPort + 1
				}
				result := h.replyFlood(t, generator, port, seconds, srcMAC, dstMAC)
				reset(variant)
				result.Generator, result.Variant, result.Round = generator, variant, round
				all = append(all, result)
				t.Logf("established flood generator=%s variant=%s round=%d sent_pps=%.0f delivered_pps=%.0f softirq_cores=%.2f softirq_ns/pkt=%.1f busy_ns/pkt=%.1f",
					generator, variant, round, result.SentPPS, result.DeliveredPPS, result.SoftIRQCores, result.SoftIRQNsPerPkt, result.BusyNsPerPkt)
				if (variant == "fw_ct" || variant == "nft_ct") && result.DeliveredPPS < 0.9*result.SentPPS {
					t.Errorf("%s delivered %.0f of %.0f pps: replies of the open flow were dropped", variant, result.DeliveredPPS, result.SentPPS)
				}
				if strings.HasSuffix(variant, "_new") && result.DeliveredPPS > 0.01*result.SentPPS {
					t.Errorf("%s delivered %.0f of %.0f pps of a flow nobody opened", variant, result.DeliveredPPS, result.SentPPS)
				}
			}
		}
	}
	var medians []firewallPerfReplyResult
	for _, generator := range generators {
		for _, variant := range variants {
			var sent, delivered, cores, softirq, busy []float64
			for _, r := range all {
				if r.Generator == generator && r.Variant == variant {
					sent, delivered, cores = append(sent, r.SentPPS), append(delivered, r.DeliveredPPS), append(cores, r.SoftIRQCores)
					softirq, busy = append(softirq, r.SoftIRQNsPerPkt), append(busy, r.BusyNsPerPkt)
				}
			}
			m := firewallPerfReplyResult{Generator: generator, Variant: variant, Round: len(sent), SentPPS: firewallPerfMedian(sent),
				DeliveredPPS: firewallPerfMedian(delivered), SoftIRQCores: firewallPerfMedian(cores), SoftIRQNsPerPkt: firewallPerfMedian(softirq),
				BusyNsPerPkt: firewallPerfMedian(busy)}
			medians = append(medians, m)
			t.Logf("established flood median generator=%s variant=%s sent_pps=%.0f delivered_pps=%.0f softirq_ns/pkt=%.1f busy_ns/pkt=%.1f rounds=%d",
				m.Generator, m.Variant, m.SentPPS, m.DeliveredPPS, m.SoftIRQNsPerPkt, m.BusyNsPerPkt, m.Round)
		}
	}
	data, _ := json.MarshalIndent(medians, "", "  ")
	t.Logf("established flood summary (medians):\n%s", data)
}

// replyFlood runs the packet generator with one UDP datagram from the
// client's flood address and firewallPerfReplySourcePort to the host's port,
// for seconds, and measures the host while it runs.
func (h *firewallPerfHarness) replyFlood(t *testing.T, generator string, port, seconds int, srcMAC, dstMAC string) firewallPerfReplyResult {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", h.topology.ClientNS, os.Args[0], "-test.run", "^TestFirewallPerfHelperProcess$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		firewallPerfHelperEnv+"=1",
		"GODEBUG=asyncpreemptoff=1",
		firewallPerfFloodGenEnv+"="+generator,
		firewallPerfFloodFrameEnv+"=udp_reply",
		firewallPerfFloodIfaceEnv+"="+h.topology.ClientNSIF,
		firewallPerfFloodSrcMACEnv+"="+srcMAC,
		firewallPerfFloodDstMACEnv+"="+dstMAC,
		firewallPerfFloodSrcIPEnv+"="+firewallPerfFloodSource,
		firewallPerfFloodDstIPEnv+"="+dataplanePerfFrontAddr,
		firewallPerfFloodDstPortEnv+"="+strconv.Itoa(port),
		firewallPerfFloodSecondsEnv+"="+strconv.Itoa(seconds),
		firewallPerfFloodSendersEnv+"=1",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
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
	time.Sleep(500 * time.Millisecond)
	delivered := func() float64 {
		return firewallPerfUDPCounter(t, "InDatagrams") + firewallPerfUDPCounter(t, "RcvbufErrors")
	}
	hz := procClockTicks(t)
	deliveredStart := delivered()
	xdpStart, xdpStartAt := firewallPerfVethXDPPackets(t, h.topology.ClientHostIF), time.Now()
	cpuStart, cpuStartAt := readDataplanePerfCPUStat(t), time.Now()
	time.Sleep(time.Duration(seconds)*time.Second - 1500*time.Millisecond)
	cpuEnd, cpuEndAt := readDataplanePerfCPUStat(t), time.Now()
	deliveredEnd := delivered()
	xdpEnd, xdpEndAt := firewallPerfVethXDPPackets(t, h.topology.ClientHostIF), time.Now()
	var last string
	for line := range lines {
		last = line
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("flood helper: %v\n%s", err, stderr.String())
	}
	var report struct {
		Sent    uint64  `json:"sent"`
		Elapsed float64 `json:"elapsed_seconds"`
	}
	if err := json.Unmarshal([]byte(last), &report); err != nil || report.Elapsed <= 0 || report.Sent == 0 {
		t.Fatalf("flood helper report %q: %v\n%s", last, err, stderr.String())
	}
	window := cpuEndAt.Sub(cpuStartAt).Seconds()
	result := firewallPerfReplyResult{
		SentPPS:      float64(report.Sent) / report.Elapsed,
		DeliveredPPS: (deliveredEnd - deliveredStart) / window,
		SoftIRQCores: float64(cpuEnd.SoftIRQ-cpuStart.SoftIRQ) / float64(hz) / window,
	}
	if generator == "xdp" {
		// The generator's own count includes each BPF_PROG_RUN call's setup;
		// what the host veth's queues took is the rate that counts.
		result.SentPPS = (xdpEnd - xdpStart) / xdpEndAt.Sub(xdpStartAt).Seconds()
	}
	busy := dataplanePerfBusyCores(cpuStart, cpuEnd, hz, cpuEndAt.Sub(cpuStartAt))
	if packets := result.SentPPS * window; packets > 0 {
		result.SoftIRQNsPerPkt = result.SoftIRQCores * window / packets * 1e9
		result.BusyNsPerPkt = busy * window / packets * 1e9
	}
	return result
}

// firewallPerfUDPCounter reads one Udp field of the host's /proc/net/snmp.
func firewallPerfUDPCounter(t *testing.T, field string) float64 {
	t.Helper()
	data, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		t.Fatal(err)
	}
	var header []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Udp:") {
			continue
		}
		fields := strings.Fields(line)
		if header == nil {
			header = fields
			continue
		}
		for i, name := range header {
			if name == field && i < len(fields) {
				value, _ := strconv.ParseFloat(fields[i], 64)
				return value
			}
		}
	}
	t.Fatalf("/proc/net/snmp has no Udp %s", field)
	return 0
}

// firewallPerfUDPFrame is one UDP datagram with an 18-byte payload and no
// UDP checksum (allowed for IPv4).
func firewallPerfUDPFrame(srcMAC, dstMAC net.HardwareAddr, src, dst net.IP, sport, dport uint16) []byte {
	frame := make([]byte, 14+20+8+18)
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:], 0x0800)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(frame)-14))
	binary.BigEndian.PutUint16(ip[6:], 0x4000)
	ip[8], ip[9] = 64, 17
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	binary.BigEndian.PutUint16(ip[10:], firewallPerfChecksum(0, ip))
	udp := frame[34:]
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	return frame
}
