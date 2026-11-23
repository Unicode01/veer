//go:build linux

package app

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// System tests for the bundled firewall plugin together with the rest of
// Veer: port forwards, the TC flow cache, the XDP forwarding engine,
// disabling and removing the plugin, and an object that does not load. Like
// TestFirewallPluginLinuxIntegration they run a real daemon and drive the
// plugin through the HTTP API; TCP connections from network namespaces show
// the verdicts.
//
//	FORWARD_RUN_PLUGIN_INTEGRATION_TEST=1 go test ./internal/app -run '^TestFirewallSystem' -v
//
// The topology: a client namespace behind the WAN veth (the firewall binds
// its host end) with one allowed and one blocked source per address family,
// and a backend namespace behind a second veth that port forwards lead to.

const (
	fwsHelperEnv         = "FORWARD_FWS_HELPER"
	fwsHelperListenEnv   = "FORWARD_FWS_LISTEN"
	fwsHelperTargetEnv   = "FORWARD_FWS_TARGET"
	fwsHelperSourceEnv   = "FORWARD_FWS_SOURCE"
	fwsHelperBytesEnv    = "FORWARD_FWS_BYTES"
	fwsHelperDownloadEnv = "FORWARD_FWS_DOWNLOAD"
	fwsHelperTimeoutEnv  = "FORWARD_FWS_TIMEOUT_MS"

	fwsWANHost4     = "10.231.0.1"
	fwsAllowed4     = "10.231.0.2"
	fwsBlocked4     = "10.231.0.3"
	fwsBackendHost4 = "10.232.0.1"
	fwsBackend4     = "10.232.0.2"
	fwsWANHost6     = "fd31::1"
	fwsAllowed6     = "fd31::2"
	fwsBlocked6     = "fd31::3"
	fwsBackendHost6 = "fd32::1"
	fwsBackend6     = "fd32::2"
)

// TestFirewallSystemHelperProcess is the listener and the client the system
// tests run inside network namespaces; it does nothing on its own.
//
// listen: accepts on every address in FORWARD_FWS_LISTEN and serves each
// connection with fwsServe. dial: connects to FORWARD_FWS_TARGET (from
// FORWARD_FWS_SOURCE when set), downloads FORWARD_FWS_DOWNLOAD bytes, sends
// FORWARD_FWS_BYTES bytes, checks the server's count and prints the address
// the server saw.
func TestFirewallSystemHelperProcess(t *testing.T) {
	role := os.Getenv(fwsHelperEnv)
	if role == "" {
		return
	}
	var err error
	switch role {
	case "listen":
		err = fwsHelperListen(strings.Split(os.Getenv(fwsHelperListenEnv), ","))
	case "dial":
		var peer string
		peer, err = fwsHelperDial()
		if err == nil {
			fmt.Println(peer)
		}
	default:
		err = fmt.Errorf("unknown helper role %q", role)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func fwsHelperListen(addrs []string) error {
	errs := make(chan error, len(addrs))
	var listeners []net.Listener
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", strings.TrimSpace(addr))
		if err != nil {
			return err
		}
		listeners = append(listeners, ln)
	}
	fmt.Println("READY")
	for _, ln := range listeners {
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					errs <- err
					return
				}
				go fwsServe(conn)
			}
		}(ln)
	}
	return <-errs
}

// fwsServe answers one connection: the peer address; then, after the
// client's request line naming a download size, that many bytes; then the
// number of bytes read until the client closed its side.
func fwsServe(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if _, err := fmt.Fprintf(conn, "%s\n", host); err != nil {
		return
	}
	reader := bufio.NewReader(conn)
	request, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	download, _ := strconv.ParseInt(strings.TrimSpace(request), 10, 64)
	if err := fwsWriteN(conn, download); err != nil {
		return
	}
	n, _ := io.Copy(io.Discard, reader)
	_, _ = fmt.Fprintf(conn, "%d\n", n)
}

func fwsWriteN(w io.Writer, total int64) error {
	chunk := make([]byte, 64<<10)
	for left := total; left > 0; {
		part := chunk
		if int64(len(part)) > left {
			part = part[:left]
		}
		n, err := w.Write(part)
		if err != nil {
			return fmt.Errorf("send after %d bytes: %w", total-left, err)
		}
		left -= int64(n)
	}
	return nil
}

func fwsHelperDial() (string, error) {
	timeout := 3 * time.Second
	if ms, err := strconv.Atoi(os.Getenv(fwsHelperTimeoutEnv)); err == nil && ms > 0 {
		timeout = time.Duration(ms) * time.Millisecond
	}
	dialer := net.Dialer{Timeout: timeout}
	if source := os.Getenv(fwsHelperSourceEnv); source != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
	}
	conn, err := dialer.Dial("tcp", os.Getenv(fwsHelperTargetEnv))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Minute))
	reader := bufio.NewReader(conn)
	peer, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read peer line: %w", err)
	}
	total, _ := strconv.ParseInt(os.Getenv(fwsHelperBytesEnv), 10, 64)
	download, _ := strconv.ParseInt(os.Getenv(fwsHelperDownloadEnv), 10, 64)
	if _, err := fmt.Fprintf(conn, "%d\n", download); err != nil {
		return "", fmt.Errorf("send request: %w", err)
	}
	if got, err := io.CopyN(io.Discard, reader, download); err != nil {
		return "", fmt.Errorf("download stopped after %d of %d bytes: %w", got, download, err)
	}
	if err := fwsWriteN(conn, total); err != nil {
		return "", err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	count, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read byte count: %w", err)
	}
	if strings.TrimSpace(count) != strconv.FormatInt(total, 10) {
		return "", fmt.Errorf("server counted %s bytes, sent %d", strings.TrimSpace(count), total)
	}
	return strings.TrimSpace(peer), nil
}

// fwsRequire gates every system test: the environment switch, root, and a
// built firewall object.
func fwsRequire(t *testing.T) string {
	t.Helper()
	if os.Getenv("FORWARD_RUN_PLUGIN_INTEGRATION_TEST") != "1" {
		t.Skip("set FORWARD_RUN_PLUGIN_INTEGRATION_TEST=1 to run the firewall system tests")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for namespaces and XDP")
	}
	root := findRepoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "plugins", "firewall", "firewall.o")); err != nil {
		t.Fatalf("build plugins/firewall first: %v", err)
	}
	return root
}

func fwsRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// fwsSuffix names this run's links and namespaces; tests in one binary run
// one after another and clean up behind themselves.
func fwsSuffix() string { return strconv.Itoa(os.Getpid() % 100000) }

type fwsTopology struct {
	ClientNS  string
	BackendNS string
	WAN       string // host end of the client veth, where the firewall binds
	Backend   string // host end of the backend veth
}

// fwsSetupTopology builds the client and backend namespaces and turns on
// IPv4 forwarding for the host (restored at cleanup). The host routes
// between them; neighbors are static so the first packets do not wait for
// resolution.
func fwsSetupTopology(t *testing.T, prefix string) fwsTopology {
	t.Helper()
	suffix := fwsSuffix()
	topo := fwsTopology{
		ClientNS:  prefix + "c" + suffix,
		BackendNS: prefix + "k" + suffix,
		WAN:       truncateIfName(prefix + "w" + suffix),
		Backend:   truncateIfName(prefix + "b" + suffix),
	}
	cleanup := func() {
		for _, link := range []string{topo.WAN, topo.Backend} {
			_ = exec.Command("ip", "link", "del", link).Run()
		}
		for _, ns := range []string{topo.ClientNS, topo.BackendNS} {
			_ = exec.Command("ip", "netns", "del", ns).Run()
		}
	}
	cleanup()
	t.Cleanup(cleanup)
	fwsEnableIPv4Forwarding(t)

	run := func(args ...string) { t.Helper(); fwsRun(t, args...) }
	run("ip", "netns", "add", topo.ClientNS)
	run("ip", "netns", "add", topo.BackendNS)
	run("ip", "link", "add", topo.WAN, "type", "veth", "peer", "name", "eth0", "netns", topo.ClientNS)
	run("ip", "link", "add", topo.Backend, "type", "veth", "peer", "name", "eth0", "netns", topo.BackendNS)
	run("ip", "address", "add", fwsWANHost4+"/24", "dev", topo.WAN)
	run("ip", "-6", "address", "add", fwsWANHost6+"/64", "dev", topo.WAN, "nodad")
	run("ip", "link", "set", topo.WAN, "up")
	run("ip", "address", "add", fwsBackendHost4+"/24", "dev", topo.Backend)
	run("ip", "-6", "address", "add", fwsBackendHost6+"/64", "dev", topo.Backend, "nodad")
	run("ip", "link", "set", topo.Backend, "up")
	for _, ns := range []string{topo.ClientNS, topo.BackendNS} {
		run("ip", "-n", ns, "link", "set", "lo", "up")
	}
	run("ip", "-n", topo.ClientNS, "address", "add", fwsAllowed4+"/24", "dev", "eth0")
	run("ip", "-n", topo.ClientNS, "address", "add", fwsBlocked4+"/24", "dev", "eth0")
	run("ip", "-n", topo.ClientNS, "-6", "address", "add", fwsAllowed6+"/64", "dev", "eth0", "nodad")
	run("ip", "-n", topo.ClientNS, "-6", "address", "add", fwsBlocked6+"/64", "dev", "eth0", "nodad")
	run("ip", "-n", topo.ClientNS, "link", "set", "eth0", "up")
	run("ip", "-n", topo.ClientNS, "route", "add", "default", "via", fwsWANHost4)
	run("ip", "-n", topo.ClientNS, "-6", "route", "add", "default", "via", fwsWANHost6)
	run("ip", "-n", topo.BackendNS, "address", "add", fwsBackend4+"/24", "dev", "eth0")
	run("ip", "-n", topo.BackendNS, "-6", "address", "add", fwsBackend6+"/64", "dev", "eth0", "nodad")
	run("ip", "-n", topo.BackendNS, "link", "set", "eth0", "up")
	run("ip", "-n", topo.BackendNS, "route", "add", "default", "via", fwsBackendHost4)
	run("ip", "-n", topo.BackendNS, "-6", "route", "add", "default", "via", fwsBackendHost6)
	// XDP redirects into a veth need NAPI on its peer, which GRO gives.
	for _, ns := range []string{topo.ClientNS, topo.BackendNS} {
		_ = exec.Command("ip", "netns", "exec", ns, "ethtool", "-K", "eth0", "gro", "on").Run()
	}

	clientMAC := fwsNetnsMAC(t, topo.ClientNS)
	backendMAC := fwsNetnsMAC(t, topo.BackendNS)
	for _, addr := range []string{fwsAllowed4, fwsBlocked4, fwsAllowed6, fwsBlocked6} {
		run("ip", "neigh", "replace", addr, "lladdr", clientMAC, "dev", topo.WAN, "nud", "permanent")
	}
	for _, addr := range []string{fwsBackend4, fwsBackend6} {
		run("ip", "neigh", "replace", addr, "lladdr", backendMAC, "dev", topo.Backend, "nud", "permanent")
	}
	wanMAC := mustReadHostInterfaceMAC(t, topo.WAN)
	backendHostMAC := mustReadHostInterfaceMAC(t, topo.Backend)
	for _, addr := range []string{fwsWANHost4, fwsWANHost6} {
		run("ip", "-n", topo.ClientNS, "neigh", "replace", addr, "lladdr", wanMAC, "dev", "eth0", "nud", "permanent")
	}
	for _, addr := range []string{fwsBackendHost4, fwsBackendHost6} {
		run("ip", "-n", topo.BackendNS, "neigh", "replace", addr, "lladdr", backendHostMAC, "dev", "eth0", "nud", "permanent")
	}
	return topo
}

func fwsNetnsMAC(t *testing.T, ns string) string {
	t.Helper()
	out := fwsRun(t, "ip", "netns", "exec", ns, "cat", "/sys/class/net/eth0/address")
	if _, err := net.ParseMAC(out); err != nil {
		t.Fatalf("MAC of eth0 in %s: %q", ns, out)
	}
	return out
}

// fwsEnableIPv4Forwarding turns on net.ipv4.ip_forward and restores the
// previous value at cleanup.
func fwsEnableIPv4Forwarding(t *testing.T) {
	t.Helper()
	const path = "/proc/sys/net/ipv4/ip_forward"
	previous, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(previous)) == "1" {
		return
	}
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(path, previous, 0o644) })
}

func fwsSelf(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return self
}

// fwsHelperCommand runs this test binary as the helper, inside ns unless ns
// is empty.
func fwsHelperCommand(t *testing.T, ns string, env ...string) *exec.Cmd {
	t.Helper()
	args := []string{fwsSelf(t), "-test.run=^TestFirewallSystemHelperProcess$"}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

// fwsStartListener runs the helper listener on addrs inside ns until the
// test ends.
func fwsStartListener(t *testing.T, ns string, addrs ...string) {
	t.Helper()
	cmd := fwsHelperCommand(t, ns, fwsHelperEnv+"=listen", fwsHelperListenEnv+"="+strings.Join(addrs, ","))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err == nil && strings.TrimSpace(line) != "READY" {
			err = fmt.Errorf("unexpected first line %q", line)
		}
		ready <- err
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("listener in %s on %v: %v: %s", ns, addrs, err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("listener in %s on %v did not start: %s", ns, addrs, stderr.String())
	}
}

// fwsDial connects from source (inside ns) to target and sends payload
// bytes; it returns the address the server saw, or ok=false when the
// connection failed.
func fwsDial(t *testing.T, ns, source, target string, payload int64, timeout time.Duration) (string, bool) {
	t.Helper()
	return fwsTransfer(t, ns, source, target, payload, 0, timeout)
}

// fwsTransfer is fwsDial that also downloads download bytes before the
// upload.
func fwsTransfer(t *testing.T, ns, source, target string, upload, download int64, timeout time.Duration) (string, bool) {
	t.Helper()
	cmd := fwsHelperCommand(t, ns, fwsHelperEnv+"=dial", fwsHelperTargetEnv+"="+target, fwsHelperSourceEnv+"="+source,
		fwsHelperBytesEnv+"="+strconv.FormatInt(upload, 10), fwsHelperDownloadEnv+"="+strconv.FormatInt(download, 10),
		fwsHelperTimeoutEnv+"="+strconv.FormatInt(timeout.Milliseconds(), 10))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(stderr.String()), false
	}
	return strings.TrimSpace(stdout.String()), true
}

type fwsProbe struct {
	name     string
	source   string
	target   string
	wantPeer string // address the server must see when the connection works
}

// fwsExpect checks each probe's reachability; want maps probe names to
// whether they must connect.
func fwsExpect(t *testing.T, ns, step string, probes []fwsProbe, want map[string]bool) {
	t.Helper()
	got := map[string]string{}
	failed := false
	for _, probe := range probes {
		w, ok := want[probe.name]
		if !ok {
			continue
		}
		timeout := 3 * time.Second
		if !w {
			timeout = 1500 * time.Millisecond
		}
		peer, reached := fwsDial(t, ns, probe.source, probe.target, 4096, timeout)
		switch {
		case reached != w:
			failed = true
			got[probe.name] = fmt.Sprintf("reachable=%t want %t (%s)", reached, w, peer)
		case reached && probe.wantPeer != "" && peer != probe.wantPeer:
			failed = true
			got[probe.name] = fmt.Sprintf("server saw %s, want %s", peer, probe.wantPeer)
		default:
			got[probe.name] = fmt.Sprintf("reachable=%t", reached)
		}
	}
	if failed {
		t.Fatalf("%s: %v", step, got)
	}
	t.Logf("%s: %v", step, got)
}

// fwsHostListener serves the helper protocol in the test process, that is
// in the host's namespace, on every address; it returns the port.
func fwsHostListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go fwsServe(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// fwsXDP reports whether an XDP program is attached to name and in which
// mode (nl.XDP_ATTACHED_DRV for native, nl.XDP_ATTACHED_SKB for generic).
func fwsXDP(t *testing.T, name string) (bool, uint32, uint32) {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	xdp := link.Attrs().Xdp
	if xdp == nil || !xdp.Attached {
		return false, 0, 0
	}
	return true, uint32(xdp.AttachMode), xdp.ProgId
}

func fwsWaitXDP(t *testing.T, name string, attached bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got, mode, prog := fwsXDP(t, name)
		if got == attached {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: XDP attached=%t (mode %d prog %d), want attached=%t", name, got, mode, prog, attached)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ----------------------------------------------------------------- daemon

type fwsDaemonOptions struct {
	Order        []string
	Experimental map[string]bool
	Plugins      []string // bundled plugins copied next to the firewall
	Prepare      func(t *testing.T, pluginsDir string)
	// RemoteInstall lets the API reload the plugin catalog from disk.
	RemoteInstall bool
	// NoPlugins runs Veer with plugins switched off, as a reference.
	NoPlugins bool
	// HotRestartMarker, when set, is the marker file that makes a stop a hot
	// restart: the next start takes over what the last one left.
	HotRestartMarker string
}

type fwsDaemon struct {
	t          *testing.T
	cfg        Config
	base       string
	work       string
	pluginsDir string
	configPath string
	logPath    string
	logFile    *os.File
	binary     string
	env        []string
	cmd        *exec.Cmd
}

func fwsStartDaemon(t *testing.T, opts fwsDaemonOptions) *fwsDaemon {
	t.Helper()
	root := findRepoRoot(t)
	work := t.TempDir()
	pluginsDir := filepath.Join(work, "plugins")
	for _, id := range append([]string{"firewall"}, opts.Plugins...) {
		copyDirForTest(t, filepath.Join(root, "plugins", id), filepath.Join(pluginsDir, id))
	}
	if opts.Prepare != nil {
		opts.Prepare(t, pluginsDir)
	}
	order := opts.Order
	if len(order) == 0 {
		order = []string{kernelEngineTC}
	}
	enabled, disabled := true, false
	cfg := Config{WebBind: "127.0.0.1", WebPort: freeTCPPort(t), WebToken: egressNATTestToken,
		PluginAdminToken: "firewall-system-admin", MaxWorkers: 1, DefaultEngine: ruleEngineKernel,
		KernelEngineOrder: order, PluginsDir: pluginsDir,
		PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled,
		PluginsMinSandboxLevel: pluginSandboxLevelNone, PluginsRequireSigned: &disabled,
		PluginsRemoteInstallEnabled: opts.RemoteInstall, Experimental: opts.Experimental}
	if opts.NoPlugins {
		cfg.PluginsEnabledSetting, cfg.PluginsDataplaneSetting = &disabled, &disabled
	}
	data, _ := json.Marshal(cfg)
	d := &fwsDaemon{t: t, cfg: cfg, base: fmt.Sprintf("http://127.0.0.1:%d", cfg.WebPort), work: work,
		pluginsDir: pluginsDir, configPath: filepath.Join(work, "config.json"), logPath: filepath.Join(work, "veer.log")}
	if err := os.WriteFile(d.configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(d.logPath)
	if err != nil {
		t.Fatal(err)
	}
	d.logFile = logFile
	d.binary = buildDataplanePerfBinary(t, root)
	d.env = append(os.Environ(),
		veerBPFStateDirEnv+"="+requireKernelHotRestartBPFStateRoot(t),
		veerRuntimeStateDirEnv+"="+filepath.Join(work, "state"))
	if opts.HotRestartMarker != "" {
		d.env = append(d.env, veerHotRestartMarkerEnv+"="+opts.HotRestartMarker)
	}
	t.Cleanup(func() {
		d.stop()
		if t.Failed() {
			b, _ := os.ReadFile(d.logPath)
			t.Logf("daemon log:\n%s", b)
		}
		_ = logFile.Close()
	})
	d.start()
	return d
}

func (d *fwsDaemon) start() {
	d.t.Helper()
	cmd := exec.Command(d.binary, "--config", d.configPath)
	cmd.Dir = d.work
	cmd.Env = d.env
	cmd.Stdout, cmd.Stderr = d.logFile, d.logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		d.t.Fatal(err)
	}
	d.cmd = cmd
	waitForEgressNATIntegrationAPIWithTimeout(d.t, d.base, cmd, d.logPath, 45*time.Second)
}

// stop ends the daemon gracefully (it detaches what it attached), killing
// its process group only if it does not exit in time.
func (d *fwsDaemon) stop() {
	cmd := d.cmd
	if cmd == nil || cmd.Process == nil {
		return
	}
	d.cmd = nil
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
}

func (d *fwsDaemon) request(method, path string, payload any) (int, []byte) {
	d.t.Helper()
	var body io.Reader
	if payload != nil {
		data, _ := json.Marshal(payload)
		body = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, d.base+path, body)
	req.Header.Set("Authorization", "Bearer "+d.cfg.WebToken)
	req.Header.Set(pluginAdminTokenHeader, d.cfg.PluginAdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		d.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (d *fwsDaemon) api(method, path string, payload any) []byte {
	d.t.Helper()
	code, out := d.request(method, path, payload)
	if code < 200 || code >= 300 {
		d.t.Fatalf("%s %s: HTTP %d: %s", method, path, code, out)
	}
	return out
}

type fwsPluginView struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Status  string `json:"status"`
	Error   string `json:"error"`
	Runtime struct {
		Mode            string `json:"mode"`
		Attached        bool   `json:"attached"`
		AttachmentCount int    `json:"attachment_count"`
		Reason          string `json:"reason"`
		Error           string `json:"error"`
	} `json:"runtime"`
	Actions []struct {
		ID string `json:"id"`
	} `json:"actions"`
}

func (p fwsPluginView) String() string {
	return fmt.Sprintf("status=%q enabled=%t error=%q runtime={mode=%q attached=%t attachments=%d reason=%q error=%q} actions=%d",
		p.Status, p.Enabled, p.Error, p.Runtime.Mode, p.Runtime.Attached, p.Runtime.AttachmentCount, p.Runtime.Reason, p.Runtime.Error, len(p.Actions))
}

func (d *fwsDaemon) plugin(id string) (fwsPluginView, bool) {
	d.t.Helper()
	var catalog struct {
		Plugins []fwsPluginView `json:"plugins"`
	}
	if err := json.Unmarshal(d.api("GET", "/api/plugins", nil), &catalog); err != nil {
		d.t.Fatalf("plugin catalog: %v", err)
	}
	for _, p := range catalog.Plugins {
		if p.ID == id {
			return p, true
		}
	}
	return fwsPluginView{}, false
}

// waitPlugin polls the catalog until ready accepts the plugin's view.
func (d *fwsDaemon) waitPlugin(id string, timeout time.Duration, what string, ready func(p fwsPluginView, present bool) bool) fwsPluginView {
	d.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		p, present := d.plugin(id)
		if ready(p, present) {
			return p
		}
		if time.Now().After(deadline) {
			d.t.Fatalf("plugin %s: %s not reached within %s: present=%t %s", id, what, timeout, present, p)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (d *fwsDaemon) waitPluginAction(id, action string) {
	d.t.Helper()
	d.waitPlugin(id, 30*time.Second, "action "+action, func(p fwsPluginView, present bool) bool {
		if !present || p.Status != pluginStatusActive {
			return false
		}
		for _, a := range p.Actions {
			if a.ID == action {
				return true
			}
		}
		return false
	})
}

// upsert writes a plugin resource record, creating it the first time.
func (d *fwsDaemon) upsert(plugin, resource, key string, data map[string]any) {
	d.t.Helper()
	path := "/api/plugins/" + plugin + "/resources/" + resource
	code, out := d.request("PUT", path+"/"+key, map[string]any{"data": data, "enabled": true})
	if code == http.StatusNotFound {
		d.api("POST", path, map[string]any{"key": key, "data": data, "enabled": true})
		return
	}
	if code < 200 || code >= 300 {
		d.t.Fatalf("PUT %s/%s: HTTP %d: %s", path, key, code, out)
	}
}

// fwSettings sets the draft's bound interfaces.
func (d *fwsDaemon) fwSettings(interfaces ...string) {
	d.t.Helper()
	if interfaces == nil {
		interfaces = []string{}
	}
	d.upsert("firewall", "settings", "default", map[string]any{"interfaces": interfaces, "confirm_timeout_seconds": 60})
}

// fwPolicy sets a TCP policy for ports: default drop, the given sources
// allowed.
func (d *fwsDaemon) fwPolicy(key string, ports []int, allowed ...string) {
	d.t.Helper()
	d.fwPolicyProto(key, "tcp", ports, allowed...)
}

// fwPolicyProto is fwPolicy for protocol: tcp, udp or tcp+udp.
func (d *fwsDaemon) fwPolicyProto(key, protocol string, ports []int, allowed ...string) {
	d.t.Helper()
	portList := make([]string, 0, len(ports))
	for _, port := range ports {
		portList = append(portList, strconv.Itoa(port))
	}
	sources := make([]map[string]string, 0, len(allowed))
	for _, cidr := range allowed {
		sources = append(sources, map[string]string{"cidr": cidr, "action": "allow"})
	}
	d.upsert("firewall", "policies", key, map[string]any{"name": key, "protocol": protocol, "ports": portList,
		"default_action": "drop", "sources": sources})
}

// fwAction runs a firewall action; apply first runs check and accepts its
// warnings, as the page does once the user agrees.
func (d *fwsDaemon) fwAction(id string) map[string]any {
	d.t.Helper()
	code, out := d.fwActionRaw(id)
	if code < 200 || code >= 300 {
		d.t.Fatalf("firewall %s: HTTP %d: %s", id, code, out)
	}
	var response struct {
		Result map[string]any `json:"result"`
	}
	_ = json.Unmarshal(out, &response)
	return response.Result
}

func (d *fwsDaemon) fwActionRaw(id string) (int, []byte) {
	d.t.Helper()
	payload := map[string]any{}
	if id == "apply" {
		var check struct {
			Result struct {
				Errors []string `json:"errors"`
				Token  string   `json:"token"`
			} `json:"result"`
		}
		if err := json.Unmarshal(d.api("POST", "/api/plugins/firewall/actions/check", map[string]any{"payload": map[string]any{}}), &check); err != nil {
			d.t.Fatalf("check: %v", err)
		}
		if len(check.Result.Errors) > 0 {
			d.t.Fatalf("check: %v", check.Result.Errors)
		}
		if check.Result.Token != "" {
			payload["accept_warnings"] = check.Result.Token
		}
	}
	return d.request("POST", "/api/plugins/firewall/actions/"+id, map[string]any{"payload": payload})
}

func (d *fwsDaemon) fwApplyConfirm() {
	d.t.Helper()
	d.fwAction("apply")
	d.fwAction("confirm")
}

// fwCounters sums the per-policy counters the status action reports.
func (d *fwsDaemon) fwCounters() (pass, drop float64) {
	d.t.Helper()
	status := d.fwAction("status")
	policies, _ := status["policies"].([]any)
	for _, p := range policies {
		counters, _ := p.(map[string]any)["counters"].(map[string]any)
		if counters == nil {
			d.t.Fatalf("policy without counters: %v", status)
		}
		pass += counters["pass"].(float64)
		drop += counters["drop"].(float64)
	}
	return pass, drop
}

type fwsRuleView struct {
	ID                    int64  `json:"id"`
	Status                string `json:"status"`
	EffectiveEngine       string `json:"effective_engine"`
	EffectiveKernelEngine string `json:"effective_kernel_engine"`
	KernelReason          string `json:"kernel_reason"`
	FallbackReason        string `json:"fallback_reason"`
}

// addRule creates a TCP port forward from the WAN veth to the backend.
func (d *fwsDaemon) addRule(topo fwsTopology, inIP string, inPort int, outIP string, outPort int, transparent bool, outSource string) int64 {
	d.t.Helper()
	payload := map[string]any{
		"in_interface": topo.WAN, "in_ip": inIP, "in_port": inPort,
		"out_interface": topo.Backend, "out_ip": outIP, "out_port": outPort,
		"protocol": "tcp", "transparent": transparent, "engine_preference": ruleEngineKernel,
		"remark": fmt.Sprintf("firewall-system-%d", inPort), "tag": "firewall-system",
	}
	if outSource != "" {
		payload["out_source_ip"] = outSource
	}
	var rule struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(d.api("POST", "/api/rules", payload), &rule); err != nil || rule.ID == 0 {
		d.t.Fatalf("create rule for port %d: %v", inPort, err)
	}
	return rule.ID
}

func (d *fwsDaemon) rule(id int64) fwsRuleView {
	d.t.Helper()
	var rules []fwsRuleView
	if err := json.Unmarshal(d.api("GET", "/api/rules", nil), &rules); err != nil {
		d.t.Fatalf("list rules: %v", err)
	}
	for _, r := range rules {
		if r.ID == id {
			return r
		}
	}
	d.t.Fatalf("rule %d not listed", id)
	return fwsRuleView{}
}

// waitRuleEngine waits until the rule runs in the kernel on kernelEngine.
func (d *fwsDaemon) waitRuleEngine(id int64, kernelEngine string, timeout time.Duration) (fwsRuleView, bool) {
	d.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		r := d.rule(id)
		if r.Status == "running" && r.EffectiveEngine == ruleEngineKernel && r.EffectiveKernelEngine == kernelEngine {
			return r, true
		}
		if time.Now().After(deadline) {
			return r, false
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (d *fwsDaemon) requireRuleEngine(id int64, kernelEngine string, timeout time.Duration) {
	d.t.Helper()
	if r, ok := d.waitRuleEngine(id, kernelEngine, timeout); !ok {
		d.t.Fatalf("rule %d did not run on %s within %s: %+v", id, kernelEngine, timeout, r)
	}
}

func (d *fwsDaemon) kernelEngine(name string) KernelEngineRuntimeView {
	d.t.Helper()
	var runtime KernelRuntimeResponse
	// refresh=1: the view is otherwise cached for a while.
	if err := json.Unmarshal(d.api("GET", "/api/kernel/runtime?refresh=1", nil), &runtime); err != nil {
		d.t.Fatalf("kernel runtime: %v", err)
	}
	engine, ok := dataplanePerfFindKernelEngine(runtime.Engines, name)
	if !ok {
		d.t.Fatalf("kernel runtime lists no %s engine", name)
	}
	return engine
}

// ------------------------------------------------------------------ tests

// TestFirewallSystemPortForwardAllowlist protects the entry ports of Veer
// port forwards (IPv4 transparent, IPv4 full NAT, IPv6 full NAT; the kernel
// has no transparent IPv6) with an allowlist on the WAN veth: the allowed
// source reaches the backend, the other source of the same family does not,
// and a forward whose port no policy names stays open to both.
func TestFirewallSystemPortForwardAllowlist(t *testing.T) {
	fwsRequire(t)
	topo := fwsSetupTopology(t, "fwsa")
	const (
		transparentPort = 31001
		fullNATPort     = 31002
		v6Port          = 31003
		openPort        = 31004
		backendOffset   = 1000
	)
	fwsStartListener(t, topo.BackendNS,
		fmt.Sprintf("[::]:%d", transparentPort+backendOffset), fmt.Sprintf("[::]:%d", fullNATPort+backendOffset),
		fmt.Sprintf("[::]:%d", v6Port+backendOffset), fmt.Sprintf("[::]:%d", openPort+backendOffset))
	d := fwsStartDaemon(t, fwsDaemonOptions{})
	d.waitPluginAction("firewall", "apply")

	rules := []int64{
		d.addRule(topo, fwsWANHost4, transparentPort, fwsBackend4, transparentPort+backendOffset, true, ""),
		d.addRule(topo, fwsWANHost4, fullNATPort, fwsBackend4, fullNATPort+backendOffset, false, fwsBackendHost4),
		d.addRule(topo, fwsWANHost6, v6Port, fwsBackend6, v6Port+backendOffset, false, fwsBackendHost6),
		d.addRule(topo, fwsWANHost4, openPort, fwsBackend4, openPort+backendOffset, true, ""),
	}
	for _, id := range rules {
		d.requireRuleEngine(id, kernelEngineTC, 30*time.Second)
	}

	front4 := func(port int) string { return net.JoinHostPort(fwsWANHost4, strconv.Itoa(port)) }
	front6 := func(port int) string { return net.JoinHostPort(fwsWANHost6, strconv.Itoa(port)) }
	probes := []fwsProbe{
		{"transparent allowed", fwsAllowed4, front4(transparentPort), fwsAllowed4},
		{"transparent blocked", fwsBlocked4, front4(transparentPort), fwsBlocked4},
		{"full NAT allowed", fwsAllowed4, front4(fullNATPort), fwsBackendHost4},
		{"full NAT blocked", fwsBlocked4, front4(fullNATPort), fwsBackendHost4},
		{"v6 full NAT allowed", fwsAllowed6, front6(v6Port), fwsBackendHost6},
		{"v6 full NAT blocked", fwsBlocked6, front6(v6Port), fwsBackendHost6},
		{"unprotected forward", fwsBlocked4, front4(openPort), fwsBlocked4},
	}
	all := func(v bool) map[string]bool {
		m := map[string]bool{}
		for _, p := range probes {
			m[p.name] = v
		}
		return m
	}
	fwsExpect(t, topo.ClientNS, "forwards before the firewall", probes, all(true))

	d.fwSettings(topo.WAN)
	d.fwPolicy("forwards", []int{transparentPort, fullNATPort, v6Port}, fwsAllowed4+"/32", fwsAllowed6+"/128")
	d.fwApplyConfirm()
	if attached, mode, _ := fwsXDP(t, topo.WAN); !attached || mode != nl.XDP_ATTACHED_DRV {
		t.Fatalf("%s: XDP attached=%t mode=%d, want native", topo.WAN, attached, mode)
	}
	want := all(false)
	for _, name := range []string{"transparent allowed", "full NAT allowed", "v6 full NAT allowed", "unprotected forward"} {
		want[name] = true
	}
	fwsExpect(t, topo.ClientNS, "allowlist on the forwards' entry ports", probes, want)
	for _, id := range rules {
		if r := d.rule(id); r.Status != "running" || r.EffectiveKernelEngine != kernelEngineTC {
			t.Fatalf("rule %d with the firewall bound: %+v", id, r)
		}
	}
	pass, drop := d.fwCounters()
	if pass == 0 || drop == 0 {
		t.Fatalf("firewall counters pass=%v drop=%v, want both", pass, drop)
	}
	t.Logf("firewall counters: pass=%v drop=%v", pass, drop)
}

// TestFirewallSystemFlowCacheUnaffected checks that the firewall does not
// take the TC flow cache away from forwarded traffic it passes: the same
// transfers through a transparent and a full-NAT forward leave from
// fast-path records about as often as in a Veer without plugins, both with
// the firewall installed but unbound and with it bound to the forwards'
// entry interface. The packets are counted where they enter the host (the
// WAN and backend veths), as the TC programs see them.
func TestFirewallSystemFlowCacheUnaffected(t *testing.T) {
	fwsRequire(t)
	topo := fwsSetupTopology(t, "fwsf")
	// Fast-path records serve packets up to the next hop's MTU: GSO and GRO
	// would hand TC 64 KB packets, which always take the full path.
	for _, dev := range [][2]string{{"", topo.WAN}, {"", topo.Backend}, {topo.ClientNS, "eth0"}, {topo.BackendNS, "eth0"}} {
		args := []string{"ethtool", "-K", dev[1], "tso", "off", "gso", "off", "gro", "off"}
		if dev[0] != "" {
			args = append([]string{"ip", "netns", "exec", dev[0]}, args...)
		}
		fwsRun(t, args...)
	}
	const (
		transparentPort = 31101
		fullNATPort     = 31102
		backendOffset   = 1000
		download        = 32 << 20
		upload          = 8 << 20
	)
	fwsStartListener(t, topo.BackendNS,
		fmt.Sprintf("[::]:%d", transparentPort+backendOffset), fmt.Sprintf("[::]:%d", fullNATPort+backendOffset))
	type forward struct {
		name string
		port int
		id   int64
		peer string
	}
	// addForwards creates the two forwards in d and waits for TC to run them.
	addForwards := func(d *fwsDaemon) []forward {
		t.Helper()
		forwards := []forward{
			{"transparent", transparentPort, d.addRule(topo, fwsWANHost4, transparentPort, fwsBackend4, transparentPort+backendOffset, true, ""), fwsAllowed4},
			{"full NAT", fullNATPort, d.addRule(topo, fwsWANHost4, fullNATPort, fwsBackend4, fullNATPort+backendOffset, false, fwsBackendHost4), fwsBackendHost4},
		}
		for _, f := range forwards {
			d.requireRuleEngine(f.id, kernelEngineTC, 30*time.Second)
		}
		if engine := d.kernelEngine(kernelEngineTC); !engine.FlowCache {
			t.Fatalf("the TC engine does not use the flow cache: disabled by %q", engine.FlowCacheDisabledBy)
		}
		return forwards
	}
	rx := func(name string) uint64 {
		data, err := os.ReadFile("/sys/class/net/" + name + "/statistics/rx_packets")
		if err != nil {
			t.Fatal(err)
		}
		n, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		return n
	}
	type sample struct{ hits, packets uint64 }
	ratio := func(s sample) float64 { return float64(s.hits) / float64(max(s.packets, 1)) }
	// measure downloads and uploads through each forward and returns the
	// fast-path hits and the packets the two host ends received meanwhile.
	measure := func(d *fwsDaemon, forwards []forward, step string) map[string]sample {
		t.Helper()
		out := map[string]sample{}
		for _, f := range forwards {
			before := d.kernelEngine(kernelEngineTC)
			rxBefore := rx(topo.WAN) + rx(topo.Backend)
			target := net.JoinHostPort(fwsWANHost4, strconv.Itoa(f.port))
			peer, ok := fwsTransfer(t, topo.ClientNS, fwsAllowed4, target, upload, download, 3*time.Second)
			if !ok || peer != f.peer {
				t.Fatalf("%s: transfer through the %s forward failed: %s", step, f.name, peer)
			}
			after := d.kernelEngine(kernelEngineTC)
			s := sample{after.DiagFlowCacheHit - before.DiagFlowCacheHit, rx(topo.WAN) + rx(topo.Backend) - rxBefore}
			t.Logf("%s, %s forward: %d of %d packets left from fast-path records (%.0f%%); diag: FIB not successful %d, redirect_neigh %d, TCP close deletes %d",
				step, f.name, s.hits, s.packets, 100*ratio(s), after.DiagFIBNonSuccess-before.DiagFIBNonSuccess,
				after.DiagRedirectNeighUsed-before.DiagRedirectNeighUsed, after.DiagTCPCloseDelete-before.DiagTCPCloseDelete)
			out[f.name] = s
		}
		return out
	}
	diag := map[string]bool{experimentalFeatureKernelTCDiag: true}

	// The reference: Veer without plugins.
	reference := fwsStartDaemon(t, fwsDaemonOptions{Experimental: diag, NoPlugins: true})
	forwards := addForwards(reference)
	measure(reference, forwards, "no plugins, warm-up")
	withoutPlugins := measure(reference, forwards, "no plugins")
	reference.stop()

	d := fwsStartDaemon(t, fwsDaemonOptions{Experimental: diag})
	d.waitPluginAction("firewall", "apply")
	forwards = addForwards(d)
	measure(d, forwards, "firewall installed, warm-up")
	unbound := measure(d, forwards, "firewall installed, unbound")

	d.fwSettings(topo.WAN)
	d.fwPolicy("forwards", []int{transparentPort, fullNATPort}, fwsAllowed4+"/32")
	d.fwApplyConfirm()
	fwsWaitXDP(t, topo.WAN, true, 10*time.Second)
	if _, ok := fwsDial(t, topo.ClientNS, fwsBlocked4, net.JoinHostPort(fwsWANHost4, strconv.Itoa(fullNATPort)), 0, 1500*time.Millisecond); ok {
		t.Fatal("the blocked source still reaches the forward with the firewall bound")
	}
	passBefore, _ := d.fwCounters()
	bound := measure(d, forwards, "firewall bound")
	passAfter, _ := d.fwCounters()
	var boundPackets uint64
	for _, s := range bound {
		boundPackets += s.packets
	}
	if passAfter-passBefore < float64(boundPackets)/8 {
		t.Fatalf("the firewall passed %v packets of the transfers (%d packets entered), so it did not see the forwards", passAfter-passBefore, boundPackets)
	}

	for _, f := range forwards {
		ref := withoutPlugins[f.name]
		if ref.hits < 100 {
			t.Errorf("%s forward in Veer without plugins: only %d of %d packets left from fast-path records; the reference is broken", f.name, ref.hits, ref.packets)
			continue
		}
		for _, c := range []struct {
			label string
			s     sample
		}{{"firewall installed, unbound", unbound[f.name]}, {"firewall bound", bound[f.name]}} {
			if c.s.hits < 100 || ratio(c.s) < 0.75*ratio(ref) {
				t.Errorf("%s forward, %s: %d of %d packets (%.2f) left from fast-path records, without plugins %d of %d (%.2f)",
					f.name, c.label, c.s.hits, c.s.packets, ratio(c.s), ref.hits, ref.packets, ratio(ref))
			}
		}
	}
	if t.Failed() {
		for _, name := range []string{"tc_flow_cache_s", "tc_plugin_confi"} {
			out, _ := exec.Command("bpftool", "map", "dump", "name", name).CombinedOutput()
			t.Logf("bpftool map dump name %s:\n%.4000s", name, out)
		}
	}
}

// TestFirewallSystemXDPEnginePinning runs a port forward on the XDP engine
// (kernel_engine_order xdp, tc), then binds the firewall to the forward's
// entry interface. The XDP plugin hook puts the core on TC: the forward keeps
// working, and the firewall filters it. Unbinding every interface removes the
// last XDP plugin hook, and the core goes back to XDP.
func TestFirewallSystemXDPEnginePinning(t *testing.T) {
	fwsRequire(t)
	topo := fwsSetupTopology(t, "fwsx")
	const (
		frontPort   = 31201
		backendPort = 32201
	)
	fwsStartListener(t, topo.BackendNS, fmt.Sprintf("[::]:%d", backendPort))
	d := fwsStartDaemon(t, fwsDaemonOptions{Order: []string{kernelEngineXDP, kernelEngineTC}})
	d.waitPluginAction("firewall", "apply")
	id := d.addRule(topo, fwsWANHost4, frontPort, fwsBackend4, backendPort, true, "")
	d.requireRuleEngine(id, kernelEngineXDP, 30*time.Second)
	_, _, coreProg := fwsXDP(t, topo.WAN)
	if coreProg == 0 {
		t.Fatalf("the XDP engine serves the rule but %s has no XDP program", topo.WAN)
	}
	target := net.JoinHostPort(fwsWANHost4, strconv.Itoa(frontPort))
	probes := []fwsProbe{
		{"allowed", fwsAllowed4, target, fwsAllowed4},
		{"blocked", fwsBlocked4, target, fwsBlocked4},
	}
	open := map[string]bool{"allowed": true, "blocked": true}
	filtered := map[string]bool{"allowed": true, "blocked": false}
	fwsExpect(t, topo.ClientNS, "XDP engine, no firewall", probes, open)

	d.fwSettings(topo.WAN)
	d.fwPolicy("forward", []int{frontPort}, fwsAllowed4+"/32")
	if code, out := d.fwActionRaw("apply"); code < 200 || code >= 300 {
		// Report it, then find out what it takes to bind the firewall.
		p, _ := d.plugin("firewall")
		attached, mode, prog := fwsXDP(t, topo.WAN)
		r := d.rule(id)
		t.Errorf("binding the firewall to %s, where the XDP engine served a rule, failed: HTTP %d: %.600s\nplugin: %s\nrule: %+v\n%s XDP attached=%t mode=%d prog=%d (core program was %d)",
			topo.WAN, code, out, p, r, topo.WAN, attached, mode, prog, coreProg)
		bound := false
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(3 * time.Second) {
			if code, _ := d.fwActionRaw("apply"); code >= 200 && code < 300 {
				_, _, prog := fwsXDP(t, topo.WAN)
				bound = prog != coreProg
				if !bound {
					p, _ := d.plugin("firewall")
					status := d.fwAction("status")
					t.Errorf("a later apply returned success although %s still runs the core's XDP program %d and no dispatcher: plugin %s; status dirty=%v last_error=%v pending=%v",
						topo.WAN, prog, p, status["dirty"], status["last_error"], status["pending"])
				}
				break
			}
		}
		if !bound {
			t.Logf("the firewall did not bind within 30 s; restarting Veer")
			d.stop()
			d.start()
			d.waitPluginAction("firewall", "apply")
			time.Sleep(2 * time.Second)
			if attached, _, _ := fwsXDP(t, topo.WAN); !attached {
				if d.fwAction("status")["pending"] != nil {
					d.fwAction("rollback")
				}
				if code, out := d.fwActionRaw("apply"); code < 200 || code >= 300 {
					t.Fatalf("binding the firewall after a Veer restart failed too: HTTP %d: %.600s", code, out)
				}
			}
			t.Logf("after a Veer restart: %s", fwsDescribeXDP(t, topo.WAN))
		}
	}
	d.fwAction("confirm")
	d.requireRuleEngine(id, kernelEngineTC, 30*time.Second)
	attached, _, dispatcherProg := fwsXDP(t, topo.WAN)
	if !attached || dispatcherProg == coreProg {
		t.Fatalf("%s: XDP attached=%t prog %d, want the plugin dispatcher instead of the core's program %d", topo.WAN, attached, dispatcherProg, coreProg)
	}
	if engine := d.kernelEngine(kernelEngineXDP); engine.ActiveEntries != 0 {
		t.Fatalf("the XDP engine still has %d entries with the firewall bound", engine.ActiveEntries)
	}
	fwsExpect(t, topo.ClientNS, "firewall bound, core on TC", probes, filtered)

	d.fwSettings()
	d.fwApplyConfirm()
	r, onXDP := d.waitRuleEngine(id, kernelEngineXDP, 45*time.Second)
	t.Logf("after unbinding: rule %+v; %s", r, fwsDescribeXDP(t, topo.WAN, topo.Backend))
	if _, ok := fwsEventually(t, topo.ClientNS, "firewall unbound", probes, open, 20*time.Second); !ok {
		t.Fatalf("the forward stopped working after the firewall was unbound: rule %+v; %s", d.rule(id), fwsDescribeXDP(t, topo.WAN, topo.Backend))
	}
	if !onXDP {
		t.Fatalf("with no XDP plugin hook left the forward stays off the XDP engine: rule %+v", r)
	}
}

// fwsDescribeXDP lists the XDP programs attached to the named interfaces.
func fwsDescribeXDP(t *testing.T, names ...string) string {
	t.Helper()
	parts := make([]string, 0, len(names))
	for _, name := range names {
		attached, mode, prog := fwsXDP(t, name)
		parts = append(parts, fmt.Sprintf("%s XDP attached=%t mode=%d prog=%d", name, attached, mode, prog))
	}
	return strings.Join(parts, "; ")
}

// fwsEventually repeats the probes until they give want or timeout passes,
// and reports how long that took.
func fwsEventually(t *testing.T, ns, step string, probes []fwsProbe, want map[string]bool, timeout time.Duration) (time.Duration, bool) {
	t.Helper()
	started := time.Now()
	for {
		matched := true
		got := map[string]bool{}
		for _, probe := range probes {
			w, ok := want[probe.name]
			if !ok {
				continue
			}
			timeout := 3 * time.Second
			if !w {
				timeout = time.Second
			}
			peer, reached := fwsDial(t, ns, probe.source, probe.target, 0, timeout)
			got[probe.name] = reached
			if reached != w || (reached && probe.wantPeer != "" && peer != probe.wantPeer) {
				matched = false
			}
		}
		if matched {
			t.Logf("%s after %s: %v", step, time.Since(started).Round(100*time.Millisecond), got)
			return time.Since(started), true
		}
		if time.Since(started) > timeout {
			t.Errorf("%s: not reached within %s: %v, want %v", step, timeout, got, want)
			return time.Since(started), false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestFirewallSystemDisableDetaches disables the plugin, enables it again and
// finally removes it. Disabled or removed, it leaves no XDP program on the
// bound interface and filters nothing; enabled again, it binds the confirmed
// rule set once more.
func TestFirewallSystemDisableDetaches(t *testing.T) {
	fwsRequire(t)
	topo := fwsSetupTopology(t, "fwsd")
	port := fwsHostListener(t)
	d := fwsStartDaemon(t, fwsDaemonOptions{RemoteInstall: true})
	d.waitPluginAction("firewall", "apply")
	target := net.JoinHostPort(fwsWANHost4, strconv.Itoa(port))
	target6 := net.JoinHostPort(fwsWANHost6, strconv.Itoa(port))
	probes := []fwsProbe{
		{"allowed", fwsAllowed4, target, fwsAllowed4},
		{"blocked", fwsBlocked4, target, fwsBlocked4},
		{"blocked v6", fwsBlocked6, target6, fwsBlocked6},
	}
	open := map[string]bool{"allowed": true, "blocked": true, "blocked v6": true}
	filtered := map[string]bool{"allowed": true, "blocked": false, "blocked v6": false}
	fwsExpect(t, topo.ClientNS, "before the firewall", probes, open)

	d.fwSettings(topo.WAN)
	d.fwPolicy("svc", []int{port}, fwsAllowed4+"/32")
	d.fwApplyConfirm()
	fwsWaitXDP(t, topo.WAN, true, 10*time.Second)
	fwsExpect(t, topo.ClientNS, "bound", probes, filtered)

	setEnabled := func(enabled bool) {
		t.Helper()
		d.api("POST", "/api/plugins/firewall/state", map[string]any{"enabled": enabled})
	}
	setEnabled(false)
	d.waitPlugin("firewall", 15*time.Second, "disabled", func(p fwsPluginView, present bool) bool {
		return present && !p.Enabled
	})
	fwsWaitXDP(t, topo.WAN, false, 15*time.Second)
	fwsExpect(t, topo.ClientNS, "disabled", probes, open)

	setEnabled(true)
	d.waitPluginAction("firewall", "apply")
	fwsWaitXDP(t, topo.WAN, true, 15*time.Second)
	// The dispatcher may attach before the control plane has rewritten the
	// maps the disabled plugin dropped; it must get there by itself.
	if _, ok := fwsEventually(t, topo.ClientNS, "enabled again, filtering", probes, filtered, 20*time.Second); !ok {
		t.FailNow()
	}
	if status := d.fwAction("status"); status["pending"] != nil || status["dirty"] == true {
		t.Fatalf("status after enabling again: %v", status)
	}

	// Removal: the plugin's directory goes away and the catalog reloads.
	if err := os.RemoveAll(filepath.Join(d.pluginsDir, "firewall")); err != nil {
		t.Fatal(err)
	}
	d.api("POST", "/api/plugins/reload", nil)
	d.waitPlugin("firewall", 15*time.Second, "removal", func(_ fwsPluginView, present bool) bool { return !present })
	fwsWaitXDP(t, topo.WAN, false, 15*time.Second)
	fwsExpect(t, topo.ClientNS, "removed", probes, open)
}

// TestFirewallSystemBrokenObjectFailsOpen runs a copy of the plugin whose
// firewall.o does not load: with an instruction the verifier rejects, and
// with a file that is not an ELF object. Either the object is broken from
// the start and an interface gets bound with a drop policy, or a bound,
// filtering firewall restarts (cold) with the broken object, as after a bad
// upgrade. Either way the failure shows (the apply action, the plugin's
// runtime error), nothing is attached, and the port is reachable.
func TestFirewallSystemBrokenObjectFailsOpen(t *testing.T) {
	fwsRequire(t)
	notAnObject := func(t *testing.T, path string) {
		if err := os.WriteFile(path, []byte("this is not an ELF object\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name       string
		corrupt    func(t *testing.T, path string)
		boundFirst bool
	}{
		{"verifier rejects", fwsBreakFirstExit, false},
		{"not an object", notAnObject, false},
		{"verifier rejects after restart", fwsBreakFirstExit, true},
		{"not an object after restart", notAnObject, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			topo := fwsSetupTopology(t, "fwso")
			port := fwsHostListener(t)
			opts := fwsDaemonOptions{Prepare: func(t *testing.T, pluginsDir string) {
				tc.corrupt(t, filepath.Join(pluginsDir, "firewall", "firewall.o"))
			}}
			if tc.boundFirst {
				opts.Prepare = nil
			}
			d := fwsStartDaemon(t, opts)
			target := net.JoinHostPort(fwsWANHost4, strconv.Itoa(port))
			probes := []fwsProbe{
				{"allowed", fwsAllowed4, target, fwsAllowed4},
				{"blocked", fwsBlocked4, target, fwsBlocked4},
			}
			open := map[string]bool{"allowed": true, "blocked": true}
			fwsExpect(t, topo.ClientNS, "before binding", probes, open)
			if tc.boundFirst {
				d.waitPluginAction("firewall", "apply")
				d.fwSettings(topo.WAN)
				d.fwPolicy("svc", []int{port}, fwsAllowed4+"/32")
				d.fwApplyConfirm()
				fwsWaitXDP(t, topo.WAN, true, 10*time.Second)
				fwsExpect(t, topo.ClientNS, "bound with the good object", probes, map[string]bool{"allowed": true, "blocked": false})
				d.stop()
				t.Logf("after a cold stop: %s", fwsDescribeXDP(t, topo.WAN))
				tc.corrupt(t, filepath.Join(d.pluginsDir, "firewall", "firewall.o"))
				d.start()
			}

			failed := func(p fwsPluginView, present bool) bool {
				return present && (p.Status == pluginStatusError || p.Runtime.Error != "")
			}
			view := d.waitPlugin("firewall", 30*time.Second, "control actions or an error", func(p fwsPluginView, present bool) bool {
				if failed(p, present) {
					return true
				}
				for _, a := range p.Actions {
					if present && a.ID == "apply" {
						return true
					}
				}
				return false
			})
			t.Logf("plugin with the broken object at start: %s", view)
			if !failed(view, true) {
				d.fwSettings(topo.WAN)
				d.fwPolicy("svc", []int{port}, fwsAllowed4+"/32")
				code, out := d.fwActionRaw("apply")
				t.Logf("apply with the broken object: HTTP %d: %.400s", code, out)
				view = d.waitPlugin("firewall", 30*time.Second, "a reported load failure", failed)
			}
			t.Logf("plugin after binding: %s", view)
			if view.Runtime.Attached || view.Runtime.AttachmentCount != 0 {
				t.Fatalf("the failed plugin reports attachments: %s", view)
			}
			// Give a late attach the chance to show.
			time.Sleep(2 * time.Second)
			if attached, mode, prog := fwsXDP(t, topo.WAN); attached {
				t.Fatalf("%s has XDP prog %d (mode %d) although the firewall object did not load", topo.WAN, prog, mode)
			}
			fwsExpect(t, topo.ClientNS, "after the failed load", probes, open)
		})
	}
}

// fwsBreakFirstExit replaces the first exit instruction of the firewall's
// XDP program with an opcode that does not exist, so the ELF still parses
// and the kernel's verifier rejects the program.
func fwsBreakFirstExit(t *testing.T, path string) {
	t.Helper()
	file, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	section := file.Section("xdp/veer/firewall")
	if section == nil {
		file.Close()
		t.Fatalf("%s has no xdp/veer/firewall section", path)
	}
	offset, size := section.Offset, section.Size
	file.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const exitOpcode = 0x95
	for i := offset; i+8 <= offset+size; i += 8 {
		insn := data[i : i+8]
		if insn[0] == exitOpcode && insn[1] == 0 && binary.LittleEndian.Uint16(insn[2:]) == 0 && binary.LittleEndian.Uint32(insn[4:]) == 0 {
			insn[0] = 0xff
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("no exit instruction in the xdp/veer/firewall section of %s", path)
}
