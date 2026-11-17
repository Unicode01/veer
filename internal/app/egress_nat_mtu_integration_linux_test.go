//go:build linux

package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	egressNATMTUUplink      = 1400
	egressNATMTUUDPPort     = 24101
	egressNATMTUTCPPort     = 24102
	egressNATMTUUploadBytes = 4 << 20
)

// runInNetNSForTest runs fn on a thread inside the named network namespace.
// Sockets fn opens stay in that namespace and may be used from anywhere.
func runInNetNSForTest(name string, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		defer orig.Close()
		target, err := os.Open(filepath.Join("/var/run/netns", name))
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		defer target.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("enter netns %s: %w", name, err)
			return
		}
		ferr := fn()
		// A thread that cannot return stays locked and ends with this goroutine.
		if err := unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET); err != nil {
			errc <- fmt.Errorf("leave netns %s: %w", name, err)
			return
		}
		runtime.UnlockOSThread()
		errc <- ferr
	}()
	return <-errc
}

type egressNATMTUDatagram struct {
	src    string
	length int
}

// egressNATMTUBackend records the datagrams it receives and answers "BIG n"
// with n bytes; its TCP side counts the bytes of a connection until EOF and
// answers with the count.
type egressNATMTUBackend struct {
	mu        sync.Mutex
	datagrams []egressNATMTUDatagram
}

func (b *egressNATMTUBackend) received() []egressNATMTUDatagram {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]egressNATMTUDatagram(nil), b.datagrams...)
}

func startEgressNATMTUBackend(t *testing.T, ns string) *egressNATMTUBackend {
	t.Helper()
	backend := &egressNATMTUBackend{}
	var udp *net.UDPConn
	var tcp net.Listener
	err := runInNetNSForTest(ns, func() error {
		var err error
		udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(egressNATBackendAddr), Port: egressNATMTUUDPPort})
		if err != nil {
			return err
		}
		tcp, err = net.Listen("tcp4", net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(egressNATMTUTCPPort)))
		return err
	})
	if err != nil {
		t.Fatalf("start backend: %v", err)
	}
	t.Cleanup(func() {
		_ = udp.Close()
		_ = tcp.Close()
	})
	go func() {
		buf := make([]byte, 65536)
		for {
			n, src, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			backend.mu.Lock()
			backend.datagrams = append(backend.datagrams, egressNATMTUDatagram{src: src.IP.String(), length: n})
			backend.mu.Unlock()
			var size int
			if _, err := fmt.Sscanf(string(buf[:n]), "BIG %d", &size); err == nil && size > 0 {
				_, _ = udp.WriteToUDP(bytes.Repeat([]byte("R"), size), src)
			}
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
				n, _ := io.Copy(io.Discard, conn)
				_, _ = conn.Write([]byte(strconv.FormatInt(n, 10)))
			}()
		}
	}()
	return backend
}

// An uplink with a smaller MTU than the LAN (PPPoE, a tunnel) is the common
// router setup. Through the TC egress NAT, a packet too big for it must make
// the client learn the path MTU, as the stack's ICMP fragmentation needed
// does, instead of vanishing on the uplink; and datagrams fragmented on
// either side must be translated whole, not only their first fragment.
func TestEgressNATTCPathMTUAndFragments(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	harness := startEgressNATIntegrationHarness(t, "mtu")
	topology := harness.Topology
	uplinkMTU := strconv.Itoa(egressNATMTUUplink)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.UplinkHostIF, "mtu", uplinkMTU)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "link", "set", topology.BackendNSIF, "mtu", uplinkMTU)
	// An Internet server on a 1500-byte link offers MSS 1460, whatever the
	// router's uplink takes.
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "route", "replace",
		"198.19.0.0/24", "dev", topology.BackendNSIF, "advmss", "1460")
	createEgressNATIntegrationEntry(t, harness.APIBase, topology)
	waitForEgressNATIntegrationStatus(t, harness.APIBase, topology, topology.ChildHostIF)
	backend := startEgressNATMTUBackend(t, topology.BackendNS)
	udpTarget := &net.UDPAddr{IP: net.ParseIP(egressNATBackendAddr), Port: egressNATMTUUDPPort}

	t.Run("tcp upload learns the uplink MTU", func(t *testing.T) {
		var conn net.Conn
		if err := runInNetNSForTest(topology.ClientNS, func() error {
			var err error
			conn, err = net.DialTimeout("tcp4", net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(egressNATMTUTCPPort)), 5*time.Second)
			return err
		}); err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		if _, err := conn.Write(bytes.Repeat([]byte("T"), egressNATMTUUploadBytes)); err != nil {
			logForwardLogOnFailure(t, harness.LogPath)
			t.Fatalf("upload stalled: %v", err)
		}
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatalf("close write: %v", err)
		}
		reply, err := io.ReadAll(conn)
		if err != nil || string(reply) != strconv.Itoa(egressNATMTUUploadBytes) {
			logForwardLogOnFailure(t, harness.LogPath)
			t.Fatalf("backend counted %q (err %v), want %d bytes", reply, err, egressNATMTUUploadBytes)
		}
	})

	t.Run("udp with DF learns the uplink MTU", func(t *testing.T) {
		var conn *net.UDPConn
		if err := runInNetNSForTest(topology.ClientNS, func() error {
			var err error
			conn, err = net.DialUDP("udp4", nil, udpTarget)
			if err != nil {
				return err
			}
			raw, err := conn.SyscallConn()
			if err != nil {
				return err
			}
			var serr error
			if err := raw.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
			}); err != nil {
				return err
			}
			return serr
		}); err != nil {
			t.Fatalf("open udp socket: %v", err)
		}
		defer conn.Close()
		// Fits the LAN, not the uplink.
		payload := bytes.Repeat([]byte("D"), 1500-28)
		deadline := time.Now().Add(5 * time.Second)
		for {
			_, err := conn.Write(payload)
			if errors.Is(err, syscall.EMSGSIZE) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the client never learned the uplink MTU (last write: %v)", err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		raw, _ := conn.SyscallConn()
		var mtu int
		_ = raw.Control(func(fd uintptr) {
			mtu, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU)
		})
		if mtu != egressNATMTUUplink {
			t.Fatalf("path MTU = %d, want %d", mtu, egressNATMTUUplink)
		}
		for _, d := range backend.received() {
			if d.length == len(payload) {
				t.Fatalf("the backend got a %d-byte datagram the uplink cannot carry", d.length)
			}
		}
	})

	// The client fragments to fit the uplink from here on.
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "route", "replace", "default",
		"via", egressNATBridgeAddr, "dev", topology.ClientNSIF, "mtu", uplinkMTU)

	t.Run("fragmented udp request is translated whole", func(t *testing.T) {
		var conn *net.UDPConn
		if err := runInNetNSForTest(topology.ClientNS, func() error {
			var err error
			conn, err = net.DialUDP("udp4", nil, udpTarget)
			return err
		}); err != nil {
			t.Fatalf("open udp socket: %v", err)
		}
		defer conn.Close()
		const size = 3000
		if _, err := conn.Write(bytes.Repeat([]byte("F"), size)); err != nil {
			t.Fatalf("send: %v", err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			for _, d := range backend.received() {
				if d.length != size {
					continue
				}
				if d.src != egressNATUplinkAddr {
					t.Fatalf("the backend got the datagram from %s, want the NAT address %s", d.src, egressNATUplinkAddr)
				}
				return
			}
			if time.Now().After(deadline) {
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("the backend never got the %d-byte datagram: %+v", size, backend.received())
			}
			time.Sleep(50 * time.Millisecond)
		}
	})

	t.Run("fragmented udp reply reaches the client", func(t *testing.T) {
		var conn *net.UDPConn
		if err := runInNetNSForTest(topology.ClientNS, func() error {
			var err error
			conn, err = net.DialUDP("udp4", nil, udpTarget)
			return err
		}); err != nil {
			t.Fatalf("open udp socket: %v", err)
		}
		defer conn.Close()
		const size = 3000
		buf := make([]byte, 65536)
		for attempt := 0; attempt < 3; attempt++ {
			if _, err := conn.Write([]byte(fmt.Sprintf("BIG %d", size))); err != nil {
				t.Fatalf("send request: %v", err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			n, err := conn.Read(buf)
			if err == nil {
				if n != size {
					t.Fatalf("got a %d-byte reply, want %d", n, size)
				}
				return
			}
		}
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("the %d-byte reply never reached the client", size)
	})

	runtimeResp := fetchDataplanePerfKernelRuntime(t, harness.APIBase)
	for _, engine := range runtimeResp.Engines {
		if engine.Name != kernelEngineTC {
			continue
		}
		if engine.DiagPMTUToStack == 0 || engine.DiagFragmentForwarded == 0 {
			t.Fatalf("tc diag pmtu_to_stack=%d fragment_forwarded=%d, want both counted", engine.DiagPMTUToStack, engine.DiagFragmentForwarded)
		}
		return
	}
	t.Fatal("kernel runtime has no tc engine")
}
