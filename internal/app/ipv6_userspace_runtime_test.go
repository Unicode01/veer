package app

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

const ipv6UserspaceTestTimeout = 5 * time.Second

func reserveTCPPortOnHost(t *testing.T, network, host string) int {
	t.Helper()

	ln, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("listen %s on %s unavailable: %v", network, host, err)
	}
	defer ln.Close()

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr == nil {
		t.Fatalf("listener addr = %T, want *net.TCPAddr", ln.Addr())
	}
	return addr.Port
}

func reserveUDPPortOnHost(t *testing.T, network, host string) int {
	t.Helper()

	addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%q, %q): %v", network, host, err)
	}
	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		t.Skipf("listen %s on %s unavailable: %v", network, host, err)
	}
	defer conn.Close()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		t.Fatalf("listener addr = %T, want *net.UDPAddr", conn.LocalAddr())
	}
	return local.Port
}

func startTCPEchoServer(t *testing.T, network, host string) int {
	t.Helper()

	ln, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("tcp echo server %s on %s unavailable: %v", network, host, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(ipv6UserspaceTestTimeout))
				buf := make([]byte, 2048)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr == nil {
		t.Fatalf("tcp echo addr = %T, want *net.TCPAddr", ln.Addr())
	}
	return addr.Port
}

func startUDPEchoServer(t *testing.T, network, host string) int {
	t.Helper()

	addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%q, %q): %v", network, host, err)
	}
	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		t.Skipf("udp echo server %s on %s unavailable: %v", network, host, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], remote)
		}
	}()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		t.Fatalf("udp echo addr = %T, want *net.UDPAddr", conn.LocalAddr())
	}
	return local.Port
}

func assertTCPEcho(t *testing.T, network, host string, port int, payload []byte) {
	t.Helper()

	conn, err := net.DialTimeout(network, net.JoinHostPort(host, strconv.Itoa(port)), ipv6UserspaceTestTimeout)
	if err != nil {
		t.Fatalf("DialTimeout(%q): %v", network, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(ipv6UserspaceTestTimeout))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write(): %v", err)
	}

	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("ReadFull(): %v", err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("reply = %q, want %q", string(reply), string(payload))
	}
}

func assertUDPEcho(t *testing.T, network, host string, port int, payload []byte) {
	t.Helper()

	remote, err := net.ResolveUDPAddr(network, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%q): %v", network, err)
	}
	conn, err := net.DialUDP(network, nil, remote)
	if err != nil {
		t.Fatalf("DialUDP(%q): %v", network, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(ipv6UserspaceTestTimeout))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write(): %v", err)
	}

	reply := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(reply)
	if err != nil {
		t.Fatalf("ReadFromUDP(): %v", err)
	}
	if string(reply[:n]) != string(payload) {
		t.Fatalf("reply = %q, want %q", string(reply[:n]), string(payload))
	}
}

func TestRuleBindingIPv6TCPEcho(t *testing.T) {
	backendPort := startTCPEchoServer(t, "tcp6", "::1")
	forwardPort := reserveTCPPortOnHost(t, "tcp6", "::1")

	binding, err := startRuleBinding(0, Rule{
		ID:       1,
		InIP:     "::1",
		InPort:   forwardPort,
		OutIP:    "::1",
		OutPort:  backendPort,
		Protocol: "tcp",
	}, &ruleStats{})
	if err != nil {
		t.Fatalf("startRuleBinding(): %v", err)
	}
	t.Cleanup(binding.Stop)

	assertTCPEcho(t, "tcp6", "::1", forwardPort, []byte("hello-ipv6-tcp"))
}

func TestRuleBindingIPv6UDPEcho(t *testing.T) {
	backendPort := startUDPEchoServer(t, "udp6", "::1")
	forwardPort := reserveUDPPortOnHost(t, "udp6", "::1")

	binding, err := startRuleBinding(0, Rule{
		ID:       2,
		InIP:     "::1",
		InPort:   forwardPort,
		OutIP:    "::1",
		OutPort:  backendPort,
		Protocol: "udp",
	}, &ruleStats{})
	if err != nil {
		t.Fatalf("startRuleBinding(): %v", err)
	}
	t.Cleanup(binding.Stop)

	assertUDPEcho(t, "udp6", "::1", forwardPort, []byte("hello-ipv6-udp"))
}

func TestRuleBindingIPv6ToIPv4UDPEcho(t *testing.T) {
	backendPort := startUDPEchoServer(t, "udp4", "127.0.0.1")
	forwardPort := reserveUDPPortOnHost(t, "udp6", "::1")

	binding, err := startRuleBinding(0, Rule{
		ID:       3,
		InIP:     "::1",
		InPort:   forwardPort,
		OutIP:    "127.0.0.1",
		OutPort:  backendPort,
		Protocol: "udp",
	}, &ruleStats{})
	if err != nil {
		t.Fatalf("startRuleBinding(): %v", err)
	}
	t.Cleanup(binding.Stop)

	assertUDPEcho(t, "udp6", "::1", forwardPort, []byte("hello-mixed-udp"))
}

func TestRangeBindingIPv6TCPEcho(t *testing.T) {
	backendPort := startTCPEchoServer(t, "tcp6", "::1")
	forwardPort := reserveTCPPortOnHost(t, "tcp6", "::1")

	binding, err := startRangeBinding(0, PortRange{
		ID:           4,
		InIP:         "::1",
		StartPort:    forwardPort,
		EndPort:      forwardPort,
		OutIP:        "::1",
		OutStartPort: backendPort,
		Protocol:     "tcp",
	}, &ruleStats{})
	if err != nil {
		t.Fatalf("startRangeBinding(): %v", err)
	}
	t.Cleanup(binding.Stop)

	assertTCPEcho(t, "tcp6", "::1", forwardPort, []byte("hello-range-ipv6-tcp"))
}

func TestRangeBindingIPv6UDPEcho(t *testing.T) {
	backendPort := startUDPEchoServer(t, "udp6", "::1")
	forwardPort := reserveUDPPortOnHost(t, "udp6", "::1")

	binding, err := startRangeBinding(0, PortRange{
		ID:           5,
		InIP:         "::1",
		StartPort:    forwardPort,
		EndPort:      forwardPort,
		OutIP:        "::1",
		OutStartPort: backendPort,
		Protocol:     "udp",
	}, &ruleStats{})
	if err != nil {
		t.Fatalf("startRangeBinding(): %v", err)
	}
	t.Cleanup(binding.Stop)

	assertUDPEcho(t, "udp6", "::1", forwardPort, []byte("hello-range-ipv6-udp"))
}
