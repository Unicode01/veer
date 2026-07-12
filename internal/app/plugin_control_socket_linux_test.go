//go:build linux

package app

import (
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestPluginControlSocketLinuxLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("SO_BINDTODEVICE integration requires root")
	}
	registry := newPluginControlSocketRegistry(newPluginControlSocketTransport())
	defer registry.CloseAll()

	tcpListener, err := registry.Listen("linux_socket", "generation-a", pluginControlSocketListenRequest{
		Network:   "tcp4",
		Interface: "lo",
		LocalIP:   net.ParseIP("127.0.0.1"),
		LocalPort: 0,
		NoDelay:   true,
	})
	if err != nil {
		t.Fatalf("TCP Listen(lo) error = %v", err)
	}
	tcpIP, tcpPort := pluginControlSocketTestHostPort(t, tcpListener.LocalAddr)
	tcpClient, err := registry.Open("linux_socket", "generation-a", pluginControlSocketOpenRequest{
		Network:    "tcp4",
		Interface:  "lo",
		RemoteIP:   net.ParseIP(tcpIP),
		RemotePort: tcpPort,
		Timeout:    time.Second,
		NoDelay:    true,
	})
	if err != nil {
		t.Fatalf("TCP Open(lo) error = %v", err)
	}
	tcpServer, timedOut, err := registry.Accept("linux_socket", "generation-a", tcpListener.Handle, time.Second)
	if err != nil || timedOut {
		t.Fatalf("TCP Accept(lo) = %+v timeout=%t error=%v", tcpServer, timedOut, err)
	}
	if _, err := registry.Write("linux_socket", "generation-a", tcpClient.Handle, pluginControlSocketWriteRequest{
		Payload: []byte{0x01, 0x02}, Timeout: time.Second,
	}); err != nil {
		t.Fatalf("TCP Write(lo) error = %v", err)
	}
	tcpRead, err := registry.Read("linux_socket", "generation-a", tcpServer.Handle, 64, time.Second)
	if err != nil || string(tcpRead.Payload) != "\x01\x02" {
		t.Fatalf("TCP Read(lo) = %+v/%v, want 0102", tcpRead, err)
	}

	udpListener, err := registry.Listen("linux_socket", "generation-a", pluginControlSocketListenRequest{
		Network:   "udp4",
		Interface: "lo",
		LocalIP:   net.ParseIP("127.0.0.1"),
		LocalPort: 0,
	})
	if err != nil {
		t.Fatalf("UDP Listen(lo) error = %v", err)
	}
	udpIP, udpPort := pluginControlSocketTestHostPort(t, udpListener.LocalAddr)
	udpClient, err := registry.Open("linux_socket", "generation-a", pluginControlSocketOpenRequest{
		Network:    "udp4",
		Interface:  "lo",
		RemoteIP:   net.ParseIP(udpIP),
		RemotePort: udpPort,
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("UDP Open(lo) error = %v", err)
	}
	if _, err := registry.Write("linux_socket", "generation-a", udpClient.Handle, pluginControlSocketWriteRequest{
		Payload: []byte{0x03}, Timeout: time.Second,
	}); err != nil {
		t.Fatalf("UDP Write(lo) error = %v", err)
	}
	udpRead, err := registry.Read("linux_socket", "generation-a", udpListener.Handle, 64, time.Second)
	if err != nil || string(udpRead.Payload) != "\x03" || udpRead.RemoteAddr == nil {
		t.Fatalf("UDP Read(lo) = %+v/%v, want datagram and peer", udpRead, err)
	}
	if _, err := registry.Write("linux_socket", "generation-a", udpListener.Handle, pluginControlSocketWriteRequest{
		Payload: []byte{0x04}, RemoteAddr: udpRead.RemoteAddr, Timeout: time.Second,
	}); err != nil {
		t.Fatalf("UDP reply(lo) error = %v", err)
	}
	udpReply, err := registry.Read("linux_socket", "generation-a", udpClient.Handle, 64, time.Second)
	if err != nil || string(udpReply.Payload) != "\x04" {
		t.Fatalf("UDP client Read(lo) = %+v/%v, want 04", udpReply, err)
	}
}

func pluginControlSocketTestHostPort(t *testing.T, address string) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) error = %v", address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		t.Fatalf("socket address %q has invalid port", address)
	}
	return host, port
}
