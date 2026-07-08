//go:build linux

package app

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func newPluginControlUDPTransport() pluginControlUDPTransport {
	return linuxPluginControlUDPTransport{}
}

type linuxPluginControlUDPTransport struct{}

func (linuxPluginControlUDPTransport) Send(req pluginControlUDPSendRequest) (pluginControlUDPResult, error) {
	conn, remote, err := listenPluginControlUDP(req.Interface, req.LocalIP, req.LocalPort, req.RemoteIP, req.RemotePort)
	if err != nil {
		return pluginControlUDPResult{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(req.Timeout)); err != nil {
		return pluginControlUDPResult{}, err
	}
	n, err := conn.WriteToUDP(req.Payload, remote)
	if err != nil {
		return pluginControlUDPResult{}, err
	}
	return pluginControlUDPResult{
		Interface:  req.Interface,
		LocalAddr:  conn.LocalAddr().(*net.UDPAddr),
		RemoteAddr: remote,
		Bytes:      n,
	}, nil
}

func (linuxPluginControlUDPTransport) Recv(req pluginControlUDPRecvRequest) (pluginControlUDPDatagram, error) {
	conn, _, err := listenPluginControlUDP(req.Interface, req.LocalIP, req.LocalPort, req.RemoteIP, req.RemotePort)
	if err != nil {
		return pluginControlUDPDatagram{}, err
	}
	defer conn.Close()
	return recvPluginControlUDPDatagram(conn, req)
}

func (linuxPluginControlUDPTransport) Exchange(req pluginControlUDPExchangeRequest) (pluginControlUDPDatagram, error) {
	conn, remote, err := listenPluginControlUDP(req.Send.Interface, req.Send.LocalIP, req.Send.LocalPort, req.Send.RemoteIP, req.Send.RemotePort)
	if err != nil {
		return pluginControlUDPDatagram{}, err
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(req.Send.Timeout)); err != nil {
		return pluginControlUDPDatagram{}, err
	}
	if _, err := conn.WriteToUDP(req.Send.Payload, remote); err != nil {
		return pluginControlUDPDatagram{}, err
	}
	return recvPluginControlUDPDatagram(conn, req.Recv)
}

func listenPluginControlUDP(iface string, localIP net.IP, localPort int, remoteIP net.IP, remotePort int) (*net.UDPConn, *net.UDPAddr, error) {
	network := pluginControlUDPNetwork(localIP, remoteIP)
	local := &net.UDPAddr{IP: localIP, Port: localPort}
	remote := &net.UDPAddr{IP: remoteIP, Port: remotePort}
	lc := net.ListenConfig{Control: bindPluginControlUDPToDevice(iface)}
	pc, err := lc.ListenPacket(context.Background(), network, local.String())
	if err != nil {
		return nil, nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, nil, fmt.Errorf("listen %s returned unsupported packet conn %T", network, pc)
	}
	return conn, remote, nil
}

func bindPluginControlUDPToDevice(iface string) func(string, string, syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(network string, address string, c syscall.RawConn) error {
		var controlErr error
		if err := c.Control(func(fd uintptr) {
			controlErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return controlErr
	}
}

func pluginControlUDPNetwork(localIP net.IP, remoteIP net.IP) string {
	if ipIsIPv6(remoteIP) || ipIsIPv6(localIP) {
		return "udp6"
	}
	return "udp4"
}

func ipIsIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil
}

func recvPluginControlUDPDatagram(conn *net.UDPConn, req pluginControlUDPRecvRequest) (pluginControlUDPDatagram, error) {
	if err := conn.SetReadDeadline(time.Now().Add(req.Timeout)); err != nil {
		return pluginControlUDPDatagram{}, err
	}
	buf := make([]byte, req.MaxBytes)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return pluginControlUDPDatagram{}, errPluginControlUDPTimeout
			}
			return pluginControlUDPDatagram{}, err
		}
		if req.HasRemoteFilter && !pluginControlUDPRemoteMatches(remote, req.RemoteIP, req.RemotePort) {
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		return pluginControlUDPDatagram{
			Interface:  req.Interface,
			LocalAddr:  conn.LocalAddr().(*net.UDPAddr),
			RemoteAddr: remote,
			Payload:    payload,
		}, nil
	}
}

func pluginControlUDPRemoteMatches(addr *net.UDPAddr, ip net.IP, port int) bool {
	if addr == nil {
		return false
	}
	if ip != nil && !addr.IP.Equal(ip) {
		return false
	}
	if port > 0 && addr.Port != port {
		return false
	}
	return true
}
