//go:build linux

package app

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

type linuxPluginControlSocketTransport struct{}

func newPluginControlSocketTransport() pluginControlSocketTransport {
	return linuxPluginControlSocketTransport{}
}

func (linuxPluginControlSocketTransport) Dial(ctx context.Context, req pluginControlSocketOpenRequest) (net.Conn, error) {
	namespace := normalizePluginControlNamespace(req.Namespace)
	if namespace != "host" {
		req.Namespace = "host"
		var conn net.Conn
		err := linuxPluginRunInNamespace(namespace, func() error {
			var operationErr error
			conn, operationErr = (linuxPluginControlSocketTransport{}).Dial(ctx, req)
			return operationErr
		})
		if err != nil && conn != nil {
			_ = conn.Close()
			conn = nil
		}
		return conn, err
	}
	dialer := net.Dialer{
		Control:   bindPluginControlSocketToDevice(req.Interface),
		KeepAlive: req.KeepAlive,
	}
	if req.LocalIP != nil || req.LocalPort > 0 {
		if pluginControlSocketIsTCP(req.Network) {
			dialer.LocalAddr = &net.TCPAddr{IP: req.LocalIP, Port: req.LocalPort}
		} else {
			dialer.LocalAddr = &net.UDPAddr{IP: req.LocalIP, Port: req.LocalPort}
		}
	}
	conn, err := dialer.DialContext(ctx, req.Network, pluginControlSocketAddress(req.RemoteIP, req.RemotePort))
	if err != nil {
		return nil, err
	}
	if pluginControlSocketIsTCP(req.Network) {
		if err := configurePluginControlTCPConn(conn, req.NoDelay, req.KeepAlive); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func (linuxPluginControlSocketTransport) Listen(ctx context.Context, req pluginControlSocketListenRequest) (pluginControlDeadlineListener, error) {
	namespace := normalizePluginControlNamespace(req.Namespace)
	if namespace != "host" {
		req.Namespace = "host"
		var listener pluginControlDeadlineListener
		err := linuxPluginRunInNamespace(namespace, func() error {
			var operationErr error
			listener, operationErr = (linuxPluginControlSocketTransport{}).Listen(ctx, req)
			return operationErr
		})
		if err != nil && listener != nil {
			_ = listener.Close()
			listener = nil
		}
		return listener, err
	}
	lc := net.ListenConfig{Control: bindPluginControlSocketToDevice(req.Interface)}
	listener, err := lc.Listen(ctx, req.Network, pluginControlSocketAddress(req.LocalIP, req.LocalPort))
	if err != nil {
		return nil, err
	}
	deadlineListener, ok := listener.(pluginControlDeadlineListener)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("listen %s returned unsupported listener %T", req.Network, listener)
	}
	return deadlineListener, nil
}

func (linuxPluginControlSocketTransport) ListenPacket(ctx context.Context, req pluginControlSocketListenRequest) (net.PacketConn, error) {
	namespace := normalizePluginControlNamespace(req.Namespace)
	if namespace != "host" {
		req.Namespace = "host"
		var packet net.PacketConn
		err := linuxPluginRunInNamespace(namespace, func() error {
			var operationErr error
			packet, operationErr = (linuxPluginControlSocketTransport{}).ListenPacket(ctx, req)
			return operationErr
		})
		if err != nil && packet != nil {
			_ = packet.Close()
			packet = nil
		}
		return packet, err
	}
	lc := net.ListenConfig{Control: bindPluginControlSocketToDevice(req.Interface)}
	return lc.ListenPacket(ctx, req.Network, pluginControlSocketAddress(req.LocalIP, req.LocalPort))
}

func bindPluginControlSocketToDevice(iface string) func(string, string, syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(network string, address string, conn syscall.RawConn) error {
		var controlErr error
		if err := conn.Control(func(fd uintptr) {
			controlErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return controlErr
	}
}
