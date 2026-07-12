//go:build !linux

package app

import (
	"context"
	"fmt"
	"net"
)

type unsupportedPluginControlSocketTransport struct{}

func newPluginControlSocketTransport() pluginControlSocketTransport {
	return unsupportedPluginControlSocketTransport{}
}

func (unsupportedPluginControlSocketTransport) Dial(context.Context, pluginControlSocketOpenRequest) (net.Conn, error) {
	return nil, fmt.Errorf("persistent plugin sockets are supported only on linux")
}

func (unsupportedPluginControlSocketTransport) Listen(context.Context, pluginControlSocketListenRequest) (pluginControlDeadlineListener, error) {
	return nil, fmt.Errorf("persistent plugin sockets are supported only on linux")
}

func (unsupportedPluginControlSocketTransport) ListenPacket(context.Context, pluginControlSocketListenRequest) (net.PacketConn, error) {
	return nil, fmt.Errorf("persistent plugin sockets are supported only on linux")
}
