//go:build !linux

package app

import "fmt"

func newPluginControlUDPTransport() pluginControlUDPTransport {
	return unsupportedPluginControlUDPTransport{}
}

type unsupportedPluginControlUDPTransport struct{}

func (unsupportedPluginControlUDPTransport) Send(pluginControlUDPSendRequest) (pluginControlUDPResult, error) {
	return pluginControlUDPResult{}, fmt.Errorf("net.udp is supported only on linux")
}

func (unsupportedPluginControlUDPTransport) Recv(pluginControlUDPRecvRequest) (pluginControlUDPDatagram, error) {
	return pluginControlUDPDatagram{}, fmt.Errorf("net.udp is supported only on linux")
}

func (unsupportedPluginControlUDPTransport) Exchange(pluginControlUDPExchangeRequest) (pluginControlUDPDatagram, error) {
	return pluginControlUDPDatagram{}, fmt.Errorf("net.udp is supported only on linux")
}
