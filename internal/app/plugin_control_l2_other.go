//go:build !linux

package app

import "fmt"

func newPluginControlL2Transport() pluginControlL2Transport {
	return unsupportedPluginControlL2Transport{}
}

type unsupportedPluginControlL2Transport struct{}

func (unsupportedPluginControlL2Transport) Send(req pluginControlL2SendRequest) error {
	return fmt.Errorf("raw l2 send is unsupported on this platform")
}

func (unsupportedPluginControlL2Transport) Recv(req pluginControlL2RecvRequest) (pluginControlL2Frame, error) {
	return pluginControlL2Frame{}, fmt.Errorf("raw l2 receive is unsupported on this platform")
}

func (unsupportedPluginControlL2Transport) RecvMany(req pluginControlL2RecvManyRequest) ([]pluginControlL2Frame, error) {
	return nil, fmt.Errorf("raw l2 receive is unsupported on this platform")
}

func (unsupportedPluginControlL2Transport) Exchange(req pluginControlL2ExchangeRequest) (pluginControlL2Frame, error) {
	return pluginControlL2Frame{}, fmt.Errorf("raw l2 exchange is unsupported on this platform")
}

func (unsupportedPluginControlL2Transport) ExchangeMany(req pluginControlL2ExchangeManyRequest) ([]pluginControlL2Frame, error) {
	return nil, fmt.Errorf("raw l2 exchange is unsupported on this platform")
}
