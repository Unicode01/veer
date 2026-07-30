//go:build !linux

package app

import "fmt"

func newPluginControlNetAdmin() pluginControlNetAdmin {
	return unsupportedPluginControlNetAdmin{}
}

type unsupportedPluginControlNetAdmin struct{}

func (unsupportedPluginControlNetAdmin) LinkGet(string) (pluginControlNetLinkInfo, error) {
	return pluginControlNetLinkInfo{}, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkLookup(string) (pluginControlNetLinkInfo, bool, error) {
	return pluginControlNetLinkInfo{}, false, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkList() ([]pluginControlNetLinkInfo, error) {
	return nil, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkEnsureBridge(pluginControlNetBridgeRequest) (pluginControlNetLinkInfo, error) {
	return pluginControlNetLinkInfo{}, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkEnsureVeth(pluginControlNetVethRequest) (pluginControlNetVethResult, error) {
	return pluginControlNetVethResult{}, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkEnsureDummy(pluginControlNetDummyRequest) (pluginControlNetDummyResult, error) {
	return pluginControlNetDummyResult{}, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkEnsureMacvlan(pluginControlNetMacvlanRequest) (pluginControlNetMacvlanResult, error) {
	return pluginControlNetMacvlanResult{}, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkEnsureVLAN(pluginControlNetVLANRequest) (pluginControlNetVLANResult, error) {
	return pluginControlNetVLANResult{}, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkEnsureVRF(pluginControlNetVRFRequest) (pluginControlNetVRFResult, error) {
	return pluginControlNetVRFResult{}, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkDelete(string) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkSetMaster(pluginControlNetMasterRequest) (pluginControlNetLinkInfo, error) {
	return pluginControlNetLinkInfo{}, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkClearMaster(string) (pluginControlNetLinkInfo, error) {
	return pluginControlNetLinkInfo{}, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkSetUp(string, bool) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkSetMTU(string, int) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkSetARP(string, bool) (pluginControlNetLinkInfo, error) {
	return pluginControlNetLinkInfo{}, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkSetPromiscuous(string, bool) (pluginControlNetLinkInfo, error) {
	return pluginControlNetLinkInfo{}, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkGetOffloads(string) (map[string]bool, error) {
	return nil, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkSetOffloads(pluginControlNetOffloadRequest) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) LinkSetGSO(pluginControlNetGSORequest) (pluginControlNetLinkInfo, error) {
	return pluginControlNetLinkInfo{}, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) AddrReplace(pluginControlNetAddrRequest) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) AddrDelete(pluginControlNetAddrRequest) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) RouteSnapshot(pluginControlNetRouteRequest) ([]pluginControlNetRouteState, error) {
	return nil, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) RouteRestore([]pluginControlNetRouteState) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) RouteReplace(pluginControlNetRouteRequest) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) RouteDelete(pluginControlNetRouteRequest) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) RuleSnapshot(pluginControlNetRuleRequest) ([]pluginControlNetRuleState, error) {
	return nil, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) RuleRestore([]pluginControlNetRuleState) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) RuleReplace(pluginControlNetRuleRequest) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) RuleDelete(pluginControlNetRuleRequest) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) NeighSnapshot(pluginControlNetNeighRequest) ([]pluginControlNetNeighState, error) {
	return nil, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) NeighRestore([]pluginControlNetNeighState) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) NeighReplace(pluginControlNetNeighRequest) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) NeighDelete(pluginControlNetNeighRequest) error {
	return fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) NeighList(pluginControlNetReadRequest) ([]pluginControlNetNeighborInfo, error) {
	return nil, fmt.Errorf("net.admin is supported only on linux")
}

func (unsupportedPluginControlNetAdmin) BridgeFDBList(pluginControlNetReadRequest) ([]pluginControlNetFDBInfo, error) {
	return nil, fmt.Errorf("net.admin is supported only on linux")
}
