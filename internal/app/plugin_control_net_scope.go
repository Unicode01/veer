package app

import (
	"fmt"
	"strings"
)

// pluginControlNetNamespaceRunner executes one bounded control-plane operation
// in a named network namespace. Implementations must restore the caller's
// namespace before returning.
type pluginControlNetNamespaceRunner interface {
	RunInNamespace(name string, fn func() error) error
}

type scopedPluginControlNetAdmin struct {
	base      pluginControlNetAdmin
	runner    pluginControlNetNamespaceRunner
	namespace string
}

func pluginControlNetAdminInNamespace(base pluginControlNetAdmin, namespace string) (pluginControlNetAdmin, error) {
	namespace = normalizePluginControlNamespace(namespace)
	if namespace == "host" {
		return base, nil
	}
	if base == nil {
		return nil, fmt.Errorf("net.admin controller is unavailable")
	}
	runner, ok := base.(pluginControlNetNamespaceRunner)
	if !ok || runner == nil {
		return nil, fmt.Errorf("network namespace scoped net.admin operations are unavailable")
	}
	return &scopedPluginControlNetAdmin{base: base, runner: runner, namespace: namespace}, nil
}

func (admin *scopedPluginControlNetAdmin) run(fn func(pluginControlNetAdmin) error) error {
	if admin == nil || admin.base == nil || admin.runner == nil {
		return fmt.Errorf("network namespace scoped net.admin controller is unavailable")
	}
	return admin.runner.RunInNamespace(admin.namespace, func() error { return fn(admin.base) })
}

func (admin *scopedPluginControlNetAdmin) annotate(info pluginControlNetLinkInfo) pluginControlNetLinkInfo {
	info.Namespace = admin.namespace
	return info
}

func (admin *scopedPluginControlNetAdmin) LinkGet(name string) (out pluginControlNetLinkInfo, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkGet(name)
		return callErr
	})
	return admin.annotate(out), err
}

func (admin *scopedPluginControlNetAdmin) LinkLookup(name string) (out pluginControlNetLinkInfo, present bool, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, present, callErr = base.LinkLookup(name)
		return callErr
	})
	return admin.annotate(out), present, err
}

func (admin *scopedPluginControlNetAdmin) LinkList() (out []pluginControlNetLinkInfo, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkList()
		return callErr
	})
	for i := range out {
		out[i] = admin.annotate(out[i])
	}
	return out, err
}

func (admin *scopedPluginControlNetAdmin) LinkEnsureBridge(req pluginControlNetBridgeRequest) (out pluginControlNetLinkInfo, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkEnsureBridge(req)
		return callErr
	})
	return admin.annotate(out), err
}

func (admin *scopedPluginControlNetAdmin) LinkEnsureVeth(req pluginControlNetVethRequest) (out pluginControlNetVethResult, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkEnsureVeth(req)
		return callErr
	})
	out.Host = admin.annotate(out.Host)
	out.Peer = admin.annotate(out.Peer)
	return out, err
}

func (admin *scopedPluginControlNetAdmin) LinkEnsureDummy(req pluginControlNetDummyRequest) (out pluginControlNetDummyResult, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkEnsureDummy(req)
		return callErr
	})
	out.Link = admin.annotate(out.Link)
	return out, err
}

func (admin *scopedPluginControlNetAdmin) LinkEnsureMacvlan(req pluginControlNetMacvlanRequest) (out pluginControlNetMacvlanResult, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkEnsureMacvlan(req)
		return callErr
	})
	out.Link = admin.annotate(out.Link)
	return out, err
}

func (admin *scopedPluginControlNetAdmin) LinkEnsureVLAN(req pluginControlNetVLANRequest) (out pluginControlNetVLANResult, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkEnsureVLAN(req)
		return callErr
	})
	out.Link = admin.annotate(out.Link)
	return out, err
}

func (admin *scopedPluginControlNetAdmin) LinkEnsureVRF(req pluginControlNetVRFRequest) (out pluginControlNetVRFResult, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkEnsureVRF(req)
		return callErr
	})
	out.Link = admin.annotate(out.Link)
	return out, err
}

func (admin *scopedPluginControlNetAdmin) LinkDelete(name string) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.LinkDelete(name) })
}

func (admin *scopedPluginControlNetAdmin) LinkSetMaster(req pluginControlNetMasterRequest) (out pluginControlNetLinkInfo, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkSetMaster(req)
		return callErr
	})
	return admin.annotate(out), err
}

func (admin *scopedPluginControlNetAdmin) LinkClearMaster(name string) (out pluginControlNetLinkInfo, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkClearMaster(name)
		return callErr
	})
	return admin.annotate(out), err
}

func (admin *scopedPluginControlNetAdmin) LinkSetUp(name string, up bool) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.LinkSetUp(name, up) })
}

func (admin *scopedPluginControlNetAdmin) LinkSetMTU(name string, mtu int) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.LinkSetMTU(name, mtu) })
}

func (admin *scopedPluginControlNetAdmin) LinkSetARP(name string, enabled bool) (out pluginControlNetLinkInfo, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkSetARP(name, enabled)
		return callErr
	})
	return admin.annotate(out), err
}

func (admin *scopedPluginControlNetAdmin) LinkSetPromiscuous(name string, enabled bool) (out pluginControlNetLinkInfo, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkSetPromiscuous(name, enabled)
		return callErr
	})
	return admin.annotate(out), err
}

func (admin *scopedPluginControlNetAdmin) LinkGetOffloads(name string) (out map[string]bool, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkGetOffloads(name)
		return callErr
	})
	return out, err
}

func (admin *scopedPluginControlNetAdmin) LinkSetOffloads(req pluginControlNetOffloadRequest) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.LinkSetOffloads(req) })
}

func (admin *scopedPluginControlNetAdmin) LinkSetGSO(req pluginControlNetGSORequest) (out pluginControlNetLinkInfo, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.LinkSetGSO(req)
		return callErr
	})
	return admin.annotate(out), err
}

func (admin *scopedPluginControlNetAdmin) AddrReplace(req pluginControlNetAddrRequest) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.AddrReplace(req) })
}

func (admin *scopedPluginControlNetAdmin) AddrDelete(req pluginControlNetAddrRequest) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.AddrDelete(req) })
}

func (admin *scopedPluginControlNetAdmin) RouteSnapshot(req pluginControlNetRouteRequest) (out []pluginControlNetRouteState, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.RouteSnapshot(req)
		return callErr
	})
	for i := range out {
		out[i].Namespace = admin.namespace
	}
	return out, err
}

func (admin *scopedPluginControlNetAdmin) RouteRestore(states []pluginControlNetRouteState) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.RouteRestore(states) })
}

func (admin *scopedPluginControlNetAdmin) RouteReplace(req pluginControlNetRouteRequest) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.RouteReplace(req) })
}

func (admin *scopedPluginControlNetAdmin) RouteDelete(req pluginControlNetRouteRequest) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.RouteDelete(req) })
}

func (admin *scopedPluginControlNetAdmin) RuleSnapshot(req pluginControlNetRuleRequest) (out []pluginControlNetRuleState, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.RuleSnapshot(req)
		return callErr
	})
	for i := range out {
		out[i].Request.Namespace = admin.namespace
	}
	return out, err
}

func (admin *scopedPluginControlNetAdmin) RuleRestore(states []pluginControlNetRuleState) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.RuleRestore(states) })
}

func (admin *scopedPluginControlNetAdmin) RuleReplace(req pluginControlNetRuleRequest) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.RuleReplace(req) })
}

func (admin *scopedPluginControlNetAdmin) RuleDelete(req pluginControlNetRuleRequest) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.RuleDelete(req) })
}

func (admin *scopedPluginControlNetAdmin) NeighSnapshot(req pluginControlNetNeighRequest) (out []pluginControlNetNeighState, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		var callErr error
		out, callErr = base.NeighSnapshot(req)
		return callErr
	})
	for i := range out {
		out[i].Request.Namespace = admin.namespace
	}
	return out, err
}

func (admin *scopedPluginControlNetAdmin) NeighRestore(states []pluginControlNetNeighState) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.NeighRestore(states) })
}

func (admin *scopedPluginControlNetAdmin) NeighReplace(req pluginControlNetNeighRequest) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.NeighReplace(req) })
}

func (admin *scopedPluginControlNetAdmin) NeighDelete(req pluginControlNetNeighRequest) error {
	return admin.run(func(base pluginControlNetAdmin) error { return base.NeighDelete(req) })
}

func (admin *scopedPluginControlNetAdmin) NeighList(req pluginControlNetReadRequest) (out []pluginControlNetNeighborInfo, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		reader, ok := base.(pluginControlNetReadAdmin)
		if !ok {
			return fmt.Errorf("read-only network inventory is unavailable")
		}
		var callErr error
		out, callErr = reader.NeighList(req)
		return callErr
	})
	for i := range out {
		out[i].Namespace = admin.namespace
	}
	return out, err
}

func (admin *scopedPluginControlNetAdmin) BridgeFDBList(req pluginControlNetReadRequest) (out []pluginControlNetFDBInfo, err error) {
	err = admin.run(func(base pluginControlNetAdmin) error {
		reader, ok := base.(pluginControlNetReadAdmin)
		if !ok {
			return fmt.Errorf("read-only network inventory is unavailable")
		}
		var callErr error
		out, callErr = reader.BridgeFDBList(req)
		return callErr
	})
	for i := range out {
		out[i].Namespace = admin.namespace
	}
	return out, err
}

func normalizePluginControlRequestNamespace(value string) (string, error) {
	namespace := normalizePluginControlNamespace(value)
	if namespace == "host" {
		return namespace, nil
	}
	return validatePluginControlNamespaceName(strings.TrimSpace(namespace), false)
}
