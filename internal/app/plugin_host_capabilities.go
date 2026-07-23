package app

import (
	"fmt"
	"sort"
)

const (
	pluginHostPhaseRegistration       = "registration"
	pluginHostPhaseRuntime            = "runtime"
	pluginHostPhaseMigration          = "migration"
	pluginHostPhaseDataplaneMigration = "dataplane_migration"
	pluginHostPhaseUpgrade            = "upgrade"
	pluginHostContextMain             = "main"
	pluginHostContextWorker           = "worker"
)

type pluginHostControlCapability struct {
	Method                 string   `json:"method"`
	Permissions            []string `json:"permissions,omitempty"`
	AnyPermissions         []string `json:"any_permissions,omitempty"`
	ConditionalPermissions []string `json:"conditional_permissions,omitempty"`
	Phases                 []string `json:"phases"`
	Contexts               []string `json:"contexts"`
	MaxRequestBytes        int      `json:"max_request_bytes"`
	MaxResponseBytes       int      `json:"max_response_bytes"`
}

type pluginHostCapabilityOptions struct {
	permissions            []string
	anyPermissions         []string
	conditionalPermissions []string
	phases                 []string
	contexts               []string
}

var pluginHostControlCapabilities = mustBuildPluginHostControlCapabilities()

func mustBuildPluginHostControlCapabilities() []pluginHostControlCapability {
	registration := []string{pluginHostPhaseRegistration}
	runtime := []string{pluginHostPhaseRuntime}
	runtimeAndDataplaneMigration := []string{pluginHostPhaseRuntime, pluginHostPhaseDataplaneMigration}
	registrationAndRuntime := []string{pluginHostPhaseRegistration, pluginHostPhaseRuntime}
	allPhases := []string{pluginHostPhaseRegistration, pluginHostPhaseRuntime, pluginHostPhaseMigration, pluginHostPhaseDataplaneMigration, pluginHostPhaseUpgrade}
	mainAndWorker := []string{pluginHostContextMain, pluginHostContextWorker}
	mainOnly := []string{pluginHostContextMain}

	capabilities := make([]pluginHostControlCapability, 0, 148)
	add := func(methods []string, options pluginHostCapabilityOptions) {
		phases := options.phases
		if len(phases) == 0 {
			phases = runtime
		}
		contexts := options.contexts
		if len(contexts) == 0 {
			contexts = mainAndWorker
		}
		for _, method := range methods {
			capabilities = append(capabilities, pluginHostControlCapability{
				Method:                 method,
				Permissions:            append([]string(nil), options.permissions...),
				AnyPermissions:         append([]string(nil), options.anyPermissions...),
				ConditionalPermissions: append([]string(nil), options.conditionalPermissions...),
				Phases:                 append([]string(nil), phases...),
				Contexts:               append([]string(nil), contexts...),
				MaxRequestBytes:        pluginHostMaxChildFrameBytes,
				MaxResponseBytes:       pluginHostMaxParentFrameBytes,
			})
		}
	}

	add([]string{"plugin.host"}, pluginHostCapabilityOptions{phases: allPhases})
	add([]string{
		"plugin.capabilities", "plugin.resource", "plugin.action", "plugin.service", "plugin.virtualInterface",
		"plugin.pipelineNode", "plugin.handoff", "pipeline.node", "pipeline.handoff",
	}, pluginHostCapabilityOptions{permissions: []string{"plugin.register"}, phases: registration})
	add([]string{"pipeline.attach", "hooks.attach"}, pluginHostCapabilityOptions{permissions: []string{"hook.attach"}, phases: registration})
	add([]string{"ebpf.loadObject"}, pluginHostCapabilityOptions{permissions: []string{"ebpf.load"}, phases: registration})
	add([]string{"ui.register"}, pluginHostCapabilityOptions{permissions: []string{"ui"}, phases: registration})
	add([]string{"events.subscribe"}, pluginHostCapabilityOptions{permissions: []string{"event", "worker"}, phases: registration})
	add([]string{"ebpf.ringSubscribe"}, pluginHostCapabilityOptions{permissions: []string{"ebpf.load", "ebpf.map_read", "worker"}, phases: registration})

	add([]string{"kv.get", "kv.set", "kv.delete", "kv.list"}, pluginHostCapabilityOptions{permissions: []string{"kv"}})
	add([]string{"resources.get", "resources.set", "resources.delete", "resources.list", "resources.transaction"}, pluginHostCapabilityOptions{permissions: []string{"resource"}})
	add([]string{
		"operations.begin", "operations.get", "operations.getByKey", "operations.list", "operations.claim",
		"operations.checkpoint", "operations.complete", "operations.retry", "operations.fail", "operations.cancel", "operations.remove", "operations.stats",
	}, pluginHostCapabilityOptions{permissions: []string{"operation"}, contexts: mainOnly})
	add([]string{
		"plugins.resources.get", "plugins.resources.list", "plugins.resources.set", "plugins.resources.delete", "plugins.resources.transaction",
	}, pluginHostCapabilityOptions{permissions: []string{"plugin.resource"}})
	add([]string{"plugins.actions.call"}, pluginHostCapabilityOptions{permissions: []string{"plugin.action"}})
	add([]string{"plugins.services.list", "plugins.services.resolve"}, pluginHostCapabilityOptions{anyPermissions: []string{"plugin.action", "plugin.resource"}})
	add([]string{"plugins.services.call"}, pluginHostCapabilityOptions{permissions: []string{"plugin.action"}})
	add([]string{"ebpf.mapPut", "ebpf.mapTransaction", "ebpf.mapDelete", "ebpf.mapClear"}, pluginHostCapabilityOptions{permissions: []string{"ebpf.map_write"}, phases: runtimeAndDataplaneMigration})
	add([]string{"ebpf.mapGet", "ebpf.mapGetPerCPU", "ebpf.mapScan", "ebpf.ringRead", "ebpf.ringStats"}, pluginHostCapabilityOptions{permissions: []string{"ebpf.map_read"}, phases: runtimeAndDataplaneMigration})

	namespaceConditional := []string{"net.namespace"}
	add([]string{"net.l2.send", "net.l2.recv", "net.l2.recvMany", "net.l2.exchange", "net.l2.exchangeMany"}, pluginHostCapabilityOptions{
		permissions: []string{"net.l2"}, conditionalPermissions: namespaceConditional,
	})
	add([]string{"net.udp.send", "net.udp.recv", "net.udp.exchange"}, pluginHostCapabilityOptions{
		permissions: []string{"net.udp"}, conditionalPermissions: namespaceConditional,
	})
	add([]string{
		"net.socket.open", "net.socket.listen", "net.socket.accept", "net.socket.read",
		"net.socket.write", "net.socket.close", "net.socket.status", "net.socket.list",
	}, pluginHostCapabilityOptions{
		anyPermissions: []string{"net.tcp", "net.udp"}, conditionalPermissions: namespaceConditional,
	})
	add([]string{"net.socket.watch", "net.socket.unwatch", "net.socket.watchList"}, pluginHostCapabilityOptions{
		permissions: []string{"worker"}, anyPermissions: []string{"net.tcp", "net.udp"}, conditionalPermissions: namespaceConditional,
	})
	add([]string{"net.http.request"}, pluginHostCapabilityOptions{
		permissions: []string{"net.http"}, conditionalPermissions: []string{"net.dns", "net.namespace"},
	})
	add([]string{"net.dns.lookup"}, pluginHostCapabilityOptions{
		permissions: []string{"net.dns"}, conditionalPermissions: namespaceConditional,
	})
	add([]string{"net.prefix.subnet"}, pluginHostCapabilityOptions{
		phases: []string{pluginHostPhaseRegistration, pluginHostPhaseRuntime, pluginHostPhaseMigration},
	})
	add([]string{"net.lease.list", "net.lease.restore"}, pluginHostCapabilityOptions{permissions: []string{"net.admin"}})
	add([]string{
		"net.namespace.get", "net.namespace.list", "net.namespace.ensure", "net.namespace.delete", "net.namespace.release", "net.namespace.owned",
	}, pluginHostCapabilityOptions{permissions: []string{"net.namespace"}})
	add([]string{
		"net.tuntap.ensure", "net.tuntap.close", "net.tuntap.read", "net.tuntap.write", "net.tuntap.list", "net.tuntap.owned",
	}, pluginHostCapabilityOptions{permissions: []string{"net.tuntap"}, conditionalPermissions: namespaceConditional})
	add([]string{
		"net.link.get", "net.link.list", "net.link.ensureBridge", "net.link.ensureVeth", "net.link.ensureDummy",
		"net.link.ensureMacvlan", "net.link.ensureVLAN", "net.link.ensureVRF", "net.link.delete", "net.link.release",
		"net.link.owned", "net.link.setMaster", "net.link.clearMaster", "net.link.setUp", "net.link.setMTU",
		"net.link.setARP", "net.link.setPromiscuous", "net.link.getOffloads", "net.link.setOffloads", "net.link.setGSO",
		"net.addr.replace", "net.addr.delete", "net.route.replace", "net.route.delete", "net.route.transaction",
		"net.rule.replace", "net.rule.delete", "net.rule.transaction", "net.neigh.replace", "net.neigh.delete", "net.neigh.transaction",
	}, pluginHostCapabilityOptions{permissions: []string{"net.admin"}, conditionalPermissions: namespaceConditional})

	add([]string{"timer.setTimeout", "timer.setInterval", "timer.clear", "timer.list"}, pluginHostCapabilityOptions{permissions: []string{"timer"}})
	add([]string{"worker.call", "worker.dispatch"}, pluginHostCapabilityOptions{permissions: []string{"worker"}, contexts: mainOnly})
	add([]string{"worker.list", "worker.stats"}, pluginHostCapabilityOptions{permissions: []string{"worker"}})
	add([]string{"events.publish", "events.deadLetters", "events.retry", "events.discard"}, pluginHostCapabilityOptions{permissions: []string{"event"}})
	add([]string{"events.stats"}, pluginHostCapabilityOptions{permissions: []string{"event"}, phases: registrationAndRuntime})
	add([]string{"metrics.counter", "metrics.gauge", "metrics.delete", "metrics.clear", "metrics.list"}, pluginHostCapabilityOptions{permissions: []string{"metrics"}})
	add([]string{"crypto.md5", "crypto.randomBytes"}, pluginHostCapabilityOptions{permissions: []string{"crypto"}})
	add([]string{"crypto.sha256File"}, pluginHostCapabilityOptions{permissions: []string{"crypto"}, phases: registrationAndRuntime})
	add([]string{"secret.get", "secret.set", "secret.delete"}, pluginHostCapabilityOptions{permissions: []string{"secret"}})
	add([]string{
		"blob.begin", "blob.write", "blob.commit", "blob.abort", "blob.put",
		"blob.read", "blob.stat", "blob.list", "blob.delete", "blob.verify",
	}, pluginHostCapabilityOptions{permissions: []string{"blob"}})
	add([]string{"log.info", "log.error", "log.warn", "log.debug"}, pluginHostCapabilityOptions{phases: allPhases})

	sort.Slice(capabilities, func(i, j int) bool { return capabilities[i].Method < capabilities[j].Method })
	for i, capability := range capabilities {
		if capability.Method == "" {
			panic("plugin host capability method is empty")
		}
		if i > 0 && capabilities[i-1].Method == capability.Method {
			panic(fmt.Sprintf("duplicate plugin host capability %s", capability.Method))
		}
	}
	return capabilities
}

func pluginHostCapabilityMethods(capabilities []pluginHostControlCapability) []string {
	methods := make([]string, len(capabilities))
	for i, capability := range capabilities {
		methods[i] = capability.Method
	}
	return methods
}
