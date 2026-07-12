package app

import (
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
)

func (h *pluginControlHost) socketOpen(call goja.FunctionCall) goja.Value {
	const api = "net.socket.open"
	registry := h.socketRegistryOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	network := h.socketNetworkObjectField(obj, "network")
	interfaceName := h.requiredUDPInterfaceObjectField(obj, "interface")
	localIP := h.optionalIPObjectField(obj, "local_ip", "bind_ip", "source_ip")
	remoteIP := h.requiredIPObjectField(obj, "remote_ip", "peer_ip", "dst_ip")
	resolvedNetwork, err := pluginControlSocketResolveNetwork(network, localIP, remoteIP)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	h.requireSocketNetworkAccess(resolvedNetwork, interfaceName, api)
	req := pluginControlSocketOpenRequest{
		Network:    resolvedNetwork,
		Interface:  interfaceName,
		LocalIP:    localIP,
		LocalPort:  h.optionalPortObjectField(obj, 0, "local_port", "bind_port", "source_port"),
		RemoteIP:   remoteIP,
		RemotePort: h.requiredPortObjectField(obj, "remote_port", "peer_port", "dst_port", "port"),
		Timeout:    h.socketTimeoutObjectField(obj, api),
		KeepAlive:  h.socketKeepAliveObjectField(obj, api),
		NoDelay:    h.socketNoDelayObjectField(obj),
	}
	info, err := registry.Open(h.plugin.ID, h.controlGeneration, req)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(pluginControlSocketInfoObject(info))
}

func (h *pluginControlHost) socketListen(call goja.FunctionCall) goja.Value {
	const api = "net.socket.listen"
	registry := h.socketRegistryOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	network := h.socketNetworkObjectField(obj, "network")
	interfaceName := h.requiredUDPInterfaceObjectField(obj, "interface")
	localIP := h.optionalIPObjectField(obj, "local_ip", "bind_ip")
	resolvedNetwork, err := pluginControlSocketResolveNetwork(network, localIP, nil)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	h.requireSocketNetworkAccess(resolvedNetwork, interfaceName, api)
	req := pluginControlSocketListenRequest{
		Network:   resolvedNetwork,
		Interface: interfaceName,
		LocalIP:   localIP,
		LocalPort: h.requiredPortObjectField(obj, "local_port", "bind_port", "port"),
		KeepAlive: h.socketKeepAliveObjectField(obj, api),
		NoDelay:   h.socketNoDelayObjectField(obj),
	}
	info, err := registry.Listen(h.plugin.ID, h.controlGeneration, req)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(pluginControlSocketInfoObject(info))
}

func (h *pluginControlHost) socketAccept(call goja.FunctionCall) goja.Value {
	const api = "net.socket.accept"
	registry := h.socketRegistryOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	handle := h.requiredStringObjectField(obj, "handle")
	info := h.socketInfoForAccess(registry, handle, api)
	if !pluginControlSocketIsTCP(info.Network) || info.Kind != "listener" {
		h.throwf("%s: socket %s is not a TCP listener", api, handle)
	}
	accepted, timedOut, err := registry.Accept(h.plugin.ID, h.controlGeneration, handle, h.socketTimeoutObjectField(obj, api))
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	if timedOut {
		return h.vm.ToValue(map[string]any{"timeout": true})
	}
	return h.vm.ToValue(pluginControlSocketInfoObject(accepted))
}

func (h *pluginControlHost) socketRead(call goja.FunctionCall) goja.Value {
	const api = "net.socket.read"
	registry := h.socketRegistryOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	handle := h.requiredStringObjectField(obj, "handle")
	h.socketInfoForAccess(registry, handle, api)
	maxBytes := 64 << 10
	if raw := h.objectField(obj, "max_bytes"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		value := raw.ToInteger()
		if value <= 0 || value > pluginControlSocketMaxPayload {
			h.throwf("%s: max_bytes must be between 1 and %d", api, pluginControlSocketMaxPayload)
		}
		maxBytes = int(value)
	}
	result, err := registry.Read(h.plugin.ID, h.controlGeneration, handle, maxBytes, h.socketTimeoutObjectField(obj, api))
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	out := map[string]any{
		"payload_hex": hex.EncodeToString(result.Payload),
		"bytes":       len(result.Payload),
		"timeout":     result.Timeout,
		"eof":         result.EOF,
	}
	pluginControlSocketAddrObject(out, "remote", result.RemoteAddr)
	return h.vm.ToValue(out)
}

func (h *pluginControlHost) socketWrite(call goja.FunctionCall) goja.Value {
	const api = "net.socket.write"
	registry := h.socketRegistryOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	handle := h.requiredStringObjectField(obj, "handle")
	info := h.socketInfoForAccess(registry, handle, api)
	payload := h.socketPayloadObjectField(obj, api)
	var remoteAddr net.Addr
	remoteIP := h.optionalIPObjectField(obj, "remote_ip", "peer_ip", "dst_ip")
	remotePort := h.optionalPortObjectField(obj, 0, "remote_port", "peer_port", "dst_port", "port")
	if remoteIP != nil || remotePort > 0 {
		if !pluginControlSocketIsUDP(info.Network) {
			h.throwf("%s: remote address is supported only for UDP datagram listeners", api)
		}
		if remoteIP == nil || remotePort <= 0 {
			h.throwf("%s: remote_ip and remote_port must be provided together", api)
		}
		if _, err := pluginControlSocketResolveNetwork(info.Network, nil, remoteIP); err != nil {
			h.throwf("%s: %v", api, err)
		}
		remoteAddr = &net.UDPAddr{IP: remoteIP, Port: remotePort}
	}
	result, err := registry.Write(h.plugin.ID, h.controlGeneration, handle, pluginControlSocketWriteRequest{
		Payload:    payload,
		RemoteAddr: remoteAddr,
		Timeout:    h.socketTimeoutObjectField(obj, api),
	})
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(map[string]any{"bytes": result.Bytes})
}

func (h *pluginControlHost) socketClose(call goja.FunctionCall) goja.Value {
	const api = "net.socket.close"
	registry := h.socketRegistryOrThrow(api)
	h.requireAnySocketPermission(api)
	obj := h.requiredObjectArg(call, 0, "request")
	handle := h.requiredStringObjectField(obj, "handle")
	if info, err := registry.Info(h.plugin.ID, h.controlGeneration, handle); err == nil {
		h.requireSocketInfoAccess(info, api)
	} else if !errors.Is(err, errPluginControlSocketNotFound) {
		h.throwf("%s: %v", api, err)
	}
	closed, err := registry.Close(h.plugin.ID, h.controlGeneration, handle)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(map[string]any{"closed": closed})
}

func (h *pluginControlHost) socketStatus(call goja.FunctionCall) goja.Value {
	const api = "net.socket.status"
	registry := h.socketRegistryOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	handle := h.requiredStringObjectField(obj, "handle")
	info := h.socketInfoForAccess(registry, handle, api)
	return h.vm.ToValue(pluginControlSocketInfoObject(info))
}

func (h *pluginControlHost) socketList(call goja.FunctionCall) goja.Value {
	const api = "net.socket.list"
	registry := h.socketRegistryOrThrow(api)
	h.requireAnySocketPermission(api)
	infos := registry.List(h.plugin.ID, h.controlGeneration)
	out := make([]map[string]any, 0, len(infos))
	for _, info := range infos {
		permission, operation := pluginControlSocketPermission(info.Network)
		if !pluginControlHasPermission(h.plugin, permission) || !pluginControlHasNetAccess(h.plugin, operation, info.Interface) {
			continue
		}
		out = append(out, pluginControlSocketInfoObject(info))
	}
	return h.vm.ToValue(out)
}

func (h *pluginControlHost) socketRegistryOrThrow(api string) *pluginControlSocketRegistry {
	if h.runtime == nil || h.runtime.socketRegistry == nil {
		h.throwf("%s: persistent socket registry is unavailable", api)
	}
	return h.runtime.socketRegistry
}

func (h *pluginControlHost) socketInfoForAccess(registry *pluginControlSocketRegistry, handle string, api string) pluginControlSocketInfo {
	info, err := registry.Info(h.plugin.ID, h.controlGeneration, handle)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	h.requireSocketInfoAccess(info, api)
	return info
}

func (h *pluginControlHost) requireSocketInfoAccess(info pluginControlSocketInfo, api string) {
	h.requireSocketNetworkAccess(info.Network, info.Interface, api)
}

func (h *pluginControlHost) requireSocketNetworkAccess(network string, interfaceName string, api string) {
	permission, operation := pluginControlSocketPermission(network)
	h.requirePermission(permission)
	h.requireNetAccess(operation, interfaceName, api)
}

func (h *pluginControlHost) requireAnySocketPermission(api string) {
	if pluginControlHasPermission(h.plugin, "net.tcp") {
		h.requirePermission("net.tcp")
		return
	}
	if pluginControlHasPermission(h.plugin, "net.udp") {
		h.requirePermission("net.udp")
		return
	}
	h.throwf("%s: permission net.tcp or net.udp is required", api)
}

func pluginControlSocketPermission(network string) (string, string) {
	if pluginControlSocketIsTCP(network) {
		return "net.tcp", "tcp"
	}
	return "net.udp", "udp"
}

func (h *pluginControlHost) socketNetworkObjectField(obj *goja.Object, field string) string {
	network, err := normalizePluginControlSocketNetwork(h.requiredStringObjectField(obj, field))
	if err != nil {
		h.throwf("%s: %v", field, err)
	}
	return network
}

func (h *pluginControlHost) socketTimeoutObjectField(obj *goja.Object, api string) time.Duration {
	timeout := pluginControlSocketDefaultTimeout
	if raw := h.objectField(obj, "timeout_ms"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		milliseconds := raw.ToInteger()
		if milliseconds <= 0 || milliseconds > pluginControlSocketMaxTimeout.Milliseconds() {
			h.throwf("%s: timeout_ms must be between 1 and %d", api, pluginControlSocketMaxTimeout.Milliseconds())
		}
		timeout = time.Duration(milliseconds) * time.Millisecond
	}
	return h.boundedTransportTimeout(timeout, api)
}

func (h *pluginControlHost) socketKeepAliveObjectField(obj *goja.Object, api string) time.Duration {
	raw := h.objectField(obj, "keepalive_ms")
	if goja.IsUndefined(raw) || goja.IsNull(raw) {
		return 0
	}
	milliseconds := raw.ToInteger()
	if milliseconds < 0 || milliseconds > (24*time.Hour).Milliseconds() {
		h.throwf("%s: keepalive_ms must be between 0 and %d", api, (24 * time.Hour).Milliseconds())
	}
	return time.Duration(milliseconds) * time.Millisecond
}

func (h *pluginControlHost) socketNoDelayObjectField(obj *goja.Object) bool {
	raw := h.objectField(obj, "no_delay")
	if goja.IsUndefined(raw) || goja.IsNull(raw) {
		return true
	}
	return raw.ToBoolean()
}

func (h *pluginControlHost) socketPayloadObjectField(obj *goja.Object, api string) []byte {
	raw := h.objectField(obj, "payload_hex")
	if goja.IsUndefined(raw) || goja.IsNull(raw) {
		raw = h.objectField(obj, "payload")
	}
	if goja.IsUndefined(raw) || goja.IsNull(raw) {
		h.throwf("%s: payload_hex is required", api)
	}
	encoded := strings.TrimSpace(raw.String())
	if len(encoded) > pluginControlSocketMaxPayload*3+2 {
		h.throwf("%s: encoded payload exceeds the %d-byte limit", api, pluginControlSocketMaxPayload)
	}
	payload, err := decodePluginControlHexBytes(encoded)
	if err != nil {
		h.throwf("%s: payload_hex: %v", api, err)
	}
	if len(payload) > pluginControlSocketMaxPayload {
		h.throwf("%s: payload exceeds %d bytes", api, pluginControlSocketMaxPayload)
	}
	return payload
}

func pluginControlSocketInfoObject(info pluginControlSocketInfo) map[string]any {
	out := map[string]any{
		"handle":        info.Handle,
		"network":       info.Network,
		"kind":          info.Kind,
		"interface":     info.Interface,
		"state":         info.State,
		"bytes_read":    info.BytesRead,
		"bytes_written": info.BytesWritten,
		"created_at":    info.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if info.ParentHandle != "" {
		out["parent_handle"] = info.ParentHandle
	}
	if info.LastError != "" {
		out["last_error"] = info.LastError
	}
	if !info.LastReadAt.IsZero() {
		out["last_read_at"] = info.LastReadAt.UTC().Format(time.RFC3339Nano)
	}
	if !info.LastWriteAt.IsZero() {
		out["last_write_at"] = info.LastWriteAt.UTC().Format(time.RFC3339Nano)
	}
	pluginControlSocketAddrStringObject(out, "local", info.LocalAddr)
	pluginControlSocketAddrStringObject(out, "remote", info.RemoteAddr)
	return out
}

func pluginControlSocketAddrObject(out map[string]any, prefix string, addr net.Addr) {
	if addr == nil {
		return
	}
	pluginControlSocketAddrStringObject(out, prefix, addr.String())
}

func pluginControlSocketAddrStringObject(out map[string]any, prefix string, address string) {
	if strings.TrimSpace(address) == "" {
		return
	}
	out[prefix+"_addr"] = address
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return
	}
	out[prefix+"_ip"] = host
	if port, err := strconv.Atoi(portText); err == nil {
		out[prefix+"_port"] = port
	}
}
