package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/dop251/goja"
)

func (h *pluginControlHost) httpRequest(call goja.FunctionCall) goja.Value {
	const api = "net.http.request"
	if err := validatePluginControlClientCallCount(call, api); err != nil {
		h.throwf("%v", err)
	}
	h.requirePermission("net.http")
	if h.registrationPhase {
		h.throwf("%s is unavailable during plugin registration", api)
	}
	obj := h.requiredObjectArg(call, 0, "request")
	interfaceName := h.requiredUDPInterfaceObjectField(obj, "interface")
	h.requireNetAccess("http", interfaceName, api)
	namespace := h.requirePluginNetworkNamespace(h.netNamespaceObjectField(obj, api), api)
	req := pluginControlHTTPRequest{
		Method: h.optionalStringObjectField(obj, "method"), URL: h.requiredStringObjectField(obj, "url"),
		Interface: interfaceName, Namespace: namespace,
		SourceIP:     h.optionalIPObjectField(obj, "source_ip", "local_ip", "bind_ip"),
		ResolverIP:   h.optionalIPObjectField(obj, "resolver_ip", "dns_server"),
		ResolverPort: h.optionalPortObjectField(obj, 53, "resolver_port", "dns_port"),
		DNSTransport: h.optionalStringObjectField(obj, "dns_transport"), Timeout: h.socketTimeoutObjectField(obj, api),
		MaxResponseBytes: h.optionalIntObjectField(obj, pluginControlHTTPMaxResponseBytes, "max_response_bytes"),
		ServerName:       h.optionalStringObjectField(obj, "server_name"),
	}
	if raw := h.objectField(obj, "follow_redirects"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		req.FollowRedirects = raw.ToBoolean()
	}
	req.MaxRedirects = h.optionalIntObjectField(obj, 3, "max_redirects")
	req.Headers = make(map[string]string)
	if raw := h.objectField(obj, "headers"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		h.exportJSONValue(raw, &req.Headers, api+" headers")
	}
	bodyText := h.optionalStringObjectField(obj, "body_text")
	bodyHex := h.optionalStringObjectField(obj, "body_hex")
	if bodyText != "" && bodyHex != "" {
		h.throwf("%s: body_text and body_hex are mutually exclusive", api)
	}
	if bodyHex != "" {
		if len(bodyHex) > pluginControlHTTPMaxRequestBytes*2 {
			h.throwf("%s: body_hex exceeds %d bytes", api, pluginControlHTTPMaxRequestBytes)
		}
		decoded, err := hex.DecodeString(strings.TrimSpace(bodyHex))
		if err != nil {
			h.throwf("%s: body_hex is invalid", api)
		}
		req.Body = decoded
	} else {
		req.Body = []byte(bodyText)
	}
	req.CAPEM = []byte(h.optionalStringObjectField(obj, "ca_pem"))
	req.ClientCertPEM = []byte(h.optionalStringObjectField(obj, "client_cert_pem"))
	req.ClientKeyPEM = []byte(h.optionalStringObjectField(obj, "client_key_pem"))
	parsedURL, err := validatePluginControlHTTPRequest(&req)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	remoteHost := parsedURL.Hostname()
	remoteIP := net.ParseIP(remoteHost)
	policyHost := remoteHost
	if remoteIP != nil {
		policyHost = ""
	}
	req.EndpointPolicy = h.requireNetEndpointAccess("http", interfaceName, policyHost, remoteIP, pluginControlHTTPRemotePort(parsedURL), api)
	if req.ResolverIP != nil {
		h.requirePermission("net.dns")
		h.requireNetAccess("dns", interfaceName, api)
		req.ResolverPolicy = h.requireNetEndpointAccess("dns", interfaceName, remoteHost, req.ResolverIP, req.ResolverPort, api)
	}
	broker := h.networkBrokerOrThrow(api)
	ctx, cancel := context.WithTimeout(context.Background(), req.Timeout)
	defer cancel()
	response, err := broker.HTTPRequest(ctx, req)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(pluginControlHTTPResponseObject(response))
}

func (h *pluginControlHost) dnsLookup(call goja.FunctionCall) goja.Value {
	const api = "net.dns.lookup"
	if err := validatePluginControlClientCallCount(call, api); err != nil {
		h.throwf("%v", err)
	}
	h.requirePermission("net.dns")
	if h.registrationPhase {
		h.throwf("%s is unavailable during plugin registration", api)
	}
	obj := h.requiredObjectArg(call, 0, "request")
	interfaceName := h.requiredUDPInterfaceObjectField(obj, "interface")
	h.requireNetAccess("dns", interfaceName, api)
	namespace := h.requirePluginNetworkNamespace(h.netNamespaceObjectField(obj, api), api)
	req := pluginControlDNSRequest{
		Name: h.requiredStringObjectField(obj, "name"), Type: h.optionalStringObjectField(obj, "type"),
		Service: h.optionalStringObjectField(obj, "service"), Protocol: h.optionalStringObjectField(obj, "protocol"),
		Interface: interfaceName, Namespace: namespace,
		SourceIP:     h.optionalIPObjectField(obj, "source_ip", "local_ip", "bind_ip"),
		ResolverIP:   h.optionalIPObjectField(obj, "resolver_ip", "server_ip", "dns_server"),
		ResolverPort: h.optionalPortObjectField(obj, 53, "resolver_port", "server_port", "dns_port"),
		Transport:    h.optionalStringObjectField(obj, "transport"), Timeout: h.socketTimeoutObjectField(obj, api),
	}
	if err := validatePluginControlDNSRequest(&req); err != nil {
		h.throwf("%s: %v", api, err)
	}
	req.EndpointPolicy = h.requireNetEndpointAccess("dns", interfaceName, req.Name, req.ResolverIP, req.ResolverPort, api)
	broker := h.networkBrokerOrThrow(api)
	ctx, cancel := context.WithTimeout(context.Background(), req.Timeout)
	defer cancel()
	response, err := broker.DNSLookup(ctx, req)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	response = sortedPluginControlDNSRecords(response)
	return h.vm.ToValue(map[string]any{"name": response.Name, "type": response.Type, "records": response.Records})
}

func (h *pluginControlHost) networkBrokerOrThrow(api string) pluginControlNetworkBroker {
	if h.runtime == nil || h.runtime.networkBroker == nil {
		h.throwf("%s: plugin network broker is unavailable", api)
	}
	return h.runtime.networkBroker
}

func validatePluginControlClientCallCount(call goja.FunctionCall, api string) error {
	if len(call.Arguments) != 1 {
		return fmt.Errorf("%s requires exactly one request object", api)
	}
	return nil
}
