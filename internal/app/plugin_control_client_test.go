package app

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type pluginControlNetworkBrokerTest struct {
	httpRequests []pluginControlHTTPRequest
	dnsRequests  []pluginControlDNSRequest
	httpResponse pluginControlHTTPResponse
	dnsResponse  pluginControlDNSResponse
	httpErr      error
	dnsErr       error
}

type pluginControlDirectNetworkTestTransport struct {
	mu    sync.Mutex
	dials []pluginControlSocketOpenRequest
}

func (t *pluginControlDirectNetworkTestTransport) Dial(ctx context.Context, req pluginControlSocketOpenRequest) (net.Conn, error) {
	t.mu.Lock()
	t.dials = append(t.dials, req)
	t.mu.Unlock()
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, req.Network, net.JoinHostPort(req.RemoteIP.String(), fmt.Sprintf("%d", req.RemotePort)))
}

func (*pluginControlDirectNetworkTestTransport) Listen(context.Context, pluginControlSocketListenRequest) (pluginControlDeadlineListener, error) {
	return nil, fmt.Errorf("listen is not used by the client broker test")
}

func (*pluginControlDirectNetworkTestTransport) ListenPacket(context.Context, pluginControlSocketListenRequest) (net.PacketConn, error) {
	return nil, fmt.Errorf("listen packet is not used by the client broker test")
}

func (b *pluginControlNetworkBrokerTest) HTTPRequest(_ context.Context, req pluginControlHTTPRequest) (pluginControlHTTPResponse, error) {
	b.httpRequests = append(b.httpRequests, req)
	return b.httpResponse, b.httpErr
}

func (b *pluginControlNetworkBrokerTest) DNSLookup(_ context.Context, req pluginControlDNSRequest) (pluginControlDNSResponse, error) {
	b.dnsRequests = append(b.dnsRequests, req)
	return b.dnsResponse, b.dnsErr
}

func TestPluginControlHTTPAndDNSUseCapabilityBroker(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "client_broker", `{
  "api_version": "v1",
  "id": "client_broker",
  "name": "Client Broker",
  "version": "1.0.0",
  "kind": "control",
  "actions": [
    {"id": "http", "runtime_update": "runtime_query"},
    {"id": "dns", "runtime_update": "runtime_query"}
  ],
  "control": {
    "main": "control.js",
    "permissions": ["net.dns", "net.http"],
    "net_access": [{
      "interfaces": ["eth0"],
      "operations": ["dns", "http"],
      "remote_hosts": ["*.example.test", "_service._tcp.example.test"],
      "remote_cidrs": ["192.0.2.0/24"],
      "remote_ports": [443, 5353]
    }]
  }
}`)
	writePluginControlScript(t, dir, "client_broker", `
exports.onAction = function (ctx) {
  if (ctx.action.id === "http") {
    return net.http.request({
      interface: "eth0",
      url: "https://api.example.test/v1/status",
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body_text: "{\"ok\":true}",
      source_ip: "192.0.2.10",
      resolver_ip: "192.0.2.53",
      resolver_port: 5353,
      dns_transport: "tcp",
      timeout_ms: 1250,
      max_response_bytes: 1024,
      follow_redirects: true,
      max_redirects: 2,
      server_name: "api.example.test"
    });
  }
  return net.dns.lookup({
    interface: "eth0",
    name: "_service._tcp.example.test",
    type: "srv",
    service: "service",
    protocol: "tcp",
    resolver_ip: "192.0.2.53",
    resolver_port: 5353,
    transport: "tcp",
    timeout_ms: 750
  });
};
`)

	broker := &pluginControlNetworkBrokerTest{
		httpResponse: pluginControlHTTPResponse{
			StatusCode: 201,
			Status:     "201 Created",
			Headers:    map[string][]string{"Content-Type": {"application/json"}},
			Body:       []byte(`{"created":true}`),
			FinalURL:   "https://api.example.test/v1/status",
		},
		dnsResponse: pluginControlDNSResponse{
			Name: "_service._tcp.example.test",
			Type: "srv",
			Records: []any{map[string]any{
				"target": "backend.example.test.", "port": uint16(8443), "priority": uint16(10), "weight": uint16(20),
			}},
		},
	}
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	runtime.networkBroker = broker
	t.Cleanup(func() { _ = runtime.Close() })

	catalog := loadPluginCatalogWithState(cfg, db)
	plugin := pluginByIDForTest(t, catalog, "client_broker")
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)

	httpResult, err := runtime.QueryPluginAction(plugin, pluginActionByIDForTest(t, plugin, "http"), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("QueryPluginAction(http) error = %v", err)
	}
	httpObject, ok := httpResult.(map[string]any)
	if !ok || fmt.Sprint(httpObject["status_code"]) != "201" || httpObject["body_text"] != `{"created":true}` {
		t.Fatalf("HTTP result = %#v, want bounded broker response", httpResult)
	}
	if len(broker.httpRequests) != 1 {
		t.Fatalf("HTTP requests = %d, want 1", len(broker.httpRequests))
	}
	httpRequest := broker.httpRequests[0]
	if httpRequest.Interface != "eth0" || httpRequest.Method != "POST" || httpRequest.URL != "https://api.example.test/v1/status" || string(httpRequest.Body) != `{"ok":true}` {
		t.Fatalf("HTTP request = %+v", httpRequest)
	}
	if !httpRequest.SourceIP.Equal(net.ParseIP("192.0.2.10")) || !httpRequest.ResolverIP.Equal(net.ParseIP("192.0.2.53")) || httpRequest.ResolverPort != 5353 || httpRequest.DNSTransport != "tcp" {
		t.Fatalf("HTTP network binding = %+v", httpRequest)
	}
	if httpRequest.Timeout != 1250*time.Millisecond || httpRequest.MaxResponseBytes != 1024 || !httpRequest.FollowRedirects || httpRequest.MaxRedirects != 2 {
		t.Fatalf("HTTP limits = %+v", httpRequest)
	}
	if !httpRequest.EndpointPolicy.AllowsIP(net.ParseIP("192.0.2.80")) || httpRequest.EndpointPolicy.AllowsIP(net.ParseIP("203.0.113.80")) {
		t.Fatalf("HTTP endpoint policy = %+v", httpRequest.EndpointPolicy)
	}
	if !httpRequest.ResolverPolicy.AllowsIP(net.ParseIP("192.0.2.53")) || httpRequest.ResolverPolicy.AllowsIP(net.ParseIP("203.0.113.53")) {
		t.Fatalf("HTTP resolver policy = %+v", httpRequest.ResolverPolicy)
	}

	dnsResult, err := runtime.QueryPluginAction(plugin, pluginActionByIDForTest(t, plugin, "dns"), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("QueryPluginAction(dns) error = %v", err)
	}
	dnsObject, ok := dnsResult.(map[string]any)
	if !ok || dnsObject["name"] != "_service._tcp.example.test" || dnsObject["type"] != "srv" {
		t.Fatalf("DNS result = %#v", dnsResult)
	}
	if len(broker.dnsRequests) != 1 {
		t.Fatalf("DNS requests = %d, want 1", len(broker.dnsRequests))
	}
	dnsRequest := broker.dnsRequests[0]
	if dnsRequest.Interface != "eth0" || dnsRequest.Name != "_service._tcp.example.test" || dnsRequest.Type != "srv" || dnsRequest.Service != "service" || dnsRequest.Protocol != "tcp" {
		t.Fatalf("DNS request = %+v", dnsRequest)
	}
	if !dnsRequest.ResolverIP.Equal(net.ParseIP("192.0.2.53")) || dnsRequest.ResolverPort != 5353 || dnsRequest.Transport != "tcp" || dnsRequest.Timeout != 750*time.Millisecond {
		t.Fatalf("DNS network binding = %+v", dnsRequest)
	}
	if !dnsRequest.EndpointPolicy.AllowsIP(net.ParseIP("192.0.2.53")) || dnsRequest.EndpointPolicy.AllowsIP(net.ParseIP("203.0.113.53")) {
		t.Fatalf("DNS endpoint policy = %+v", dnsRequest.EndpointPolicy)
	}
}

func TestPluginControlHTTPRejectsPermissionScopeAndExtraArguments(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "client_denied", `{
  "api_version": "v1",
  "id": "client_denied",
  "name": "Client Denied",
  "version": "1.0.0",
  "kind": "control",
  "actions": [{"id": "request", "runtime_update": "runtime_query"}],
  "control": {
    "main": "control.js",
    "permissions": ["net.http"],
    "net_access": [{"interfaces": ["eth1"], "operations": ["http"]}]
  }
}`)
	writePluginControlScript(t, dir, "client_denied", `
exports.onAction = function () {
  return net.http.request({interface: "eth0", url: "https://example.test"});
};
`)
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	broker := &pluginControlNetworkBrokerTest{}
	runtime.networkBroker = broker
	t.Cleanup(func() { _ = runtime.Close() })
	plugin := pluginWithRuntimeSurfaceForTest(t, pluginByIDForTest(t, loadPluginCatalogWithState(cfg, db), "client_denied"))
	action := pluginActionByIDForTest(t, plugin, "request")
	_, err := runtime.QueryPluginAction(plugin, action, json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "net_access operation http on interface eth0 is not declared") {
		t.Fatalf("HTTP scope error = %v", err)
	}
	if len(broker.httpRequests) != 0 {
		t.Fatalf("denied HTTP call reached broker: %+v", broker.httpRequests)
	}

	writePluginControlScript(t, dir, "client_denied", `
exports.onAction = function () {
  return net.http.request({interface: "eth1", url: "https://example.test"}, {});
};
`)
	plugin = pluginByIDForTest(t, loadPluginCatalogWithState(cfg, db), "client_denied")
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	_, err = runtime.QueryPluginAction(plugin, pluginActionByIDForTest(t, plugin, "request"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "net.http.request requires exactly one request object") {
		t.Fatalf("HTTP argument count error = %v", err)
	}

	writePluginControlScript(t, dir, "client_denied", `
exports.onAction = function () {
  return net.http.request({
    interface: "eth1",
    url: "https://example.test",
    resolver_ip: "192.0.2.53"
  });
};
`)
	plugin = pluginByIDForTest(t, loadPluginCatalogWithState(cfg, db), "client_denied")
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	_, err = runtime.QueryPluginAction(plugin, pluginActionByIDForTest(t, plugin, "request"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "permission net.dns is required") {
		t.Fatalf("HTTP custom resolver permission error = %v, want net.dns denial", err)
	}
	if len(broker.httpRequests) != 0 {
		t.Fatalf("HTTP call with unauthorized resolver reached broker: %+v", broker.httpRequests)
	}
}

func TestNormalizePluginControlHTTPAndDNSPermissions(t *testing.T) {
	control := PluginControl{
		Main:        "control.js",
		Permissions: []string{"net.http", "net.dns"},
		NetAccess: []PluginNetAccess{{
			Interfaces: []string{"eth0"},
			Operations: []string{"http", "dns"},
		}},
	}
	if err := normalizePluginControl(&control); err != nil {
		t.Fatalf("normalizePluginControl() error = %v", err)
	}

	missingAccess := PluginControl{Main: "control.js", Permissions: []string{"net.http"}}
	if err := normalizePluginControl(&missingAccess); err == nil || !strings.Contains(err.Error(), "net_access is required") {
		t.Fatalf("missing HTTP net_access error = %v", err)
	}

	wrongPermission := PluginControl{
		Main:        "control.js",
		Permissions: []string{"net.dns"},
		NetAccess:   []PluginNetAccess{{Interfaces: []string{"eth0"}, Operations: []string{"http"}}},
	}
	if err := normalizePluginControl(&wrongPermission); err == nil || !strings.Contains(err.Error(), "requires net.http permission") {
		t.Fatalf("HTTP permission mismatch error = %v", err)
	}
}

func TestPluginControlNetEndpointPolicyScopesHostCIDRAndPort(t *testing.T) {
	plugin := LoadedPlugin{PluginManifest: PluginManifest{
		ID: "endpoint_scope",
		Control: &PluginControl{NetAccess: []PluginNetAccess{{
			Interfaces:  []string{"wan*"},
			Operations:  []string{"http"},
			RemoteHosts: []string{"*.example.test"},
			RemoteCIDRs: []string{"192.0.2.0/24", "2001:db8::/32"},
			RemotePorts: []int{443},
		}}},
	}}
	policy, err := pluginControlNetEndpointPolicyFor(plugin, "http", "wan0", "api.example.test", net.ParseIP("192.0.2.10"), 443)
	if err != nil || !policy.AllowsIP(net.ParseIP("192.0.2.20")) || !policy.AllowsIP(net.ParseIP("2001:db8::20")) {
		t.Fatalf("allowed endpoint policy = %+v/%v", policy, err)
	}
	for _, test := range []struct {
		host string
		ip   string
		port int
	}{
		{host: "example.test", ip: "192.0.2.10", port: 443},
		{host: "api.example.test", ip: "203.0.113.10", port: 443},
		{host: "api.example.test", ip: "192.0.2.10", port: 80},
	} {
		if _, err := pluginControlNetEndpointPolicyFor(plugin, "http", "wan0", test.host, net.ParseIP(test.ip), test.port); err == nil {
			t.Fatalf("endpoint %s/%s:%d was allowed", test.host, test.ip, test.port)
		}
	}
}

func TestNormalizePluginNetEndpointScopes(t *testing.T) {
	access := []PluginNetAccess{{
		Interfaces:  []string{"wan0"},
		Operations:  []string{"http"},
		RemoteHosts: []string{"API.Example.Test.", "*.Example.Test", "api.example.test"},
		RemoteCIDRs: []string{"192.0.2.10", "192.0.2.0/24", "192.0.2.10/32"},
		RemotePorts: []int{443, 80, 443},
	}}
	if err := normalizePluginNetAccess(access); err != nil {
		t.Fatalf("normalizePluginNetAccess() error = %v", err)
	}
	if got := strings.Join(access[0].RemoteHosts, ","); got != "*.example.test,api.example.test" {
		t.Fatalf("remote hosts = %q", got)
	}
	if got := strings.Join(access[0].RemoteCIDRs, ","); got != "192.0.2.0/24,192.0.2.10/32" {
		t.Fatalf("remote CIDRs = %q", got)
	}
	if len(access[0].RemotePorts) != 2 || access[0].RemotePorts[0] != 80 || access[0].RemotePorts[1] != 443 {
		t.Fatalf("remote ports = %+v", access[0].RemotePorts)
	}

	invalidHost := []PluginNetAccess{{Interfaces: []string{"wan0"}, Operations: []string{"http"}, RemoteHosts: []string{"api.*.test"}}}
	if err := normalizePluginNetAccess(invalidHost); err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("invalid host pattern error = %v", err)
	}
	invalidCIDR := []PluginNetAccess{{Interfaces: []string{"wan0"}, Operations: []string{"http"}, RemoteCIDRs: []string{"192.0.2.1/99"}}}
	if err := normalizePluginNetAccess(invalidCIDR); err == nil || !strings.Contains(err.Error(), "CIDR") {
		t.Fatalf("invalid CIDR error = %v", err)
	}
	invalidRawHost := []PluginNetAccess{{Interfaces: []string{"wan0"}, Operations: []string{"tcp"}, RemoteHosts: []string{"example.test"}}}
	if err := normalizePluginNetAccess(invalidRawHost); err == nil || !strings.Contains(err.Error(), "raw socket") {
		t.Fatalf("raw socket host scope error = %v", err)
	}
}

func TestDefaultPluginControlNetworkBrokerRequiresEndpointPolicy(t *testing.T) {
	broker := newPluginControlNetworkBroker(newPluginControlSocketTransport())
	_, err := broker.HTTPRequest(context.Background(), pluginControlHTTPRequest{
		URL: "https://example.test", Timeout: time.Second, Headers: map[string]string{},
	})
	if err == nil || !strings.Contains(err.Error(), "endpoint policy is required") {
		t.Fatalf("missing HTTP policy error = %v", err)
	}
	_, err = broker.DNSLookup(context.Background(), pluginControlDNSRequest{
		Name: "example.test", Type: "a", Timeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "endpoint policy is required") {
		t.Fatalf("missing DNS policy error = %v", err)
	}
}

func TestDefaultPluginControlNetworkBrokerHTTPAndTLS(t *testing.T) {
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("wrong origin"))
	}))
	defer redirectTarget.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/cross-origin":
			http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
		default:
			w.Header().Set("X-Test", "bounded")
			_, _ = w.Write([]byte("broker-ok"))
		}
	}))
	defer server.Close()

	transport := &pluginControlDirectNetworkTestTransport{}
	broker := newPluginControlNetworkBroker(transport)
	policy := pluginControlNetEndpointPolicy{Authorized: true, Prefixes: mustPluginControlTestPrefixes(t, "127.0.0.1/32")}
	request := pluginControlHTTPRequest{
		URL: server.URL + "/redirect", Interface: "test0", Timeout: 2 * time.Second,
		Headers: map[string]string{}, FollowRedirects: true, MaxRedirects: 2,
		EndpointPolicy: policy,
	}
	response, err := broker.HTTPRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("HTTPRequest() error = %v", err)
	}
	if response.StatusCode != http.StatusOK || string(response.Body) != "broker-ok" || response.Headers["X-Test"][0] != "bounded" || !strings.HasSuffix(response.FinalURL, "/ok") {
		t.Fatalf("HTTP response = %+v", response)
	}

	request.URL = server.URL + "/cross-origin"
	if _, err := broker.HTTPRequest(context.Background(), request); err == nil || !strings.Contains(err.Error(), "cross-origin") {
		t.Fatalf("cross-origin redirect error = %v", err)
	}

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tls-ok"))
	}))
	defer tlsServer.Close()
	certificate := tlsServer.Certificate()
	request.URL = tlsServer.URL
	request.CAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	request.FollowRedirects = false
	response, err = broker.HTTPRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("HTTPS request with private CA error = %v", err)
	}
	if string(response.Body) != "tls-ok" {
		t.Fatalf("HTTPS response body = %q", response.Body)
	}
	request.CAPEM = nil
	if _, err := broker.HTTPRequest(context.Background(), request); err == nil {
		t.Fatal("HTTPS request without trusted CA unexpectedly succeeded")
	}

	transport.mu.Lock()
	dials := append([]pluginControlSocketOpenRequest(nil), transport.dials...)
	transport.mu.Unlock()
	if len(dials) < 4 {
		t.Fatalf("network dials = %d, want HTTP, redirects, and TLS", len(dials))
	}
	for _, dial := range dials {
		if dial.Interface != "test0" {
			t.Fatalf("dial did not preserve interface binding: %+v", dial)
		}
	}
}

func TestDefaultPluginControlNetworkBrokerDNSLookup(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 4096)
		n, client, readErr := conn.ReadFrom(buffer)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		var parser dnsmessage.Parser
		header, parseErr := parser.Start(buffer[:n])
		if parseErr != nil {
			serverDone <- parseErr
			return
		}
		question, parseErr := parser.Question()
		if parseErr != nil {
			serverDone <- parseErr
			return
		}
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true})
		builder.EnableCompression()
		if buildErr := builder.StartQuestions(); buildErr != nil {
			serverDone <- buildErr
			return
		}
		if buildErr := builder.Question(question); buildErr != nil {
			serverDone <- buildErr
			return
		}
		if buildErr := builder.StartAnswers(); buildErr != nil {
			serverDone <- buildErr
			return
		}
		if buildErr := builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 55}}); buildErr != nil {
			serverDone <- buildErr
			return
		}
		message, buildErr := builder.Finish()
		if buildErr == nil {
			_, buildErr = conn.WriteTo(message, client)
		}
		serverDone <- buildErr
	}()

	resolverAddress := conn.LocalAddr().(*net.UDPAddr)
	transport := &pluginControlDirectNetworkTestTransport{}
	broker := newPluginControlNetworkBroker(transport)
	response, err := broker.DNSLookup(context.Background(), pluginControlDNSRequest{
		Name: "example.test", Type: "a", Interface: "test0",
		ResolverIP: resolverAddress.IP, ResolverPort: resolverAddress.Port, Transport: "udp", Timeout: 2 * time.Second,
		EndpointPolicy: pluginControlNetEndpointPolicy{Authorized: true, Prefixes: mustPluginControlTestPrefixes(t, "127.0.0.1/32")},
	})
	if err != nil {
		t.Fatalf("DNSLookup() error = %v", err)
	}
	if len(response.Records) != 1 || fmt.Sprint(response.Records[0]) != "192.0.2.55" {
		t.Fatalf("DNS response = %+v", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("DNS server error = %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.dials) != 1 || transport.dials[0].Interface != "test0" || transport.dials[0].RemotePort != resolverAddress.Port {
		t.Fatalf("DNS dials = %+v", transport.dials)
	}
}

func mustPluginControlTestPrefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			t.Fatalf("ParsePrefix(%q) error = %v", value, err)
		}
		result = append(result, prefix)
	}
	return result
}

func TestValidatePluginControlClientRequests(t *testing.T) {
	httpRequest := pluginControlHTTPRequest{
		URL:              "https://example.test/path",
		Timeout:          time.Second,
		MaxResponseBytes: 1024,
		Headers:          map[string]string{"Accept": "application/json"},
		EndpointPolicy:   pluginControlNetEndpointPolicy{Authorized: true, AnyIP: true},
	}
	parsed, err := validatePluginControlHTTPRequest(&httpRequest)
	if err != nil || parsed.Hostname() != "example.test" || httpRequest.Method != "GET" || httpRequest.DNSTransport != "udp" {
		t.Fatalf("validatePluginControlHTTPRequest() = %v/%v request=%+v", parsed, err, httpRequest)
	}

	invalidHeader := httpRequest
	invalidHeader.Headers = map[string]string{"Host": "attacker.test"}
	if _, err := validatePluginControlHTTPRequest(&invalidHeader); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved Host header error = %v", err)
	}

	userinfo := httpRequest
	userinfo.URL = "https://user:pass@example.test/"
	if _, err := validatePluginControlHTTPRequest(&userinfo); err == nil || !strings.Contains(err.Error(), "userinfo") {
		t.Fatalf("URL userinfo error = %v", err)
	}

	dnsRequest := pluginControlDNSRequest{
		Name: "Example.TEST.", Type: "AAAA", Timeout: time.Second,
		EndpointPolicy: pluginControlNetEndpointPolicy{Authorized: true, AnyIP: true},
	}
	if err := validatePluginControlDNSRequest(&dnsRequest); err != nil {
		t.Fatalf("validatePluginControlDNSRequest() error = %v", err)
	}
	if dnsRequest.Name != "example.test" || dnsRequest.Type != "aaaa" || dnsRequest.Transport != "udp" || dnsRequest.ResolverPort != 53 {
		t.Fatalf("normalized DNS request = %+v", dnsRequest)
	}
}
