package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/http/httpguts"
)

const (
	pluginControlHTTPMaxRequestBytes  = 1 << 20
	pluginControlHTTPMaxResponseBytes = 4 << 20
	pluginControlHTTPMaxHeaders       = 64
	pluginControlHTTPMaxHeaderBytes   = 64 << 10
	pluginControlHTTPMaxURLBytes      = 4096
	pluginControlHTTPMaxRedirects     = 5
	pluginControlDNSMaxRecords        = 128
	pluginControlDNSMaxRecordBytes    = 64 << 10
)

type pluginControlNetworkBroker interface {
	HTTPRequest(context.Context, pluginControlHTTPRequest) (pluginControlHTTPResponse, error)
	DNSLookup(context.Context, pluginControlDNSRequest) (pluginControlDNSResponse, error)
}

type pluginControlHTTPRequest struct {
	Method           string
	URL              string
	Headers          map[string]string
	Body             []byte
	Interface        string
	Namespace        string
	SourceIP         net.IP
	ResolverIP       net.IP
	ResolverPort     int
	DNSTransport     string
	Timeout          time.Duration
	MaxResponseBytes int
	FollowRedirects  bool
	MaxRedirects     int
	ServerName       string
	CAPEM            []byte
	ClientCertPEM    []byte
	ClientKeyPEM     []byte
	EndpointPolicy   pluginControlNetEndpointPolicy
	ResolverPolicy   pluginControlNetEndpointPolicy
}

type pluginControlHTTPResponse struct {
	StatusCode int
	Status     string
	Headers    map[string][]string
	Body       []byte
	FinalURL   string
}

type pluginControlDNSRequest struct {
	Name           string
	Type           string
	Service        string
	Protocol       string
	Interface      string
	Namespace      string
	SourceIP       net.IP
	ResolverIP     net.IP
	ResolverPort   int
	Transport      string
	Timeout        time.Duration
	EndpointPolicy pluginControlNetEndpointPolicy
}

type pluginControlDNSResponse struct {
	Name    string
	Type    string
	Records []any
}

type defaultPluginControlNetworkBroker struct {
	transport pluginControlSocketTransport
}

func newPluginControlNetworkBroker(transport pluginControlSocketTransport) pluginControlNetworkBroker {
	return &defaultPluginControlNetworkBroker{transport: transport}
}

func (b *defaultPluginControlNetworkBroker) HTTPRequest(ctx context.Context, req pluginControlHTTPRequest) (pluginControlHTTPResponse, error) {
	if b == nil || b.transport == nil {
		return pluginControlHTTPResponse{}, fmt.Errorf("plugin HTTP transport is unavailable")
	}
	parsed, err := validatePluginControlHTTPRequest(&req)
	if err != nil {
		return pluginControlHTTPResponse{}, err
	}
	if !req.EndpointPolicy.Authorized {
		return pluginControlHTTPResponse{}, fmt.Errorf("HTTP endpoint policy is required")
	}
	if req.ResolverIP != nil && !req.ResolverPolicy.Authorized {
		return pluginControlHTTPResponse{}, fmt.Errorf("HTTP custom resolver endpoint policy is required")
	}
	tlsConfig, err := pluginControlHTTPClientTLSConfig(req, parsed)
	if err != nil {
		return pluginControlHTTPResponse{}, err
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            b.pluginHTTPDialContext(req),
		ForceAttemptHTTP2:      false,
		DisableCompression:     false,
		DisableKeepAlives:      true,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    minDuration(req.Timeout, 10*time.Second),
		ResponseHeaderTimeout:  req.Timeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: pluginControlHTTPMaxHeaderBytes,
	}
	defer transport.CloseIdleConnections()
	origin := pluginControlHTTPOrigin(parsed)
	client := &http.Client{Transport: transport, Timeout: req.Timeout}
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if !req.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) > req.MaxRedirects {
			return fmt.Errorf("HTTP redirect limit %d exceeded", req.MaxRedirects)
		}
		if next.URL.Scheme != "http" && next.URL.Scheme != "https" {
			return fmt.Errorf("HTTP redirect uses unsupported scheme %q", next.URL.Scheme)
		}
		if pluginControlHTTPOrigin(next.URL) != origin {
			return fmt.Errorf("cross-origin HTTP redirects are not allowed")
		}
		return nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, parsed.String(), bytes.NewReader(req.Body))
	if err != nil {
		return pluginControlHTTPResponse{}, err
	}
	for name, value := range req.Headers {
		httpReq.Header.Set(name, value)
	}
	response, err := client.Do(httpReq)
	if err != nil {
		return pluginControlHTTPResponse{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(req.MaxResponseBytes)+1))
	if err != nil {
		return pluginControlHTTPResponse{}, err
	}
	if len(body) > req.MaxResponseBytes {
		return pluginControlHTTPResponse{}, fmt.Errorf("HTTP response body exceeds %d bytes", req.MaxResponseBytes)
	}
	headers, err := boundedPluginControlHTTPHeaders(response.Header)
	if err != nil {
		return pluginControlHTTPResponse{}, err
	}
	return pluginControlHTTPResponse{
		StatusCode: response.StatusCode, Status: response.Status, Headers: headers,
		Body: body, FinalURL: response.Request.URL.String(),
	}, nil
}

func (b *defaultPluginControlNetworkBroker) pluginHTTPDialContext(req pluginControlHTTPRequest) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("HTTP destination port is invalid")
		}
		ips, err := b.lookupPluginControlIPs(ctx, host, pluginControlDNSDialConfig{
			Interface: req.Interface, Namespace: req.Namespace, SourceIP: req.SourceIP,
			ResolverIP: req.ResolverIP, ResolverPort: req.ResolverPort, Transport: req.DNSTransport, Timeout: req.Timeout,
			EndpointPolicy: req.ResolverPolicy,
		})
		if err != nil {
			return nil, err
		}
		var failures []string
		for _, ip := range ips {
			if !req.EndpointPolicy.AllowsIP(ip) {
				failures = append(failures, ip.String()+": destination is outside declared remote_cidrs")
				continue
			}
			resolvedNetwork, err := pluginControlSocketResolveNetwork("tcp", req.SourceIP, ip)
			if err != nil {
				failures = append(failures, err.Error())
				continue
			}
			conn, err := b.transport.Dial(ctx, pluginControlSocketOpenRequest{
				Network: resolvedNetwork, Namespace: req.Namespace, Interface: req.Interface,
				LocalIP: req.SourceIP, RemoteIP: ip, RemotePort: port, Timeout: req.Timeout,
				KeepAlive: 30 * time.Second, NoDelay: true,
			})
			if err == nil {
				return conn, nil
			}
			failures = append(failures, ip.String()+": "+err.Error())
		}
		return nil, fmt.Errorf("HTTP destination dial failed: %s", strings.Join(failures, "; "))
	}
}

func (b *defaultPluginControlNetworkBroker) DNSLookup(ctx context.Context, req pluginControlDNSRequest) (pluginControlDNSResponse, error) {
	if b == nil || b.transport == nil {
		return pluginControlDNSResponse{}, fmt.Errorf("plugin DNS transport is unavailable")
	}
	if err := validatePluginControlDNSRequest(&req); err != nil {
		return pluginControlDNSResponse{}, err
	}
	if !req.EndpointPolicy.Authorized {
		return pluginControlDNSResponse{}, fmt.Errorf("DNS endpoint policy is required")
	}
	resolver := b.pluginControlResolver(pluginControlDNSDialConfig{
		Interface: req.Interface, Namespace: req.Namespace, SourceIP: req.SourceIP,
		ResolverIP: req.ResolverIP, ResolverPort: req.ResolverPort, Transport: req.Transport, Timeout: req.Timeout,
		EndpointPolicy: req.EndpointPolicy,
	})
	response := pluginControlDNSResponse{Name: req.Name, Type: req.Type, Records: []any{}}
	switch req.Type {
	case "ip", "a", "aaaa":
		network := "ip"
		if req.Type == "a" {
			network = "ip4"
		} else if req.Type == "aaaa" {
			network = "ip6"
		}
		values, err := resolver.LookupIP(ctx, network, req.Name)
		if err != nil {
			return pluginControlDNSResponse{}, err
		}
		for _, value := range values {
			response.Records = append(response.Records, value.String())
		}
	case "txt":
		values, err := resolver.LookupTXT(ctx, req.Name)
		if err != nil {
			return pluginControlDNSResponse{}, err
		}
		for _, value := range values {
			response.Records = append(response.Records, value)
		}
	case "mx":
		values, err := resolver.LookupMX(ctx, req.Name)
		if err != nil {
			return pluginControlDNSResponse{}, err
		}
		for _, value := range values {
			response.Records = append(response.Records, map[string]any{"host": value.Host, "preference": value.Pref})
		}
	case "srv":
		_, values, err := resolver.LookupSRV(ctx, req.Service, req.Protocol, req.Name)
		if err != nil {
			return pluginControlDNSResponse{}, err
		}
		for _, value := range values {
			response.Records = append(response.Records, map[string]any{
				"target": value.Target, "port": value.Port, "priority": value.Priority, "weight": value.Weight,
			})
		}
	case "cname":
		value, err := resolver.LookupCNAME(ctx, req.Name)
		if err != nil {
			return pluginControlDNSResponse{}, err
		}
		response.Records = append(response.Records, value)
	case "ptr":
		values, err := resolver.LookupAddr(ctx, req.Name)
		if err != nil {
			return pluginControlDNSResponse{}, err
		}
		for _, value := range values {
			response.Records = append(response.Records, value)
		}
	}
	if err := validatePluginControlDNSResponse(response); err != nil {
		return pluginControlDNSResponse{}, err
	}
	return response, nil
}

type pluginControlDNSDialConfig struct {
	Interface      string
	Namespace      string
	SourceIP       net.IP
	ResolverIP     net.IP
	ResolverPort   int
	Transport      string
	Timeout        time.Duration
	EndpointPolicy pluginControlNetEndpointPolicy
}

func (b *defaultPluginControlNetworkBroker) pluginControlResolver(cfg pluginControlDNSDialConfig) *net.Resolver {
	return &net.Resolver{
		PreferGo: true, StrictErrors: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			resolverIP := cfg.ResolverIP
			resolverPort := cfg.ResolverPort
			if resolverIP == nil {
				host, portText, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				resolverIP = net.ParseIP(strings.Trim(host, "[]"))
				resolverPort, _ = strconv.Atoi(portText)
			}
			if resolverIP == nil || resolverPort < 1 || resolverPort > 65535 {
				return nil, fmt.Errorf("DNS resolver address is invalid")
			}
			if cfg.EndpointPolicy.Authorized && !cfg.EndpointPolicy.AllowsIP(resolverIP) {
				return nil, fmt.Errorf("DNS resolver %s is outside declared remote_cidrs", net.JoinHostPort(resolverIP.String(), strconv.Itoa(resolverPort)))
			}
			transport := cfg.Transport
			if transport == "" {
				transport = "udp"
			}
			resolvedNetwork, err := pluginControlSocketResolveNetwork(transport, cfg.SourceIP, resolverIP)
			if err != nil {
				return nil, err
			}
			return b.transport.Dial(ctx, pluginControlSocketOpenRequest{
				Network: resolvedNetwork, Namespace: cfg.Namespace, Interface: cfg.Interface,
				LocalIP: cfg.SourceIP, RemoteIP: resolverIP, RemotePort: resolverPort,
				Timeout: cfg.Timeout, NoDelay: true,
			})
		},
	}
}

func (b *defaultPluginControlNetworkBroker) lookupPluginControlIPs(ctx context.Context, host string, cfg pluginControlDNSDialConfig) ([]net.IP, error) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return []net.IP{ip}, nil
	}
	if _, err := normalizePluginControlDNSName(host, false); err != nil {
		return nil, fmt.Errorf("HTTP destination hostname: %w", err)
	}
	values, err := b.pluginControlResolver(cfg).LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("HTTP destination hostname resolved to no addresses")
	}
	return values, nil
}

func validatePluginControlHTTPRequest(req *pluginControlHTTPRequest) (*url.URL, error) {
	if req == nil {
		return nil, fmt.Errorf("HTTP request is required")
	}
	req.Method = strings.ToUpper(strings.TrimSpace(req.Method))
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		return nil, fmt.Errorf("HTTP method %q is not allowed", req.Method)
	}
	if len(req.URL) == 0 || len(req.URL) > pluginControlHTTPMaxURLBytes {
		return nil, fmt.Errorf("HTTP URL must contain 1 to %d bytes", pluginControlHTTPMaxURLBytes)
	}
	parsed, err := url.Parse(req.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("HTTP URL is invalid")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("HTTP URL scheme must be http or https")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("HTTP URL userinfo is not allowed")
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("HTTP URL fragments are not allowed")
	}
	if portText := parsed.Port(); portText != "" {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("HTTP URL port is invalid")
		}
	}
	if len(req.Body) > pluginControlHTTPMaxRequestBytes {
		return nil, fmt.Errorf("HTTP request body exceeds %d bytes", pluginControlHTTPMaxRequestBytes)
	}
	if len(req.Headers) > pluginControlHTTPMaxHeaders {
		return nil, fmt.Errorf("HTTP request headers exceed %d entries", pluginControlHTTPMaxHeaders)
	}
	headerBytes := 0
	normalizedHeaders := make(map[string]string, len(req.Headers))
	for name, value := range req.Headers {
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		if name == "" || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) || strings.EqualFold(name, "Host") {
			return nil, fmt.Errorf("HTTP request header %q is invalid or reserved", name)
		}
		headerBytes += len(name) + len(value)
		if headerBytes > pluginControlHTTPMaxHeaderBytes {
			return nil, fmt.Errorf("HTTP request headers exceed %d bytes", pluginControlHTTPMaxHeaderBytes)
		}
		normalizedHeaders[name] = value
	}
	req.Headers = normalizedHeaders
	if req.Timeout <= 0 || req.Timeout > pluginControlSocketMaxTimeout {
		return nil, fmt.Errorf("HTTP timeout must be between 1ms and %s", pluginControlSocketMaxTimeout)
	}
	if req.MaxResponseBytes == 0 {
		req.MaxResponseBytes = pluginControlHTTPMaxResponseBytes
	}
	if req.MaxResponseBytes < 1 || req.MaxResponseBytes > pluginControlHTTPMaxResponseBytes {
		return nil, fmt.Errorf("HTTP max_response_bytes must be between 1 and %d", pluginControlHTTPMaxResponseBytes)
	}
	if req.MaxRedirects == 0 {
		req.MaxRedirects = 3
	}
	if req.MaxRedirects < 1 || req.MaxRedirects > pluginControlHTTPMaxRedirects {
		return nil, fmt.Errorf("HTTP max_redirects must be between 1 and %d", pluginControlHTTPMaxRedirects)
	}
	if req.ResolverPort == 0 {
		req.ResolverPort = 53
	}
	if req.ResolverIP != nil && (req.ResolverPort < 1 || req.ResolverPort > 65535) {
		return nil, fmt.Errorf("HTTP resolver_port is invalid")
	}
	req.DNSTransport = strings.ToLower(strings.TrimSpace(req.DNSTransport))
	if req.DNSTransport == "" {
		req.DNSTransport = "udp"
	}
	if req.DNSTransport != "udp" && req.DNSTransport != "tcp" {
		return nil, fmt.Errorf("HTTP dns_transport must be udp or tcp")
	}
	if len(req.CAPEM) > pluginControlHTTPMaxResponseBytes || len(req.ClientCertPEM) > pluginControlHTTPMaxResponseBytes || len(req.ClientKeyPEM) > pluginControlHTTPMaxResponseBytes {
		return nil, fmt.Errorf("HTTP TLS material exceeds the bounded input limit")
	}
	if (len(req.ClientCertPEM) == 0) != (len(req.ClientKeyPEM) == 0) {
		return nil, fmt.Errorf("HTTP client certificate and key must be provided together")
	}
	return parsed, nil
}

func pluginControlHTTPClientTLSConfig(req pluginControlHTTPRequest, parsed *url.URL) (*tls.Config, error) {
	serverName := strings.TrimSpace(req.ServerName)
	if serverName == "" && parsed != nil {
		serverName = parsed.Hostname()
	}
	if strings.ContainsAny(serverName, "\x00\r\n \t") {
		return nil, fmt.Errorf("HTTP TLS server_name is invalid")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if len(req.CAPEM) > 0 {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(req.CAPEM) {
			return nil, fmt.Errorf("HTTP ca_pem contains no valid certificates")
		}
		config.RootCAs = roots
	}
	if len(req.ClientCertPEM) > 0 {
		certificate, err := tls.X509KeyPair(req.ClientCertPEM, req.ClientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("HTTP client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

func boundedPluginControlHTTPHeaders(headers http.Header) (map[string][]string, error) {
	if len(headers) > pluginControlHTTPMaxHeaders {
		return nil, fmt.Errorf("HTTP response headers exceed %d entries", pluginControlHTTPMaxHeaders)
	}
	out := make(map[string][]string, len(headers))
	bytes := 0
	for name, values := range headers {
		copyValues := make([]string, len(values))
		for i, value := range values {
			bytes += len(name) + len(value)
			if bytes > pluginControlHTTPMaxHeaderBytes {
				return nil, fmt.Errorf("HTTP response headers exceed %d bytes", pluginControlHTTPMaxHeaderBytes)
			}
			copyValues[i] = value
		}
		out[name] = copyValues
	}
	return out, nil
}

func pluginControlHTTPOrigin(value *url.URL) string {
	if value == nil {
		return ""
	}
	port := value.Port()
	if port == "" {
		if strings.EqualFold(value.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	return strings.ToLower(value.Scheme) + "://" + strings.ToLower(value.Hostname()) + ":" + port
}

func pluginControlHTTPRemotePort(value *url.URL) int {
	if value == nil {
		return 0
	}
	if port := value.Port(); port != "" {
		parsed, _ := strconv.Atoi(port)
		return parsed
	}
	if strings.EqualFold(value.Scheme, "https") {
		return 443
	}
	return 80
}

func validatePluginControlDNSRequest(req *pluginControlDNSRequest) error {
	if req == nil {
		return fmt.Errorf("DNS request is required")
	}
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	if req.Type == "" {
		req.Type = "ip"
	}
	switch req.Type {
	case "ip", "a", "aaaa", "txt", "mx", "srv", "cname", "ptr":
	default:
		return fmt.Errorf("DNS type must be one of ip, a, aaaa, txt, mx, srv, cname, ptr")
	}
	name, err := normalizePluginControlDNSName(req.Name, req.Type == "ptr")
	if err != nil {
		return err
	}
	req.Name = name
	if req.Type == "srv" {
		req.Service = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(req.Service)), "_")
		req.Protocol = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(req.Protocol)), "_")
		if !validPluginControlDNSLabel(req.Service) || !validPluginControlDNSLabel(req.Protocol) {
			return fmt.Errorf("DNS SRV service and protocol are required")
		}
	}
	if req.Timeout <= 0 || req.Timeout > pluginControlSocketMaxTimeout {
		return fmt.Errorf("DNS timeout must be between 1ms and %s", pluginControlSocketMaxTimeout)
	}
	if req.ResolverPort == 0 {
		req.ResolverPort = 53
	}
	if req.ResolverIP != nil && (req.ResolverPort < 1 || req.ResolverPort > 65535) {
		return fmt.Errorf("DNS resolver_port is invalid")
	}
	req.Transport = strings.ToLower(strings.TrimSpace(req.Transport))
	if req.Transport == "" {
		req.Transport = "udp"
	}
	if req.Transport != "udp" && req.Transport != "tcp" {
		return fmt.Errorf("DNS transport must be udp or tcp")
	}
	return nil
}

func normalizePluginControlDNSName(value string, address bool) (string, error) {
	value = strings.TrimSpace(value)
	if address {
		if net.ParseIP(value) == nil {
			return "", fmt.Errorf("DNS PTR name must be an IP address")
		}
		return value, nil
	}
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if value == "" || len(value) > 253 || strings.Contains(value, "..") {
		return "", fmt.Errorf("DNS name is invalid")
	}
	for _, label := range strings.Split(value, ".") {
		if !validPluginControlDNSLabel(label) {
			return "", fmt.Errorf("DNS name is invalid")
		}
	}
	return value, nil
}

func validPluginControlDNSLabel(value string) bool {
	if value == "" || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func validatePluginControlDNSResponse(response pluginControlDNSResponse) error {
	if len(response.Records) > pluginControlDNSMaxRecords {
		return fmt.Errorf("DNS response records exceed %d", pluginControlDNSMaxRecords)
	}
	total := 0
	for _, record := range response.Records {
		total += len(fmt.Sprint(record))
		if total > pluginControlDNSMaxRecordBytes {
			return fmt.Errorf("DNS response records exceed %d bytes", pluginControlDNSMaxRecordBytes)
		}
	}
	return nil
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func pluginControlHTTPResponseObject(response pluginControlHTTPResponse) map[string]any {
	out := map[string]any{
		"status_code": response.StatusCode, "status": response.Status, "headers": response.Headers,
		"body_hex": hex.EncodeToString(response.Body), "bytes": len(response.Body), "final_url": response.FinalURL,
	}
	if utf8.Valid(response.Body) {
		out["body_text"] = string(response.Body)
	}
	return out
}

func sortedPluginControlDNSRecords(response pluginControlDNSResponse) pluginControlDNSResponse {
	if response.Type == "ip" || response.Type == "a" || response.Type == "aaaa" || response.Type == "txt" || response.Type == "cname" || response.Type == "ptr" {
		sort.Slice(response.Records, func(i, j int) bool { return fmt.Sprint(response.Records[i]) < fmt.Sprint(response.Records[j]) })
	}
	return response
}
