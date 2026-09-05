package app

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type sharedHTTPContextKey struct{}

type sharedHTTPBufferPool struct{}

func (sharedHTTPBufferPool) Get() []byte  { return getTCPProxyBuffer() }
func (sharedHTTPBufferPool) Put(b []byte) { putTCPProxyBuffer(b) }

// Each frontend connection owns its backend pool, including transparent source IP.
type sharedHTTPSession struct {
	mu        sync.Mutex
	transport *http.Transport
	route     sharedProxyRoute
}

func (s *sharedHTTPSession) closeIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
}

func (sp *sharedProxyEngine) serveHTTP(ctx context.Context, ln net.Listener, addr string) {
	var sessions sync.Map
	server := &http.Server{
		Handler:           http.HandlerFunc(sp.handleHTTPRequest),
		ReadHeaderTimeout: sharedProxyInitialReadTimeout,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    sharedProxyMaxHeaderBytes,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			session := &sharedHTTPSession{}
			sessions.Store(conn, session)
			return context.WithValue(ctx, sharedHTTPContextKey{}, session)
		},
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				if session, ok := sessions.LoadAndDelete(conn); ok {
					session.(*sharedHTTPSession).closeIdle()
				}
			}
		},
	}
	// Closing a listener stops accepts, but existing requests and upgrades can drain.
	_ = server.Serve(budgetTCPListener{ln})
}

func (sp *sharedProxyEngine) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	host, err := normalizeSharedProxyHostHeader(r.Host)
	if err != nil || r.Method == http.MethodConnect {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	host = strings.TrimSuffix(host, ".")
	sp.mu.RLock()
	route, ok := sp.httpRoutes[host]
	sp.mu.RUnlock()
	if !ok {
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return
	}
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	clientIP = normalizeSharedProxyClientIP(clientIP)
	session, ok := r.Context().Value(sharedHTTPContextKey{}).(*sharedHTTPSession)
	if !ok {
		session = &sharedHTTPSession{}
		defer session.closeIdle()
	}
	session.mu.Lock()
	if session.transport == nil || session.route != route {
		if session.transport != nil {
			session.transport.CloseIdleConnections()
		}
		session.route = route
		session.transport = &http.Transport{
			DialContext:           route.httpDialContext(clientIP),
			MaxIdleConns:          1,
			MaxIdleConnsPerHost:   1,
			IdleConnTimeout:       120 * time.Second,
			ExpectContinueTimeout: time.Second,
			DisableCompression:    true,
		}
	}
	transport := session.transport
	session.mu.Unlock()
	proxy := httputil.ReverseProxy{
		Transport:  transport,
		BufferPool: sharedHTTPBufferPool{},
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = route.backend
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Del("X-Real-IP")
			// Rewrite runs after hop-by-hop and untrusted forwarding headers are removed.
			for _, line := range buildSharedProxyForwardingHeaders(clientIP) {
				name, value, _ := strings.Cut(line, ": ")
				pr.Out.Header.Set(name, value)
			}
		},
	}
	if r.Header.Get("Upgrade") != "" {
		w = sharedHTTPUpgradeWriter{w}
	}
	proxy.ServeHTTP(w, r)
}

type sharedHTTPUpgradeWriter struct{ http.ResponseWriter }

func (w sharedHTTPUpgradeWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w sharedHTTPUpgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	// ReverseProxy copies from the hijacked Conn, not its buffered Reader.
	return &sharedHTTPBufferedConn{Conn: conn, reader: brw.Reader}, brw, nil
}

type sharedHTTPBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *sharedHTTPBufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *sharedHTTPBufferedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

func (route sharedProxyRoute) httpDialContext(clientIP string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: 10 * time.Second}
		network := "tcp"
		if route.transparent {
			ip := net.ParseIP(clientIP).To4()
			if ip == nil {
				return nil, fmt.Errorf("transparent HTTP requires an IPv4 client")
			}
			dialer.LocalAddr = &net.TCPAddr{IP: ip}
			dialer.Control = controlTransparent(ip, "")
			network = "tcp4"
		} else if err := configureOutboundTCPDialer(&dialer, "", route.sourceIP); err != nil {
			return nil, err
		}
		conn, err := dialer.DialContext(ctx, network, route.backend)
		if err != nil || route.stats == nil {
			return conn, err
		}
		atomic.AddInt64(&route.stats.totalConns, 1)
		atomic.AddInt64(&route.stats.activeConns, 1)
		return &sharedHTTPStatsConn{Conn: conn, stats: route.stats}, nil
	}
}

type sharedHTTPStatsConn struct {
	net.Conn
	stats  *siteStats
	closed sync.Once
}

func (c *sharedHTTPStatsConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	atomic.AddInt64(&c.stats.bytesOut, int64(n))
	return n, err
}

func (c *sharedHTTPStatsConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	atomic.AddInt64(&c.stats.bytesIn, int64(n))
	return n, err
}

func (c *sharedHTTPStatsConn) Close() error {
	var err error
	c.closed.Do(func() { err = c.Conn.Close(); atomic.AddInt64(&c.stats.activeConns, -1) })
	return err
}

func (c *sharedHTTPStatsConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}
