package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func startSharedHTTPTestProxy(t *testing.T, sp *sharedProxyEngine) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); sp.serveHTTP(context.Background(), ln, ln.Addr().String()) }()
	t.Cleanup(func() { ln.Close(); <-done })
	return ln.Addr().String()
}

func TestSharedHTTPKeepAlivePipeliningRoutesAndSanitizesEveryRequest(t *testing.T) {
	backend := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			fmt.Fprintf(w, "%s|%s|%s|%s|%s|%s", name, r.Host, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), r.Header.Get("Forwarded"), body)
		}))
	}
	a, b := backend("a"), backend("b")
	defer a.Close()
	defer b.Close()
	statsA, statsB := &siteStats{}, &siteStats{}
	sp := &sharedProxyEngine{httpRoutes: map[string]sharedProxyRoute{
		"a.test": {backend: strings.TrimPrefix(a.URL, "http://"), stats: statsA},
		"b.test": {backend: strings.TrimPrefix(b.URL, "http://"), stats: statsB},
	}}
	conn, err := net.Dial("tcp4", startSharedHTTPTestProxy(t, sp))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	requests := ""
	for _, host := range []string{"a.test", "a.test", "b.test"} {
		requests += "POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 3\r\nX-Forwarded-For: spoof\r\nX-Real-IP: spoof\r\nForwarded: spoof\r\nConnection: X-Real-IP\r\n\r\nabc"
	}
	if _, err := io.WriteString(conn, requests); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	for _, host := range []string{"a", "a", "b"} {
		res, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		want := host + "|" + host + ".test|127.0.0.1|127.0.0.1|for=127.0.0.1|abc"
		if err != nil || string(body) != want {
			t.Fatalf("response=%q, err=%v, want=%q", body, err, want)
		}
	}
	if atomic.LoadInt64(&statsA.totalConns) != 1 || atomic.LoadInt64(&statsB.totalConns) != 1 {
		t.Fatalf("backend keepalive not preserved or stats mixed: a=%d b=%d", statsA.totalConns, statsB.totalConns)
	}
}

func TestSharedHTTPChunkedBodyAbsoluteURIAndUnknownHost(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s|%s|%s", r.Host, r.URL.RequestURI(), body)
	}))
	defer backend.Close()
	sp := &sharedProxyEngine{httpRoutes: map[string]sharedProxyRoute{"a.test": {backend: strings.TrimPrefix(backend.URL, "http://")}}}
	conn, err := net.Dial("tcp4", startSharedHTTPTestProxy(t, sp))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(conn, "POST http://a.test/path?q=1 HTTP/1.1\r\nHost: ignored.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: unknown.test\r\n\r\n")
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "a.test|/path?q=1|abc" {
		t.Fatalf("body = %q", body)
	}
	res, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("unknown host status = %d", res.StatusCode)
	}
}

func TestSharedHTTPUpgradePreservesBufferedBytes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(brw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		brw.Flush()
		io.Copy(conn, brw)
	}))
	defer backend.Close()
	sp := &sharedProxyEngine{httpRoutes: map[string]sharedProxyRoute{"a.test": {backend: strings.TrimPrefix(backend.URL, "http://"), stats: &siteStats{}}}}
	conn, err := net.Dial("tcp4", startSharedHTTPTestProxy(t, sp))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\nping")
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d", res.StatusCode)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestSharedRoutesKeepProtocolSpecificMetadata(t *testing.T) {
	sp := &sharedProxyEngine{listeners: map[string]*managedListener{}, quicListeners: map[string]*managedQUICListener{}}
	for _, port := range []string{"80", "443"} {
		addr := net.JoinHostPort("127.0.0.1", port)
		sp.listeners[listenerKey("", addr)] = &managedListener{}
	}
	sp.quicListeners[listenerKey("", "127.0.0.1:443")] = &managedQUICListener{}
	sites := []Site{
		{ID: 1, Domain: "a.test", ListenIP: "127.0.0.1", BackendIP: "192.0.2.1", BackendHTTP: 80, BackendSourceIP: "192.0.2.10"},
		{ID: 2, Domain: "a.test", ListenIP: "127.0.0.1", BackendIP: "192.0.2.2", BackendHTTPS: 443, Transparent: true, QUIC: true},
	}
	sp.applySites(context.Background(), sites, 1)
	first := sp.domainStats[1]
	for i := 0; i < 2; i++ {
		httpRoute, httpsRoute := sp.httpRoutes["a.test"], sp.httpsRoutes["a.test"]
		if httpRoute.sourceIP != "192.0.2.10" || httpRoute.transparent || !httpsRoute.transparent || httpsRoute.sourceIP != "" || httpRoute.stats == httpsRoute.stats || httpRoute.stats != first || sp.quicRoutes["a.test"] != httpsRoute {
			t.Fatalf("metadata mixed: HTTP=%+v HTTPS=%+v", httpRoute, httpsRoute)
		}
		sites[0], sites[1] = sites[1], sites[0]
		sp.applySites(context.Background(), sites, 2)
	}
}

func BenchmarkSharedHTTPKeepAlive(b *testing.B) {
	payload := strings.Repeat("x", 1024)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, payload)
	}))
	defer backend.Close()
	sp := &sharedProxyEngine{httpRoutes: map[string]sharedProxyRoute{
		"bench.test": {backend: strings.TrimPrefix(backend.URL, "http://")},
	}}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); sp.serveHTTP(context.Background(), ln, ln.Addr().String()) }()
	defer func() { ln.Close(); <-done }()
	transport := &http.Transport{MaxIdleConnsPerHost: 32}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	url := "http://" + ln.Addr().String()
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest(http.MethodGet, url, nil)
			req.Host = "bench.test"
			response, err := client.Do(req)
			if err != nil {
				b.Error(err)
				return
			}
			n, err := io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK || n != int64(len(payload)) {
				b.Errorf("response status=%d bytes=%d error=%v", response.StatusCode, n, err)
				return
			}
		}
	})
}
