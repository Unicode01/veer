package app

import (
	"bufio"
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// With web_tls on, the panel port takes both protocols. The first byte of a
// connection tells them apart: 0x16 opens a TLS handshake, anything else is
// plain HTTP. Plain HTTP is still served to clients on this host (loopback,
// or a connection from one of the host's own addresses), so deploy.sh's
// readiness probe, a local WHMCS and a reverse proxy in front of the panel
// keep working unchanged. A remote browser is sent to https; any other
// remote request is refused rather than let its token cross the network in
// clear text.
const (
	apiTLSRecordHandshake = 0x16
	apiProtocolPeekWait   = 10 * time.Second
	apiPlainRefusalLogGap = time.Minute
)

// apiServer is the running panel: one http.Server, or with TLS one for each
// protocol on the same listener.
type apiServer struct {
	servers []*http.Server
}

func (s *apiServer) Shutdown(ctx context.Context) error {
	var errs []error
	for _, server := range s.servers {
		errs = append(errs, server.Shutdown(ctx))
	}
	return errors.Join(errs...)
}

func (s *apiServer) Close() error {
	var errs []error
	for _, server := range s.servers {
		errs = append(errs, server.Close())
	}
	return errors.Join(errs...)
}

// serveAPIListener serves handler on listener, over HTTPS and plain HTTP when
// panel is set. It owns listener from here on.
func serveAPIListener(listener net.Listener, handler http.Handler, panel *panelTLS, newServer func(http.Handler) *http.Server) *apiServer {
	serve := func(name string, run func() error) {
		go func() {
			if err := run(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("%s server: %v", name, err)
			}
		}()
	}
	if panel == nil {
		server := newServer(handler)
		serve("http", func() error { return server.Serve(listener) })
		return &apiServer{servers: []*http.Server{server}}
	}
	split := newAPIProtocolListener(listener)
	secure := newServer(handler)
	secure.TLSConfig = panel.config
	plain := newServer(newAPIPlainHTTPGuard(handler))
	go split.run()
	serve("https", func() error { return secure.ServeTLS(split.tls, "", "") })
	serve("http", func() error { return plain.Serve(split.plain) })
	return &apiServer{servers: []*http.Server{secure, plain}}
}

type apiProtocolListener struct {
	raw       net.Listener
	tls       *apiConnQueue
	plain     *apiConnQueue
	done      chan struct{}
	closeOnce sync.Once

	mu     sync.Mutex
	queues int // queues not yet closed by their server
}

func newAPIProtocolListener(raw net.Listener) *apiProtocolListener {
	l := &apiProtocolListener{raw: raw, done: make(chan struct{}), queues: 2}
	l.tls = &apiConnQueue{owner: l, conns: make(chan net.Conn), closed: make(chan struct{})}
	l.plain = &apiConnQueue{owner: l, conns: make(chan net.Conn), closed: make(chan struct{})}
	return l
}

func (l *apiProtocolListener) close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.done)
		err = l.raw.Close()
	})
	return err
}

func (l *apiProtocolListener) run() {
	for {
		conn, err := l.raw.Accept()
		if err != nil {
			var temporary interface{ Temporary() bool }
			if errors.As(err, &temporary) && temporary.Temporary() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			_ = l.close()
			return
		}
		go l.classify(conn)
	}
}

// classify waits for the first byte off the accept loop, so a client that
// connects and stays silent holds up no one but itself.
func (l *apiProtocolListener) classify(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(apiProtocolPeekWait))
	reader := bufio.NewReader(conn)
	first, err := reader.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return
	}
	queue := l.plain
	if first[0] == apiTLSRecordHandshake {
		queue = l.tls
	}
	select {
	case queue.conns <- &apiPeekedConn{Conn: conn, reader: reader}:
	case <-queue.closed:
		_ = conn.Close()
	case <-l.done:
		_ = conn.Close()
	}
}

// apiConnQueue hands one protocol's connections to its http.Server. Each
// server closes its own queue on shutdown; the shared listener closes with
// the second one, so shutting down one server never fails the other's Serve.
type apiConnQueue struct {
	owner     *apiProtocolListener
	conns     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func (q *apiConnQueue) Accept() (net.Conn, error) {
	select {
	case conn := <-q.conns:
		return conn, nil
	case <-q.closed:
		return nil, net.ErrClosed
	case <-q.owner.done:
		return nil, net.ErrClosed
	}
}

func (q *apiConnQueue) Close() error {
	var err error
	q.closeOnce.Do(func() {
		close(q.closed)
		q.owner.mu.Lock()
		q.owner.queues--
		last := q.owner.queues == 0
		q.owner.mu.Unlock()
		if last {
			err = q.owner.close()
		}
	})
	return err
}

func (q *apiConnQueue) Addr() net.Addr { return q.owner.raw.Addr() }

// apiPeekedConn replays the byte the classifier read.
type apiPeekedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *apiPeekedConn) Read(p []byte) (int, error) {
	if c.reader.Buffered() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}

// apiPlainRequestIsLocal tells whether a plain HTTP request comes from this
// host. Tests replace it.
var apiPlainRequestIsLocal = func(r *http.Request) bool {
	remote := apiAddrIP(r.RemoteAddr)
	if remote == nil {
		return false
	}
	if remote.IsLoopback() {
		return true
	}
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return local != nil && remote.Equal(apiAddrIP(local.String()))
}

func apiAddrIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func newAPIPlainHTTPGuard(next http.Handler) http.Handler {
	var mu sync.Mutex
	var lastLog time.Time
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiPlainRequestIsLocal(r) {
			next.ServeHTTP(w, r)
			return
		}
		mu.Lock()
		if time.Since(lastLog) >= apiPlainRefusalLogGap {
			lastLog = time.Now()
			log.Printf("web server: plain HTTP %s %s from %s refused; the panel serves remote clients over HTTPS only", r.Method, r.URL.Path, r.RemoteAddr)
		}
		mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.Host != "" {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusPermanentRedirect)
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "this panel accepts remote requests over HTTPS only"})
	})
}
