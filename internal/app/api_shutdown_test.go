package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func startTestAPIServer(t *testing.T, handler http.Handler) (*apiServer, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := serveAPIListener(listener, handler, nil, nil, func(h http.Handler) *http.Server {
		return &http.Server{Handler: h, ReadHeaderTimeout: apiServerReadHeaderTimeout, IdleTimeout: apiServerIdleTimeout}
	})
	t.Cleanup(func() { _ = server.Close() })
	return server, listener.Addr().String()
}

// A connection that never sends a request (a browser's preconnect, a spare
// connection an HTTP client dialed) must not hold a shutdown up: the plain
// http.Server waits until it is 5 seconds old.
func TestAPIServerShutdownClosesConnectionsWithoutARequest(t *testing.T) {
	server, addr := startTestAPIServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(100 * time.Millisecond) // let the server accept it

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	begin := time.Now()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("Shutdown took %v with one connection that sent no request", elapsed)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection without a request is still open after Shutdown")
	}
}

// A request in flight still finishes: only connections without one are cut.
func TestAPIServerShutdownWaitsForARequestInFlight(t *testing.T) {
	started := make(chan struct{})
	server, addr := startTestAPIServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(500 * time.Millisecond)
		_, _ = io.WriteString(w, "finished")
	}))
	type result struct {
		body string
		err  error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			got <- result{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		got <- result{body: string(body), err: err}
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	r := <-got
	if r.err != nil || r.body != "finished" {
		t.Fatalf("request in flight during Shutdown: body %q, err %v", r.body, r.err)
	}
}
