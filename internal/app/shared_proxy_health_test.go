package app

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestSharedProxyListenerStatusTracksRuntimeFailureBySite(t *testing.T) {
	done := make(chan struct{})
	sp := &sharedProxyEngine{
		listeners:         map[string]*managedListener{"http": {done: done}, "https": {}},
		listenerSites:     map[string]map[int64]struct{}{"http": {1: {}}, "https": {2: {}}},
		quicListenerSites: map[string]map[int64]struct{}{"quic": {2: {}}},
	}
	result := sp.listenerStatusLocked()
	if result.activeListenerCount != 2 || !reflect.DeepEqual(result.failedSiteIDs, []int64{2}) {
		t.Fatalf("startup status=%+v", result)
	}
	close(done)
	result = sp.listenerStatusLocked()
	if result.activeListenerCount != 1 || !reflect.DeepEqual(result.failedSiteIDs, []int64{1, 2}) {
		t.Fatalf("dead listener status=%+v", result)
	}
	sp.listeners["http"].done = make(chan struct{})
	sp.quicListeners = map[string]*managedQUICListener{"quic": {}}
	result = sp.listenerStatusLocked()
	if result.activeListenerCount != 3 || len(result.failedSiteIDs) > 0 {
		t.Fatalf("recovered status=%+v", result)
	}
}

func TestSharedHTTPSClosedListenerDoesNotSpin(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&sharedProxyEngine{}).serveHTTPS(context.Background(), ln, ln.Addr().String())
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HTTPS accept loop spun on a closed listener")
	}
}
