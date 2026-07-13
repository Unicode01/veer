package app

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	udpCleanupInterval                  = 30 * time.Second
	udpNatIdleTimeout                   = 120 * time.Second
	tcpProxyBufferSize                  = 128 * 1024
	udpPacketBufferSize                 = 65535
	udpSocketBufferSize                 = 4 * 1024 * 1024
	userspaceUDPNATMaxEntriesPerProcess = 1024

	workerStatsActiveUpdateInterval = 1 * time.Second
	workerStatsIdleUpdateInterval   = 5 * time.Second
	workerStatsActiveSendInterval   = 2 * time.Second
	workerStatsIdleSendInterval     = 10 * time.Second
)

var (
	tcpProxyBufferPool = sync.Pool{
		New: func() any {
			return new([tcpProxyBufferSize]byte)
		},
	}
	udpPacketBufferPool = sync.Pool{
		New: func() any {
			return new([udpPacketBufferSize]byte)
		},
	}
	userspaceUDPNATBudget = udpNATEntryBudget{limit: userspaceUDPNATMaxEntriesPerProcess}
)

type udpNATEntryBudget struct {
	active int64
	limit  int64
}

func (b *udpNATEntryBudget) tryAcquire() bool {
	if b == nil || b.limit <= 0 {
		return false
	}
	for {
		active := atomic.LoadInt64(&b.active)
		if active >= b.limit {
			return false
		}
		if atomic.CompareAndSwapInt64(&b.active, active, active+1) {
			return true
		}
	}
}

func (b *udpNATEntryBudget) release() {
	if b == nil {
		return
	}
	for {
		active := atomic.LoadInt64(&b.active)
		if active <= 0 {
			return
		}
		if atomic.CompareAndSwapInt64(&b.active, active, active-1) {
			return
		}
	}
}

func (b *udpNATEntryBudget) activeEntries() int64 {
	if b == nil {
		return 0
	}
	return atomic.LoadInt64(&b.active)
}

func getTCPProxyBuffer() []byte {
	return tcpProxyBufferPool.Get().(*[tcpProxyBufferSize]byte)[:]
}

func putTCPProxyBuffer(buf []byte) {
	if cap(buf) < tcpProxyBufferSize {
		return
	}
	buf = buf[:tcpProxyBufferSize]
	tcpProxyBufferPool.Put((*[tcpProxyBufferSize]byte)(buf))
}

func getUDPPacketBuffer() []byte {
	return udpPacketBufferPool.Get().(*[udpPacketBufferSize]byte)[:]
}

func putUDPPacketBuffer(buf []byte) {
	if cap(buf) < udpPacketBufferSize {
		return
	}
	buf = buf[:udpPacketBufferSize]
	udpPacketBufferPool.Put((*[udpPacketBufferSize]byte)(buf))
}

func statsUpdateInterval(active bool) time.Duration {
	if active {
		return workerStatsActiveUpdateInterval
	}
	return workerStatsIdleUpdateInterval
}

func statsSendInterval(active bool) time.Duration {
	if active {
		return workerStatsActiveSendInterval
	}
	return workerStatsIdleSendInterval
}

func stopTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func resetTimer(timer *time.Timer, interval time.Duration) {
	if timer == nil {
		return
	}
	stopTimer(timer)
	timer.Reset(interval)
}

type closerSet struct {
	mu      sync.Mutex
	closers []io.Closer
	closed  bool
}

func (s *closerSet) Add(c io.Closer) bool {
	if c == nil {
		return false
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		c.Close()
		return false
	}
	s.closers = append(s.closers, c)
	s.mu.Unlock()
	return true
}

func (s *closerSet) CloseAll() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	closers := s.closers
	s.closers = nil
	s.mu.Unlock()

	for _, c := range closers {
		c.Close()
	}
}
