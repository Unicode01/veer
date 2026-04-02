package app

import (
	"io"
	"sync"
	"time"
)

const (
	udpCleanupInterval  = 30 * time.Second
	udpNatIdleTimeout   = 120 * time.Second
	tcpProxyBufferSize  = 128 * 1024
	udpPacketBufferSize = 65535
	udpSocketBufferSize = 4 * 1024 * 1024

	workerStatsActiveUpdateInterval = 1 * time.Second
	workerStatsIdleUpdateInterval   = 5 * time.Second
	workerStatsActiveSendInterval   = 2 * time.Second
	workerStatsIdleSendInterval     = 10 * time.Second
)

var (
	tcpProxyBufferPool = sync.Pool{
		New: func() any {
			return make([]byte, tcpProxyBufferSize)
		},
	}
	udpPacketBufferPool = sync.Pool{
		New: func() any {
			return make([]byte, udpPacketBufferSize)
		},
	}
)

func getTCPProxyBuffer() []byte {
	return tcpProxyBufferPool.Get().([]byte)
}

func putTCPProxyBuffer(buf []byte) {
	if cap(buf) < tcpProxyBufferSize {
		return
	}
	tcpProxyBufferPool.Put(buf[:tcpProxyBufferSize])
}

func getUDPPacketBuffer() []byte {
	return udpPacketBufferPool.Get().([]byte)
}

func putUDPPacketBuffer(buf []byte) {
	if cap(buf) < udpPacketBufferSize {
		return
	}
	udpPacketBufferPool.Put(buf[:udpPacketBufferSize])
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
