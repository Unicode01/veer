package app

import (
	"io"
	"sync"
	"time"
)

const (
	udpCleanupInterval = 30 * time.Second
	udpNatIdleTimeout  = 120 * time.Second
)

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
