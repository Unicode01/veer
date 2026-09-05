package app

import (
	"context"
	"net"
	"sync"
	"time"
)

var userspaceTCPBudget = udpNATEntryBudget{limit: userspaceListenerLimit()}

func acceptUserspaceTCP(ctx context.Context, ln net.Listener) (net.Conn, error) {
	delay := 5 * time.Millisecond
	for {
		conn, err := ln.Accept()
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Match net/http's accept retry contract, including descriptor exhaustion.
		temporary, ok := err.(interface{ Temporary() bool })
		if !ok || !temporary.Temporary() {
			return nil, err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		delay = min(2*delay, time.Second)
	}
}

type budgetTCPListener struct{ net.Listener }

func (ln budgetTCPListener) Accept() (net.Conn, error) {
	for {
		conn, err := ln.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if userspaceTCPBudget.tryAcquire() {
			return &budgetTCPConn{Conn: conn}, nil
		}
		conn.Close()
	}
}

type budgetTCPConn struct {
	net.Conn
	once sync.Once
}

func (c *budgetTCPConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); userspaceTCPBudget.release() })
	return err
}

func (c *budgetTCPConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}
