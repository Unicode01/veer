package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

var userspaceListenerBudget = udpNATEntryBudget{limit: userspaceListenerLimit()}

type userspaceEndpoint struct {
	rule   Rule
	closer io.Closer
	done   chan struct{}
	err    error
}

type userspaceBindingGroup struct {
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	endpoints []userspaceEndpoint
	stats     *ruleStats
	stopOnce  sync.Once
}

func newUserspaceBindingGroup(rules []Rule, stats *ruleStats) (*userspaceBindingGroup, error) {
	if len(rules) == 0 || !userspaceListenerBudget.tryAcquireN(int64(len(rules))) {
		return nil, fmt.Errorf("userspace listener budget exceeded: requested %d, process limit %d", len(rules), userspaceListenerBudget.limit)
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &userspaceBindingGroup{ctx: ctx, cancel: cancel, stats: stats, endpoints: make([]userspaceEndpoint, len(rules))}
	for i, rule := range rules {
		g.endpoints[i].rule = rule
	}
	g.Repair()
	return g, nil
}

func (g *userspaceBindingGroup) Repair() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx.Err() != nil {
		return
	}
	for i := range g.endpoints {
		e := &g.endpoints[i]
		if e.done != nil {
			select {
			case <-e.done:
			default:
				continue
			}
		}
		var serve func() error
		switch e.rule.Protocol {
		case "tcp":
			ln, err := listenTCP(g.ctx, &e.rule)
			if err != nil {
				e.err = err
				continue
			}
			e.closer = ln
			serve = func() error { return serveTCP(g.ctx, ln, &e.rule, g.stats) }
		case "udp":
			if _, err := net.ResolveUDPAddr("udp", net.JoinHostPort(e.rule.OutIP, fmt.Sprint(e.rule.OutPort))); err != nil {
				e.err = err
				continue
			}
			pc, err := listenUDP(g.ctx, &e.rule)
			if err != nil {
				e.err = err
				continue
			}
			e.closer = pc
			serve = func() error { return serveUDP(g.ctx, pc, &e.rule, g.stats) }
		default:
			e.err = fmt.Errorf("unsupported userspace protocol %q", e.rule.Protocol)
			continue
		}
		e.err = nil
		e.done = make(chan struct{})
		go func() {
			err := serve()
			g.mu.Lock()
			defer g.mu.Unlock()
			_ = e.closer.Close()
			if err == nil {
				err = errors.New("listener stopped")
			}
			e.err = err
			close(e.done)
		}()
	}
}

func (g *userspaceBindingGroup) Status() (int, error) {
	if g == nil {
		return 0, errors.New("listener binding unavailable")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.ctx.Err(); err != nil {
		return 0, err
	}
	bound, failed := 0, 0
	var firstErr error
	for i := range g.endpoints {
		e := &g.endpoints[i]
		if e.err == nil && e.done != nil {
			bound++
			continue
		}
		failed++
		if firstErr == nil {
			firstErr = e.err
		}
	}
	if failed > 0 {
		return bound, fmt.Errorf("%d/%d listeners unavailable: %w", failed, len(g.endpoints), firstErr)
	}
	return bound, nil
}

func (g *userspaceBindingGroup) Stop() {
	if g == nil {
		return
	}
	g.stopOnce.Do(func() {
		g.mu.Lock()
		g.cancel()
		var done []chan struct{}
		for i := range g.endpoints {
			e := &g.endpoints[i]
			if e.closer != nil {
				_ = e.closer.Close()
			}
			if e.done != nil {
				done = append(done, e.done)
			}
		}
		g.mu.Unlock()
		for _, ch := range done {
			<-ch
		}
		userspaceListenerBudget.releaseN(int64(len(g.endpoints)))
	})
}

func userspaceRuleProtocols(rule Rule) []Rule {
	if rule.Protocol == "tcp+udp" {
		tcp, udp := rule, rule
		tcp.Protocol, udp.Protocol = "tcp", "udp"
		return []Rule{tcp, udp}
	}
	return []Rule{rule}
}
