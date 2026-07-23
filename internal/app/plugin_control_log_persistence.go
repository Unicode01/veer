package app

import (
	"database/sql"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

const (
	pluginLogPersistQueueSize = 2048
	pluginLogPersistBatchSize = 64
	pluginLogPersistInterval  = 250 * time.Millisecond
	pluginLogPersistTimeout   = 2 * time.Second
)

type pluginLogPersistence struct {
	db      *sql.DB
	queue   chan PluginLogEntry
	flush   chan chan struct{}
	stop    chan chan struct{}
	closed  atomic.Bool
	mu      sync.RWMutex
	dropMu  sync.Mutex
	dropped map[string]uint64
}

func newPluginLogPersistence(db *sql.DB) *pluginLogPersistence {
	if db == nil {
		return nil
	}
	persistence := &pluginLogPersistence{
		db:      db,
		queue:   make(chan PluginLogEntry, pluginLogPersistQueueSize),
		flush:   make(chan chan struct{}, 1),
		stop:    make(chan chan struct{}, 1),
		dropped: make(map[string]uint64),
	}
	go persistence.run()
	return persistence
}

func (p *pluginLogPersistence) enqueue(entry PluginLogEntry) bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed.Load() {
		return false
	}
	select {
	case p.queue <- entry:
		return true
	default:
		p.recordDropped(entry.PluginID, 1)
		return false
	}
}

func (p *pluginLogPersistence) flushPending(timeout time.Duration) bool {
	if p == nil || p.closed.Load() {
		return true
	}
	ack := make(chan struct{})
	select {
	case p.flush <- ack:
	case <-time.After(timeout):
		return false
	}
	select {
	case <-ack:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (p *pluginLogPersistence) closeAndFlush(timeout time.Duration) bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	if p.closed.Swap(true) {
		p.mu.Unlock()
		return true
	}
	ack := make(chan struct{})
	select {
	case p.stop <- ack:
		p.mu.Unlock()
	case <-time.After(timeout):
		p.mu.Unlock()
		return false
	}
	select {
	case <-ack:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (p *pluginLogPersistence) run() {
	ticker := time.NewTicker(pluginLogPersistInterval)
	defer ticker.Stop()
	batch := make([]PluginLogEntry, 0, pluginLogPersistBatchSize)
	persist := func() {
		if len(batch) == 0 {
			return
		}
		items := make([]store.PluginLog, 0, len(batch))
		for _, entry := range batch {
			fieldsJSON := "{}"
			if len(entry.Fields) > 0 {
				if raw, err := json.Marshal(entry.Fields); err == nil {
					fieldsJSON = string(raw)
				}
			}
			items = append(items, store.PluginLog{
				PluginID:   entry.PluginID,
				Level:      entry.Level,
				Message:    entry.Message,
				FieldsJSON: fieldsJSON,
				Event:      entry.Event,
				Worker:     entry.Worker,
				CreatedAt:  entry.CreatedAt,
			})
		}
		if err := store.AddPluginLogs(p.db, items); err != nil {
			for _, entry := range batch {
				p.recordDropped(entry.PluginID, 1)
			}
			log.Printf("plugin log persistence failed for %d entry(s): %v", len(batch), err)
		}
		batch = batch[:0]
	}
	drain := func() {
		for {
			select {
			case entry := <-p.queue:
				batch = append(batch, entry)
				if len(batch) >= pluginLogPersistBatchSize {
					persist()
				}
			default:
				persist()
				return
			}
		}
	}

	for {
		select {
		case entry := <-p.queue:
			batch = append(batch, entry)
			if len(batch) >= pluginLogPersistBatchSize {
				persist()
			}
		case <-ticker.C:
			persist()
		case ack := <-p.flush:
			drain()
			close(ack)
		case ack := <-p.stop:
			drain()
			close(ack)
			return
		}
	}
}

func (p *pluginLogPersistence) recordDropped(pluginID string, count uint64) {
	if p == nil || pluginID == "" || count == 0 {
		return
	}
	p.dropMu.Lock()
	p.dropped[pluginID] += count
	p.dropMu.Unlock()
}

func (p *pluginLogPersistence) droppedEntries(pluginID string) uint64 {
	if p == nil {
		return 0
	}
	p.dropMu.Lock()
	defer p.dropMu.Unlock()
	return p.dropped[pluginID]
}
