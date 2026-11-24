package app

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

type kernelSkipSummaryKey string

type kernelSkipSummary struct {
	reason     string
	ruleIDs    map[int64]struct{}
	rangeIDs   map[int64]struct{}
	entryCount int
}

type kernelSkipLogger struct {
	engine string
	items  map[kernelSkipSummaryKey]*kernelSkipSummary
}

type kernelStateLogger struct {
	last string
}

type kernelKeyedStateLogger struct {
	last map[string]string
}

// kernelCountLogState rate-limits a line about things maintenance passes
// removed. The first removal is reported at once; later ones are added up and
// reported at most once per interval, so a steady trickle costs one line per
// interval however much the per-pass counts vary.
type kernelCountLogState struct {
	pending int
	lastAt  time.Time
}

func newKernelSkipLogger(engine string) *kernelSkipLogger {
	return &kernelSkipLogger{
		engine: engine,
		items:  make(map[kernelSkipSummaryKey]*kernelSkipSummary),
	}
}

func (l *kernelSkipLogger) Add(rule Rule, err error) {
	if l == nil || err == nil {
		return
	}
	reason := strings.TrimSpace(err.Error())
	if reason == "" {
		reason = "unknown reason"
	}
	key := kernelSkipSummaryKey(reason)
	item := l.items[key]
	if item == nil {
		item = &kernelSkipSummary{
			reason:   reason,
			ruleIDs:  make(map[int64]struct{}),
			rangeIDs: make(map[int64]struct{}),
		}
		l.items[key] = item
	}
	switch kernelRuleLogKind(rule) {
	case "range":
		item.rangeIDs[kernelRuleLogOwnerID(rule)] = struct{}{}
	default:
		item.ruleIDs[kernelRuleLogOwnerID(rule)] = struct{}{}
	}
	item.entryCount++
}

func (l *kernelSkipLogger) Snapshot() map[string]struct{} {
	if l == nil || len(l.items) == 0 {
		return map[string]struct{}{}
	}
	keys := make([]string, 0, len(l.items))
	for key := range l.items {
		keys = append(keys, string(key))
	}
	sort.Strings(keys)

	snapshot := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		item := l.items[kernelSkipSummaryKey(key)]
		line := fmt.Sprintf("%s dataplane skipped: %s", l.engine, item.reason)
		snapshot[line] = struct{}{}
	}
	return snapshot
}

func (l *kernelStateLogger) Logf(format string, args ...interface{}) {
	if l == nil {
		log.Printf(format, args...)
		return
	}
	line := fmt.Sprintf(format, args...)
	if line == l.last {
		return
	}
	l.last = line
	log.Print(line)
}

func (l *kernelStateLogger) Reset() {
	if l == nil {
		return
	}
	l.last = ""
}

// Observe adds one pass's count and returns the total to report now, if a
// line is due: on the first removal, or once repeatEvery has passed since the
// last line. A pass that removed nothing still reports what earlier passes
// left pending once the interval is up.
func (s *kernelCountLogState) Observe(count int, now time.Time, repeatEvery time.Duration) (int, bool) {
	if s == nil {
		return count, count > 0
	}
	if count > 0 {
		s.pending += count
	}
	if s.pending == 0 {
		return 0, false
	}
	if !s.lastAt.IsZero() && repeatEvery > 0 && now.Sub(s.lastAt) < repeatEvery {
		return 0, false
	}
	total := s.pending
	s.pending = 0
	s.lastAt = now
	return total, true
}

func (l *kernelKeyedStateLogger) Logf(key string, format string, args ...interface{}) {
	if l == nil {
		log.Printf(format, args...)
		return
	}
	if l.last == nil {
		l.last = make(map[string]string)
	}
	line := fmt.Sprintf(format, args...)
	if l.last[key] == line {
		return
	}
	l.last[key] = line
	log.Print(line)
}

func (l *kernelKeyedStateLogger) Retain(keys map[string]struct{}) {
	if l == nil || len(l.last) == 0 {
		return
	}
	if len(keys) == 0 {
		l.last = nil
		return
	}
	for key := range l.last {
		if _, ok := keys[key]; ok {
			continue
		}
		delete(l.last, key)
	}
	if len(l.last) == 0 {
		l.last = nil
	}
}

func logKernelLineSetDelta(previous map[string]struct{}, next map[string]struct{}) map[string]struct{} {
	if len(next) == 0 {
		return map[string]struct{}{}
	}

	lines := make([]string, 0, len(next))
	for line := range next {
		if _, ok := previous[line]; ok {
			continue
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	for _, line := range lines {
		log.Print(line)
	}

	snapshot := make(map[string]struct{}, len(next))
	for line := range next {
		snapshot[line] = struct{}{}
	}
	return snapshot
}

func logKernelLineSetOnce(seen map[string]struct{}, next map[string]struct{}) map[string]struct{} {
	if len(seen) == 0 && len(next) == 0 {
		return map[string]struct{}{}
	}
	if len(next) == 0 {
		if len(seen) == 0 {
			return map[string]struct{}{}
		}
		out := make(map[string]struct{}, len(seen))
		for line := range seen {
			out[line] = struct{}{}
		}
		return out
	}

	lines := make([]string, 0, len(next))
	for line := range next {
		if _, ok := seen[line]; ok {
			continue
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	for _, line := range lines {
		log.Print(line)
	}

	out := make(map[string]struct{}, len(seen)+len(next))
	for line := range seen {
		out[line] = struct{}{}
	}
	for line := range next {
		out[line] = struct{}{}
	}
	return out
}

func kernelRuleLogKind(rule Rule) string {
	kind := strings.TrimSpace(rule.kernelLogKind)
	if kind == "" {
		return "rule"
	}
	return kind
}

func kernelRuleLogOwnerID(rule Rule) int64 {
	if rule.kernelLogOwnerID != 0 {
		return rule.kernelLogOwnerID
	}
	return rule.ID
}

func kernelRuleLogLabel(rule Rule) string {
	return fmt.Sprintf("%s %d", kernelRuleLogKind(rule), kernelRuleLogOwnerID(rule))
}

func normalizeKernelRuntimeNoteKey(key string) string {
	return strings.TrimSpace(key)
}

func (pm *ProcessManager) snapshotKernelRuntimeDismissedNoteKeysLocked() []string {
	if pm == nil || len(pm.kernelRuntimeDismissedNoteKeys) == 0 {
		return nil
	}
	keys := make([]string, 0, len(pm.kernelRuntimeDismissedNoteKeys))
	for key := range pm.kernelRuntimeDismissedNoteKeys {
		key = normalizeKernelRuntimeNoteKey(key)
		if key == "" {
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	return keys
}

func (pm *ProcessManager) dismissKernelRuntimeNote(key string) []string {
	if pm == nil {
		return nil
	}
	key = normalizeKernelRuntimeNoteKey(key)
	if key == "" {
		return nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.kernelRuntimeDismissedNoteKeys == nil {
		pm.kernelRuntimeDismissedNoteKeys = make(map[string]struct{})
	}
	pm.kernelRuntimeDismissedNoteKeys[key] = struct{}{}
	pm.kernelRuntimeSnapshot = KernelRuntimeResponse{}
	pm.kernelRuntimeSnapshotAt = time.Time{}
	return pm.snapshotKernelRuntimeDismissedNoteKeysLocked()
}
