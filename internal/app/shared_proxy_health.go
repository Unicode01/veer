package app

import (
	"sort"
	"strings"
)

func sharedListenerStopped(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func (sp *sharedProxyEngine) listenerStatusLocked() sharedProxyApplyResult {
	failed := make(map[int64]struct{})
	for id := range sp.routeFailures {
		failed[id] = struct{}{}
	}
	result := sharedProxyApplyResult{}
	for key, sites := range sp.listenerSites {
		listener := sp.listeners[key]
		if listener != nil && !sharedListenerStopped(listener.done) {
			result.activeListenerCount++
			continue
		}
		for id := range sites {
			failed[id] = struct{}{}
		}
		result.failedListeners = append(result.failedListeners, "TCP "+strings.ReplaceAll(key, "\x00", " "))
	}
	for key, sites := range sp.quicListenerSites {
		listener := sp.quicListeners[key]
		if listener != nil && !sharedListenerStopped(listener.done) {
			result.activeListenerCount++
			continue
		}
		for id := range sites {
			failed[id] = struct{}{}
		}
		result.failedListeners = append(result.failedListeners, "UDP "+strings.ReplaceAll(key, "\x00", " "))
	}
	result.failedSiteIDs = sortedInt64SetKeys(failed)
	sort.Strings(result.failedListeners)
	return result
}
