package app

import (
	"database/sql"
	"fmt"
	"sort"
	"sync"
)

// Serialize only overlapping resource mutations. Plugin VMs run concurrently;
// an ownership check followed by netlink must not race another VM's claim or
// crash recovery. Entries disappear when the last waiter releases its lease.
type pluginNetResourceLockKey struct {
	db *sql.DB
	pluginOwnedResourceRef
}

type pluginNetResourceLock struct {
	mu   sync.Mutex
	refs int
}

var pluginNetResourceLocks = struct {
	sync.Mutex
	items map[pluginNetResourceLockKey]*pluginNetResourceLock
}{items: make(map[pluginNetResourceLockKey]*pluginNetResourceLock)}

func lockPluginNetResources(db *sql.DB, refs []pluginOwnedResourceRef) func() {
	unique := make(map[pluginOwnedResourceRef]bool, len(refs))
	for _, ref := range refs {
		unique[ref] = true
	}
	ordered := make([]pluginOwnedResourceRef, 0, len(unique))
	for ref := range unique {
		ordered = append(ordered, ref)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].ResourceType != ordered[j].ResourceType {
			return ordered[i].ResourceType < ordered[j].ResourceType
		}
		return ordered[i].ResourceKey < ordered[j].ResourceKey
	})
	locks := make([]*pluginNetResourceLock, len(ordered))
	pluginNetResourceLocks.Lock()
	for i, ref := range ordered {
		key := pluginNetResourceLockKey{db, ref}
		lock := pluginNetResourceLocks.items[key]
		if lock == nil {
			lock = &pluginNetResourceLock{}
			pluginNetResourceLocks.items[key] = lock
		}
		lock.refs++
		locks[i] = lock
	}
	pluginNetResourceLocks.Unlock()
	for _, lock := range locks {
		lock.mu.Lock()
	}
	return func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].mu.Unlock()
		}
		pluginNetResourceLocks.Lock()
		defer pluginNetResourceLocks.Unlock()
		for i, ref := range ordered {
			locks[i].refs--
			if locks[i].refs == 0 {
				delete(pluginNetResourceLocks.items, pluginNetResourceLockKey{db, ref})
			}
		}
	}
}

func (h *pluginControlHost) lockPluginNetMutation(refs []pluginOwnedResourceRef, operation string, related ...pluginOwnedResourceRef) func() {
	// Retry pending work before taking our locks; recovery may need several
	// slots. A failed unrelated slot never prevents this mutation.
	_ = recoverPluginNetTransactionsForResources(h.db, h.netAdmin, refs, "")
	lockRefs := append(append([]pluginOwnedResourceRef(nil), refs...), related...)
	unlock := lockPluginNetResources(h.db, lockRefs)
	if err := checkPendingPluginNetResources(h.db, h.plugin.ID, refs); err != nil {
		unlock()
		h.throwf("%s: %v", operation, err)
	}
	return unlock
}

func pluginNetResourceSlot(ref pluginOwnedResourceRef) string {
	return fmt.Sprintf("%s\x00%s", ref.ResourceType, ref.ResourceKey)
}

func (h *pluginControlHost) lockPluginNetLinks(namespace, operation string, names ...string) func() {
	var refs []pluginOwnedResourceRef
	if normalizePluginControlNamespace(namespace) != "host" {
		refs = append(refs, pluginOwnedResourceRef{pluginOwnedResourceTypeNamespace, normalizePluginControlNamespace(namespace)})
	}
	for _, name := range names {
		if name != "" {
			refs = append(refs, pluginOwnedResourceRef{pluginOwnedResourceTypeLink, pluginControlNetScopedResourceKey(namespace, name)})
		}
	}
	return h.lockPluginNetMutation(refs, operation)
}
