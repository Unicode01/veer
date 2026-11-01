package app

import (
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Unicode01/veer/internal/store"
)

const (
	pluginNetTransactionJournalVersion = 2
	pluginNetTransactionStateMaxBytes  = 2 << 20
	pluginNetTransactionKindRoute      = "route"
	pluginNetTransactionKindRule       = "rule"
	pluginNetTransactionKindNeighbor   = "neighbor"
)

type pluginNetLeaseSnapshot struct {
	Exists       bool   `json:"exists,omitempty"`
	PluginID     string `json:"plugin_id,omitempty"`
	MetadataJSON string `json:"metadata_json,omitempty"`
}

type pluginNetTransactionState struct {
	Version int                         `json:"version"`
	BootID  string                      `json:"boot_id,omitempty"`
	Entries []pluginNetTransactionEntry `json:"entries"`
}

type pluginNetTransactionEntry struct {
	Resolved          bool                               `json:"resolved,omitempty"`
	LinkIdentities    []pluginNetTransactionLinkIdentity `json:"link_identities,omitempty"`
	Present           bool                               `json:"present"`
	ResourceType      string                             `json:"resource_type"`
	ResourceKey       string                             `json:"resource_key"`
	LeaseBefore       pluginNetLeaseSnapshot             `json:"lease_before"`
	NamespaceIdentity pluginControlNetNamespaceIdentity  `json:"namespace_identity,omitempty"`

	RouteRequest  *pluginControlNetRouteRequest `json:"route_request,omitempty"`
	RouteOriginal []pluginControlNetRouteState  `json:"route_original,omitempty"`
	RuleRequest   *pluginControlNetRuleRequest  `json:"rule_request,omitempty"`
	RuleOriginal  []pluginControlNetRuleState   `json:"rule_original,omitempty"`
	NeighRequest  *pluginControlNetNeighRequest `json:"neigh_request,omitempty"`
	NeighOriginal []pluginControlNetNeighState  `json:"neigh_original,omitempty"`
}

type pluginNetTransactionLinkIdentity struct {
	Name    string `json:"name"`
	IfIndex int    `json:"ifindex"`
	Kind    string `json:"kind,omitempty"`
	MAC     string `json:"mac,omitempty"`
}

func beginPluginRouteNetTransaction(db *sql.DB, pluginID string, items []pluginControlNetRouteBatchItem) (*store.PluginNetTransaction, error) {
	entries := make([]pluginNetTransactionEntry, 0, len(items))
	for _, item := range items {
		request := item.request
		entries = append(entries, pluginNetTransactionEntry{
			LinkIdentities: item.links,
			Present:        item.present, ResourceType: pluginOwnedResourceTypeRoute,
			ResourceKey: pluginControlNetRouteLeaseKey(item.request), LeaseBefore: item.leaseBefore,
			NamespaceIdentity: item.namespaceID, RouteRequest: &request, RouteOriginal: clonePluginControlNetRouteStates(item.original),
		})
	}
	return beginPluginNetTransaction(db, pluginID, pluginNetTransactionKindRoute, entries)
}

func beginPluginRuleNetTransaction(db *sql.DB, pluginID string, items []pluginControlNetRuleBatchItem) (*store.PluginNetTransaction, error) {
	entries := make([]pluginNetTransactionEntry, 0, len(items))
	for _, item := range items {
		request := item.request
		entries = append(entries, pluginNetTransactionEntry{
			LinkIdentities: item.links,
			Present:        item.present, ResourceType: pluginOwnedResourceTypeRule,
			ResourceKey: pluginControlNetRuleLeaseKey(item.request), LeaseBefore: item.leaseBefore,
			NamespaceIdentity: item.namespaceID, RuleRequest: &request, RuleOriginal: append([]pluginControlNetRuleState(nil), item.original...),
		})
	}
	return beginPluginNetTransaction(db, pluginID, pluginNetTransactionKindRule, entries)
}

func beginPluginNeighNetTransaction(db *sql.DB, pluginID string, items []pluginControlNetNeighBatchItem) (*store.PluginNetTransaction, error) {
	entries := make([]pluginNetTransactionEntry, 0, len(items))
	for _, item := range items {
		request := item.request
		entries = append(entries, pluginNetTransactionEntry{
			LinkIdentities: item.links,
			Present:        item.present, ResourceType: pluginOwnedResourceTypeNeighbor,
			ResourceKey: pluginControlNetNeighLeaseKey(item.request), LeaseBefore: item.leaseBefore,
			NamespaceIdentity: item.namespaceID, NeighRequest: &request, NeighOriginal: append([]pluginControlNetNeighState(nil), item.original...),
		})
	}
	return beginPluginNetTransaction(db, pluginID, pluginNetTransactionKindNeighbor, entries)
}

func beginPluginNetTransaction(db *sql.DB, pluginID, kind string, entries []pluginNetTransactionEntry) (*store.PluginNetTransaction, error) {
	if db == nil {
		return nil, fmt.Errorf("plugin network transaction journal is unavailable")
	}
	transactionID, err := newPluginNetTransactionID()
	if err != nil {
		return nil, err
	}
	state, err := json.Marshal(pluginNetTransactionState{Version: pluginNetTransactionJournalVersion, BootID: pluginOwnershipBootID, Entries: entries})
	if err != nil {
		return nil, err
	}
	if len(state) == 0 || len(state) > pluginNetTransactionStateMaxBytes {
		return nil, fmt.Errorf("plugin network transaction state size %d exceeds limit %d", len(state), pluginNetTransactionStateMaxBytes)
	}
	record := &store.PluginNetTransaction{
		TransactionID: transactionID,
		PluginID:      pluginID,
		Kind:          kind,
		StateJSON:     string(state),
	}
	if err := store.AddPluginNetTransaction(db, *record); err != nil {
		return nil, err
	}
	return record, nil
}

func newPluginNetTransactionID() (string, error) {
	raw := make([]byte, 16)
	if _, err := cryptorand.Read(raw); err != nil {
		return "", fmt.Errorf("generate plugin network transaction id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func markPluginNetTransactionStarted(db *sql.DB, record *store.PluginNetTransaction, count int) error {
	if record == nil || count < 1 {
		return fmt.Errorf("plugin network transaction journal is invalid")
	}
	if err := store.UpdatePluginNetTransactionStarted(db, record.TransactionID, count); err != nil {
		return err
	}
	record.StartedCount = count
	return nil
}

func completePluginNetTransaction(db *sql.DB, record *store.PluginNetTransaction) error {
	if record == nil {
		return fmt.Errorf("plugin network transaction journal is invalid")
	}
	return store.DeletePluginNetTransaction(db, record.TransactionID)
}

func recoverPendingPluginNetTransactions(db *sql.DB, admin pluginControlNetAdmin) error {
	return recoverPluginNetTransactionsForResources(db, admin, nil, "")
}

func recoverPluginNetTransactionsForResources(db *sql.DB, admin pluginControlNetAdmin, refs []pluginOwnedResourceRef, pluginID string) error {
	if db == nil {
		return nil
	}
	// Recovery walks overlapping snapshots in reverse order. Two concurrent
	// walks must not interleave an older restore with a newer failed restore.
	unlockRecovery := lockPluginNetResources(db, []pluginOwnedResourceRef{{"net-recovery", "journals"}})
	defer unlockRecovery()
	records, err := store.GetPluginNetTransactions(db)
	if err != nil {
		return err
	}
	failures := make([]string, 0)
	blocked := make(map[string]bool)
	blockedKinds := make(map[string]bool)
	if len(refs) > 0 {
		// Include overlapping journals transitively. Otherwise retrying X in a
		// journal containing X/Y could bypass a newer failed journal for Y.
		selected := make(map[string]bool)
		for changed := true; changed; {
			changed = false
			for _, record := range records {
				if selected[record.TransactionID] || !pluginNetTransactionTouches(record, refs) {
					continue
				}
				selected[record.TransactionID], changed = true, true
				if state, err := decodePluginNetTransactionState(&record); err == nil {
					for _, entry := range state.Entries {
						refs = append(refs, pluginOwnedResourceRef{entry.ResourceType, entry.ResourceKey})
					}
				}
			}
		}
	}
	// Undo newer snapshots first. If a newer entry cannot be recovered, its
	// older snapshots must wait; unrelated entries can still make progress.
	for i := len(records) - 1; i >= 0; i-- {
		record := records[i]
		if pluginID != "" && record.PluginID != pluginID {
			continue
		}
		if len(refs) > 0 && !pluginNetTransactionTouches(record, refs) {
			continue
		}
		scope := record.PluginID + "\x00" + record.Kind
		if blockedKinds[scope] {
			failures = append(failures, record.TransactionID+": newer journal is invalid")
			continue
		}
		if _, err := decodePluginNetTransactionState(&record); err != nil && record.StartedCount != 0 {
			blockedKinds[scope] = true
			failures = append(failures, record.TransactionID+": "+err.Error())
			continue
		}
		if err := rollbackPendingPluginNetTransactionWithBlocked(db, admin, &record, blocked); err != nil {
			failures = append(failures, record.TransactionID+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("recover plugin network transactions: %s", strings.Join(failures, "; "))
	}
	return nil
}

func rollbackPendingPluginNetTransactionWithBlocked(db *sql.DB, admin pluginControlNetAdmin, record *store.PluginNetTransaction, blocked map[string]bool) error {
	if record == nil {
		return fmt.Errorf("plugin network transaction recovery is unavailable")
	}
	// Even an unstarted journal belongs to an in-flight operation until its
	// slot locks are released. Never delete it before acquiring those locks.
	state, err := decodePluginNetTransactionState(record)
	if err != nil && record.StartedCount != 0 {
		return err
	}
	refs := pluginNetTransactionRefs(state)
	unlock := lockPluginNetResources(db, refs)
	defer unlock()
	return rollbackPendingPluginNetTransactionLocked(db, admin, record, blocked)
}

// Caller holds the resource locks, including when rolling back an in-flight
// transaction. Re-read durable progress so retries never replay resolved slots.
func rollbackPendingPluginNetTransactionLocked(db *sql.DB, admin pluginControlNetAdmin, record *store.PluginNetTransaction, blocked map[string]bool) error {
	if db == nil || record == nil {
		return fmt.Errorf("plugin network transaction recovery is unavailable")
	}
	current, err := store.PluginNetTransactionOrNil(db, record.TransactionID)
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}
	*record = *current
	if record.StartedCount < 0 {
		return fmt.Errorf("journal started_count %d is invalid", record.StartedCount)
	}
	if record.StartedCount == 0 {
		if err := store.DeletePluginNetTransaction(db, record.TransactionID); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("delete unstarted journal: %w", err)
		}
		return nil
	}
	if admin == nil {
		return fmt.Errorf("plugin network transaction recovery is unavailable")
	}
	state, err := decodePluginNetTransactionState(record)
	if err != nil {
		return err
	}
	failures := make([]string, 0)
	for index := record.StartedCount - 1; index >= 0; index-- {
		entry := state.Entries[index]
		if entry.Resolved {
			continue
		}
		slot := pluginNetResourceSlot(pluginOwnedResourceRef{entry.ResourceType, entry.ResourceKey})
		fail := func(err error) {
			failures = append(failures, fmt.Sprintf("operation %d: %v", index, err))
			if blocked != nil {
				blocked[slot] = true
			}
		}
		if blocked[slot] {
			fail(fmt.Errorf("newer recovery for this slot is still pending"))
			continue
		}
		owned, err := store.PluginOwnedResourceOrNil(db, entry.ResourceType, entry.ResourceKey)
		if err != nil {
			fail(err)
			continue
		}
		// A superseded journal cannot delete or restore the new owner's state.
		superseded := owned != nil && owned.PluginID != record.PluginID
		if owned != nil && !superseded {
			superseded, err = pluginNetTransactionLeaseSuperseded(entry, *owned)
			if err != nil {
				fail(err)
				continue
			}
		}
		if state.Version == 1 && !superseded {
			entry, err = hydrateLegacyPluginNetTransactionIdentity(db, record.PluginID, &state, entry, owned)
			if err != nil {
				fail(err)
				continue
			}
			state.Entries[index] = entry
		}
		stale := state.BootID != "" && pluginOwnershipBootID != "" && state.BootID != pluginOwnershipBootID
		if !superseded && !stale {
			stale, err = pluginNetTransactionLinksChanged(admin, entry)
			if err != nil {
				fail(err)
				continue
			}
		}
		// Name-based policy rules survive link deletion. If the lease still
		// belongs to this generation, remove that exact rule without restoring
		// its old interface selectors onto a newly created interface.
		if stale && !superseded && record.Kind == pluginNetTransactionKindRule && owned != nil &&
			(state.BootID == "" || pluginOwnershipBootID == "" || state.BootID == pluginOwnershipBootID) &&
			pluginNetTransactionOwnsOldGeneration(state, entry, *owned) {
			staleEntry := entry
			staleEntry.RuleOriginal = nil
			if err := restorePluginNetTransactionKernelEntry(admin, record.Kind, staleEntry); err != nil {
				fail(err)
				continue
			}
		}
		if !superseded && !stale {
			if err := restorePluginNetTransactionKernelEntry(admin, record.Kind, entry); err != nil {
				fail(err)
				continue
			}
		}
		state.Entries[index].Resolved = true
		tx, err := db.Begin()
		if err != nil {
			state.Entries[index].Resolved = false
			fail(err)
			continue
		}
		if !superseded && !stale {
			err = restorePluginNetTransactionLeaseInTx(tx, record.PluginID, entry)
		}
		if err == nil && stale && !superseded && owned != nil && pluginNetTransactionOwnsOldGeneration(state, entry, *owned) {
			err = store.DeletePluginOwnedResource(tx, record.PluginID, entry.ResourceType, entry.ResourceKey)
		}
		if err == nil {
			var raw []byte
			raw, err = json.Marshal(state)
			if err == nil {
				err = store.UpdatePluginNetTransactionState(tx, record.TransactionID, string(raw))
			}
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err != nil {
			_ = tx.Rollback()
			state.Entries[index].Resolved = false
			fail(err)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("rollback failed: %s", strings.Join(failures, "; "))
	}
	if err := store.DeletePluginNetTransaction(db, record.TransactionID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("delete recovered journal: %w", err)
	}
	return nil
}

func decodePluginNetTransactionState(record *store.PluginNetTransaction) (pluginNetTransactionState, error) {
	var state pluginNetTransactionState
	decoder := json.NewDecoder(strings.NewReader(record.StateJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, fmt.Errorf("decode journal: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return state, fmt.Errorf("journal contains trailing JSON values")
		}
		return state, fmt.Errorf("decode trailing journal content: %w", err)
	}
	if err := validatePluginNetTransactionState(record, state); err != nil {
		return state, err
	}
	return state, nil
}

func validatePluginNetTransactionState(record *store.PluginNetTransaction, state pluginNetTransactionState) error {
	if (state.Version != 1 && state.Version != pluginNetTransactionJournalVersion) || len(state.Entries) < 1 || len(state.Entries) > pluginControlNetBatchMaxOperations {
		return fmt.Errorf("journal shape is invalid")
	}
	if strings.TrimSpace(record.PluginID) == "" || record.StartedCount > len(state.Entries) {
		return fmt.Errorf("journal identity or started_count %d is invalid", record.StartedCount)
	}
	for index, entry := range state.Entries {
		if err := validatePluginNetTransactionEntry(record, entry); err != nil {
			return fmt.Errorf("journal operation %d: %w", index, err)
		}
	}
	return nil
}

func validatePluginNetTransactionEntry(record *store.PluginNetTransaction, entry pluginNetTransactionEntry) error {
	if entry.ResourceKey == "" {
		return fmt.Errorf("resource key is missing")
	}
	if entry.LeaseBefore.Exists {
		if entry.LeaseBefore.PluginID != record.PluginID || strings.TrimSpace(entry.LeaseBefore.MetadataJSON) == "" || !json.Valid([]byte(entry.LeaseBefore.MetadataJSON)) {
			return fmt.Errorf("previous lease snapshot is invalid")
		}
	} else if entry.LeaseBefore.PluginID != "" || entry.LeaseBefore.MetadataJSON != "" {
		return fmt.Errorf("absent lease snapshot contains state")
	}

	var expectedKey string
	switch record.Kind {
	case pluginNetTransactionKindRoute:
		if entry.RouteRequest == nil || entry.RuleRequest != nil || entry.NeighRequest != nil || entry.ResourceType != pluginOwnedResourceTypeRoute {
			return fmt.Errorf("route journal entry is invalid")
		}
		normalized, err := validatePluginControlRouteRequest(*entry.RouteRequest)
		if err != nil {
			return fmt.Errorf("route request is invalid: %w", err)
		}
		expectedKey = pluginControlNetRouteLeaseKey(normalized)
		for _, original := range entry.RouteOriginal {
			originalRequest, err := pluginControlNetRouteRequestForState(original)
			if err != nil {
				return fmt.Errorf("original route is invalid: %w", err)
			}
			originalKey := pluginControlNetRouteLeaseKey(originalRequest)
			if originalKey != expectedKey {
				return fmt.Errorf("original route belongs to a different slot")
			}
		}
	case pluginNetTransactionKindRule:
		if entry.RuleRequest == nil || entry.RouteRequest != nil || entry.NeighRequest != nil || entry.ResourceType != pluginOwnedResourceTypeRule {
			return fmt.Errorf("rule journal entry is invalid")
		}
		if _, err := normalizePluginControlRuleRequest(*entry.RuleRequest); err != nil {
			return fmt.Errorf("policy rule request is invalid: %w", err)
		}
		expectedKey = pluginControlNetRuleLeaseKey(*entry.RuleRequest)
		for _, original := range entry.RuleOriginal {
			if pluginControlNetRuleLeaseKey(original.Request) != expectedKey {
				return fmt.Errorf("original policy rule belongs to a different slot")
			}
		}
	case pluginNetTransactionKindNeighbor:
		if entry.NeighRequest == nil || entry.RouteRequest != nil || entry.RuleRequest != nil || entry.ResourceType != pluginOwnedResourceTypeNeighbor {
			return fmt.Errorf("neighbor journal entry is invalid")
		}
		if _, err := normalizePluginControlNeighRequest(*entry.NeighRequest, entry.Present); err != nil {
			return fmt.Errorf("neighbor request is invalid: %w", err)
		}
		expectedKey = pluginControlNetNeighLeaseKey(*entry.NeighRequest)
		for _, original := range entry.NeighOriginal {
			if pluginControlNetNeighLeaseKey(original.Request) != expectedKey {
				return fmt.Errorf("original neighbor belongs to a different slot")
			}
		}
	default:
		return fmt.Errorf("unsupported journal kind %q", record.Kind)
	}
	if entry.ResourceKey != expectedKey {
		return fmt.Errorf("resource key %q does not match request key %q", entry.ResourceKey, expectedKey)
	}
	return nil
}

func restorePluginNetTransactionKernelEntry(admin pluginControlNetAdmin, kind string, entry pluginNetTransactionEntry) error {
	failures := make([]string, 0, 2)
	namespace := pluginNetTransactionEntryNamespace(entry)
	scoped, currentNamespace, err := pluginControlNetAdminForOwnedNamespace(admin, namespace, entry.NamespaceIdentity)
	if err != nil || !currentNamespace {
		return err
	}
	admin = scoped
	switch kind {
	case pluginNetTransactionKindRoute:
		if entry.RouteRequest == nil || entry.RuleRequest != nil || entry.NeighRequest != nil || entry.ResourceType != pluginOwnedResourceTypeRoute {
			return fmt.Errorf("route journal entry is invalid")
		}
		if entry.Present {
			entry.RouteRequest.expectedLinkIndices = pluginNetTransactionLinkIndices(entry.LinkIdentities)
			if err := admin.RouteDelete(*entry.RouteRequest); err != nil {
				return fmt.Errorf("delete intended route: %w", err)
			}
		}
		originals, err := pluginNetRecoverableRouteStates(admin, entry.RouteOriginal)
		if err != nil {
			return err
		}
		if err := admin.RouteRestore(originals); err != nil {
			failures = append(failures, "restore original route: "+err.Error())
		}
	case pluginNetTransactionKindRule:
		if entry.RuleRequest == nil || entry.RouteRequest != nil || entry.NeighRequest != nil || entry.ResourceType != pluginOwnedResourceTypeRule {
			return fmt.Errorf("rule journal entry is invalid")
		}
		if entry.Present {
			if err := admin.RuleDelete(*entry.RuleRequest); err != nil {
				return fmt.Errorf("delete intended rule: %w", err)
			}
		}
		if err := admin.RuleRestore(entry.RuleOriginal); err != nil {
			failures = append(failures, "restore original rule: "+err.Error())
		}
	case pluginNetTransactionKindNeighbor:
		if entry.NeighRequest == nil || entry.RouteRequest != nil || entry.RuleRequest != nil || entry.ResourceType != pluginOwnedResourceTypeNeighbor {
			return fmt.Errorf("neighbor journal entry is invalid")
		}
		if entry.Present {
			entry.NeighRequest.expectedIfIndex = pluginNetTransactionLinkIndices(entry.LinkIdentities)[entry.NeighRequest.Interface]
			if err := admin.NeighDelete(*entry.NeighRequest); err != nil {
				return fmt.Errorf("delete intended neighbor: %w", err)
			}
		}
		if err := admin.NeighRestore(entry.NeighOriginal); err != nil {
			failures = append(failures, "restore original neighbor: "+err.Error())
		}
	default:
		return fmt.Errorf("unsupported journal kind %q", kind)
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func pluginNetTransactionEntryNamespace(entry pluginNetTransactionEntry) string {
	if entry.RouteRequest != nil {
		return entry.RouteRequest.Namespace
	}
	if entry.RuleRequest != nil {
		return entry.RuleRequest.Namespace
	}
	if entry.NeighRequest != nil {
		return entry.NeighRequest.Namespace
	}
	return "host"
}

func restorePluginNetTransactionLeaseInTx(tx *sql.Tx, pluginID string, entry pluginNetTransactionEntry) error {
	current, err := store.PluginOwnedResourceOrNil(tx, entry.ResourceType, entry.ResourceKey)
	if err != nil {
		return err
	}
	if current != nil && current.PluginID != pluginID {
		return fmt.Errorf("lease is now owned by plugin %s", current.PluginID)
	}
	if entry.LeaseBefore.Exists {
		if entry.LeaseBefore.PluginID != pluginID || strings.TrimSpace(entry.LeaseBefore.MetadataJSON) == "" {
			return fmt.Errorf("previous lease snapshot is invalid")
		}
		if current == nil {
			err = store.AddPluginOwnedResource(tx, store.PluginOwnedResource{
				PluginID: pluginID, ResourceType: entry.ResourceType, ResourceKey: entry.ResourceKey, MetadataJSON: entry.LeaseBefore.MetadataJSON,
			})
		} else {
			err = store.UpdatePluginOwnedResource(tx, pluginID, entry.ResourceType, entry.ResourceKey, entry.LeaseBefore.MetadataJSON)
		}
	} else if current != nil {
		err = store.DeletePluginOwnedResource(tx, pluginID, entry.ResourceType, entry.ResourceKey)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func pluginNetTransactionRefs(state pluginNetTransactionState) []pluginOwnedResourceRef {
	refs := make([]pluginOwnedResourceRef, 0, len(state.Entries))
	for _, entry := range state.Entries {
		refs = append(refs, pluginOwnedResourceRef{entry.ResourceType, entry.ResourceKey})
		refs = append(refs, pluginNetTransactionLinkRefs(entry)...)
	}
	return refs
}

func pluginNetTransactionLinkRefs(entry pluginNetTransactionEntry) []pluginOwnedResourceRef {
	namespace := pluginNetTransactionEntryNamespace(entry)
	var refs []pluginOwnedResourceRef
	if namespace != "host" {
		refs = append(refs, pluginOwnedResourceRef{pluginOwnedResourceTypeNamespace, namespace})
	}
	for _, name := range pluginNetTransactionInterfaceNames(entry) {
		refs = append(refs, pluginOwnedResourceRef{pluginOwnedResourceTypeLink, pluginControlNetScopedResourceKey(namespace, name)})
	}
	return refs
}

func pluginNetTransactionInterfaceNames(entry pluginNetTransactionEntry) []string {
	names := make(map[string]bool)
	add := func(name string) {
		if name != "" {
			names[name] = true
		}
	}
	if req := entry.RouteRequest; req != nil {
		for _, name := range pluginControlNetRouteInterfaces(*req) {
			add(name)
		}
	}
	if req := entry.RuleRequest; req != nil {
		add(req.IIF)
		add(req.OIF)
	}
	if req := entry.NeighRequest; req != nil {
		add(req.Interface)
	}
	var ordered []string
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	return ordered
}

func pluginNetTransactionTouches(record store.PluginNetTransaction, refs []pluginOwnedResourceRef) bool {
	state, err := decodePluginNetTransactionState(&record)
	if err != nil {
		return true
	}
	for _, entry := range state.Entries {
		if entry.Resolved {
			continue
		}
		for _, ref := range refs {
			if ref.ResourceType == entry.ResourceType && ref.ResourceKey == entry.ResourceKey {
				return true
			}
			for _, link := range pluginNetTransactionLinkRefs(entry) {
				if ref == link {
					return true
				}
			}
		}
	}
	return false
}

func checkPendingPluginNetResources(db *sql.DB, pluginID string, refs []pluginOwnedResourceRef) error {
	if db == nil {
		return fmt.Errorf("plugin ownership store is unavailable")
	}
	records, err := store.GetPluginNetTransactions(db)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.StartedCount == 0 {
			continue
		}
		state, err := decodePluginNetTransactionState(&record)
		if err != nil {
			if record.PluginID == pluginID {
				return fmt.Errorf("network recovery journal %s is invalid: %w", record.TransactionID, err)
			}
			continue
		}
		for _, entry := range state.Entries[:record.StartedCount] {
			if entry.Resolved {
				continue
			}
			for _, ref := range refs {
				if ref.ResourceType == entry.ResourceType && ref.ResourceKey == entry.ResourceKey {
					return fmt.Errorf("%s slot %s has pending recovery %s", ref.ResourceType, ref.ResourceKey, record.TransactionID)
				}
				if ref.ResourceType == pluginOwnedResourceTypeLink || ref.ResourceType == pluginOwnedResourceTypeNamespace {
					for _, dependency := range pluginNetTransactionLinkRefs(entry) {
						if ref == dependency {
							return fmt.Errorf("interface %s has pending network recovery %s", ref.ResourceKey, record.TransactionID)
						}
					}
				}
			}
		}
	}
	return nil
}

func capturePluginNetTransactionLinks(admin pluginControlNetAdmin, entry pluginNetTransactionEntry) ([]pluginNetTransactionLinkIdentity, error) {
	ordered := pluginNetTransactionInterfaceNames(entry)
	links := make([]pluginNetTransactionLinkIdentity, 0, len(ordered))
	for _, name := range ordered {
		link, err := admin.LinkGet(name)
		if err != nil {
			return nil, fmt.Errorf("inspect transaction interface %s: %w", name, err)
		}
		links = append(links, pluginNetTransactionLinkIdentity{Name: name, IfIndex: link.IfIndex, Kind: link.Kind, MAC: link.MAC})
	}
	return links, nil
}

func pluginNetTransactionLinksChanged(admin pluginControlNetAdmin, entry pluginNetTransactionEntry) (bool, error) {
	scoped, present, err := pluginControlNetAdminForOwnedNamespace(admin, pluginNetTransactionEntryNamespace(entry), entry.NamespaceIdentity)
	if err != nil || !present {
		return !present, err
	}
	for _, expected := range entry.LinkIdentities {
		current, present, err := scoped.LinkLookup(expected.Name)
		if err != nil {
			return false, err
		}
		if !present || !pluginOwnedLinkIdentityMatches(current, expected.IfIndex, expected.Kind, expected.MAC) {
			return true, nil
		}
	}
	return false, nil
}

func (h *pluginControlHost) validatePluginNetTransactionLinks(namespaceID pluginControlNetNamespaceIdentity, namespace string, links []pluginNetTransactionLinkIdentity) error {
	// Namespace identity and link identity are stable across carrier/MTU/IP
	// changes, but never across deletion and recreation of the same name.
	entry := pluginNetTransactionEntry{NamespaceIdentity: namespaceID, LinkIdentities: links, RouteRequest: &pluginControlNetRouteRequest{Namespace: namespace}}
	changed, err := pluginNetTransactionLinksChanged(h.netAdmin, entry)
	if err != nil {
		return err
	}
	if changed {
		return fmt.Errorf("network interface or namespace changed during transaction")
	}
	return nil
}

func pluginNetTransactionLinkIndices(links []pluginNetTransactionLinkIdentity) map[string]int {
	indices := make(map[string]int, len(links))
	for _, link := range links {
		indices[link.Name] = link.IfIndex
	}
	return indices
}

func pluginNetTransactionOwnsOldGeneration(state pluginNetTransactionState, entry pluginNetTransactionEntry, owned store.PluginOwnedResource) bool {
	var metadata struct {
		BootID         string                         `json:"boot_id"`
		DevIfIndex     int                            `json:"dev_ifindex"`
		LinkIdentities []pluginOwnedRouteLinkIdentity `json:"link_identities"`
	}
	if json.Unmarshal([]byte(owned.MetadataJSON), &metadata) != nil {
		return false
	}
	if state.BootID != "" && metadata.BootID != state.BootID {
		return false
	}
	for _, old := range entry.LinkIdentities {
		if metadata.DevIfIndex > 0 && metadata.DevIfIndex != old.IfIndex {
			return false
		}
		for _, current := range metadata.LinkIdentities {
			if current.Dev == old.Name && (current.IfIndex != old.IfIndex ||
				(current.Kind != "" && old.Kind != "" && current.Kind != old.Kind) ||
				(current.MAC != "" && old.MAC != "" && !strings.EqualFold(current.MAC, old.MAC))) {
				return false
			}
		}
	}
	return true
}

func capturePluginNetLeaseSnapshot(db *sql.DB, pluginID, resourceType, resourceKey string, metadata any) (pluginNetLeaseSnapshot, error) {
	if db == nil {
		return pluginNetLeaseSnapshot{}, fmt.Errorf("plugin ownership store is unavailable")
	}
	owned, err := store.PluginOwnedResourceOrNil(db, resourceType, resourceKey)
	if err != nil || owned == nil {
		return pluginNetLeaseSnapshot{}, err
	}
	if owned.PluginID != pluginID {
		return pluginNetLeaseSnapshot{}, fmt.Errorf("%s slot %s is owned by plugin %s", resourceType, resourceKey, owned.PluginID)
	}
	if err := json.Unmarshal([]byte(owned.MetadataJSON), metadata); err != nil {
		return pluginNetLeaseSnapshot{}, fmt.Errorf("decode %s ownership metadata: %w", resourceType, err)
	}
	return pluginNetLeaseSnapshot{Exists: true, PluginID: owned.PluginID, MetadataJSON: owned.MetadataJSON}, nil
}

// Link removal deletes its routes in the kernel. A stale snapshot must not
// recreate those routes using a new device that happens to reuse the name.
func pluginNetRecoverableRouteStates(admin pluginControlNetAdmin, states []pluginControlNetRouteState) ([]pluginControlNetRouteState, error) {
	var eligible []pluginControlNetRouteState
	for _, state := range states {
		identities := make(map[string]int)
		if state.Dev != "" {
			identities[state.Dev] = state.DevIfIndex
		}
		for _, hop := range state.Nexthops {
			identities[hop.Dev] = hop.DevIfIndex
		}
		valid := true
		for name, index := range identities {
			current, present, err := admin.LinkLookup(name)
			if err != nil {
				return nil, err
			}
			// Legacy snapshots without an index are still handled by RouteRestore.
			if index > 0 && (!present || current.IfIndex != index) {
				valid = false
				break
			}
		}
		if valid {
			eligible = append(eligible, state)
		}
	}
	return eligible, nil
}

// Legacy journals lacked device identities. Recover only when the existing
// lease or owned link still supplies that identity; guessing from today's
// interface name would allow an old journal to mutate a replacement device.
func hydrateLegacyPluginNetTransactionIdentity(db *sql.DB, pluginID string, state *pluginNetTransactionState, entry pluginNetTransactionEntry, owned *store.PluginOwnedResource) (pluginNetTransactionEntry, error) {
	var metadata struct {
		BootID         string                         `json:"boot_id"`
		DevIfIndex     int                            `json:"dev_ifindex"`
		LinkIdentities []pluginOwnedRouteLinkIdentity `json:"link_identities"`
	}
	if owned != nil {
		if err := json.Unmarshal([]byte(owned.MetadataJSON), &metadata); err != nil {
			return entry, err
		}
	}
	if state.BootID == "" {
		state.BootID = metadata.BootID
	}
	if state.BootID != "" && pluginOwnershipBootID != "" && state.BootID != pluginOwnershipBootID {
		return entry, nil
	}
	if len(entry.LinkIdentities) > 0 {
		return entry, nil
	}
	names := pluginNetTransactionInterfaceNames(entry)
	for _, name := range names {
		identity := pluginNetTransactionLinkIdentity{Name: name}
		for _, known := range metadata.LinkIdentities {
			if known.Dev == name {
				identity.IfIndex, identity.Kind, identity.MAC = known.IfIndex, known.Kind, known.MAC
			}
		}
		if identity.IfIndex == 0 && len(names) == 1 {
			identity.IfIndex = metadata.DevIfIndex
		}
		if identity.IfIndex == 0 {
			link, err := store.PluginOwnedResourceOrNil(db, pluginOwnedResourceTypeLink, pluginControlNetScopedResourceKey(pluginNetTransactionEntryNamespace(entry), name))
			if err != nil {
				return entry, err
			}
			if link != nil && link.PluginID == pluginID {
				var claim pluginOwnedLinkClaim
				if err := json.Unmarshal([]byte(link.MetadataJSON), &claim); err != nil {
					return entry, err
				}
				identity.IfIndex, identity.Kind, identity.MAC = claim.IfIndex, claim.Kind, claim.MAC
				if state.BootID == "" {
					state.BootID = claim.BootID
				}
			}
		}
		if identity.IfIndex == 0 {
			return entry, fmt.Errorf("legacy recovery lacks recorded identity for interface %s", name)
		}
		entry.LinkIdentities = append(entry.LinkIdentities, identity)
	}
	if state.BootID == "" && pluginOwnershipBootID != "" {
		return entry, fmt.Errorf("legacy recovery lacks a recorded boot identity")
	}
	return entry, nil
}

func pluginNetTransactionLeaseSuperseded(entry pluginNetTransactionEntry, owned store.PluginOwnedResource) (bool, error) {
	if entry.LeaseBefore.Exists && entry.LeaseBefore.MetadataJSON == owned.MetadataJSON {
		return false, nil
	}
	var metadata struct {
		Current        json.RawMessage                `json:"current"`
		Present        bool                           `json:"current_present"`
		DevIfIndex     int                            `json:"dev_ifindex"`
		LinkIdentities []pluginOwnedRouteLinkIdentity `json:"link_identities"`
	}
	if err := json.Unmarshal([]byte(owned.MetadataJSON), &metadata); err != nil {
		return false, err
	}
	for _, old := range entry.LinkIdentities {
		if metadata.DevIfIndex > 0 && metadata.DevIfIndex != old.IfIndex {
			return true, nil
		}
		for _, current := range metadata.LinkIdentities {
			if current.Dev == old.Name && (current.IfIndex != old.IfIndex || (current.Kind != "" && old.Kind != "" && current.Kind != old.Kind) || (current.MAC != "" && old.MAC != "" && !strings.EqualFold(current.MAC, old.MAC))) {
				return true, nil
			}
		}
	}
	if len(metadata.Current) == 0 || string(metadata.Current) == "null" {
		return false, nil
	}
	if metadata.Present != entry.Present {
		return true, nil
	}
	var current, expected any
	switch {
	case entry.RouteRequest != nil:
		var req pluginControlNetRouteRequest
		if err := json.Unmarshal(metadata.Current, &req); err != nil {
			return false, err
		}
		current, expected = normalizePluginControlRouteRequest(req), normalizePluginControlRouteRequest(*entry.RouteRequest)
	case entry.RuleRequest != nil:
		var req pluginControlNetRuleRequest
		if err := json.Unmarshal(metadata.Current, &req); err != nil {
			return false, err
		}
		normalized, err := normalizePluginControlRuleRequest(req)
		if err != nil {
			return false, err
		}
		current = normalized
		expected, _ = normalizePluginControlRuleRequest(*entry.RuleRequest)
	case entry.NeighRequest != nil:
		var req pluginControlNetNeighRequest
		if err := json.Unmarshal(metadata.Current, &req); err != nil {
			return false, err
		}
		normalized, err := normalizePluginControlNeighRequest(req, false)
		if err != nil {
			return false, err
		}
		current = normalized
		expected, _ = normalizePluginControlNeighRequest(*entry.NeighRequest, false)
	}
	actualJSON, err := json.Marshal(current)
	if err != nil {
		return false, err
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		return false, err
	}
	return string(actualJSON) != string(expectedJSON), nil
}
