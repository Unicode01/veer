package app

import (
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Unicode01/veer/internal/store"
)

const (
	pluginNetTransactionJournalVersion = 1
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
	Entries []pluginNetTransactionEntry `json:"entries"`
}

type pluginNetTransactionEntry struct {
	Present           bool                              `json:"present"`
	ResourceType      string                            `json:"resource_type"`
	ResourceKey       string                            `json:"resource_key"`
	LeaseBefore       pluginNetLeaseSnapshot            `json:"lease_before"`
	NamespaceIdentity pluginControlNetNamespaceIdentity `json:"namespace_identity,omitempty"`

	RouteRequest  *pluginControlNetRouteRequest `json:"route_request,omitempty"`
	RouteOriginal []pluginControlNetRouteState  `json:"route_original,omitempty"`
	RuleRequest   *pluginControlNetRuleRequest  `json:"rule_request,omitempty"`
	RuleOriginal  []pluginControlNetRuleState   `json:"rule_original,omitempty"`
	NeighRequest  *pluginControlNetNeighRequest `json:"neigh_request,omitempty"`
	NeighOriginal []pluginControlNetNeighState  `json:"neigh_original,omitempty"`
}

func beginPluginRouteNetTransaction(db *sql.DB, pluginID string, items []pluginControlNetRouteBatchItem) (*store.PluginNetTransaction, error) {
	entries := make([]pluginNetTransactionEntry, 0, len(items))
	for _, item := range items {
		request := item.request
		entries = append(entries, pluginNetTransactionEntry{
			Present: item.present, ResourceType: pluginOwnedResourceTypeRoute,
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
			Present: item.present, ResourceType: pluginOwnedResourceTypeRule,
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
			Present: item.present, ResourceType: pluginOwnedResourceTypeNeighbor,
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
	state, err := json.Marshal(pluginNetTransactionState{Version: pluginNetTransactionJournalVersion, Entries: entries})
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

func finishPluginNetTransactionAfterRollback(db *sql.DB, record *store.PluginNetTransaction, rollbackErr error) error {
	if rollbackErr != nil {
		return rollbackErr
	}
	if err := completePluginNetTransaction(db, record); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("delete recovery journal after rollback: %w", err)
	}
	return nil
}

func recoverPendingPluginNetTransactions(db *sql.DB, admin pluginControlNetAdmin) error {
	if db == nil {
		return nil
	}
	records, err := store.GetPluginNetTransactions(db)
	if err != nil {
		return err
	}
	failures := make([]string, 0)
	for _, record := range records {
		if err := rollbackPendingPluginNetTransaction(db, admin, &record); err != nil {
			failures = append(failures, record.TransactionID+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("recover plugin network transactions: %s", strings.Join(failures, "; "))
	}
	return nil
}

func rollbackPendingPluginNetTransaction(db *sql.DB, admin pluginControlNetAdmin, record *store.PluginNetTransaction) error {
	if db == nil || record == nil {
		return fmt.Errorf("plugin network transaction recovery is unavailable")
	}
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
	var state pluginNetTransactionState
	decoder := json.NewDecoder(strings.NewReader(record.StateJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("decode journal: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("journal contains trailing JSON values")
		}
		return fmt.Errorf("decode trailing journal content: %w", err)
	}
	if err := validatePluginNetTransactionState(record, state); err != nil {
		return err
	}
	failures := make([]string, 0)
	for index := record.StartedCount - 1; index >= 0; index-- {
		entry := state.Entries[index]
		if err := restorePluginNetTransactionKernelEntry(admin, record.Kind, entry); err != nil {
			failures = append(failures, fmt.Sprintf("operation %d kernel: %v", index, err))
		}
		if err := restorePluginNetTransactionLease(db, record.PluginID, entry); err != nil {
			failures = append(failures, fmt.Sprintf("operation %d lease: %v", index, err))
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

func validatePluginNetTransactionState(record *store.PluginNetTransaction, state pluginNetTransactionState) error {
	if state.Version != pluginNetTransactionJournalVersion || len(state.Entries) < 1 || len(state.Entries) > pluginControlNetBatchMaxOperations {
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
			if err := admin.RouteDelete(*entry.RouteRequest); err != nil {
				failures = append(failures, "delete intended route: "+err.Error())
			}
		}
		if err := admin.RouteRestore(entry.RouteOriginal); err != nil {
			failures = append(failures, "restore original route: "+err.Error())
		}
	case pluginNetTransactionKindRule:
		if entry.RuleRequest == nil || entry.RouteRequest != nil || entry.NeighRequest != nil || entry.ResourceType != pluginOwnedResourceTypeRule {
			return fmt.Errorf("rule journal entry is invalid")
		}
		if entry.Present {
			if err := admin.RuleDelete(*entry.RuleRequest); err != nil {
				failures = append(failures, "delete intended rule: "+err.Error())
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
			if err := admin.NeighDelete(*entry.NeighRequest); err != nil {
				failures = append(failures, "delete intended neighbor: "+err.Error())
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

func restorePluginNetTransactionLease(db *sql.DB, pluginID string, entry pluginNetTransactionEntry) error {
	if entry.ResourceKey == "" || entry.ResourceType == "" {
		return fmt.Errorf("lease identity is missing")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
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
	return tx.Commit()
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
