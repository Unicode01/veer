package app

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/dop251/goja"
)

const pluginControlNetBatchMaxOperations = 128

type pluginControlNetBatchValue struct {
	operation string
	request   goja.Value
}

type pluginControlNetRouteBatchItem struct {
	request     pluginControlNetRouteRequest
	namespaceID pluginControlNetNamespaceIdentity
	present     bool
	original    []pluginControlNetRouteState
	identities  []pluginOwnedRouteLinkIdentity
	leaseBefore pluginNetLeaseSnapshot
}

type pluginControlNetRuleBatchItem struct {
	request     pluginControlNetRuleRequest
	namespaceID pluginControlNetNamespaceIdentity
	present     bool
	original    []pluginControlNetRuleState
	leaseBefore pluginNetLeaseSnapshot
}

type pluginControlNetNeighBatchItem struct {
	request     pluginControlNetNeighRequest
	namespaceID pluginControlNetNamespaceIdentity
	present     bool
	original    []pluginControlNetNeighState
	ifIndex     int
	leaseBefore pluginNetLeaseSnapshot
}

type pluginControlNetRouteBatchJournal struct {
	request  pluginControlNetRouteRequest
	present  bool
	original []pluginControlNetRouteState
	previous pluginOwnedRouteMutation
	created  bool
	leased   bool
}

type pluginControlNetRuleBatchJournal struct {
	request  pluginControlNetRuleRequest
	present  bool
	previous pluginOwnedRuleMutation
	created  bool
}

type pluginControlNetNeighBatchJournal struct {
	request  pluginControlNetNeighRequest
	present  bool
	original []pluginControlNetNeighState
	previous pluginOwnedNeighMutation
	created  bool
	leased   bool
}

func (h *pluginControlHost) netRouteTransaction(call goja.FunctionCall) goja.Value {
	values := h.netBatchValues(call, "net.route.transaction")
	items := make([]pluginControlNetRouteBatchItem, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		req := h.netRouteRequest(goja.FunctionCall{Arguments: []goja.Value{value.request}}, "net.route.transaction")
		h.requireRouteNetAccess(req, "net.route.transaction")
		key := pluginControlNetRouteLeaseKey(req)
		if _, duplicate := seen[key]; duplicate {
			h.throwf("net.route.transaction: duplicate route slot %s", key)
		}
		seen[key] = struct{}{}
		items = append(items, pluginControlNetRouteBatchItem{request: req, present: value.operation == "replace"})
	}
	namespace := pluginControlNetRouteBatchNamespace(h, items, "net.route.transaction")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.route.transaction")
	namespaceID, err := h.pluginControlNamespaceIdentity(namespace)
	if err != nil {
		h.throwf("net.route.transaction: inspect namespace identity: %v", err)
	}
	for i := range items {
		item := &items[i]
		item.namespaceID = namespaceID
		var err error
		item.identities, err = h.pluginRouteLinkIdentities(admin, item.request, "net.route.transaction")
		if err != nil {
			h.throwf("net.route.transaction: %v", err)
		}
		var metadata pluginOwnedRouteMutation
		item.leaseBefore, err = capturePluginNetLeaseSnapshot(h.db, h.plugin.ID, pluginOwnedResourceTypeRoute, pluginControlNetRouteLeaseKey(item.request), &metadata)
		if err != nil {
			h.throwf("net.route.transaction: %v", err)
		}
		item.original, err = admin.RouteSnapshot(item.request)
		if err != nil {
			h.throwf("net.route.transaction: snapshot current route: %v", err)
		}
	}
	persistent, err := beginPluginRouteNetTransaction(h.db, h.plugin.ID, items)
	if err != nil {
		h.throwf("net.route.transaction: create recovery journal: %v", err)
	}

	journal := make([]pluginControlNetRouteBatchJournal, 0, len(items))
	for index, item := range items {
		if err := markPluginNetTransactionStarted(h.db, persistent, index+1); err != nil {
			rollbackErr := h.rollbackPluginRouteBatch(admin, journal)
			rollbackErr = finishPluginNetTransactionAfterRollback(h.db, persistent, rollbackErr)
			h.throwPluginNetMutationError("net.route.transaction", fmt.Errorf("advance recovery journal: %w", err), rollbackErr)
		}
		entry, changed, err := h.applyPluginRouteBatchItem(admin, item)
		if err != nil {
			rollbackErr := h.rollbackPluginRouteBatch(admin, journal)
			rollbackErr = finishPluginNetTransactionAfterRollback(h.db, persistent, rollbackErr)
			h.throwPluginNetMutationError("net.route.transaction", err, rollbackErr)
		}
		if changed {
			journal = append(journal, entry)
		}
	}
	for _, item := range items {
		if err := h.releaseRestoredPluginRouteLease(item.request, item.present); err != nil {
			rollbackErr := rollbackPendingPluginNetTransaction(h.db, admin, persistent)
			h.throwPluginNetMutationError("net.route.transaction", fmt.Errorf("finalize route lease: %w", err), rollbackErr)
		}
	}
	if err := completePluginNetTransaction(h.db, persistent); err != nil {
		rollbackErr := rollbackPendingPluginNetTransaction(h.db, admin, persistent)
		h.throwPluginNetMutationError("net.route.transaction", fmt.Errorf("commit recovery journal: %w", err), rollbackErr)
	}
	return h.vm.ToValue(map[string]any{"status": "completed", "operations": len(items)})
}

func (h *pluginControlHost) netRuleTransaction(call goja.FunctionCall) goja.Value {
	values := h.netBatchValues(call, "net.rule.transaction")
	items := make([]pluginControlNetRuleBatchItem, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		req := h.netRuleRequest(goja.FunctionCall{Arguments: []goja.Value{value.request}}, "net.rule.transaction")
		h.requireRuleNetAccess(req, "net.rule.transaction")
		key := pluginControlNetRuleLeaseKey(req)
		if _, duplicate := seen[key]; duplicate {
			h.throwf("net.rule.transaction: duplicate policy rule slot %s", key)
		}
		seen[key] = struct{}{}
		items = append(items, pluginControlNetRuleBatchItem{request: req, present: value.operation == "replace"})
	}
	namespace := pluginControlNetRuleBatchNamespace(h, items, "net.rule.transaction")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.rule.transaction")
	namespaceID, err := h.pluginControlNamespaceIdentity(namespace)
	if err != nil {
		h.throwf("net.rule.transaction: inspect namespace identity: %v", err)
	}
	for i := range items {
		item := &items[i]
		item.namespaceID = namespaceID
		var metadata pluginOwnedRuleMutation
		var err error
		item.leaseBefore, err = capturePluginNetLeaseSnapshot(h.db, h.plugin.ID, pluginOwnedResourceTypeRule, pluginControlNetRuleLeaseKey(item.request), &metadata)
		if err != nil {
			h.throwf("net.rule.transaction: %v", err)
		}
		item.original, err = admin.RuleSnapshot(item.request)
		if err != nil {
			h.throwf("net.rule.transaction: snapshot current policy rule: %v", err)
		}
	}
	persistent, err := beginPluginRuleNetTransaction(h.db, h.plugin.ID, items)
	if err != nil {
		h.throwf("net.rule.transaction: create recovery journal: %v", err)
	}

	journal := make([]pluginControlNetRuleBatchJournal, 0, len(items))
	for index, item := range items {
		if err := markPluginNetTransactionStarted(h.db, persistent, index+1); err != nil {
			rollbackErr := h.rollbackPluginRuleBatch(admin, journal)
			rollbackErr = finishPluginNetTransactionAfterRollback(h.db, persistent, rollbackErr)
			h.throwPluginNetMutationError("net.rule.transaction", fmt.Errorf("advance recovery journal: %w", err), rollbackErr)
		}
		entry, changed, err := h.applyPluginRuleBatchItem(admin, item)
		if err != nil {
			rollbackErr := h.rollbackPluginRuleBatch(admin, journal)
			rollbackErr = finishPluginNetTransactionAfterRollback(h.db, persistent, rollbackErr)
			h.throwPluginNetMutationError("net.rule.transaction", err, rollbackErr)
		}
		if changed {
			journal = append(journal, entry)
		}
	}
	for _, item := range items {
		if err := h.releaseRestoredPluginRuleLease(item.request, item.present); err != nil {
			rollbackErr := rollbackPendingPluginNetTransaction(h.db, admin, persistent)
			h.throwPluginNetMutationError("net.rule.transaction", fmt.Errorf("finalize policy rule lease: %w", err), rollbackErr)
		}
	}
	if err := completePluginNetTransaction(h.db, persistent); err != nil {
		rollbackErr := rollbackPendingPluginNetTransaction(h.db, admin, persistent)
		h.throwPluginNetMutationError("net.rule.transaction", fmt.Errorf("commit recovery journal: %w", err), rollbackErr)
	}
	return h.vm.ToValue(map[string]any{"status": "completed", "operations": len(items)})
}

func (h *pluginControlHost) netNeighTransaction(call goja.FunctionCall) goja.Value {
	values := h.netBatchValues(call, "net.neigh.transaction")
	items := make([]pluginControlNetNeighBatchItem, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		present := value.operation == "replace"
		req := h.netNeighRequest(goja.FunctionCall{Arguments: []goja.Value{value.request}}, "net.neigh.transaction", present)
		h.requireNetAccess("neigh.write", req.Interface, "net.neigh.transaction")
		key := pluginControlNetNeighLeaseKey(req)
		if _, duplicate := seen[key]; duplicate {
			h.throwf("net.neigh.transaction: duplicate neighbor slot %s", key)
		}
		seen[key] = struct{}{}
		items = append(items, pluginControlNetNeighBatchItem{request: req, present: present})
	}
	namespace := pluginControlNetNeighBatchNamespace(h, items, "net.neigh.transaction")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.neigh.transaction")
	namespaceID, err := h.pluginControlNamespaceIdentity(namespace)
	if err != nil {
		h.throwf("net.neigh.transaction: inspect namespace identity: %v", err)
	}
	for i := range items {
		item := &items[i]
		item.namespaceID = namespaceID
		dev, err := admin.LinkGet(item.request.Interface)
		if err != nil {
			h.throwf("net.neigh.transaction: inspect neighbor interface %s: %v", item.request.Interface, err)
		}
		if _, err := h.pluginOwnedLinkState(item.request.Namespace, item.request.Interface, "net.neigh.transaction"); err != nil {
			h.throwf("net.neigh.transaction: %v", err)
		}
		var metadata pluginOwnedNeighMutation
		item.leaseBefore, err = capturePluginNetLeaseSnapshot(h.db, h.plugin.ID, pluginOwnedResourceTypeNeighbor, pluginControlNetNeighLeaseKey(item.request), &metadata)
		if err != nil {
			h.throwf("net.neigh.transaction: %v", err)
		}
		item.original, err = admin.NeighSnapshot(item.request)
		if err != nil {
			h.throwf("net.neigh.transaction: snapshot current neighbor: %v", err)
		}
		item.ifIndex = dev.IfIndex
	}
	persistent, err := beginPluginNeighNetTransaction(h.db, h.plugin.ID, items)
	if err != nil {
		h.throwf("net.neigh.transaction: create recovery journal: %v", err)
	}

	journal := make([]pluginControlNetNeighBatchJournal, 0, len(items))
	for index, item := range items {
		if err := markPluginNetTransactionStarted(h.db, persistent, index+1); err != nil {
			rollbackErr := h.rollbackPluginNeighBatch(admin, journal)
			rollbackErr = finishPluginNetTransactionAfterRollback(h.db, persistent, rollbackErr)
			h.throwPluginNetMutationError("net.neigh.transaction", fmt.Errorf("advance recovery journal: %w", err), rollbackErr)
		}
		entry, changed, err := h.applyPluginNeighBatchItem(admin, item)
		if err != nil {
			rollbackErr := h.rollbackPluginNeighBatch(admin, journal)
			rollbackErr = finishPluginNetTransactionAfterRollback(h.db, persistent, rollbackErr)
			h.throwPluginNetMutationError("net.neigh.transaction", err, rollbackErr)
		}
		if changed {
			journal = append(journal, entry)
		}
	}
	for _, item := range items {
		if err := h.releaseRestoredPluginNeighLease(item.request, item.present); err != nil {
			rollbackErr := rollbackPendingPluginNetTransaction(h.db, admin, persistent)
			h.throwPluginNetMutationError("net.neigh.transaction", fmt.Errorf("finalize neighbor lease: %w", err), rollbackErr)
		}
	}
	if err := completePluginNetTransaction(h.db, persistent); err != nil {
		rollbackErr := rollbackPendingPluginNetTransaction(h.db, admin, persistent)
		h.throwPluginNetMutationError("net.neigh.transaction", fmt.Errorf("commit recovery journal: %w", err), rollbackErr)
	}
	return h.vm.ToValue(map[string]any{"status": "completed", "operations": len(items)})
}

func pluginControlNetRouteBatchNamespace(h *pluginControlHost, items []pluginControlNetRouteBatchItem, operation string) string {
	namespaces := make([]string, 0, len(items))
	for _, item := range items {
		namespaces = append(namespaces, item.request.Namespace)
	}
	return h.requireSinglePluginNetBatchNamespace(namespaces, operation)
}

func pluginControlNetRuleBatchNamespace(h *pluginControlHost, items []pluginControlNetRuleBatchItem, operation string) string {
	namespaces := make([]string, 0, len(items))
	for _, item := range items {
		namespaces = append(namespaces, item.request.Namespace)
	}
	return h.requireSinglePluginNetBatchNamespace(namespaces, operation)
}

func pluginControlNetNeighBatchNamespace(h *pluginControlHost, items []pluginControlNetNeighBatchItem, operation string) string {
	namespaces := make([]string, 0, len(items))
	for _, item := range items {
		namespaces = append(namespaces, item.request.Namespace)
	}
	return h.requireSinglePluginNetBatchNamespace(namespaces, operation)
}

func (h *pluginControlHost) requireSinglePluginNetBatchNamespace(namespaces []string, operation string) string {
	selected := "host"
	for index, namespace := range namespaces {
		normalized, err := normalizePluginControlRequestNamespace(namespace)
		if err != nil {
			h.throwf("%s: operation %d: %v", operation, index, err)
		}
		if index == 0 {
			selected = normalized
			continue
		}
		if normalized != selected {
			h.throwf("%s: all operations must target the same namespace", operation)
		}
	}
	return selected
}

func (h *pluginControlHost) netBatchValues(call goja.FunctionCall, operation string) []pluginControlNetBatchValue {
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("%s: operations are required", operation)
	}
	array := call.Arguments[0].ToObject(h.vm)
	if array.ClassName() != "Array" {
		h.throwf("%s: operations must be an array", operation)
	}
	lengthValue := h.objectField(array, "length")
	if goja.IsUndefined(lengthValue) || goja.IsNull(lengthValue) {
		h.throwf("%s: operations must be an array", operation)
	}
	length := int(lengthValue.ToInteger())
	if length < 1 || length > pluginControlNetBatchMaxOperations {
		h.throwf("%s: operation count must be between 1 and %d", operation, pluginControlNetBatchMaxOperations)
	}
	out := make([]pluginControlNetBatchValue, 0, length)
	for i := 0; i < length; i++ {
		value := array.Get(strconv.Itoa(i))
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			h.throwf("%s: operation %d is missing", operation, i)
		}
		item := value.ToObject(h.vm)
		op := strings.ToLower(h.firstStringObjectField(item, "op", "operation"))
		if op != "replace" && op != "delete" {
			h.throwf("%s: operation %d op must be replace or delete", operation, i)
		}
		request := h.objectField(item, "request")
		if goja.IsUndefined(request) || goja.IsNull(request) {
			request = value
		}
		out = append(out, pluginControlNetBatchValue{operation: op, request: request})
	}
	return out
}

func (h *pluginControlHost) applyPluginRouteBatchItem(admin pluginControlNetAdmin, item pluginControlNetRouteBatchItem) (pluginControlNetRouteBatchJournal, bool, error) {
	if !item.present && len(item.original) == 0 {
		return pluginControlNetRouteBatchJournal{}, false, admin.RouteDelete(item.request)
	}
	previous, created, leased, err := h.claimPluginRouteMutation(item.request, item.present, item.original, item.identities)
	if err != nil {
		return pluginControlNetRouteBatchJournal{}, false, err
	}
	entry := pluginControlNetRouteBatchJournal{request: item.request, present: item.present, original: item.original, previous: previous, created: created, leased: leased}
	if item.present {
		err = admin.RouteReplace(item.request)
	} else {
		err = admin.RouteDelete(item.request)
	}
	if err != nil {
		rollbackErr := h.rollbackPluginRouteBatchEntry(admin, entry)
		return pluginControlNetRouteBatchJournal{}, false, combinePluginNetBatchErrors(err, rollbackErr)
	}
	return entry, true, nil
}

func (h *pluginControlHost) applyPluginRuleBatchItem(admin pluginControlNetAdmin, item pluginControlNetRuleBatchItem) (pluginControlNetRuleBatchJournal, bool, error) {
	if !item.present && len(item.original) == 0 {
		return pluginControlNetRuleBatchJournal{}, false, admin.RuleDelete(item.request)
	}
	previous, created, err := h.claimPluginRuleMutation(item.request, item.present, item.original)
	if err != nil {
		return pluginControlNetRuleBatchJournal{}, false, err
	}
	entry := pluginControlNetRuleBatchJournal{request: item.request, present: item.present, previous: previous, created: created}
	if item.present {
		err = admin.RuleReplace(item.request)
	} else {
		err = admin.RuleDelete(item.request)
	}
	if err != nil {
		rollbackErr := h.rollbackPluginRuleOperation(admin, item.request, item.present, previous, created)
		return pluginControlNetRuleBatchJournal{}, false, combinePluginNetBatchErrors(err, rollbackErr)
	}
	return entry, true, nil
}

func (h *pluginControlHost) applyPluginNeighBatchItem(admin pluginControlNetAdmin, item pluginControlNetNeighBatchItem) (pluginControlNetNeighBatchJournal, bool, error) {
	if !item.present && len(item.original) == 0 {
		return pluginControlNetNeighBatchJournal{}, false, admin.NeighDelete(item.request)
	}
	previous, created, leased, err := h.claimPluginNeighMutation(item.request, item.present, item.original, item.ifIndex)
	if err != nil {
		return pluginControlNetNeighBatchJournal{}, false, err
	}
	entry := pluginControlNetNeighBatchJournal{request: item.request, present: item.present, original: item.original, previous: previous, created: created, leased: leased}
	if item.present {
		err = admin.NeighReplace(item.request)
	} else {
		err = admin.NeighDelete(item.request)
	}
	if err != nil {
		rollbackErr := h.rollbackPluginNeighBatchEntry(admin, entry)
		return pluginControlNetNeighBatchJournal{}, false, combinePluginNetBatchErrors(err, rollbackErr)
	}
	return entry, true, nil
}

func (h *pluginControlHost) rollbackPluginRouteBatch(admin pluginControlNetAdmin, entries []pluginControlNetRouteBatchJournal) error {
	return rollbackPluginNetBatch(len(entries), func(i int) error { return h.rollbackPluginRouteBatchEntry(admin, entries[i]) })
}

func (h *pluginControlHost) rollbackPluginRuleBatch(admin pluginControlNetAdmin, entries []pluginControlNetRuleBatchJournal) error {
	return rollbackPluginNetBatch(len(entries), func(i int) error {
		entry := entries[i]
		return h.rollbackPluginRuleOperation(admin, entry.request, entry.present, entry.previous, entry.created)
	})
}

func (h *pluginControlHost) rollbackPluginNeighBatch(admin pluginControlNetAdmin, entries []pluginControlNetNeighBatchJournal) error {
	return rollbackPluginNetBatch(len(entries), func(i int) error { return h.rollbackPluginNeighBatchEntry(admin, entries[i]) })
}

func (h *pluginControlHost) rollbackPluginRouteBatchEntry(admin pluginControlNetAdmin, entry pluginControlNetRouteBatchJournal) error {
	if entry.leased {
		return h.rollbackPluginRouteOperation(admin, entry.request, entry.present, entry.previous, entry.created)
	}
	var failures []string
	if entry.present {
		if err := admin.RouteDelete(entry.request); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if err := admin.RouteRestore(entry.original); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("restore route batch entry: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (h *pluginControlHost) rollbackPluginNeighBatchEntry(admin pluginControlNetAdmin, entry pluginControlNetNeighBatchJournal) error {
	if entry.leased {
		return h.rollbackPluginNeighOperation(admin, entry.request, entry.present, entry.previous, entry.created)
	}
	var failures []string
	if entry.present {
		if err := admin.NeighDelete(entry.request); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if err := admin.NeighRestore(entry.original); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("restore neighbor batch entry: %s", strings.Join(failures, "; "))
	}
	return nil
}

func rollbackPluginNetBatch(count int, rollback func(int) error) error {
	failures := make([]string, 0)
	for i := count - 1; i >= 0; i-- {
		if err := rollback(i); err != nil {
			failures = append(failures, fmt.Sprintf("operation %d: %v", i, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("batch rollback failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

func combinePluginNetBatchErrors(operationErr, rollbackErr error) error {
	if rollbackErr == nil {
		return operationErr
	}
	return fmt.Errorf("%v; rollback failed: %v", operationErr, rollbackErr)
}
