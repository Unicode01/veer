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
	links       []pluginNetTransactionLinkIdentity
	leaseBefore pluginNetLeaseSnapshot
}

type pluginControlNetRuleBatchItem struct {
	request     pluginControlNetRuleRequest
	namespaceID pluginControlNetNamespaceIdentity
	present     bool
	original    []pluginControlNetRuleState
	links       []pluginNetTransactionLinkIdentity
	leaseBefore pluginNetLeaseSnapshot
}

type pluginControlNetNeighBatchItem struct {
	request     pluginControlNetNeighRequest
	namespaceID pluginControlNetNamespaceIdentity
	present     bool
	original    []pluginControlNetNeighState
	ifIndex     int
	links       []pluginNetTransactionLinkIdentity
	leaseBefore pluginNetLeaseSnapshot
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
	return h.netRouteTransactionItems(items)
}

func (h *pluginControlHost) netRouteTransactionItems(items []pluginControlNetRouteBatchItem) goja.Value {
	refs := make([]pluginOwnedResourceRef, 0, len(items))
	for _, item := range items {
		refs = append(refs, pluginOwnedResourceRef{pluginOwnedResourceTypeRoute, pluginControlNetRouteLeaseKey(item.request)})
	}
	var related []pluginOwnedResourceRef
	for _, item := range items {
		related = append(related, pluginNetTransactionLinkRefs(pluginNetTransactionEntry{RouteRequest: &item.request})...)
	}
	unlock := h.lockPluginNetMutation(refs, "net.route.transaction", related...)
	defer unlock()

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
		item.links, err = capturePluginNetTransactionLinks(admin, pluginNetTransactionEntry{RouteRequest: &item.request, RouteOriginal: item.original})
		if err != nil {
			h.throwf("inspect network transaction interfaces: %v", err)
		}
	}
	persistent, err := beginPluginRouteNetTransaction(h.db, h.plugin.ID, items)
	if err != nil {
		h.throwf("net.route.transaction: create recovery journal: %v", err)
	}

	for index, item := range items {
		if err := markPluginNetTransactionStarted(h.db, persistent, index+1); err != nil {
			rollbackErr := rollbackPendingPluginNetTransactionLocked(h.db, h.netAdmin, persistent, nil)
			h.throwPluginNetMutationError("net.route.transaction", fmt.Errorf("advance recovery journal: %w", err), rollbackErr)
		}
		err := h.applyPluginRouteBatchItem(admin, item)
		if err != nil {
			rollbackErr := rollbackPendingPluginNetTransactionLocked(h.db, h.netAdmin, persistent, nil)
			h.throwPluginNetMutationError("net.route.transaction", err, rollbackErr)
		}
	}
	for _, item := range items {
		if err := h.releaseRestoredPluginRouteLease(item.request, item.present); err != nil {
			rollbackErr := rollbackPendingPluginNetTransactionLocked(h.db, h.netAdmin, persistent, nil)
			h.throwPluginNetMutationError("net.route.transaction", fmt.Errorf("finalize route lease: %w", err), rollbackErr)
		}
	}
	if err := completePluginNetTransaction(h.db, persistent); err != nil {
		rollbackErr := rollbackPendingPluginNetTransactionLocked(h.db, h.netAdmin, persistent, nil)
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
	return h.netRuleTransactionItems(items)
}

func (h *pluginControlHost) netRuleTransactionItems(items []pluginControlNetRuleBatchItem) goja.Value {
	refs := make([]pluginOwnedResourceRef, 0, len(items))
	for _, item := range items {
		refs = append(refs, pluginOwnedResourceRef{pluginOwnedResourceTypeRule, pluginControlNetRuleLeaseKey(item.request)})
	}
	var related []pluginOwnedResourceRef
	for _, item := range items {
		related = append(related, pluginNetTransactionLinkRefs(pluginNetTransactionEntry{RuleRequest: &item.request})...)
	}
	unlock := h.lockPluginNetMutation(refs, "net.rule.transaction", related...)
	defer unlock()

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
		item.links, err = capturePluginNetTransactionLinks(admin, pluginNetTransactionEntry{RuleRequest: &item.request, RuleOriginal: item.original})
		if err != nil {
			h.throwf("inspect network transaction interfaces: %v", err)
		}
	}
	persistent, err := beginPluginRuleNetTransaction(h.db, h.plugin.ID, items)
	if err != nil {
		h.throwf("net.rule.transaction: create recovery journal: %v", err)
	}

	for index, item := range items {
		if err := markPluginNetTransactionStarted(h.db, persistent, index+1); err != nil {
			rollbackErr := rollbackPendingPluginNetTransactionLocked(h.db, h.netAdmin, persistent, nil)
			h.throwPluginNetMutationError("net.rule.transaction", fmt.Errorf("advance recovery journal: %w", err), rollbackErr)
		}
		err := h.applyPluginRuleBatchItem(admin, item)
		if err != nil {
			rollbackErr := rollbackPendingPluginNetTransactionLocked(h.db, h.netAdmin, persistent, nil)
			h.throwPluginNetMutationError("net.rule.transaction", err, rollbackErr)
		}
	}
	for _, item := range items {
		if err := h.releaseRestoredPluginRuleLease(item.request, item.present); err != nil {
			rollbackErr := rollbackPendingPluginNetTransactionLocked(h.db, h.netAdmin, persistent, nil)
			h.throwPluginNetMutationError("net.rule.transaction", fmt.Errorf("finalize policy rule lease: %w", err), rollbackErr)
		}
	}
	if err := completePluginNetTransaction(h.db, persistent); err != nil {
		rollbackErr := rollbackPendingPluginNetTransactionLocked(h.db, h.netAdmin, persistent, nil)
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
	return h.netNeighTransactionItems(items)
}

func (h *pluginControlHost) netNeighTransactionItems(items []pluginControlNetNeighBatchItem) goja.Value {
	refs := make([]pluginOwnedResourceRef, 0, len(items))
	for _, item := range items {
		refs = append(refs, pluginOwnedResourceRef{pluginOwnedResourceTypeNeighbor, pluginControlNetNeighLeaseKey(item.request)})
	}
	var related []pluginOwnedResourceRef
	for _, item := range items {
		related = append(related, pluginNetTransactionLinkRefs(pluginNetTransactionEntry{NeighRequest: &item.request})...)
	}
	unlock := h.lockPluginNetMutation(refs, "net.neigh.transaction", related...)
	defer unlock()

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
		item.links, err = capturePluginNetTransactionLinks(admin, pluginNetTransactionEntry{NeighRequest: &item.request, NeighOriginal: item.original})
		if err != nil {
			h.throwf("inspect network transaction interfaces: %v", err)
		}
	}
	persistent, err := beginPluginNeighNetTransaction(h.db, h.plugin.ID, items)
	if err != nil {
		h.throwf("net.neigh.transaction: create recovery journal: %v", err)
	}

	for index, item := range items {
		if err := markPluginNetTransactionStarted(h.db, persistent, index+1); err != nil {
			rollbackErr := rollbackPendingPluginNetTransactionLocked(h.db, h.netAdmin, persistent, nil)
			h.throwPluginNetMutationError("net.neigh.transaction", fmt.Errorf("advance recovery journal: %w", err), rollbackErr)
		}
		err := h.applyPluginNeighBatchItem(admin, item)
		if err != nil {
			rollbackErr := rollbackPendingPluginNetTransactionLocked(h.db, h.netAdmin, persistent, nil)
			h.throwPluginNetMutationError("net.neigh.transaction", err, rollbackErr)
		}
	}
	for _, item := range items {
		if err := h.releaseRestoredPluginNeighLease(item.request, item.present); err != nil {
			rollbackErr := rollbackPendingPluginNetTransactionLocked(h.db, h.netAdmin, persistent, nil)
			h.throwPluginNetMutationError("net.neigh.transaction", fmt.Errorf("finalize neighbor lease: %w", err), rollbackErr)
		}
	}
	if err := completePluginNetTransaction(h.db, persistent); err != nil {
		rollbackErr := rollbackPendingPluginNetTransactionLocked(h.db, h.netAdmin, persistent, nil)
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

func (h *pluginControlHost) applyPluginRouteBatchItem(admin pluginControlNetAdmin, item pluginControlNetRouteBatchItem) error {
	if err := h.validatePluginNetTransactionLinks(item.namespaceID, item.request.Namespace, item.links); err != nil {
		return err
	}
	if _, _, _, err := h.claimPluginRouteMutation(item.request, item.present, item.original, item.identities); err != nil {
		return err
	}
	item.request.expectedLinkIndices = pluginNetTransactionLinkIndices(item.links)
	if item.present {
		if len(item.original) == 1 && pluginControlRouteRequestMatchesState(item.request, item.original[0]) {
			return nil
		}
		return admin.RouteReplace(item.request)
	}
	return admin.RouteDelete(item.request)
}

func (h *pluginControlHost) applyPluginRuleBatchItem(admin pluginControlNetAdmin, item pluginControlNetRuleBatchItem) error {
	if err := h.validatePluginNetTransactionLinks(item.namespaceID, item.request.Namespace, item.links); err != nil {
		return err
	}
	if _, _, err := h.claimPluginRuleMutation(item.request, item.present, item.original, item.links); err != nil {
		return err
	}
	if item.present {
		if len(item.original) > 0 {
			return nil
		}
		return admin.RuleReplace(item.request)
	}
	return admin.RuleDelete(item.request)
}

func (h *pluginControlHost) applyPluginNeighBatchItem(admin pluginControlNetAdmin, item pluginControlNetNeighBatchItem) error {
	if err := h.validatePluginNetTransactionLinks(item.namespaceID, item.request.Namespace, item.links); err != nil {
		return err
	}
	if _, _, _, err := h.claimPluginNeighMutation(item.request, item.present, item.original, item.ifIndex, item.links); err != nil {
		return err
	}
	item.request.expectedIfIndex = item.ifIndex
	if item.present {
		if len(item.original) == 1 && pluginControlNeighRequestMatchesState(item.request, item.original[0]) && item.original[0].LinkIfIndex == item.ifIndex {
			return nil
		}
		return admin.NeighReplace(item.request)
	}
	return admin.NeighDelete(item.request)
}
