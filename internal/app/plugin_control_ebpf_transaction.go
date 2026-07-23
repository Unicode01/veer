package app

import (
	"fmt"
	"strings"

	"github.com/dop251/goja"
)

func (h *pluginControlHost) ebpfMapTransaction(call goja.FunctionCall) goja.Value {
	h.requirePermission("ebpf.map_write")
	controller, ok := h.mapController.(pluginEBPFMapTransactionController)
	if !ok || controller == nil {
		h.throwf("ebpf.mapTransaction: eBPF map transaction controller is unavailable")
	}
	request := h.ebpfMapTransactionRequest(call)
	if err := controller.TransactionPluginMaps(h.plugin.ID, request); err != nil {
		h.throwf("ebpf.mapTransaction: %v", err)
	}
	return h.vm.ToValue(map[string]any{
		"status":     "completed",
		"operations": len(request.Operations),
		"committed":  request.Commit != nil,
	})
}

func (h *pluginControlHost) ebpfMapTransactionRequest(call goja.FunctionCall) pluginEBPFMapTransactionRequest {
	requestObject := h.requiredObjectArg(call, 0, "request")
	operationsValue := h.objectField(requestObject, "operations")
	if goja.IsUndefined(operationsValue) || goja.IsNull(operationsValue) {
		h.throwf("ebpf.mapTransaction: operations are required")
	}
	operationsObject := operationsValue.ToObject(h.vm)
	if operationsObject == nil || operationsObject.ClassName() != "Array" {
		h.throwf("ebpf.mapTransaction: operations must be an array")
	}
	length := int(h.objectField(operationsObject, "length").ToInteger())
	if length < 1 || length > pluginControlMapTransactionMaxOps {
		h.throwf("ebpf.mapTransaction: operation count must be between 1 and %d", pluginControlMapTransactionMaxOps)
	}

	request := pluginEBPFMapTransactionRequest{Operations: make([]pluginEBPFMapMutation, 0, length)}
	seen := make(map[string]struct{}, length+1)
	totalBytes := 0
	for index := 0; index < length; index++ {
		value := operationsObject.Get(fmt.Sprint(index))
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			h.throwf("ebpf.mapTransaction: operation %d is missing", index)
		}
		mutation := h.ebpfMapMutationFromValue(value, false, fmt.Sprintf("operation %d", index))
		totalBytes += len(mutation.Key) + len(mutation.Value)
		if totalBytes > pluginControlMapTransactionMaxBytes {
			h.throwf("ebpf.mapTransaction: key/value bytes %d exceed limit %d", totalBytes, pluginControlMapTransactionMaxBytes)
		}
		h.requireUniqueEBPFMapMutation(seen, mutation, "ebpf.mapTransaction")
		request.Operations = append(request.Operations, mutation)
	}

	commitValue := h.objectField(requestObject, "commit")
	if !goja.IsUndefined(commitValue) && !goja.IsNull(commitValue) {
		commit := h.ebpfMapMutationFromValue(commitValue, true, "commit")
		totalBytes += len(commit.Key) + len(commit.Value)
		if totalBytes > pluginControlMapTransactionMaxBytes {
			h.throwf("ebpf.mapTransaction: key/value bytes %d exceed limit %d", totalBytes, pluginControlMapTransactionMaxBytes)
		}
		h.requireUniqueEBPFMapMutation(seen, commit, "ebpf.mapTransaction")
		request.Commit = &commit
	}
	return request
}

func (h *pluginControlHost) ebpfMapMutationFromValue(value goja.Value, commit bool, label string) pluginEBPFMapMutation {
	obj := value.ToObject(h.vm)
	if obj == nil || obj.ClassName() == "Array" {
		h.throwf("ebpf.mapTransaction: %s must be an object", label)
	}
	operation := strings.ToLower(h.firstStringObjectField(obj, "op", "operation"))
	if commit && operation == "" {
		operation = pluginEBPFMapMutationPut
	}
	if operation != pluginEBPFMapMutationPut && operation != pluginEBPFMapMutationDelete {
		h.throwf("ebpf.mapTransaction: %s op must be put or delete", label)
	}
	if commit && operation != pluginEBPFMapMutationPut {
		h.throwf("ebpf.mapTransaction: commit op must be put")
	}
	objectID := strings.ToLower(h.firstStringObjectField(obj, "object", "object_id"))
	if objectID != "" && !pluginIDPattern.MatchString(objectID) {
		h.throwf("ebpf.mapTransaction: %s object must match %s", label, pluginIDPattern.String())
	}
	mapName := h.firstStringObjectField(obj, "map", "map_name")
	if !pluginBPFMapPattern.MatchString(mapName) {
		h.throwf("ebpf.mapTransaction: %s map must match %s", label, pluginBPFMapPattern.String())
	}
	h.requirePluginObjectID(objectID, "ebpf.mapTransaction")
	h.requireWritablePluginMap(mapName, "ebpf.mapTransaction")
	key, err := decodePluginControlMapTransactionHex(h.firstStringObjectField(obj, "key", "key_hex"))
	if err != nil {
		h.throwf("ebpf.mapTransaction: %s key: %v", label, err)
	}
	mutation := pluginEBPFMapMutation{Operation: operation, ObjectID: objectID, MapName: mapName, Key: key}
	if operation == pluginEBPFMapMutationPut {
		mutation.Value, err = decodePluginControlMapTransactionHex(h.firstStringObjectField(obj, "value", "value_hex"))
		if err != nil {
			h.throwf("ebpf.mapTransaction: %s value: %v", label, err)
		}
	}
	return mutation
}

func decodePluginControlMapTransactionHex(value string) ([]byte, error) {
	if len(value) > pluginControlMapTransactionMaxBytes*2+1024 {
		return nil, fmt.Errorf("hex value exceeds transaction byte limit")
	}
	return decodePluginControlHexBytes(value)
}

func (h *pluginControlHost) requireUniqueEBPFMapMutation(seen map[string]struct{}, mutation pluginEBPFMapMutation, api string) {
	key := mutation.ObjectID + "\x00" + mutation.MapName + "\x00" + string(mutation.Key)
	if _, duplicate := seen[key]; duplicate {
		h.throwf("%s: duplicate map slot object=%s map=%s key=%x", api, mutation.ObjectID, mutation.MapName, mutation.Key)
	}
	seen[key] = struct{}{}
}
