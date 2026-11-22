package app

import (
	"encoding/hex"
	"errors"
	"os"
	"strings"

	hv "github.com/Unicode01/veer/internal/hostvalue"
)

func (h *pluginControlHost) blobBegin(call hv.FunctionCall) hv.Value {
	const api = "blob.begin"
	store := h.pluginBlobStoreOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	key := h.requiredStringObjectField(obj, "key")
	expectedBytes := h.optionalNonNegativeInt64ObjectField(obj, "expected_bytes", api)
	expectedSHA256 := h.blobOptionalStringObjectField(obj, "sha256", "expected_sha256")
	info, err := store.Begin(h.plugin.ID, h.controlGeneration, key, expectedBytes, expectedSHA256)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(pluginBlobUploadInfoObject(info))
}

func (h *pluginControlHost) blobWrite(call hv.FunctionCall) hv.Value {
	const api = "blob.write"
	store := h.pluginBlobStoreOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	uploadID := h.requiredStringObjectField(obj, "upload_id")
	offset := h.optionalNonNegativeInt64ObjectField(obj, "offset", api)
	data := h.blobPayloadObjectField(obj, api)
	info, err := store.Write(h.plugin.ID, h.controlGeneration, uploadID, offset, data)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(pluginBlobUploadInfoObject(info))
}

func (h *pluginControlHost) blobCommit(call hv.FunctionCall) hv.Value {
	const api = "blob.commit"
	store := h.pluginBlobStoreOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	uploadID := h.requiredStringObjectField(obj, "upload_id")
	info, err := store.Commit(h.plugin.ID, h.controlGeneration, uploadID)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(pluginBlobInfoObject(info))
}

func (h *pluginControlHost) blobAbort(call hv.FunctionCall) hv.Value {
	const api = "blob.abort"
	store := h.pluginBlobStoreOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	uploadID := h.requiredStringObjectField(obj, "upload_id")
	aborted, err := store.Abort(h.plugin.ID, h.controlGeneration, uploadID)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(map[string]any{"aborted": aborted})
}

func (h *pluginControlHost) blobPut(call hv.FunctionCall) hv.Value {
	const api = "blob.put"
	store := h.pluginBlobStoreOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	key := h.requiredStringObjectField(obj, "key")
	data := h.blobPayloadObjectField(obj, api)
	expectedSHA256 := h.blobOptionalStringObjectField(obj, "sha256", "expected_sha256")
	info, err := store.Put(h.plugin.ID, h.controlGeneration, key, data, expectedSHA256)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(pluginBlobInfoObject(info))
}

func (h *pluginControlHost) blobRead(call hv.FunctionCall) hv.Value {
	const api = "blob.read"
	store := h.pluginBlobStoreOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	key := h.requiredStringObjectField(obj, "key")
	offset := h.optionalNonNegativeInt64ObjectField(obj, "offset", api)
	maxBytes := 0
	if raw := h.objectField(obj, "max_bytes"); !hv.IsUndefined(raw) && !hv.IsNull(raw) {
		value := raw.ToInteger()
		if value < 1 || value > pluginBlobMaxChunkBytes {
			h.throwf("%s: max_bytes must be between 1 and %d", api, pluginBlobMaxChunkBytes)
		}
		maxBytes = int(value)
	}
	result, err := store.Read(h.plugin.ID, key, offset, maxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return hv.Null()
	}
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(map[string]any{
		"blob": pluginBlobInfoObject(result.Info), "offset": result.Offset,
		"payload_hex": hex.EncodeToString(result.Data), "bytes": len(result.Data), "eof": result.EOF,
	})
}

func (h *pluginControlHost) blobStat(call hv.FunctionCall) hv.Value {
	const api = "blob.stat"
	store := h.pluginBlobStoreOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	info, err := store.Stat(h.plugin.ID, h.requiredStringObjectField(obj, "key"))
	if errors.Is(err, os.ErrNotExist) {
		return hv.Null()
	}
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(pluginBlobInfoObject(info))
}

func (h *pluginControlHost) blobList(call hv.FunctionCall) hv.Value {
	const api = "blob.list"
	store := h.pluginBlobStoreOrThrow(api)
	after := ""
	limit := 0
	if len(call.Arguments) > 0 && !hv.IsUndefined(call.Arguments[0]) && !hv.IsNull(call.Arguments[0]) {
		obj := call.Arguments[0].ToObject(h.vm)
		after = h.blobOptionalStringObjectField(obj, "after")
		if raw := h.objectField(obj, "limit"); !hv.IsUndefined(raw) && !hv.IsNull(raw) {
			limit = int(raw.ToInteger())
		}
	}
	infos, err := store.List(h.plugin.ID, after, limit)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	out := make([]map[string]any, 0, len(infos))
	for _, info := range infos {
		out = append(out, pluginBlobInfoObject(info))
	}
	return h.vm.ToValue(out)
}

func (h *pluginControlHost) blobDelete(call hv.FunctionCall) hv.Value {
	const api = "blob.delete"
	store := h.pluginBlobStoreOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	deleted, err := store.Delete(h.plugin.ID, h.requiredStringObjectField(obj, "key"))
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(map[string]any{"deleted": deleted})
}

func (h *pluginControlHost) blobVerify(call hv.FunctionCall) hv.Value {
	const api = "blob.verify"
	store := h.pluginBlobStoreOrThrow(api)
	obj := h.requiredObjectArg(call, 0, "request")
	info, err := store.Verify(h.plugin.ID, h.requiredStringObjectField(obj, "key"))
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(map[string]any{"verified": true, "blob": pluginBlobInfoObject(info)})
}

func (h *pluginControlHost) pluginBlobStoreOrThrow(api string) *pluginBlobStore {
	h.requirePermission("blob")
	if h.runtime == nil {
		h.throwf("%s: plugin blob runtime is unavailable", api)
	}
	store, err := h.runtime.pluginBlobStoreOrCreate()
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return store
}

func (h *pluginControlHost) blobPayloadObjectField(obj *hv.Object, api string) []byte {
	raw := h.objectField(obj, "payload_hex")
	if hv.IsUndefined(raw) || hv.IsNull(raw) {
		raw = h.objectField(obj, "data")
	}
	if hv.IsUndefined(raw) || hv.IsNull(raw) {
		h.throwf("%s: payload_hex is required", api)
	}
	encoded := strings.TrimSpace(raw.String())
	if len(encoded) > pluginBlobMaxChunkBytes*2 {
		h.throwf("%s: encoded payload exceeds %d bytes", api, pluginBlobMaxChunkBytes)
	}
	data, err := decodePluginControlHexBytes(encoded)
	if err != nil {
		h.throwf("%s: payload_hex: %v", api, err)
	}
	if len(data) > pluginBlobMaxChunkBytes {
		h.throwf("%s: payload exceeds %d bytes", api, pluginBlobMaxChunkBytes)
	}
	return data
}

func (h *pluginControlHost) optionalNonNegativeInt64ObjectField(obj *hv.Object, field, api string) int64 {
	raw := h.objectField(obj, field)
	if hv.IsUndefined(raw) || hv.IsNull(raw) {
		return 0
	}
	value := raw.ToInteger()
	if value < 0 {
		h.throwf("%s: %s must be non-negative", api, field)
	}
	return value
}

func (h *pluginControlHost) blobOptionalStringObjectField(obj *hv.Object, fields ...string) string {
	for _, field := range fields {
		raw := h.objectField(obj, field)
		if !hv.IsUndefined(raw) && !hv.IsNull(raw) {
			return strings.TrimSpace(raw.String())
		}
	}
	return ""
}

func pluginBlobInfoObject(info pluginBlobInfo) map[string]any {
	return map[string]any{
		"key": info.Key, "bytes": info.Bytes, "sha256": info.SHA256,
		"created_at": info.CreatedAt, "updated_at": info.UpdatedAt,
	}
}

func pluginBlobUploadInfoObject(info pluginBlobUploadInfo) map[string]any {
	out := map[string]any{
		"upload_id": info.UploadID, "key": info.Key, "bytes": info.Bytes, "created_at": info.CreatedAt,
	}
	if info.ExpectedBytes > 0 {
		out["expected_bytes"] = info.ExpectedBytes
	}
	if info.ExpectedSHA256 != "" {
		out["expected_sha256"] = info.ExpectedSHA256
	}
	return out
}
