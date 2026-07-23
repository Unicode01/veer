//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const pluginControlMapClearMaxEntries = 16384

func (rt *linuxKernelRuleRuntime) PutPluginMapValue(pluginID string, objectID string, mapName string, key []byte, value []byte) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return putPluginMapValueInRefs(rt.pluginPipelineLoaded, pluginID, objectID, mapName, key, value)
}

func (rt *linuxKernelRuleRuntime) TransactionPluginMaps(pluginID string, request pluginEBPFMapTransactionRequest) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return transactPluginMapsInRefs(rt.pluginPipelineLoaded, pluginID, request)
}

func (rt *linuxKernelRuleRuntime) GetPluginMapValue(pluginID string, objectID string, mapName string, key []byte) ([]byte, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return getPluginMapValueInRefs(rt.pluginPipelineLoaded, pluginID, objectID, mapName, key)
}

func (rt *linuxKernelRuleRuntime) GetPluginMapPerCPUValues(pluginID string, objectID string, mapName string, key []byte) ([][]byte, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return getPluginMapPerCPUValuesInRefs(rt.pluginPipelineLoaded, pluginID, objectID, mapName, key)
}

func (rt *linuxKernelRuleRuntime) ScanPluginMap(pluginID string, objectID string, mapName string, request pluginEBPFMapScanRequest) (pluginEBPFMapScanResult, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return scanPluginMapInRefs(rt.pluginPipelineLoaded, pluginID, objectID, mapName, request)
}

func (rt *linuxKernelRuleRuntime) ReadPluginRingBuffer(pluginID string, objectID string, mapName string, request pluginEBPFRingReadRequest) (pluginEBPFRingReadResult, error) {
	rt.mu.Lock()
	m, err := clonePluginMapInRefs(rt.pluginPipelineLoaded, pluginID, objectID, mapName)
	rt.mu.Unlock()
	if err != nil {
		return pluginEBPFRingReadResult{}, err
	}
	defer m.Close()
	return readPluginRingBuffer(m, mapName, request)
}

func (rt *linuxKernelRuleRuntime) DeletePluginMapValue(pluginID string, objectID string, mapName string, key []byte) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return deletePluginMapValueInRefs(rt.pluginPipelineLoaded, pluginID, objectID, mapName, key)
}

func (rt *linuxKernelRuleRuntime) ClearPluginMap(pluginID string, objectID string, mapName string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return clearPluginMapInRefs(rt.pluginPipelineLoaded, pluginID, objectID, mapName)
}

func (rt *kernelXDPPluginPipelineRuntime) PutPluginMapValue(pluginID string, objectID string, mapName string, key []byte, value []byte) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return putPluginMapValueInRefs(rt.loaded, pluginID, objectID, mapName, key, value)
}

func (rt *kernelXDPPluginPipelineRuntime) TransactionPluginMaps(pluginID string, request pluginEBPFMapTransactionRequest) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return transactPluginMapsInRefs(rt.loaded, pluginID, request)
}

func (rt *kernelXDPPluginPipelineRuntime) GetPluginMapValue(pluginID string, objectID string, mapName string, key []byte) ([]byte, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return getPluginMapValueInRefs(rt.loaded, pluginID, objectID, mapName, key)
}

func (rt *kernelXDPPluginPipelineRuntime) GetPluginMapPerCPUValues(pluginID string, objectID string, mapName string, key []byte) ([][]byte, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return getPluginMapPerCPUValuesInRefs(rt.loaded, pluginID, objectID, mapName, key)
}

func (rt *kernelXDPPluginPipelineRuntime) ScanPluginMap(pluginID string, objectID string, mapName string, request pluginEBPFMapScanRequest) (pluginEBPFMapScanResult, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return scanPluginMapInRefs(rt.loaded, pluginID, objectID, mapName, request)
}

func (rt *kernelXDPPluginPipelineRuntime) ReadPluginRingBuffer(pluginID string, objectID string, mapName string, request pluginEBPFRingReadRequest) (pluginEBPFRingReadResult, error) {
	rt.mu.Lock()
	m, err := clonePluginMapInRefs(rt.loaded, pluginID, objectID, mapName)
	rt.mu.Unlock()
	if err != nil {
		return pluginEBPFRingReadResult{}, err
	}
	defer m.Close()
	return readPluginRingBuffer(m, mapName, request)
}

func (rt *kernelXDPPluginPipelineRuntime) DeletePluginMapValue(pluginID string, objectID string, mapName string, key []byte) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return deletePluginMapValueInRefs(rt.loaded, pluginID, objectID, mapName, key)
}

func (rt *kernelXDPPluginPipelineRuntime) ClearPluginMap(pluginID string, objectID string, mapName string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return clearPluginMapInRefs(rt.loaded, pluginID, objectID, mapName)
}

func (rt *linuxPluginDataplaneRuntime) PutPluginMapValue(pluginID string, objectID string, mapName string, key []byte, value []byte) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return putPluginMapValueInRefs(rt.loadedPluginObjectRefsLocked(pluginID), pluginID, objectID, mapName, key, value)
}

func (rt *linuxPluginDataplaneRuntime) TransactionPluginMaps(pluginID string, request pluginEBPFMapTransactionRequest) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return transactPluginMapsInRefs(rt.loadedPluginObjectRefsLocked(pluginID), pluginID, request)
}

func (rt *linuxPluginDataplaneRuntime) GetPluginMapValue(pluginID string, objectID string, mapName string, key []byte) ([]byte, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return getPluginMapValueInRefs(rt.loadedPluginObjectRefsLocked(pluginID), pluginID, objectID, mapName, key)
}

func (rt *linuxPluginDataplaneRuntime) GetPluginMapPerCPUValues(pluginID string, objectID string, mapName string, key []byte) ([][]byte, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return getPluginMapPerCPUValuesInRefs(rt.loadedPluginObjectRefsLocked(pluginID), pluginID, objectID, mapName, key)
}

func (rt *linuxPluginDataplaneRuntime) ScanPluginMap(pluginID string, objectID string, mapName string, request pluginEBPFMapScanRequest) (pluginEBPFMapScanResult, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return scanPluginMapInRefs(rt.loadedPluginObjectRefsLocked(pluginID), pluginID, objectID, mapName, request)
}

func (rt *linuxPluginDataplaneRuntime) ReadPluginRingBuffer(pluginID string, objectID string, mapName string, request pluginEBPFRingReadRequest) (pluginEBPFRingReadResult, error) {
	rt.mu.Lock()
	m, err := clonePluginMapInRefs(rt.loadedPluginObjectRefsLocked(pluginID), pluginID, objectID, mapName)
	rt.mu.Unlock()
	if err != nil {
		return pluginEBPFRingReadResult{}, err
	}
	defer m.Close()
	return readPluginRingBuffer(m, mapName, request)
}

func (rt *linuxPluginDataplaneRuntime) DeletePluginMapValue(pluginID string, objectID string, mapName string, key []byte) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return deletePluginMapValueInRefs(rt.loadedPluginObjectRefsLocked(pluginID), pluginID, objectID, mapName, key)
}

func (rt *linuxPluginDataplaneRuntime) ClearPluginMap(pluginID string, objectID string, mapName string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return clearPluginMapInRefs(rt.loadedPluginObjectRefsLocked(pluginID), pluginID, objectID, mapName)
}

func (rt *linuxPluginDataplaneRuntime) loadedPluginObjectRefsLocked(pluginID string) []loadedPluginObjectRef {
	if rt == nil || rt.loaded == nil {
		return nil
	}
	loaded := rt.loaded[pluginID]
	if loaded == nil {
		return nil
	}
	return loaded.objects
}

func putPluginMapValueInRefs(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string, key []byte, value []byte) error {
	m, err := findPluginLoadedMap(refs, pluginID, objectID, mapName)
	if err != nil {
		return err
	}
	if err := validatePluginMapKeyValue(m, key, value); err != nil {
		return err
	}
	if err := m.Put(key, value); err != nil {
		return fmt.Errorf("put map %s: %w", mapName, err)
	}
	return nil
}

type pluginEBPFMapTransactionEntry struct {
	mutation pluginEBPFMapMutation
	mapRef   *ebpf.Map
	previous []byte
	existed  bool
}

func transactPluginMapsInRefs(refs []loadedPluginObjectRef, pluginID string, request pluginEBPFMapTransactionRequest) error {
	mutations := append([]pluginEBPFMapMutation(nil), request.Operations...)
	if request.Commit != nil {
		mutations = append(mutations, *request.Commit)
	}
	if len(request.Operations) < 1 || len(request.Operations) > pluginControlMapTransactionMaxOps {
		return fmt.Errorf("map transaction operation count must be between 1 and %d", pluginControlMapTransactionMaxOps)
	}
	if request.Commit != nil && request.Commit.Operation != pluginEBPFMapMutationPut {
		return fmt.Errorf("map transaction commit must be a put operation")
	}

	entries := make([]pluginEBPFMapTransactionEntry, 0, len(mutations))
	seen := make(map[string]struct{}, len(mutations))
	totalBytes := 0
	snapshotBytes := 0
	for index, mutation := range mutations {
		if mutation.Operation != pluginEBPFMapMutationPut && mutation.Operation != pluginEBPFMapMutationDelete {
			return fmt.Errorf("map transaction operation %d must be put or delete", index)
		}
		totalBytes += len(mutation.Key) + len(mutation.Value)
		if totalBytes > pluginControlMapTransactionMaxBytes {
			return fmt.Errorf("map transaction key/value bytes %d exceed limit %d", totalBytes, pluginControlMapTransactionMaxBytes)
		}
		m, err := findPluginLoadedMap(refs, pluginID, mutation.ObjectID, mutation.MapName)
		if err != nil {
			return err
		}
		slot := fmt.Sprintf("%d\x00%s", m.FD(), mutation.Key)
		if _, duplicate := seen[slot]; duplicate {
			return fmt.Errorf("map transaction contains duplicate slot object=%s map=%s key=%x", mutation.ObjectID, mutation.MapName, mutation.Key)
		}
		seen[slot] = struct{}{}
		if !pluginMapSupportsTransaction(m.Type()) {
			return fmt.Errorf("map %s type %s does not support transactional raw values", mutation.MapName, m.Type())
		}
		snapshotBytes += int(m.KeySize()) + int(m.ValueSize())
		if snapshotBytes > pluginControlMapTransactionMaxBytes {
			return fmt.Errorf("map transaction snapshot bytes %d exceed limit %d", snapshotBytes, pluginControlMapTransactionMaxBytes)
		}
		if mutation.Operation == pluginEBPFMapMutationPut {
			if err := validatePluginMapKeyValue(m, mutation.Key, mutation.Value); err != nil {
				return fmt.Errorf("map transaction operation %d: %w", index, err)
			}
		} else {
			if len(mutation.Value) != 0 {
				return fmt.Errorf("map transaction operation %d: delete value must be empty", index)
			}
			if m.Type() == ebpf.Array {
				return fmt.Errorf("map transaction operation %d: array map entries cannot be deleted", index)
			}
			if int(m.KeySize()) != len(mutation.Key) {
				return fmt.Errorf("map transaction operation %d: map key size = %d, want %d", index, len(mutation.Key), m.KeySize())
			}
		}
		previous, err := m.LookupBytes(mutation.Key)
		entry := pluginEBPFMapTransactionEntry{mutation: mutation, mapRef: m}
		if err == nil && previous != nil {
			entry.existed = true
			entry.previous = append([]byte(nil), previous...)
		} else if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("snapshot map %s key %x: %w", mutation.MapName, mutation.Key, err)
		}
		entries = append(entries, entry)
	}

	for index := range entries {
		if err := applyPluginMapTransactionEntry(entries[index]); err != nil {
			rollbackErr := rollbackPluginMapTransactionEntries(entries[:index+1])
			if rollbackErr != nil {
				return fmt.Errorf("map transaction operation %d failed: %v; rollback failed: %w", index, err, rollbackErr)
			}
			return fmt.Errorf("map transaction operation %d failed: %w", index, err)
		}
	}
	return nil
}

func pluginMapSupportsTransaction(mapType ebpf.MapType) bool {
	switch mapType {
	case ebpf.Hash, ebpf.Array, ebpf.LRUHash, ebpf.LRUCPUHash, ebpf.LPMTrie:
		return true
	default:
		return false
	}
}

func applyPluginMapTransactionEntry(entry pluginEBPFMapTransactionEntry) error {
	if entry.mutation.Operation == pluginEBPFMapMutationPut {
		if err := entry.mapRef.Put(entry.mutation.Key, entry.mutation.Value); err != nil {
			return fmt.Errorf("put map %s: %w", entry.mutation.MapName, err)
		}
		return nil
	}
	if err := entry.mapRef.Delete(entry.mutation.Key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete map %s: %w", entry.mutation.MapName, err)
	}
	return nil
}

func rollbackPluginMapTransactionEntries(entries []pluginEBPFMapTransactionEntry) error {
	failures := make([]string, 0)
	for index := len(entries) - 1; index >= 0; index-- {
		entry := entries[index]
		var err error
		if entry.existed {
			err = entry.mapRef.Put(entry.mutation.Key, entry.previous)
		} else {
			err = entry.mapRef.Delete(entry.mutation.Key)
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				err = nil
			}
		}
		if err != nil {
			failures = append(failures, fmt.Sprintf("operation %d map %s: %v", index, entry.mutation.MapName, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func getPluginMapValueInRefs(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string, key []byte) ([]byte, error) {
	m, err := findPluginLoadedMap(refs, pluginID, objectID, mapName)
	if err != nil {
		return nil, err
	}
	if int(m.KeySize()) != len(key) {
		return nil, fmt.Errorf("map %s key size = %d, want %d", mapName, len(key), m.KeySize())
	}
	value := make([]byte, int(m.ValueSize()))
	if err := m.Lookup(key, value); err != nil {
		return nil, fmt.Errorf("get map %s: %w", mapName, err)
	}
	return value, nil
}

func getPluginMapPerCPUValuesInRefs(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string, key []byte) ([][]byte, error) {
	m, err := findPluginLoadedMap(refs, pluginID, objectID, mapName)
	if err != nil {
		return nil, err
	}
	if int(m.KeySize()) != len(key) {
		return nil, fmt.Errorf("map %s key size = %d, want %d", mapName, len(key), m.KeySize())
	}
	switch m.Type() {
	case ebpf.PerCPUArray, ebpf.PerCPUHash, ebpf.PerCPUCGroupStorage:
	default:
		return nil, fmt.Errorf("map %s type %s is not per-CPU", mapName, m.Type())
	}
	raw, err := m.LookupBytes(key)
	if err != nil {
		return nil, fmt.Errorf("get per-CPU map %s: %w", mapName, err)
	}
	if raw == nil {
		return nil, fmt.Errorf("get per-CPU map %s: %w", mapName, ebpf.ErrKeyNotExist)
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("get possible CPUs: %w", err)
	}
	valueSize := int(m.ValueSize())
	stride := (valueSize + 7) &^ 7
	if len(raw) != possibleCPUs*stride {
		return nil, fmt.Errorf("map %s per-CPU value size = %d, want %d", mapName, len(raw), possibleCPUs*stride)
	}
	values := make([][]byte, possibleCPUs)
	for cpu := 0; cpu < possibleCPUs; cpu++ {
		start := cpu * stride
		values[cpu] = append([]byte(nil), raw[start:start+valueSize]...)
	}
	return values, nil
}

func scanPluginMapInRefs(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string, request pluginEBPFMapScanRequest) (pluginEBPFMapScanResult, error) {
	m, err := findPluginLoadedMap(refs, pluginID, objectID, mapName)
	if err != nil {
		return pluginEBPFMapScanResult{}, err
	}
	if request.Limit < 1 || request.Limit > pluginControlMapScanMaxEntries {
		return pluginEBPFMapScanResult{}, fmt.Errorf("map scan limit must be between 1 and %d", pluginControlMapScanMaxEntries)
	}
	if request.MaxBytes < 1 || request.MaxBytes > pluginControlMapScanMaxBytes {
		return pluginEBPFMapScanResult{}, fmt.Errorf("map scan byte limit must be between 1 and %d", pluginControlMapScanMaxBytes)
	}
	keySize := int(m.KeySize())
	valueSize := int(m.ValueSize())
	if keySize <= 0 || valueSize <= 0 {
		return pluginEBPFMapScanResult{}, fmt.Errorf("map %s does not support key/value scanning", mapName)
	}
	if len(request.Cursor) > 0 && len(request.Cursor) != keySize {
		return pluginEBPFMapScanResult{}, fmt.Errorf("map %s cursor size = %d, want %d", mapName, len(request.Cursor), keySize)
	}
	switch m.Type() {
	case ebpf.PerCPUArray, ebpf.PerCPUHash, ebpf.PerCPUCGroupStorage:
		return pluginEBPFMapScanResult{}, fmt.Errorf("map %s type %s requires per-CPU lookup", mapName, m.Type())
	}
	result := pluginEBPFMapScanResult{Entries: make([]pluginEBPFMapScanEntry, 0, request.Limit)}
	cursor := append([]byte(nil), request.Cursor...)
	used := 0
	seen := make(map[string]struct{}, request.Limit)
	for len(result.Entries) < request.Limit {
		var current any
		if len(cursor) > 0 {
			current = cursor
		}
		next, err := m.NextKeyBytes(current)
		if err != nil {
			return pluginEBPFMapScanResult{}, fmt.Errorf("scan map %s next key: %w", mapName, err)
		}
		if next == nil {
			result.Done = true
			break
		}
		if _, duplicate := seen[string(next)]; duplicate {
			break
		}
		seen[string(next)] = struct{}{}
		value, err := m.LookupBytes(next)
		cursor = append(cursor[:0], next...)
		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return pluginEBPFMapScanResult{}, fmt.Errorf("scan map %s value: %w", mapName, err)
		}
		if value == nil {
			continue
		}
		entryBytes := len(next) + len(value)
		if entryBytes > request.MaxBytes-used {
			if len(result.Entries) == 0 {
				return pluginEBPFMapScanResult{}, fmt.Errorf("map %s entry size %d exceeds scan byte limit %d", mapName, entryBytes, request.MaxBytes)
			}
			break
		}
		result.Entries = append(result.Entries, pluginEBPFMapScanEntry{
			Key: append([]byte(nil), next...), Value: append([]byte(nil), value...),
		})
		used += entryBytes
		result.Cursor = append(result.Cursor[:0], cursor...)
	}
	if !result.Done && len(result.Cursor) > 0 && len(result.Entries) >= request.Limit {
		next, err := m.NextKeyBytes(result.Cursor)
		if err != nil {
			return pluginEBPFMapScanResult{}, fmt.Errorf("scan map %s completion: %w", mapName, err)
		}
		result.Done = next == nil
	}
	if result.Done {
		result.Cursor = nil
	}
	return result, nil
}

func clonePluginMapInRefs(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string) (*ebpf.Map, error) {
	m, err := findPluginLoadedMap(refs, pluginID, objectID, mapName)
	if err != nil {
		return nil, err
	}
	clone, err := m.Clone()
	if err != nil {
		return nil, fmt.Errorf("clone map %s: %w", mapName, err)
	}
	return clone, nil
}

func readPluginRingBuffer(m *ebpf.Map, mapName string, request pluginEBPFRingReadRequest) (pluginEBPFRingReadResult, error) {
	if request.MaxRecords < 1 || request.MaxRecords > pluginControlRingMaxRecords {
		return pluginEBPFRingReadResult{}, fmt.Errorf("ring read record limit must be between 1 and %d", pluginControlRingMaxRecords)
	}
	if request.MaxBytes < 1 || request.MaxBytes > pluginControlRingMaxBytes {
		return pluginEBPFRingReadResult{}, fmt.Errorf("ring read byte limit must be between 1 and %d", pluginControlRingMaxBytes)
	}
	if request.TimeoutMS < 1 || request.TimeoutMS > int64((15*time.Second)/time.Millisecond) {
		return pluginEBPFRingReadResult{}, fmt.Errorf("ring read timeout must be between 1 and %d ms", (15 * time.Second).Milliseconds())
	}
	reader, err := ringbuf.NewReader(m)
	if err != nil {
		return pluginEBPFRingReadResult{}, fmt.Errorf("open ring buffer map %s: %w", mapName, err)
	}
	defer reader.Close()
	reader.SetDeadline(time.Now().Add(time.Duration(request.TimeoutMS) * time.Millisecond))
	result := pluginEBPFRingReadResult{Records: make([]pluginEBPFRingRecord, 0, request.MaxRecords)}
	for len(result.Records) < request.MaxRecords {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				result.TimedOut = len(result.Records) == 0
				break
			}
			return pluginEBPFRingReadResult{}, fmt.Errorf("read ring buffer map %s: %w", mapName, err)
		}
		result.Remaining = record.Remaining
		if len(record.RawSample) > request.MaxBytes-result.Bytes {
			result.DroppedRecords++
			result.LimitReached = true
			break
		}
		result.Records = append(result.Records, pluginEBPFRingRecord{
			RawSample: append([]byte(nil), record.RawSample...), Remaining: record.Remaining,
		})
		result.Bytes += len(record.RawSample)
		if result.Bytes >= request.MaxBytes {
			result.LimitReached = record.Remaining > 0
			break
		}
		reader.SetDeadline(time.Now())
	}
	if len(result.Records) >= request.MaxRecords && result.Remaining > 0 {
		result.LimitReached = true
	}
	return result, nil
}

func deletePluginMapValueInRefs(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string, key []byte) error {
	m, err := findPluginLoadedMap(refs, pluginID, objectID, mapName)
	if err != nil {
		return err
	}
	if int(m.KeySize()) != len(key) {
		return fmt.Errorf("map %s key size = %d, want %d", mapName, len(key), m.KeySize())
	}
	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete map %s: %w", mapName, err)
	}
	return nil
}

func clearPluginMapInRefs(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string) error {
	m, err := findPluginLoadedMap(refs, pluginID, objectID, mapName)
	if err != nil {
		return err
	}
	keySize := int(m.KeySize())
	valueSize := int(m.ValueSize())
	if keySize <= 0 || valueSize <= 0 {
		return fmt.Errorf("map %s has invalid key/value size %d/%d", mapName, keySize, valueSize)
	}
	maxEntries := m.MaxEntries()
	if maxEntries > pluginControlMapClearMaxEntries {
		return fmt.Errorf("map %s max entries = %d exceeds clear limit %d; delete keys explicitly", mapName, maxEntries, pluginControlMapClearMaxEntries)
	}
	if m.Type() == ebpf.Array || m.Type() == ebpf.PerCPUArray {
		var perCPUValues [][]byte
		if m.Type() == ebpf.PerCPUArray {
			possibleCPUs, err := ebpf.PossibleCPU()
			if err != nil {
				return fmt.Errorf("get possible CPUs: %w", err)
			}
			perCPUValues = make([][]byte, possibleCPUs)
			for cpu := range perCPUValues {
				perCPUValues[cpu] = make([]byte, valueSize)
			}
		}
		for index := uint32(0); index < maxEntries; index++ {
			var value any = make([]byte, valueSize)
			if perCPUValues != nil {
				value = perCPUValues
			}
			if err := m.Put(index, value); err != nil {
				return fmt.Errorf("zero map %s index %d: %w", mapName, index, err)
			}
		}
		return nil
	}
	key := make([]byte, keySize)
	value := make([]byte, valueSize)
	keys := make([][]byte, 0, maxEntries)
	iter := m.Iterate()
	for iter.Next(key, value) {
		keys = append(keys, append([]byte(nil), key...))
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate map %s: %w", mapName, err)
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("clear map %s: %w", mapName, err)
		}
	}
	return nil
}

func findPluginLoadedMap(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string) (*ebpf.Map, error) {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	objectID = strings.TrimSpace(strings.ToLower(objectID))
	mapName = strings.TrimSpace(mapName)
	if pluginID == "" || mapName == "" {
		return nil, errPluginRuntimeTargetNotLoaded
	}
	for _, ref := range refs {
		if ref.PluginID != pluginID || ref.coll == nil {
			continue
		}
		if objectID != "" && ref.ObjectID != objectID {
			continue
		}
		if m := ref.coll.Maps[mapName]; m != nil {
			return m, nil
		}
	}
	return nil, fmt.Errorf("%w: plugin %s object %s map %s", errPluginRuntimeTargetNotLoaded, pluginID, objectID, mapName)
}

func validatePluginMapKeyValue(m *ebpf.Map, key []byte, value []byte) error {
	if m == nil {
		return fmt.Errorf("map is nil")
	}
	if int(m.KeySize()) != len(key) {
		return fmt.Errorf("map key size = %d, want %d", len(key), m.KeySize())
	}
	if int(m.ValueSize()) != len(value) {
		return fmt.Errorf("map value size = %d, want %d", len(value), m.ValueSize())
	}
	return nil
}
