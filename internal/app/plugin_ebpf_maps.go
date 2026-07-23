package app

import "errors"

const (
	pluginControlMapScanDefaultEntries  = 64
	pluginControlMapScanMaxEntries      = 256
	pluginControlMapScanDefaultBytes    = 256 << 10
	pluginControlMapScanMaxBytes        = 1 << 20
	pluginControlRingDefaultRecords     = 64
	pluginControlRingMaxRecords         = 256
	pluginControlRingDefaultBytes       = 256 << 10
	pluginControlRingMaxBytes           = 1 << 20
	pluginControlMapTransactionMaxOps   = 256
	pluginControlMapTransactionMaxBytes = 1 << 20
)

const (
	pluginEBPFMapMutationPut    = "put"
	pluginEBPFMapMutationDelete = "delete"
)

type pluginEBPFMapMutation struct {
	Operation string
	ObjectID  string
	MapName   string
	Key       []byte
	Value     []byte
}

type pluginEBPFMapTransactionRequest struct {
	Operations []pluginEBPFMapMutation
	Commit     *pluginEBPFMapMutation
}

type pluginEBPFMapTransactionController interface {
	TransactionPluginMaps(pluginID string, request pluginEBPFMapTransactionRequest) error
}

type pluginEBPFMapScanEntry struct {
	Key   []byte
	Value []byte
}

type pluginEBPFMapScanRequest struct {
	Cursor   []byte
	Limit    int
	MaxBytes int
}

type pluginEBPFMapScanResult struct {
	Entries []pluginEBPFMapScanEntry
	Cursor  []byte
	Done    bool
}

type pluginEBPFMapScanController interface {
	ScanPluginMap(pluginID string, objectID string, mapName string, request pluginEBPFMapScanRequest) (pluginEBPFMapScanResult, error)
}

type pluginEBPFRingReadRequest struct {
	MaxRecords int
	MaxBytes   int
	TimeoutMS  int64
}

type pluginEBPFRingRecord struct {
	RawSample []byte
	Remaining int
}

type pluginEBPFRingReadResult struct {
	Records        []pluginEBPFRingRecord
	Bytes          int
	DroppedRecords int
	Remaining      int
	TimedOut       bool
	LimitReached   bool
}

type pluginEBPFRingReadController interface {
	ReadPluginRingBuffer(pluginID string, objectID string, mapName string, request pluginEBPFRingReadRequest) (pluginEBPFRingReadResult, error)
}

func (pm *ProcessManager) GetPluginMapValue(pluginID string, objectID string, mapName string, key []byte) ([]byte, error) {
	var out []byte
	err := pm.withPluginMapController(func(controller pluginEBPFMapController) error {
		value, err := controller.GetPluginMapValue(pluginID, objectID, mapName, key)
		if err != nil {
			return err
		}
		out = value
		return nil
	})
	return out, err
}

func (pm *ProcessManager) GetPluginMapPerCPUValues(pluginID string, objectID string, mapName string, key []byte) ([][]byte, error) {
	if pm == nil {
		return nil, errPluginRuntimeTargetNotLoaded
	}
	var notLoaded error
	for _, candidate := range []any{pm.kernelRuntime, pm.pluginRuntime} {
		controller, ok := candidate.(pluginEBPFPerCPUMapController)
		if !ok || controller == nil {
			continue
		}
		values, err := controller.GetPluginMapPerCPUValues(pluginID, objectID, mapName, key)
		if err == nil {
			return values, nil
		}
		if errors.Is(err, errPluginRuntimeTargetNotLoaded) {
			notLoaded = err
			continue
		}
		return nil, err
	}
	if notLoaded != nil {
		return nil, notLoaded
	}
	return nil, errPluginRuntimeTargetNotLoaded
}

func (pm *ProcessManager) ScanPluginMap(pluginID string, objectID string, mapName string, request pluginEBPFMapScanRequest) (pluginEBPFMapScanResult, error) {
	if pm == nil {
		return pluginEBPFMapScanResult{}, errPluginRuntimeTargetNotLoaded
	}
	var notLoaded error
	for _, candidate := range []any{pm.kernelRuntime, pm.pluginRuntime} {
		controller, ok := candidate.(pluginEBPFMapScanController)
		if !ok || controller == nil {
			continue
		}
		result, err := controller.ScanPluginMap(pluginID, objectID, mapName, request)
		if err == nil {
			return result, nil
		}
		if errors.Is(err, errPluginRuntimeTargetNotLoaded) {
			notLoaded = err
			continue
		}
		return pluginEBPFMapScanResult{}, err
	}
	if notLoaded != nil {
		return pluginEBPFMapScanResult{}, notLoaded
	}
	return pluginEBPFMapScanResult{}, errPluginRuntimeTargetNotLoaded
}

func (pm *ProcessManager) ReadPluginRingBuffer(pluginID string, objectID string, mapName string, request pluginEBPFRingReadRequest) (pluginEBPFRingReadResult, error) {
	if pm == nil {
		return pluginEBPFRingReadResult{}, errPluginRuntimeTargetNotLoaded
	}
	var notLoaded error
	for _, candidate := range []any{pm.kernelRuntime, pm.pluginRuntime} {
		controller, ok := candidate.(pluginEBPFRingReadController)
		if !ok || controller == nil {
			continue
		}
		result, err := controller.ReadPluginRingBuffer(pluginID, objectID, mapName, request)
		if err == nil {
			return result, nil
		}
		if errors.Is(err, errPluginRuntimeTargetNotLoaded) {
			notLoaded = err
			continue
		}
		return pluginEBPFRingReadResult{}, err
	}
	if notLoaded != nil {
		return pluginEBPFRingReadResult{}, notLoaded
	}
	return pluginEBPFRingReadResult{}, errPluginRuntimeTargetNotLoaded
}

func (pm *ProcessManager) PutPluginMapValue(pluginID string, objectID string, mapName string, key []byte, value []byte) error {
	return pm.withPluginMapController(func(controller pluginEBPFMapController) error {
		return controller.PutPluginMapValue(pluginID, objectID, mapName, key, value)
	})
}

func (pm *ProcessManager) TransactionPluginMaps(pluginID string, request pluginEBPFMapTransactionRequest) error {
	if pm == nil {
		return errPluginRuntimeTargetNotLoaded
	}
	var notLoaded error
	for _, candidate := range []any{pm.kernelRuntime, pm.pluginRuntime} {
		controller, ok := candidate.(pluginEBPFMapTransactionController)
		if !ok || controller == nil {
			continue
		}
		err := controller.TransactionPluginMaps(pluginID, request)
		if err == nil {
			return nil
		}
		if errors.Is(err, errPluginRuntimeTargetNotLoaded) {
			notLoaded = err
			continue
		}
		return err
	}
	if notLoaded != nil {
		return notLoaded
	}
	return errPluginRuntimeTargetNotLoaded
}

func (pm *ProcessManager) DeletePluginMapValue(pluginID string, objectID string, mapName string, key []byte) error {
	return pm.withPluginMapController(func(controller pluginEBPFMapController) error {
		return controller.DeletePluginMapValue(pluginID, objectID, mapName, key)
	})
}

func (pm *ProcessManager) ClearPluginMap(pluginID string, objectID string, mapName string) error {
	return pm.withPluginMapController(func(controller pluginEBPFMapController) error {
		return controller.ClearPluginMap(pluginID, objectID, mapName)
	})
}

func (pm *ProcessManager) withPluginMapController(fn func(pluginEBPFMapController) error) error {
	if pm == nil {
		return errPluginRuntimeTargetNotLoaded
	}
	var notLoaded error
	for _, candidate := range []any{pm.kernelRuntime, pm.pluginRuntime} {
		controller, ok := candidate.(pluginEBPFMapController)
		if !ok || controller == nil {
			continue
		}
		err := fn(controller)
		if err == nil {
			return nil
		}
		if errors.Is(err, errPluginRuntimeTargetNotLoaded) {
			notLoaded = err
			continue
		}
		return err
	}
	if notLoaded != nil {
		return notLoaded
	}
	return errPluginRuntimeTargetNotLoaded
}
