package app

import "errors"

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

func (pm *ProcessManager) PutPluginMapValue(pluginID string, objectID string, mapName string, key []byte, value []byte) error {
	return pm.withPluginMapController(func(controller pluginEBPFMapController) error {
		return controller.PutPluginMapValue(pluginID, objectID, mapName, key, value)
	})
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
