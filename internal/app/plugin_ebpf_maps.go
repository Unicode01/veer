package app

import "errors"

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
