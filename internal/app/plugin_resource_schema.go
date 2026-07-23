package app

import "fmt"

func normalizePluginResourceSchema(resource *PluginResource) error {
	return normalizePluginSchema(&resource.SchemaVersion, &resource.Schema, &resource.SchemaDigest)
}

func validatePluginResourceData(resource PluginResource, data []byte) error {
	if err := validatePluginSchema(resource.SchemaDigest, resource.Schema, data); err != nil {
		return fmt.Errorf("resource %s data %w", resource.ID, err)
	}
	return nil
}
