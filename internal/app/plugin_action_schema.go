package app

import (
	"encoding/json"
	"fmt"
)

func normalizePluginActionSchemas(action *PluginAction) error {
	if action == nil {
		return fmt.Errorf("action is required")
	}
	if err := normalizePluginSchema(&action.RequestSchemaVersion, &action.RequestSchema, &action.RequestSchemaDigest); err != nil {
		return fmt.Errorf("request_schema: %w", err)
	}
	if err := normalizePluginSchema(&action.ResponseSchemaVersion, &action.ResponseSchema, &action.ResponseSchemaDigest); err != nil {
		return fmt.Errorf("response_schema: %w", err)
	}
	if len(action.ResponseSchema) > 0 && action.RuntimeUpdate != "runtime_query" {
		return fmt.Errorf("response_schema is supported only for runtime_query actions")
	}
	return nil
}

func validatePluginActionRequest(action PluginAction, payload []byte) error {
	if len(payload) == 0 {
		payload = []byte(`{}`)
	}
	if len(payload) > pluginActionMaxPayloadBytes(action) {
		return fmt.Errorf("action %s request exceeds %d bytes", action.ID, pluginActionMaxPayloadBytes(action))
	}
	if err := validatePluginSchema(action.RequestSchemaDigest, action.RequestSchema, payload); err != nil {
		return fmt.Errorf("action %s request %w", action.ID, err)
	}
	return nil
}

func validatePluginActionResponse(action PluginAction, result any) error {
	if len(action.ResponseSchema) == 0 {
		return nil
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("action %s response is not JSON serializable: %w", action.ID, err)
	}
	if err := validatePluginSchema(action.ResponseSchemaDigest, action.ResponseSchema, raw); err != nil {
		return fmt.Errorf("action %s response %w", action.ID, err)
	}
	return nil
}

func validatePluginSchemaVersionChange(kind, id, side string, previousVersion int, previousDigest string, candidateVersion int, candidateDigest string) error {
	if previousVersion == candidateVersion && previousDigest != candidateDigest {
		return fmt.Errorf("%s %s %s schema changed without increasing schema_version %d", kind, id, side, candidateVersion)
	}
	return nil
}

func validatePluginActionContractUpgrade(previous, candidate LoadedPlugin) error {
	previousActions := make(map[string]PluginAction, len(previous.Actions))
	for _, action := range previous.Actions {
		previousActions[action.ID] = action
	}
	for _, action := range candidate.Actions {
		old, ok := previousActions[action.ID]
		if !ok {
			continue
		}
		if err := validatePluginSchemaVersionChange("action", action.ID, "request", old.RequestSchemaVersion, old.RequestSchemaDigest, action.RequestSchemaVersion, action.RequestSchemaDigest); err != nil {
			return err
		}
		if err := validatePluginSchemaVersionChange("action", action.ID, "response", old.ResponseSchemaVersion, old.ResponseSchemaDigest, action.ResponseSchemaVersion, action.ResponseSchemaDigest); err != nil {
			return err
		}
	}
	return nil
}
