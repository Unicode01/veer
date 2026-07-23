package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	pluginSchemaMaxBytes   = 64 << 10
	pluginSchemaMaxVersion = 1_000_000
	pluginSchemaCacheLimit = 512
)

var pluginSchemas = struct {
	sync.Mutex
	values map[string]*jsonschema.Schema
}{values: make(map[string]*jsonschema.Schema)}

type pluginSchemaLoader struct{}

func (pluginSchemaLoader) Load(location string) (any, error) {
	return nil, fmt.Errorf("external schema reference %q is not allowed", location)
}

func normalizePluginSchema(version *int, raw *json.RawMessage, digest *string) error {
	if version == nil || raw == nil || digest == nil {
		return fmt.Errorf("schema contract is invalid")
	}
	if *version <= 0 {
		*version = 1
	}
	if *version > pluginSchemaMaxVersion {
		return fmt.Errorf("schema_version exceeds %d", pluginSchemaMaxVersion)
	}
	*digest = ""
	if len(*raw) == 0 || bytes.Equal(bytes.TrimSpace(*raw), []byte("null")) {
		*raw = nil
		return nil
	}
	if len(*raw) > pluginSchemaMaxBytes {
		return fmt.Errorf("schema exceeds %d bytes", pluginSchemaMaxBytes)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(*raw))
	if err != nil {
		return fmt.Errorf("schema must be valid JSON: %w", err)
	}
	if _, ok := document.(map[string]any); !ok {
		return fmt.Errorf("schema must be a JSON object")
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("canonicalize schema: %w", err)
	}
	if len(canonical) > pluginSchemaMaxBytes {
		return fmt.Errorf("schema exceeds %d bytes", pluginSchemaMaxBytes)
	}
	hash := sha256.Sum256(canonical)
	*raw = json.RawMessage(canonical)
	*digest = hex.EncodeToString(hash[:])
	if _, err := compilePluginSchema(*digest, *raw); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	return nil
}

func validatePluginSchema(digest string, raw json.RawMessage, data []byte) error {
	if !json.Valid(data) {
		return fmt.Errorf("value is not valid JSON")
	}
	if len(raw) == 0 {
		return nil
	}
	schema, err := compilePluginSchema(digest, raw)
	if err != nil {
		return fmt.Errorf("schema is invalid: %w", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("value is invalid JSON: %w", err)
	}
	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("value does not match schema: %s", compactPluginSchemaError(err))
	}
	return nil
}

func compilePluginSchema(digest string, raw json.RawMessage) (*jsonschema.Schema, error) {
	digest = strings.TrimSpace(strings.ToLower(digest))
	if len(raw) == 0 || len(digest) != sha256.Size*2 {
		return nil, fmt.Errorf("schema digest is missing or invalid")
	}
	actual := sha256.Sum256(raw)
	if hex.EncodeToString(actual[:]) != digest {
		return nil, fmt.Errorf("schema digest does not match schema content")
	}
	pluginSchemas.Lock()
	if schema := pluginSchemas.values[digest]; schema != nil {
		pluginSchemas.Unlock()
		return schema, nil
	}
	pluginSchemas.Unlock()

	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.UseLoader(pluginSchemaLoader{})
	location := "https://veer.invalid/plugin-schema/" + digest + "/schema.json"
	if err := compiler.AddResource(location, document); err != nil {
		return nil, err
	}
	schema, err := compiler.Compile(location)
	if err != nil {
		return nil, err
	}
	pluginSchemas.Lock()
	if existing := pluginSchemas.values[digest]; existing != nil {
		pluginSchemas.Unlock()
		return existing, nil
	}
	if len(pluginSchemas.values) >= pluginSchemaCacheLimit {
		pluginSchemas.values = make(map[string]*jsonschema.Schema)
	}
	pluginSchemas.values[digest] = schema
	pluginSchemas.Unlock()
	return schema, nil
}

func compactPluginSchemaError(err error) string {
	message := strings.Join(strings.Fields(strings.TrimSpace(err.Error())), " ")
	if len(message) > 1024 {
		message = message[:1024] + "...<truncated>"
	}
	return message
}
