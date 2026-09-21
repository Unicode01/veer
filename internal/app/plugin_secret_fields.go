package app

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Top-level AAD is unchanged so existing encrypted records remain readable.
// Nested locations use an unambiguous encoding distinct from field tokens.
func pluginSecretValuePath(path []string) string {
	if len(path) == 1 {
		return path[0]
	}
	encoded, _ := json.Marshal(path)
	return "$" + string(encoded)
}

func walkPluginJSON(raw json.RawMessage, path []string, visit func([]string, json.RawMessage) (json.RawMessage, bool, error)) (json.RawMessage, error) {
	next, handled, err := visit(path, raw)
	if err != nil || handled {
		return next, err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return raw, nil
	}
	changed := false
	switch trimmed[0] {
	case '{':
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return nil, err
		}
		for key, value := range object {
			updated, err := walkPluginJSON(value, append(path, key), visit)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(value, updated) {
				object[key], changed = updated, true
			}
		}
		if changed {
			return json.Marshal(object)
		}
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, err
		}
		for i, value := range items {
			index, _ := json.Marshal(i)
			updated, err := walkPluginJSON(value, append(path, string(index)), visit)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(value, updated) {
				items[i], changed = updated, true
			}
		}
		if changed {
			return json.Marshal(items)
		}
	}
	return raw, nil
}

func transformPluginSecretFields(raw json.RawMessage, resource PluginResource, transform func(string, json.RawMessage) (json.RawMessage, error)) (json.RawMessage, error) {
	fields := pluginSecretFieldSet(resource)
	return walkPluginJSON(raw, nil, func(path []string, value json.RawMessage) (json.RawMessage, bool, error) {
		if len(path) == 0 {
			return value, false, nil
		}
		if _, secret := fields[strings.ToLower(path[len(path)-1])]; !secret {
			return value, false, nil
		}
		next, err := transform(pluginSecretValuePath(path), value)
		return next, true, err
	})
}

// An omitted object retains only its secret descendants. Arrays are matched by
// position only when still present; removing an array removes its elements.
func mergePluginSecretJSON(next, existing json.RawMessage, fields map[string]struct{}) (json.RawMessage, error) {
	var previous map[string]json.RawMessage
	if json.Unmarshal(existing, &previous) == nil && previous != nil {
		current := make(map[string]json.RawMessage)
		if len(next) > 0 && (json.Unmarshal(next, &current) != nil || current == nil) {
			return next, nil
		}
		changed := false
		for key, value := range previous {
			nextKey := key
			if _, ok := current[key]; !ok {
				for candidate := range current {
					if strings.EqualFold(candidate, key) {
						nextKey = candidate
						break
					}
				}
			}
			input, present := current[nextKey]
			var merged json.RawMessage
			if _, secret := fields[strings.ToLower(key)]; secret {
				if present && !pluginSecretFieldValueIsRedacted(input) {
					continue
				}
				merged = value
			} else {
				var err error
				merged, err = mergePluginSecretJSON(input, value, fields)
				if err != nil {
					return nil, err
				}
			}
			if len(merged) > 0 && !bytes.Equal(input, merged) {
				current[nextKey], changed = merged, true
			}
		}
		if changed {
			return json.Marshal(current)
		}
		return next, nil
	}
	var oldItems, newItems []json.RawMessage
	if len(next) > 0 && json.Unmarshal(existing, &oldItems) == nil && json.Unmarshal(next, &newItems) == nil {
		changed := false
		for i := 0; i < len(oldItems) && i < len(newItems); i++ {
			merged, err := mergePluginSecretJSON(newItems[i], oldItems[i], fields)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(newItems[i], merged) {
				newItems[i], changed = merged, true
			}
		}
		if changed {
			return json.Marshal(newItems)
		}
	}
	return next, nil
}
