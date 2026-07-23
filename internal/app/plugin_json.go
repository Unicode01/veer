package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

const pluginJSONMaxDepth = 64

func rejectPluginDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var consumeValue func(int) error
	consumeValue = func(depth int) error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		if depth >= pluginJSONMaxDepth {
			return fmt.Errorf("JSON nesting exceeds %d levels", pluginJSONMaxDepth)
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("JSON object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("JSON object contains duplicate key %q", key)
				}
				seen[key] = struct{}{}
				if err := consumeValue(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				if err != nil {
					return err
				}
				return fmt.Errorf("JSON object is not terminated")
			}
		case '[':
			for decoder.More() {
				if err := consumeValue(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				if err != nil {
					return err
				}
				return fmt.Errorf("JSON array is not terminated")
			}
		default:
			return fmt.Errorf("invalid JSON delimiter %q", delimiter)
		}
		return nil
	}
	if err := consumeValue(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("JSON contains trailing values")
		}
		return err
	}
	return nil
}
