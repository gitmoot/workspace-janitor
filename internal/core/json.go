package core

import (
	"bytes"
	"encoding/json"
)

// MarshalJSON encodes v as compact JSON without HTML escaping.
//
// Determinism is a contract: struct fields encode in declaration order, map
// keys are sorted by encoding/json, and no timestamp or randomness is added
// here. Callers that need stable output must pass values that contain no
// unordered collections other than string-keyed maps.
func MarshalJSON(v any) ([]byte, error) { return encodeJSON(v, "") }

// MarshalIndentJSON is MarshalJSON with two-space indentation.
func MarshalIndentJSON(v any) ([]byte, error) { return encodeJSON(v, "  ") }

func encodeJSON(v any, indent string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent != "" {
		enc.SetIndent("", indent)
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
