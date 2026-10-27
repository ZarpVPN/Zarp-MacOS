package connection

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ValidateDocumentJSON exposes the same grammar for bounded internal protocols.
// The caller's limit cannot exceed the shared request boundary.
func ValidateDocumentJSON(data []byte, maxBytes int) error {
	if maxBytes <= 0 || maxBytes > MaxRequestBytes || len(data) > maxBytes || !strictJSON(data) {
		return Error{Parameters}
	}
	return nil
}

// Reject duplicates, replacement Unicode, non-integer numbers and deep nesting
// before encoding/json can normalize the input.
func strictJSON(data []byte) bool {
	if !utf8.Valid(data) || !json.Valid(data) || !pairedSurrogates(data) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if !walkJSON(d, 0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func walkJSON(d *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	token, err := d.Token()
	if err != nil {
		return false
	}
	switch value := token.(type) {
	case json.Delim:
		if value != '{' && value != '[' {
			return false
		}
		seen := map[string]bool{}
		for d.More() {
			if value == '{' {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
			}
			if !walkJSON(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && (value == '{' && end == json.Delim('}') || value == '[' && end == json.Delim(']'))
	case json.Number:
		return !strings.ContainsAny(string(value), ".eE")
	default:
		return true
	}
}

func pairedSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
		} else if inString && data[i] == '\\' {
			i++
			if i >= len(data) || data[i] != 'u' {
				continue
			}
			value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16) // json.Valid checked the escape length.
			if err != nil {
				return false
			}
			i += 4
			if value >= 0xdc00 && value <= 0xdfff {
				return false
			}
			if value >= 0xd800 && value <= 0xdbff {
				if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
					return false
				}
				low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			}
		}
	}
	return true
}

type object map[string]json.RawMessage

func decodeObject(data []byte, field Field, keys ...string) (object, error) {
	var result object
	if json.Unmarshal(data, &result) != nil || result == nil {
		return nil, Error{field}
	}
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for key := range result {
		if !allowed[key] {
			return nil, Error{Parameters}
		}
	}
	return result, nil
}

func required[T any](o object, key string, field Field) (T, error) {
	var result T
	data, present := o[key]
	if !present || bytes.Equal(data, []byte("null")) {
		return result, Error{field}
	}
	if err := json.Unmarshal(data, &result); err != nil {
		if contract, ok := err.(Error); ok {
			return result, contract
		}
		return result, Error{field}
	}
	return result, nil
}

func optional[T any](o object, key string, field Field, fallback T) (T, error) {
	if data, present := o[key]; !present || bytes.Equal(data, []byte("null")) {
		return fallback, nil
	}
	return required[T](o, key, field)
}
