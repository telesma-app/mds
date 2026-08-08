package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// MetadataStatementDocument preserves the raw JSON representation of each
// field in a FIDO Metadata Statement.
type MetadataStatementDocument map[string]json.RawMessage

// ParseMetadataStatementDocument parses exactly one JSON object without
// applying Metadata Statement semantics.
func ParseMetadataStatementDocument(raw []byte) (MetadataStatementDocument, error) {
	if err := validateMetadataStatementDocument(raw); err != nil {
		return nil, fmt.Errorf("decode metadata statement document: %w", err)
	}

	var document MetadataStatementDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode metadata statement document: %w", err)
	}

	return document, nil
}

func validateMetadataStatementDocument(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8")
	}
	if err := validateJSONUnicodeEscapes(raw); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("top-level value must be an object")
	}
	if err := validateJSONObject(decoder); err != nil {
		return err
	}

	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("trailing data: %w", err)
		}

		return errors.New("trailing JSON value")
	}

	return nil
}

func validateJSONObject(decoder *json.Decoder) error {
	names := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}

		name, ok := token.(string)
		if !ok {
			return errors.New("object member name is not a string")
		}
		if _, duplicate := names[name]; duplicate {
			return fmt.Errorf("duplicate object member %q", name)
		}
		names[name] = struct{}{}

		if err := validateJSONValue(decoder); err != nil {
			return err
		}
	}

	return consumeJSONDelimiter(decoder, '}')
}

func validateJSONArray(decoder *json.Decoder) error {
	for decoder.More() {
		if err := validateJSONValue(decoder); err != nil {
			return err
		}
	}

	return consumeJSONDelimiter(decoder, ']')
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		return validateJSONObject(decoder)
	case '[':
		return validateJSONArray(decoder)
	default:
		return fmt.Errorf("unexpected delimiter %q", delimiter)
	}
}

func consumeJSONDelimiter(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != want {
		return fmt.Errorf("unexpected delimiter %v", token)
	}

	return nil
}

func validateJSONUnicodeEscapes(raw []byte) error {
	for offset := 0; offset < len(raw); offset++ {
		if raw[offset] != '"' {
			continue
		}

		end, err := validateJSONStringUnicodeEscapes(raw, offset+1)
		if err != nil {
			return err
		}
		offset = end
	}

	return nil
}

func validateJSONStringUnicodeEscapes(raw []byte, offset int) (int, error) {
	for offset < len(raw) {
		switch raw[offset] {
		case '"':
			return offset, nil
		case '\\':
			if offset+1 >= len(raw) {
				return 0, errors.New("unterminated string escape")
			}
			if raw[offset+1] != 'u' {
				offset += 2

				continue
			}

			codeUnit, ok := decodeJSONHexCodeUnit(raw, offset+2)
			if !ok {
				return 0, errors.New("invalid Unicode escape")
			}
			offset += 6

			switch {
			case codeUnit >= 0xd800 && codeUnit <= 0xdbff:
				if offset+6 > len(raw) || raw[offset] != '\\' || raw[offset+1] != 'u' {
					return 0, errors.New("high surrogate is not followed by a low surrogate")
				}

				low, ok := decodeJSONHexCodeUnit(raw, offset+2)
				if !ok || low < 0xdc00 || low > 0xdfff {
					return 0, errors.New("high surrogate is not followed by a low surrogate")
				}
				offset += 6
			case codeUnit >= 0xdc00 && codeUnit <= 0xdfff:
				return 0, errors.New("low surrogate is not preceded by a high surrogate")
			}
		default:
			_, size := utf8.DecodeRune(raw[offset:])
			offset += size
		}
	}

	return 0, errors.New("unterminated string")
}

func decodeJSONHexCodeUnit(raw []byte, offset int) (uint16, bool) {
	if offset+4 > len(raw) {
		return 0, false
	}

	var value uint16
	for _, digit := range raw[offset : offset+4] {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value |= uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}

	return value, true
}

// DecodeField reports whether name is present and, when it is, decodes its
// raw JSON value into target.
func (document MetadataStatementDocument) DecodeField(name string, target any) (bool, error) {
	raw, present := document[name]
	if !present {
		return false, nil
	}

	if err := json.Unmarshal(raw, target); err != nil {
		return true, fmt.Errorf("decode metadata statement field %q: %w", name, err)
	}

	return true, nil
}
