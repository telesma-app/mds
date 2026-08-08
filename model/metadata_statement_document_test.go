package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

var errRejectJSONValue = errors.New("reject JSON value")

type rejectingJSONValue struct{}

func (*rejectingJSONValue) UnmarshalJSON([]byte) error {
	return errRejectJSONValue
}

func TestParseMetadataStatementDocumentPreservesFieldRepresentations(t *testing.T) {
	document, err := ParseMetadataStatementDocument([]byte(`{
		"nullValue": null,
		"falseValue": false,
		"zeroValue": 0,
		"wrongType": "false"
	}`))
	if err != nil {
		t.Fatalf("ParseMetadataStatementDocument: %v", err)
	}

	want := map[string][]byte{
		"nullValue":  []byte("null"),
		"falseValue": []byte("false"),
		"zeroValue":  []byte("0"),
		"wrongType":  []byte(`"false"`),
	}
	for name, wantRaw := range want {
		raw, present := document[name]
		if !present {
			t.Errorf("field %q is absent", name)
			continue
		}
		if !bytes.Equal(raw, wantRaw) {
			t.Errorf("field %q = %s, want %s", name, raw, wantRaw)
		}
	}

	if _, present := document["absentValue"]; present {
		t.Error("absentValue is present")
	}
}

func TestMetadataStatementDocumentDecodeField(t *testing.T) {
	document, err := ParseMetadataStatementDocument([]byte(`{
		"nullValue": null,
		"falseValue": false,
		"zeroValue": 0,
		"wrongType": "false"
	}`))
	if err != nil {
		t.Fatalf("ParseMetadataStatementDocument: %v", err)
	}

	var absent bool
	present, err := document.DecodeField("absentValue", &absent)
	if err != nil {
		t.Fatalf("DecodeField(absentValue): %v", err)
	}
	if present {
		t.Error("DecodeField(absentValue) present = true, want false")
	}

	nullValue := new(bool)
	present, err = document.DecodeField("nullValue", &nullValue)
	if err != nil {
		t.Fatalf("DecodeField(nullValue): %v", err)
	}
	if !present {
		t.Fatal("DecodeField(nullValue) present = false, want true")
	}
	if nullValue != nil {
		t.Errorf("DecodeField(nullValue) = %v, want nil", *nullValue)
	}

	var falseValue bool
	present, err = document.DecodeField("falseValue", &falseValue)
	if err != nil {
		t.Fatalf("DecodeField(falseValue): %v", err)
	}
	if !present {
		t.Fatal("DecodeField(falseValue) present = false, want true")
	}
	if falseValue {
		t.Error("DecodeField(falseValue) = true, want false")
	}

	var zeroValue int
	present, err = document.DecodeField("zeroValue", &zeroValue)
	if err != nil {
		t.Fatalf("DecodeField(zeroValue): %v", err)
	}
	if !present {
		t.Fatal("DecodeField(zeroValue) present = false, want true")
	}
	if zeroValue != 0 {
		t.Errorf("DecodeField(zeroValue) = %d, want 0", zeroValue)
	}

	present, err = document.DecodeField("wrongType", &falseValue)
	if !present {
		t.Fatal("DecodeField(wrongType) present = false, want true")
	}
	if err == nil {
		t.Fatal("DecodeField(wrongType) succeeded")
	}
	if !strings.Contains(err.Error(), `field "wrongType"`) {
		t.Errorf("DecodeField(wrongType) error = %q, want field context", err)
	}

	var typeError *json.UnmarshalTypeError
	if !errors.As(err, &typeError) {
		t.Errorf("errors.As(%v, *json.UnmarshalTypeError) = false", err)
	}

	var rejecting rejectingJSONValue
	present, err = document.DecodeField("falseValue", &rejecting)
	if !present {
		t.Fatal("DecodeField(falseValue) present = false, want true")
	}
	if !errors.Is(err, errRejectJSONValue) {
		t.Errorf("errors.Is(%v, errRejectJSONValue) = false", err)
	}
	if !strings.Contains(err.Error(), `field "falseValue"`) {
		t.Errorf("DecodeField(falseValue) error = %q, want field context", err)
	}
}

func TestParseMetadataStatementDocumentRejectsDuplicateMembers(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "top level", raw: `{"name": 1, "name": 2}`},
		{name: "escaped equivalent", raw: `{"name": 1, "\u006eame": 2}`},
		{name: "surrogate equivalent", raw: `{"😀": 1, "\uD83D\uDE00": 2}`},
		{name: "nested object", raw: `{"nested": {"name": 1, "name": 2}}`},
		{name: "object in array", raw: `{"nested": [{"name": 1, "name": 2}]}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseMetadataStatementDocument([]byte(test.raw)); err == nil {
				t.Fatal("ParseMetadataStatementDocument succeeded")
			}
		})
	}
}

func TestParseMetadataStatementDocumentRejectsInvalidUTF8(t *testing.T) {
	invalidValue := append([]byte(`{"nested":{"value":"`), 0xff)
	invalidValue = append(invalidValue, []byte(`"}}`)...)

	invalidKey := append([]byte(`{"nested":{"`), 0xff)
	invalidKey = append(invalidKey, []byte(`":true}}`)...)

	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{name: "nested value", raw: invalidValue},
		{name: "nested key", raw: invalidKey},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseMetadataStatementDocument(test.raw); err == nil {
				t.Fatal("ParseMetadataStatementDocument succeeded")
			}
		})
	}
}

func TestParseMetadataStatementDocumentRejectsInvalidSurrogateEscapes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "lone high surrogate", raw: `{"value":"\uD800"}`},
		{name: "lone low surrogate", raw: `{"value":"\uDC00"}`},
		{name: "high followed by non-surrogate", raw: `{"value":"\uD800\u0041"}`},
		{name: "high followed by high", raw: `{"value":"\uD800\uD801"}`},
		{name: "nested value", raw: `{"nested":[{"value":"\uD800"}]}`},
		{name: "object member name", raw: `{"\uD800":true}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseMetadataStatementDocument([]byte(test.raw)); err == nil {
				t.Fatal("ParseMetadataStatementDocument succeeded")
			}
		})
	}
}

func TestParseMetadataStatementDocumentPreservesNestedFieldRepresentation(t *testing.T) {
	document, err := ParseMetadataStatementDocument([]byte(`{
		"nested": {"items":[ 1, {"flag":false} ],"escaped":"\uD83D\uDE00"},
		"array": [null, 0]
	}`))
	if err != nil {
		t.Fatalf("ParseMetadataStatementDocument: %v", err)
	}

	want := map[string][]byte{
		"nested": []byte(`{"items":[ 1, {"flag":false} ],"escaped":"\uD83D\uDE00"}`),
		"array":  []byte(`[null, 0]`),
	}
	for name, wantRaw := range want {
		if got := document[name]; !bytes.Equal(got, wantRaw) {
			t.Errorf("field %q = %s, want %s", name, got, wantRaw)
		}
	}
}

func TestParseMetadataStatementDocumentAcceptsEmptyObject(t *testing.T) {
	document, err := ParseMetadataStatementDocument([]byte(" \n\t{} \r\n"))
	if err != nil {
		t.Fatalf("ParseMetadataStatementDocument: %v", err)
	}
	if len(document) != 0 {
		t.Fatalf("len(document) = %d, want 0", len(document))
	}
}

func TestParseMetadataStatementDocumentRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "trailing value", raw: `{}` + ` {}`},
		{name: "trailing malformed data", raw: `{} trailing`},
		{name: "array", raw: `[]`},
		{name: "string", raw: `"object"`},
		{name: "number", raw: `1`},
		{name: "boolean", raw: `false`},
		{name: "null", raw: `null`},
		{name: "malformed object", raw: `{"description":`},
		{name: "empty", raw: ``},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseMetadataStatementDocument([]byte(test.raw)); err == nil {
				t.Fatal("ParseMetadataStatementDocument succeeded")
			}
		})
	}
}
