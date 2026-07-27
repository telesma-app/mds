package model

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMetadataStatementDecodesAuthenticatorGetInfoByteStringsFromHex(t *testing.T) {
	var statement MetadataStatement
	err := json.Unmarshal([]byte(`{
		"description":"Authenticator",
		"authenticatorGetInfo":{
			"encIdentifier":"00ff",
			"pinComplexityPolicyURL":"68747470733a2f2f797562692e636f2f70696e",
			"encCredStoreState":"010203"
		}
	}`), &statement)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if statement.Description != "Authenticator" {
		t.Fatalf("Description = %q", statement.Description)
	}

	if !bytes.Equal(statement.AuthenticatorGetInfo.EncIdentifier, []byte{0x00, 0xff}) {
		t.Fatalf("EncIdentifier = %x", statement.AuthenticatorGetInfo.EncIdentifier)
	}

	if got := string(statement.AuthenticatorGetInfo.PinComplexityPolicyURL); got != "https://yubi.co/pin" {
		t.Fatalf("PinComplexityPolicyURL = %q", got)
	}

	if !bytes.Equal(statement.AuthenticatorGetInfo.EncCredStoreState, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("EncCredStoreState = %x", statement.AuthenticatorGetInfo.EncCredStoreState)
	}
}

func TestMetadataStatementRejectsInvalidAuthenticatorGetInfoHex(t *testing.T) {
	var statement MetadataStatement
	err := json.Unmarshal([]byte(`{
		"authenticatorGetInfo":{"pinComplexityPolicyURL":"not hex"}
	}`), &statement)
	if err == nil {
		t.Fatal("Unmarshal succeeded with invalid byte string")
	}
}

func TestMDSJSONFieldContracts(t *testing.T) {
	const batchCertificate = "batch-certificate"

	statusJSON, err := json.Marshal(StatusReport{BatchCertificate: stringPointer(batchCertificate)})
	if err != nil {
		t.Fatalf("marshal status report: %v", err)
	}
	if !strings.Contains(string(statusJSON), `"batchCertificate":"batch-certificate"`) {
		t.Fatalf("status JSON = %s, want batchCertificate", statusJSON)
	}
	emptyStatusJSON, err := json.Marshal(StatusReport{})
	if err != nil {
		t.Fatalf("marshal empty status report: %v", err)
	}
	if strings.Contains(string(emptyStatusJSON), "batchCertificate") {
		t.Fatalf("empty status JSON = %s, want omitted batchCertificate", emptyStatusJSON)
	}
}

func stringPointer(value string) *string {
	return &value
}
