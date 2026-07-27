package model

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/go-ctap/ctap/protocol"
)

var authenticatorGetInfoByteStringFields = [...]string{
	"encIdentifier",
	"pinComplexityPolicyURL",
	"encCredStoreState",
}

func (statement *MetadataStatement) UnmarshalJSON(data []byte) error {
	type metadataStatement MetadataStatement

	var decoded metadataStatement
	wire := struct {
		*metadataStatement
		AuthenticatorGetInfo json.RawMessage `json:"authenticatorGetInfo"`
	}{
		metadataStatement: &decoded,
	}

	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}

	if len(wire.AuthenticatorGetInfo) != 0 && string(wire.AuthenticatorGetInfo) != "null" {
		info, err := unmarshalAuthenticatorGetInfo(wire.AuthenticatorGetInfo)
		if err != nil {
			return err
		}
		decoded.AuthenticatorGetInfo = info
	}

	*statement = MetadataStatement(decoded)

	return nil
}

func unmarshalAuthenticatorGetInfo(data []byte) (protocol.AuthenticatorGetInfoResponse, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return protocol.AuthenticatorGetInfoResponse{}, err
	}

	for _, name := range authenticatorGetInfoByteStringFields {
		raw, present := fields[name]
		if !present || string(raw) == "null" {
			continue
		}

		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return protocol.AuthenticatorGetInfoResponse{}, fmt.Errorf("decode authenticatorGetInfo.%s: %w", name, err)
		}

		value, err := hex.DecodeString(encoded)
		if err != nil {
			return protocol.AuthenticatorGetInfoResponse{}, fmt.Errorf("decode authenticatorGetInfo.%s: %w", name, err)
		}

		fields[name], err = json.Marshal(value)
		if err != nil {
			return protocol.AuthenticatorGetInfoResponse{}, err
		}
	}

	normalized, err := json.Marshal(fields)
	if err != nil {
		return protocol.AuthenticatorGetInfoResponse{}, err
	}

	var info protocol.AuthenticatorGetInfoResponse
	if err := json.Unmarshal(normalized, &info); err != nil {
		return protocol.AuthenticatorGetInfoResponse{}, err
	}

	return info, nil
}
