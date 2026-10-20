# telesma-app/mds

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/mds.svg)](https://pkg.go.dev/github.com/telesma-app/mds)
[![Go](https://github.com/telesma-app/mds/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/mds/actions/workflows/go.yml)

`telesma-app/mds` is a Go client for the FIDO Metadata Service (MDS3).

> [!WARNING]
> This module is under active development. Its public API may change during `v0.x`.

## Features

- downloads and verifies the signed FIDO metadata BLOB;
- validates the signing certificate chain and CRLs;
- rejects metadata rollback;
- caches verified metadata and limits network requests;
- looks up metadata by AAGUID;
- checks verified authenticator attestations against metadata roots and status
  reports.

## Installation

```sh
go get github.com/telesma-app/mds@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Quick start

```go
client := mds.NewClient()

result, err := client.Lookup(ctx, aaguid, mds.LookupOptions{})
if err != nil {
    return err
}
if result.Found {
    fmt.Println(result.Entry.MetadataStatement.Description)
}
```

`Lookup` uses the official FIDO MDS endpoint by default.

## Caching

The client shares an in-memory cache and stores verified, signed BLOBs in the
platform user cache directory; use `mds.WithCacheDir` to choose another location.
Cached metadata refreshes automatically after a day. `LookupOptions{Refresh: true}`
requests an earlier refresh, subject to a one-hour minimum interval.

`Cached` identifies a local result, and `CheckedAt` records its last successful
network check. If an update fails, verified cached data remains available with
`RefreshErr`; failures without usable cache and canceled refreshes return an error.

## Attestation checks

`AssessAttestation` compares an already verified attestation with metadata roots
and status reports. Parse and verify the attestation with
[`ctap/attestation`](https://pkg.go.dev/github.com/telesma-app/ctap/attestation)
first; the relying party owns acceptance policy. An AAGUID lookup alone does not
authenticate the connected device.

## Testing

```sh
go test ./...
go vet ./...
```

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
