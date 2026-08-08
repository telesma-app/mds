# go-ctap/mds

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/mds.svg)](https://pkg.go.dev/github.com/telesma-app/mds)
[![Go](https://github.com/telesma-app/mds/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/mds/actions/workflows/go.yml)

`go-ctap/mds` is a Go client for the FIDO Metadata Service (MDS3).

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

The client always checks its verified cache before making a network request.
It uses an in-memory cache and stores the signed BLOB in the platform user
cache directory.

Use `WithCacheDir` when the application owns the cache location:

```go
client := mds.NewClient(
    mds.WithCacheDir("/var/cache/my-service/fido-mds"),
)
```

Automatic refresh runs at most once per day. An explicit refresh is limited to
one request per hour for each cache key:

```go
result, err := client.Lookup(ctx, aaguid, mds.LookupOptions{
    Refresh: true,
})
```

The request includes `localCopySerial` when a local BLOB exists. If refresh
fails, the client returns the last verified local BLOB and delays the next
automatic attempt.

## Attestation checks

`AssessAttestation` compares an already verified authenticator attestation
certificate chain with the matching metadata statement. It reports trust facts
and authenticator status issues.

Attestation parsing and format-level signature verification belong to
[`github.com/telesma-app/ctap/attestation`](https://pkg.go.dev/github.com/telesma-app/ctap/attestation).
The relying party remains responsible for its acceptance policy.

## Testing

```sh
go test ./...
go vet ./...
```

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
