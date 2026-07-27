# go-ctap/mds

`go-ctap/mds` fetches, verifies, caches, and queries FIDO Metadata Service
(MDS3) blobs.

The client verifies the compact JWT signature, validates the MDS signing
certificate chain and its revocation status, rejects blob rollback, and indexes
metadata entries by AAGUID.

`AssessAttestation` can then validate an already format-verified authenticator
attestation certificate chain against roots in the matching metadata statement
and report relevant authenticator statuses. The result contains trust facts and
stable issue codes; relying-party acceptance policy remains outside this module.

## Usage

```go
client := &mds.Client{}
result, err := client.Lookup(ctx, aaguid, mds.LookupOptions{
    AllowStaleOnFetchError: true,
})
```

Format-level attestation parsing and signature verification belongs to
[`github.com/go-ctap/ctap/attestation`](https://pkg.go.dev/github.com/go-ctap/ctap/attestation).
