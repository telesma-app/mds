package mdsverify

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	appmds "github.com/go-ctap/mds/model"
	"github.com/golang-jwt/jwt/v5"
)

const (
	DefaultMaxX5UBytes = 1 << 20  // 1 MiB
	DefaultMaxCRLBytes = 16 << 20 // 16 MiB
)

var ErrVerify = errors.New("verify MDS blob")

// Blob is the verified MDS JWT payload extracted by this package.
type Blob struct {
	Number uint64

	// IssuedAt is best-effort metadata. The MDS draft places iat in the JWT
	// header, while golang-jwt parses the standard payload iat into
	// RegisteredClaims.IssuedAt. Some published blobs omit the header value, so
	// absence is tolerated and represented as zero when neither form is present.
	IssuedAt time.Time

	Entries []appmds.PayloadEntry
}

// Verifier verifies MDS compact JWT blobs according to the MDS processing rules.
// It intentionally knows nothing about local caching, lookup, or RP policy.
type Verifier struct {
	Source       string
	HTTPClient   *http.Client
	TrustAnchors []*x509.Certificate
	Now          func() time.Time

	MaxX5UBytes int64
	MaxCRLBytes int64
}

// Verify parses a compact MDS JWT, verifies its JWS signature, validates the
// MDS signing certificate chain, and checks revocation for that chain.
func (v *Verifier) Verify(ctx context.Context, raw []byte) (*Blob, error) {
	claims := metadataClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{
		jwt.SigningMethodRS256.Alg(),
		jwt.SigningMethodES256.Alg(),
	}), jwt.WithTimeFunc(v.now))

	token, err := parser.ParseWithClaims(string(raw), &claims, func(token *jwt.Token) (any, error) {
		return v.signingKey(ctx, token)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerify, err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("%w: invalid JWT signature", ErrVerify)
	}

	issuedAt, err := tokenIssuedAt(token.Header["iat"], claims.IssuedAt)
	if err != nil {
		return nil, err
	}

	if claims.Number == nil {
		return nil, fmt.Errorf("%w: missing required payload field no", ErrVerify)
	}

	if claims.Entries == nil {
		return nil, fmt.Errorf("%w: missing required payload field entries", ErrVerify)
	}

	return &Blob{
		Number:   *claims.Number,
		IssuedAt: issuedAt,
		Entries:  claims.Entries,
	}, nil
}

func (v *Verifier) signingKey(ctx context.Context, token *jwt.Token) (any, error) {
	certs, err := v.headerCertificates(ctx, token)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		anchors, err := v.trustAnchors()
		if err != nil {
			return nil, err
		}

		if len(anchors) != 1 {
			return nil, fmt.Errorf("%w: exactly one trust anchor is required when JWT header has neither x5u nor x5c", ErrVerify)
		}

		return anchors[0].PublicKey, nil
	}

	if err := v.verifyCertificateChain(ctx, certs); err != nil {
		return nil, err
	}

	return certs[0].PublicKey, nil
}

func (v *Verifier) headerCertificates(ctx context.Context, token *jwt.Token) ([]*x509.Certificate, error) {
	if rawX5U, ok := token.Header["x5u"]; ok {
		x5u, ok := rawX5U.(string)
		if !ok || strings.TrimSpace(x5u) == "" {
			return nil, fmt.Errorf("%w: x5u certificate URL must be a non-empty string", ErrVerify)
		}

		return v.fetchX5UCertificates(ctx, x5u)
	}

	rawValues, ok := token.Header["x5c"].([]any)
	if !ok {
		return nil, nil
	}

	if len(rawValues) == 0 {
		return nil, fmt.Errorf("%w: x5c certificate chain is empty", ErrVerify)
	}

	certs := make([]*x509.Certificate, 0, len(rawValues))
	for _, rawValue := range rawValues {
		value, ok := rawValue.(string)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("%w: x5c certificate value must be a non-empty string", ErrVerify)
		}

		der, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("%w: decode x5c certificate: %w", ErrVerify, err)
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: parse x5c certificate: %w", ErrVerify, err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func (v *Verifier) fetchX5UCertificates(ctx context.Context, rawURL string) ([]*x509.Certificate, error) {
	sourceURL, err := url.Parse(v.Source)
	if err != nil {
		return nil, fmt.Errorf("%w: parse metadata source URL: %w", ErrVerify, err)
	}

	certURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: parse x5u certificate URL: %w", ErrVerify, err)
	}

	if !certURL.IsAbs() || certURL.Fragment != "" {
		return nil, fmt.Errorf("%w: x5u certificate URL must be absolute and must not include a fragment", ErrVerify)
	}

	if !sameWebOrigin(sourceURL, certURL) {
		return nil, fmt.Errorf("%w: x5u certificate URL must have the same web origin as the metadata source", ErrVerify)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, certURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build x5u certificate request: %w", ErrVerify, err)
	}

	resp, err := v.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch x5u certificate chain: %w", ErrVerify, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: fetch x5u certificate chain: unexpected HTTP status %s", ErrVerify, resp.Status)
	}

	body, err := readLimited(resp.Body, v.maxX5UBytes())
	if err != nil {
		return nil, fmt.Errorf("%w: read x5u certificate chain: %w", ErrVerify, err)
	}

	return parseCertificateChain(body)
}

func (v *Verifier) verifyCertificateChain(ctx context.Context, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("%w: certificate chain is empty", ErrVerify)
	}

	anchors, err := v.trustAnchors()
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	for _, anchor := range anchors {
		roots.AddCert(anchor)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	chains, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   v.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("%w: certificate chain: %w", ErrVerify, err)
	}

	if len(chains) == 0 {
		return fmt.Errorf("%w: certificate chain verification returned no chains", ErrVerify)
	}

	return v.verifyCertificateRevocation(ctx, chains[0])
}

func (v *Verifier) verifyCertificateRevocation(ctx context.Context, chain []*x509.Certificate) error {
	for i := 0; i < len(chain)-1; i++ {
		if err := v.verifyCertificateNotRevoked(ctx, chain[i], chain[i+1]); err != nil {
			return err
		}
	}

	return nil
}

func (v *Verifier) verifyCertificateNotRevoked(ctx context.Context, cert, issuer *x509.Certificate) error {
	if len(cert.CRLDistributionPoints) == 0 {
		return fmt.Errorf("%w: certificate %s has no CRL distribution points", ErrVerify, cert.Subject.String())
	}

	var lastErr error
	for _, distributionPoint := range cert.CRLDistributionPoints {
		crl, err := v.fetchRevocationList(ctx, distributionPoint)
		if err != nil {
			lastErr = err
			continue
		}

		if err := crl.CheckSignatureFrom(issuer); err != nil {
			lastErr = fmt.Errorf("%w: CRL signature for certificate %s: %w", ErrVerify, cert.Subject.String(), err)
			continue
		}

		now := v.now()
		if now.Before(crl.ThisUpdate) {
			return fmt.Errorf("%w: CRL for certificate %s is not valid yet", ErrVerify, cert.Subject.String())
		}

		if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
			return fmt.Errorf("%w: CRL for certificate %s is expired", ErrVerify, cert.Subject.String())
		}

		for _, revoked := range crl.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("%w: certificate %s is revoked", ErrVerify, cert.Subject.String())
			}
		}

		return nil
	}

	if lastErr != nil {
		return lastErr
	}

	return fmt.Errorf("%w: certificate %s has no usable CRL distribution points", ErrVerify, cert.Subject.String())
}

func (v *Verifier) fetchRevocationList(ctx context.Context, rawURL string) (*x509.RevocationList, error) {
	crlURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: parse CRL URL: %w", ErrVerify, err)
	}

	if !crlURL.IsAbs() || crlURL.Fragment != "" {
		return nil, fmt.Errorf("%w: CRL URL must be absolute and must not include a fragment", ErrVerify)
	}

	scheme := strings.ToLower(crlURL.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("%w: unsupported CRL URL scheme %q", ErrVerify, crlURL.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build CRL request: %w", ErrVerify, err)
	}

	resp, err := v.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch CRL: %w", ErrVerify, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: fetch CRL: unexpected HTTP status %s", ErrVerify, resp.Status)
	}

	body, err := readLimited(resp.Body, v.maxCRLBytes())
	if err != nil {
		return nil, fmt.Errorf("%w: read CRL: %w", ErrVerify, err)
	}

	if block, _ := pem.Decode(body); block != nil {
		body = block.Bytes
	}

	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("%w: parse CRL: %w", ErrVerify, err)
	}

	return crl, nil
}

func (v *Verifier) trustAnchors() ([]*x509.Certificate, error) {
	if len(v.TrustAnchors) == 0 {
		return DefaultTrustAnchors()
	}

	anchors := make([]*x509.Certificate, 0, len(v.TrustAnchors))
	for _, anchor := range v.TrustAnchors {
		if anchor != nil {
			anchors = append(anchors, anchor)
		}
	}

	if len(anchors) == 0 {
		return nil, fmt.Errorf("%w: trust anchor set is empty", ErrVerify)
	}

	return anchors, nil
}

func (v *Verifier) httpClient() *http.Client {
	base := http.DefaultClient
	if v.HTTPClient != nil {
		base = v.HTTPClient
	}

	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &client
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}

	return time.Now()
}

func (v *Verifier) maxX5UBytes() int64 {
	if v.MaxX5UBytes > 0 {
		return v.MaxX5UBytes
	}

	return DefaultMaxX5UBytes
}

func (v *Verifier) maxCRLBytes() int64 {
	if v.MaxCRLBytes > 0 {
		return v.MaxCRLBytes
	}

	return DefaultMaxCRLBytes
}

func tokenIssuedAt(rawHeader any, payloadIssuedAt *jwt.NumericDate) (time.Time, error) {
	headerIssuedAt, err := parseOptionalHeaderIssuedAt(rawHeader)
	if err != nil {
		return time.Time{}, err
	}

	if !headerIssuedAt.IsZero() {
		return headerIssuedAt, nil
	}

	if payloadIssuedAt != nil {
		return payloadIssuedAt.Time.UTC(), nil
	}

	return time.Time{}, nil
}

func parseOptionalHeaderIssuedAt(raw any) (time.Time, error) {
	if raw == nil {
		return time.Time{}, nil
	}

	var seconds int64
	switch value := raw.(type) {
	case float64:
		seconds = int64(value)
		if value <= 0 || value != float64(seconds) {
			return time.Time{}, fmt.Errorf("%w: JWT header iat must be a positive integer", ErrVerify)
		}
	case json.Number:
		parsed, err := value.Int64()
		if err != nil || parsed <= 0 {
			return time.Time{}, fmt.Errorf("%w: JWT header iat must be a positive integer", ErrVerify)
		}
		seconds = parsed
	case int64:
		if value <= 0 {
			return time.Time{}, fmt.Errorf("%w: JWT header iat must be a positive integer", ErrVerify)
		}
		seconds = value
	case int:
		if value <= 0 {
			return time.Time{}, fmt.Errorf("%w: JWT header iat must be a positive integer", ErrVerify)
		}
		seconds = int64(value)
	default:
		return time.Time{}, fmt.Errorf("%w: JWT header iat must be numeric", ErrVerify)
	}

	return time.Unix(seconds, 0).UTC(), nil
}

func parseCertificateChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}

		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse PEM certificate: %w", ErrVerify, err)
		}
		certs = append(certs, cert)
	}

	if len(certs) > 0 {
		return certs, nil
	}

	derCerts, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("%w: parse certificate chain: %w", ErrVerify, err)
	}

	if len(derCerts) == 0 {
		return nil, fmt.Errorf("%w: certificate chain is empty", ErrVerify)
	}

	return derCerts, nil
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	n, err := buf.ReadFrom(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}

	if n > limit {
		return nil, fmt.Errorf("object exceeds %d bytes", limit)
	}

	return buf.Bytes(), nil
}

func sameWebOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		originPort(a) == originPort(b)
}

func originPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}

	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

type metadataClaims struct {
	jwt.RegisteredClaims

	Number  *uint64               `json:"no"`
	Entries []appmds.PayloadEntry `json:"entries"`
}
