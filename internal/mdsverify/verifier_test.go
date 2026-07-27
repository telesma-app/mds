package mdsverify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type testPKI struct {
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	leaf    *x509.Certificate
}

func TestVerifierChecksCertificateChainAndCRL(t *testing.T) {
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	pki := newTestPKI(t, now)
	verifier := &Verifier{
		Source:       "https://mds.example.test/blob",
		TrustAnchors: []*x509.Certificate{pki.root},
		Now:          func() time.Time { return now },
	}

	verifier.HTTPClient = responseClient(http.StatusOK, testCRL(t, pki, now.Add(-time.Hour), now.Add(time.Hour)))
	if err := verifier.verifyCertificateChain(t.Context(), []*x509.Certificate{pki.leaf}); err != nil {
		t.Fatalf("valid chain: %v", err)
	}

	verifier.HTTPClient = responseClient(
		http.StatusOK,
		testCRL(t, pki, now.Add(-time.Hour), now.Add(time.Hour), pki.leaf.SerialNumber),
	)
	if err := verifier.verifyCertificateChain(t.Context(), []*x509.Certificate{pki.leaf}); err == nil || !strings.Contains(err.Error(), "is revoked") {
		t.Fatalf("revoked chain error = %v", err)
	}

	verifier.HTTPClient = responseClient(http.StatusOK, testCRL(t, pki, now.Add(-2*time.Hour), now.Add(-time.Hour)))
	if err := verifier.verifyCertificateChain(t.Context(), []*x509.Certificate{pki.leaf}); err == nil || !strings.Contains(err.Error(), "is expired") {
		t.Fatalf("expired CRL error = %v", err)
	}

	verifier.Now = func() time.Time { return now.Add(7 * time.Hour) }
	if err := verifier.verifyCertificateChain(t.Context(), []*x509.Certificate{pki.leaf}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired certificate error = %v", err)
	}

	verifier.Now = func() time.Time { return now }
	verifier.TrustAnchors = []*x509.Certificate{newTestPKI(t, now).root}
	if err := verifier.verifyCertificateChain(t.Context(), []*x509.Certificate{pki.leaf}); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("untrusted chain error = %v", err)
	}
}

func TestVerifierUsesInjectedClockForJWTClaims(t *testing.T) {
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	pki := newTestPKI(t, now)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"no":      1,
		"entries": []any{},
		"nbf":     now.Add(-time.Hour).Unix(),
		"exp":     now.Add(time.Hour).Unix(),
	})
	raw, err := token.SignedString(pki.rootKey)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	verifier := &Verifier{
		TrustAnchors: []*x509.Certificate{pki.root},
		Now:          func() time.Time { return now },
	}
	if _, err := verifier.Verify(t.Context(), []byte(raw)); err != nil {
		t.Fatalf("valid injected time: %v", err)
	}

	verifier.Now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err := verifier.Verify(t.Context(), []byte(raw)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired JWT error = %v", err)
	}

	verifier.Now = func() time.Time { return now.Add(-2 * time.Hour) }
	if _, err := verifier.Verify(t.Context(), []byte(raw)); err == nil || !strings.Contains(err.Error(), "not valid yet") {
		t.Fatalf("not-before JWT error = %v", err)
	}
}

func TestVerifierHTTPPolicies(t *testing.T) {
	verifier := &Verifier{Source: "https://mds.example.test/blob"}
	if _, err := verifier.fetchX5UCertificates(t.Context(), "https://other.example.test/chain.pem"); err == nil || !strings.Contains(err.Error(), "same web origin") {
		t.Fatalf("cross-origin x5u error = %v", err)
	}

	verifier.HTTPClient = responseClient(http.StatusFound, nil)
	if _, err := verifier.fetchX5UCertificates(t.Context(), "https://mds.example.test/chain.pem"); err == nil || !strings.Contains(err.Error(), "unexpected HTTP status") {
		t.Fatalf("x5u redirect error = %v", err)
	}
	if _, err := verifier.fetchRevocationList(t.Context(), "https://crl.example.test/list"); err == nil || !strings.Contains(err.Error(), "unexpected HTTP status") {
		t.Fatalf("CRL redirect error = %v", err)
	}

	verifier.HTTPClient = responseClient(http.StatusOK, []byte("1234"))
	verifier.MaxX5UBytes = 3
	verifier.MaxCRLBytes = 3
	if _, err := verifier.fetchX5UCertificates(t.Context(), "https://mds.example.test/chain.pem"); err == nil || !strings.Contains(err.Error(), "object exceeds 3 bytes") {
		t.Fatalf("x5u limit error = %v", err)
	}
	if _, err := verifier.fetchRevocationList(t.Context(), "https://crl.example.test/list"); err == nil || !strings.Contains(err.Error(), "object exceeds 3 bytes") {
		t.Fatalf("CRL limit error = %v", err)
	}
}

func newTestPKI(t *testing.T, now time.Time) testPKI {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "MDS Test Root"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	root := createCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leaf := createCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "MDS Test Signer"},
		NotBefore:             now.Add(-6 * time.Hour),
		NotAfter:              now.Add(6 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		CRLDistributionPoints: []string{"https://crl.example.test/list"},
	}, root, &leafKey.PublicKey, rootKey)

	return testPKI{root: root, rootKey: rootKey, leaf: leaf}
}

func createCertificate(
	t *testing.T,
	template, parent *x509.Certificate,
	publicKey *ecdsa.PublicKey,
	parentKey *ecdsa.PrivateKey,
) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return cert
}

func testCRL(t *testing.T, pki testPKI, thisUpdate, nextUpdate time.Time, revoked ...*big.Int) []byte {
	t.Helper()

	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, serial := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: thisUpdate,
		})
	}

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, pki.root, pki.rootKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}

	return der
}

func responseClient(status int, body []byte) *http.Client {
	return &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Status:     http.StatusText(status),
			Header:     http.Header{"Location": {"https://redirected.example.test/"}},
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    request,
		}, nil
	})}
}
