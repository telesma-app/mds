package mds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/go-ctap/mds/model"
	"github.com/google/uuid"
)

func TestAssessAttestationTrustsChainAnchoredByMetadata(t *testing.T) {
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	rootKey := assessmentKey(t)
	root := assessmentCertificate(t, rootKey, nil, rootKey, true, now)
	leafKey := assessmentKey(t)
	leaf := assessmentCertificate(t, leafKey, root, rootKey, false, now)
	aaguid := uuid.MustParse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf")
	metadata := model.LookupResult{
		AAGUID: aaguid,
		Found:  true,
		Entry: &model.PayloadEntry{
			AAGUID: aaguid,
			MetadataStatement: model.MetadataStatement{
				AttestationRootCertificates: []string{
					base64.StdEncoding.EncodeToString(root.Raw),
				},
			},
		},
	}

	assessment := AssessAttestation(AttestationEvidence{
		AAGUID:           aaguid,
		Type:             AttestationTypeBasic,
		CertificateChain: [][]byte{leaf.Raw},
	}, metadata, now)
	if assessment.Status != model.AttestationTrustStatusTrusted {
		t.Fatalf("status = %q, want trusted; issues = %v", assessment.Status, assessment.Issues)
	}
	if assessment.CertificateChainTrusted == nil || !*assessment.CertificateChainTrusted {
		t.Fatalf("certificate chain trusted = %v, want true", assessment.CertificateChainTrusted)
	}
}

func TestAssessAttestationRejectsRevokedAuthenticator(t *testing.T) {
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	rootKey := assessmentKey(t)
	root := assessmentCertificate(t, rootKey, nil, rootKey, true, now)
	leafKey := assessmentKey(t)
	leaf := assessmentCertificate(t, leafKey, root, rootKey, false, now)
	aaguid := uuid.MustParse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf")
	metadata := model.LookupResult{
		AAGUID: aaguid,
		Found:  true,
		Entry: &model.PayloadEntry{
			AAGUID: aaguid,
			MetadataStatement: model.MetadataStatement{
				AttestationRootCertificates: []string{
					base64.StdEncoding.EncodeToString(root.Raw),
				},
			},
			StatusReports: []model.StatusReport{{
				Status: model.AuthenticatorStatusRevoked,
			}},
		},
	}

	assessment := AssessAttestation(AttestationEvidence{
		AAGUID:           aaguid,
		Type:             AttestationTypeBasic,
		CertificateChain: [][]byte{leaf.Raw},
	}, metadata, now)
	if assessment.Status != model.AttestationTrustStatusUntrusted {
		t.Fatalf("status = %q, want untrusted", assessment.Status)
	}
	if assessment.CertificateChainTrusted == nil || !*assessment.CertificateChainTrusted {
		t.Fatalf("certificate chain trusted = %v, want true", assessment.CertificateChainTrusted)
	}
}

func TestAssessAttestationMarksSelfAttestationNotApplicable(t *testing.T) {
	aaguid := uuid.MustParse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf")
	assessment := AssessAttestation(AttestationEvidence{
		AAGUID: aaguid,
		Type:   AttestationTypeSelf,
	}, model.LookupResult{
		AAGUID: aaguid,
		Found:  true,
		Entry:  &model.PayloadEntry{AAGUID: aaguid},
	}, time.Time{})
	if assessment.Status != model.AttestationTrustStatusNotApplicable {
		t.Fatalf("status = %q, want not_applicable", assessment.Status)
	}
}

func TestAssessAttestationScopesKeyCompromiseToReportedCertificate(t *testing.T) {
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	rootKey := assessmentKey(t)
	root := assessmentCertificate(t, rootKey, nil, rootKey, true, now)
	leafKey := assessmentKey(t)
	leaf := assessmentCertificate(t, leafKey, root, rootKey, false, now)
	otherKey := assessmentKey(t)
	other := assessmentCertificate(t, otherKey, root, rootKey, false, now)
	aaguid := uuid.MustParse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf")
	compromisedCertificate := base64.StdEncoding.EncodeToString(other.Raw)
	metadata := assessmentMetadata(aaguid, root, model.StatusReport{
		Status:           model.AuthenticatorStatusAttestationKeyCompromise,
		BatchCertificate: &compromisedCertificate,
	})

	assessment := AssessAttestation(AttestationEvidence{
		AAGUID:           aaguid,
		Type:             AttestationTypeBasic,
		CertificateChain: [][]byte{leaf.Raw},
	}, metadata, now)
	if assessment.Status != model.AttestationTrustStatusTrusted {
		t.Fatalf("status = %q, want trusted; issues = %v", assessment.Status, assessment.Issues)
	}
}

func TestAssessAttestationRejectsMatchingCompromisedRoot(t *testing.T) {
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	rootKey := assessmentKey(t)
	root := assessmentCertificate(t, rootKey, nil, rootKey, true, now)
	leafKey := assessmentKey(t)
	leaf := assessmentCertificate(t, leafKey, root, rootKey, false, now)
	aaguid := uuid.MustParse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf")
	compromisedCertificate := base64.StdEncoding.EncodeToString(root.Raw)
	metadata := assessmentMetadata(aaguid, root, model.StatusReport{
		Status:      model.AuthenticatorStatusAttestationKeyCompromise,
		Certificate: &compromisedCertificate,
	})

	assessment := AssessAttestation(AttestationEvidence{
		AAGUID:           aaguid,
		Type:             AttestationTypeBasic,
		CertificateChain: [][]byte{leaf.Raw},
	}, metadata, now)
	if assessment.Status != model.AttestationTrustStatusUntrusted {
		t.Fatalf("status = %q, want untrusted; issues = %v", assessment.Status, assessment.Issues)
	}
}

func assessmentMetadata(
	aaguid uuid.UUID,
	root *x509.Certificate,
	statusReports ...model.StatusReport,
) model.LookupResult {
	return model.LookupResult{
		AAGUID: aaguid,
		Found:  true,
		Entry: &model.PayloadEntry{
			AAGUID: aaguid,
			MetadataStatement: model.MetadataStatement{
				AttestationRootCertificates: []string{
					base64.StdEncoding.EncodeToString(root.Raw),
				},
			},
			StatusReports: statusReports,
		},
	}
}

func assessmentKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return key
}

func assessmentCertificate(
	t *testing.T,
	subjectKey *ecdsa.PrivateKey,
	parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
	isCA bool,
	now time.Time,
) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "MDS attestation test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent = template
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, parent, &subjectKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return certificate
}
