package mds

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/telesma-app/mds/model"
	"github.com/google/uuid"
)

// AttestationType describes the trust material exposed by a format-level
// attestation verifier. It deliberately does not prescribe relying-party
// certification policy.
type AttestationType string

const (
	AttestationTypeNone        AttestationType = "none"
	AttestationTypeSelf        AttestationType = "self"
	AttestationTypeBasic       AttestationType = "basic"
	AttestationTypeUnsupported AttestationType = "unsupported"
)

// AttestationEvidence identifies the authenticator and carries the untrusted
// certificate chain extracted from a verified attestation statement.
type AttestationEvidence struct {
	AAGUID           uuid.UUID
	Type             AttestationType
	CertificateChain [][]byte
}

// AssessAttestation evaluates attestation evidence against one verified MDS
// lookup result. It does not apply relying-party certification policy.
func AssessAttestation(
	evidence AttestationEvidence,
	metadata model.LookupResult,
	currentTime time.Time,
) model.AttestationTrustAssessment {
	assessment := model.AttestationTrustAssessment{
		Status:        model.AttestationTrustStatusUnavailable,
		MetadataFound: metadata.Found && metadata.Entry != nil,
	}
	if !assessment.MetadataFound {
		assessment.Issues = append(assessment.Issues, model.AttestationTrustIssueMetadataNotFound)

		return assessment
	}
	if metadata.AAGUID != evidence.AAGUID || metadata.Entry.AAGUID != uuid.Nil && metadata.Entry.AAGUID != evidence.AAGUID {
		assessment.Status = model.AttestationTrustStatusUntrusted
		assessment.Issues = append(assessment.Issues, model.AttestationTrustIssueMetadataAAGUIDMismatch)

		return assessment
	}

	statusReports := metadata.Entry.StatusReports
	for _, report := range statusReports {
		assessment.AuthenticatorStatuses = append(assessment.AuthenticatorStatuses, report.Status)
	}

	if evidence.Type == AttestationTypeNone || evidence.Type == AttestationTypeSelf {
		assessment.Status = model.AttestationTrustStatusNotApplicable

		return assessment
	}
	if evidence.Type != AttestationTypeBasic {
		return assessment
	}
	if len(evidence.CertificateChain) == 0 {
		assessment.Status = model.AttestationTrustStatusUntrusted
		assessment.Issues = append(assessment.Issues, model.AttestationTrustIssueCertificateChainMissing)

		return assessment
	}

	chain, ok := parseCertificateChain(evidence.CertificateChain)
	if !ok {
		assessment.Status = model.AttestationTrustStatusUntrusted
		assessment.Issues = append(assessment.Issues, model.AttestationTrustIssueCertificateChainMalformed)

		return assessment
	}
	roots, malformedRoot := attestationRoots(metadata.Entry.MetadataStatement.AttestationRootCertificates)
	if malformedRoot {
		assessment.Issues = append(assessment.Issues, model.AttestationTrustIssueAttestationRootMalformed)
	}
	if len(roots) == 0 {
		assessment.Issues = append(assessment.Issues, model.AttestationTrustIssueAttestationRootsMissing)

		return assessment
	}

	rootPool := x509.NewCertPool()
	for _, root := range roots {
		rootPool.AddCert(root)
	}
	intermediatePool := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediatePool.AddCert(certificate)
	}
	if currentTime.IsZero() {
		currentTime = time.Now()
	}
	verifiedChains, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   currentTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	trusted := err == nil
	assessment.CertificateChainTrusted = &trusted
	if !trusted {
		assessment.Status = model.AttestationTrustStatusUntrusted
		assessment.Issues = append(assessment.Issues, model.AttestationTrustIssueCertificateChainUntrusted)

		return assessment
	}
	if len(statusReports) != 0 {
		currentStatus := statusReports[len(statusReports)-1]
		switch currentStatus.Status {
		case model.AuthenticatorStatusRevoked:
			assessment.Status = model.AttestationTrustStatusUntrusted
			assessment.Issues = append(assessment.Issues, model.AttestationTrustIssueAuthenticatorRevoked)

			return assessment
		case model.AuthenticatorStatusAttestationKeyCompromise:
			applies, malformed := attestationKeyCompromiseApplies(currentStatus, verifiedChains)
			if malformed {
				assessment.Issues = append(assessment.Issues, model.AttestationTrustIssueStatusCertificateMalformed)

				return assessment
			}
			if applies {
				assessment.Status = model.AttestationTrustStatusUntrusted
				assessment.Issues = append(assessment.Issues, model.AttestationTrustIssueAttestationKeyCompromise)

				return assessment
			}
		}
	}

	assessment.Status = model.AttestationTrustStatusTrusted

	return assessment
}

func parseCertificateChain(values [][]byte) ([]*x509.Certificate, bool) {
	chain := make([]*x509.Certificate, 0, len(values))
	for _, value := range values {
		certificate, err := x509.ParseCertificate(value)
		if err != nil {
			return nil, false
		}
		chain = append(chain, certificate)
	}

	return chain, true
}

func attestationRoots(values []string) ([]*x509.Certificate, bool) {
	roots := make([]*x509.Certificate, 0, len(values))
	malformed := false
	for _, value := range values {
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			malformed = true
			continue
		}
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			malformed = true
			continue
		}
		roots = append(roots, certificate)
	}

	return roots, malformed
}

func attestationKeyCompromiseApplies(
	report model.StatusReport,
	verifiedChains [][]*x509.Certificate,
) (bool, bool) {
	values := []*string{report.BatchCertificate, report.Certificate}
	hasScopedCertificate := false
	for _, value := range values {
		if value == nil {
			continue
		}
		hasScopedCertificate = true
		raw, err := base64.StdEncoding.DecodeString(*value)
		if err != nil {
			return false, true
		}
		if _, err := x509.ParseCertificate(raw); err != nil {
			return false, true
		}
		for _, chain := range verifiedChains {
			for _, certificate := range chain {
				if bytes.Equal(certificate.Raw, raw) {
					return true, false
				}
			}
		}
	}

	return !hasScopedCertificate, false
}
