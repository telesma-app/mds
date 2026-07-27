package model

// AttestationTrustStatus is the outcome of evaluating attestation evidence
// against one verified MDS entry.
type AttestationTrustStatus string

const (
	AttestationTrustStatusTrusted       AttestationTrustStatus = "trusted"
	AttestationTrustStatusUntrusted     AttestationTrustStatus = "untrusted"
	AttestationTrustStatusUnavailable   AttestationTrustStatus = "unavailable"
	AttestationTrustStatusNotApplicable AttestationTrustStatus = "not_applicable"
)

// AttestationTrustIssueCode identifies a stable reason for an attestation
// trust outcome.
type AttestationTrustIssueCode string

const (
	AttestationTrustIssueMetadataNotFound           AttestationTrustIssueCode = "mds.attestation.metadata_not_found"
	AttestationTrustIssueMetadataAAGUIDMismatch     AttestationTrustIssueCode = "mds.attestation.metadata_aaguid_mismatch"
	AttestationTrustIssueEvidenceMalformed          AttestationTrustIssueCode = "mds.attestation.evidence_malformed"
	AttestationTrustIssueEvidenceUnverified         AttestationTrustIssueCode = "mds.attestation.evidence_unverified"
	AttestationTrustIssueFormatUnsupported          AttestationTrustIssueCode = "mds.attestation.format_unsupported"
	AttestationTrustIssueCertificateChainMissing    AttestationTrustIssueCode = "mds.attestation.certificate_chain_missing"
	AttestationTrustIssueCertificateChainMalformed  AttestationTrustIssueCode = "mds.attestation.certificate_chain_malformed"
	AttestationTrustIssueAttestationRootsMissing    AttestationTrustIssueCode = "mds.attestation.roots_missing"
	AttestationTrustIssueAttestationRootMalformed   AttestationTrustIssueCode = "mds.attestation.root_malformed"
	AttestationTrustIssueCertificateChainUntrusted  AttestationTrustIssueCode = "mds.attestation.certificate_chain_untrusted"
	AttestationTrustIssueAuthenticatorRevoked       AttestationTrustIssueCode = "mds.attestation.authenticator_revoked"
	AttestationTrustIssueAttestationKeyCompromise   AttestationTrustIssueCode = "mds.attestation.attestation_key_compromise"
	AttestationTrustIssueStatusCertificateMalformed AttestationTrustIssueCode = "mds.attestation.status_certificate_malformed"
)

// AttestationTrustAssessment contains policy-neutral MDS trust facts. Status
// reports are preserved so a relying party can apply stricter product policy.
type AttestationTrustAssessment struct {
	Status                  AttestationTrustStatus      `json:"status"`
	MetadataFound           bool                        `json:"metadataFound"`
	CertificateChainTrusted *bool                       `json:"certificateChainTrusted,omitempty"`
	AuthenticatorStatuses   []AuthenticatorStatus       `json:"authenticatorStatuses,omitempty"`
	Issues                  []AttestationTrustIssueCode `json:"issues,omitempty"`
}
