package model

import (
	"time"
	"uuid"

	"github.com/telesma-app/ctap/protocol"
)

// LookupResult is the public result of a verified FIDO Metadata Service AAGUID lookup.
type LookupResult struct {
	AAGUID     uuid.UUID     `json:"aaguid"`
	Found      bool          `json:"found"`
	Entry      *PayloadEntry `json:"entry,omitempty"`
	BlobNumber uint64        `json:"blobNumber"`
	Source     string        `json:"source"`
	Cached     bool          `json:"cached"`
	CachedAt   time.Time     `json:"cachedAt"`
}

// PayloadEntry contains the MDS payload entry for one authenticator model.
type PayloadEntry struct {
	AAID                                 *string                 `json:"aaid,omitempty"`
	AAGUID                               uuid.UUID               `json:"aaguid,omitempty"`
	AttestationCertificateKeyIdentifiers []string                `json:"attestationCertificateKeyIdentifiers,omitempty"`
	MetadataStatement                    MetadataStatement       `json:"metadataStatement"`
	BiometricStatusReports               []BiometricStatusReport `json:"biometricStatusReports,omitempty"`
	StatusReports                        []StatusReport          `json:"statusReports,omitempty"`
	TimeOfLastStatusChange               string                  `json:"timeOfLastStatusChange,omitempty"`
	RogueListURL                         *string                 `json:"rogueListURL,omitempty"`
	RogueListHash                        *string                 `json:"rogueListHash,omitempty"`
}

// StatusReport describes the current or historical status of an authenticator model.
type StatusReport struct {
	Status                           AuthenticatorStatus `json:"status"`
	EffectiveDate                    *string             `json:"effectiveDate,omitempty"`
	AuthenticatorVersion             *uint64             `json:"authenticatorVersion,omitempty"`
	BatchCertificate                 *string             `json:"batchCertificate,omitempty"`
	Certificate                      *string             `json:"certificate,omitempty"`
	URL                              *string             `json:"url,omitempty"`
	CertificationDescriptor          *string             `json:"certificationDescriptor,omitempty"`
	CertificateNumber                *string             `json:"certificateNumber,omitempty"`
	CertificationPolicyVersion       *string             `json:"certificationPolicyVersion,omitempty"`
	CertificationProfiles            []string            `json:"certificationProfiles,omitempty"`
	CertificationRequirementsVersion *string             `json:"certificationRequirementsVersion,omitempty"`
	SunsetDate                       *string             `json:"sunsetDate,omitempty"`
	FIPSRevision                     *uint32             `json:"fipsRevision,omitempty"`
	FIPSPhysicalSecurityLevel        *uint32             `json:"fipsPhysicalSecurityLevel,omitempty"`
}

// BiometricStatusReport describes biometric certification status for an authenticator model.
type BiometricStatusReport struct {
	CertLevel                        uint32  `json:"certLevel"`
	Modality                         string  `json:"modality"`
	EffectiveDate                    *string `json:"effectiveDate,omitempty"`
	CertificationDescriptor          *string `json:"certificationDescriptor,omitempty"`
	CertificateNumber                *string `json:"certificateNumber,omitempty"`
	CertificationPolicyVersion       *string `json:"certificationPolicyVersion,omitempty"`
	CertificationRequirementsVersion *string `json:"certificationRequirementsVersion,omitempty"`
}

// AuthenticatorStatus is an MDS authenticator status value.
type AuthenticatorStatus string

//goland:noinspection GoUnusedConst
const (
	AuthenticatorStatusNotFIDOCertified          AuthenticatorStatus = "NOT_FIDO_CERTIFIED"
	AuthenticatorStatusFIDOCertified             AuthenticatorStatus = "FIDO_CERTIFIED"
	AuthenticatorStatusUserVerificationBypass    AuthenticatorStatus = "USER_VERIFICATION_BYPASS"
	AuthenticatorStatusAttestationKeyCompromise  AuthenticatorStatus = "ATTESTATION_KEY_COMPROMISE"
	AuthenticatorStatusUserKeyRemoteCompromise   AuthenticatorStatus = "USER_KEY_REMOTE_COMPROMISE"
	AuthenticatorStatusUserKeyPhysicalCompromise AuthenticatorStatus = "USER_KEY_PHYSICAL_COMPROMISE"
	AuthenticatorStatusUpdateAvailable           AuthenticatorStatus = "UPDATE_AVAILABLE"
	AuthenticatorStatusRetired                   AuthenticatorStatus = "RETIRED"
	AuthenticatorStatusRevoked                   AuthenticatorStatus = "REVOKED"
	AuthenticatorStatusSelfAssertionSubmitted    AuthenticatorStatus = "SELF_ASSERTION_SUBMITTED"
	AuthenticatorStatusFIDOCertifiedL1           AuthenticatorStatus = "FIDO_CERTIFIED_L1"
	AuthenticatorStatusFIDOCertifiedL1Plus       AuthenticatorStatus = "FIDO_CERTIFIED_L1plus"
	AuthenticatorStatusFIDOCertifiedL2           AuthenticatorStatus = "FIDO_CERTIFIED_L2"
	AuthenticatorStatusFIDOCertifiedL2Plus       AuthenticatorStatus = "FIDO_CERTIFIED_L2plus"
	AuthenticatorStatusFIDOCertifiedL3           AuthenticatorStatus = "FIDO_CERTIFIED_L3"
	AuthenticatorStatusFIDOCertifiedL3Plus       AuthenticatorStatus = "FIDO_CERTIFIED_L3plus"
	AuthenticatorStatusFIPS140CertifiedL1        AuthenticatorStatus = "FIPS140_CERTIFIED_L1"
	AuthenticatorStatusFIPS140CertifiedL2        AuthenticatorStatus = "FIPS140_CERTIFIED_L2"
	AuthenticatorStatusFIPS140CertifiedL3        AuthenticatorStatus = "FIPS140_CERTIFIED_L3"
	AuthenticatorStatusFIPS140CertifiedL4        AuthenticatorStatus = "FIPS140_CERTIFIED_L4"
)

type MetadataStatement struct {
	LegalHeader                          *string                               `json:"legalHeader,omitempty"`
	AAID                                 *string                               `json:"aaid,omitempty"`
	AAGUID                               *uuid.UUID                            `json:"aaguid,omitempty"`
	AttestationCertificateKeyIdentifiers []string                              `json:"attestationCertificateKeyIdentifiers,omitempty"`
	FriendlyNames                        map[string]string                     `json:"friendlyNames,omitempty"`
	Description                          string                                `json:"description,omitempty"`
	AlternativeDescriptions              map[string]string                     `json:"alternativeDescriptions,omitempty"`
	AuthenticatorVersion                 *uint32                               `json:"authenticatorVersion"`
	ProtocolFamily                       string                                `json:"protocolFamily"`
	Schema                               uint16                                `json:"schema"`
	UPV                                  []Version                             `json:"upv"`
	AuthenticationAlgorithms             []string                              `json:"authenticationAlgorithms"`
	PublicKeyAlgAndEncodings             []string                              `json:"publicKeyAlgAndEncodings"`
	AttestationTypes                     []string                              `json:"attestationTypes"`
	UserVerificationDetails              []any                                 `json:"userVerificationDetails"`
	KeyProtection                        []string                              `json:"keyProtection"`
	IsKeyRestricted                      *bool                                 `json:"isKeyRestricted,omitempty"`
	IsFreshUserVerificationRequired      *bool                                 `json:"isFreshUserVerificationRequired,omitempty"`
	MatcherProtection                    []string                              `json:"matcherProtection"`
	CryptoStrength                       *uint16                               `json:"cryptoStrength,omitempty"`
	AttachmentHint                       []string                              `json:"attachmentHint,omitempty"`
	TcDisplay                            []string                              `json:"tcDisplay"`
	TcDisplayContentType                 *string                               `json:"tcDisplayContentType,omitempty"`
	TcDisplayPNGCharacteristics          []DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics,omitempty"`
	AttestationRootCertificates          []string                              `json:"attestationRootCertificates"`
	ECDAATrustAnchor                     []ECDAATrustAnchor                    `json:"ECDAATrustAnchor,omitempty"`
	Icon                                 *string                               `json:"icon,omitempty"`
	IconDark                             *string                               `json:"iconDark,omitempty"`
	ProviderLogoLight                    *string                               `json:"providerLogoLight,omitempty"`
	ProviderLogoDark                     *string                               `json:"providerLogoDark,omitempty"`
	ExtensionDescriptor                  []ExtensionDescriptor                 `json:"extensionDescriptor,omitempty"`
	MultiDeviceCredentialSupport         *string                               `json:"multiDeviceCredentialSupport"`
	AuthenticatorGetInfo                 protocol.AuthenticatorGetInfoResponse `json:"authenticatorGetInfo"`
	CxConfigURL                          *string                               `json:"cxConfigURL"`
}

type Version struct {
	Major uint16 `json:"major"`
	Minor uint16 `json:"minor"`
}

type VerificationMethodDescriptor struct {
	UserVerificationMethod *string                      `json:"userVerificationMethod,omitempty"`
	CADesc                 *CodeAccuracyDescriptor      `json:"caDesc,omitempty"`
	BADesc                 *BiometricAccuracyDescriptor `json:"baDesc,omitempty"`
	PADesc                 *PatternAccuracyDescriptor   `json:"paDesc,omitempty"`
}

type CodeAccuracyDescriptor struct {
	Base          uint16  `json:"base"`
	MinLength     uint16  `json:"minLength"`
	MaxRetries    *uint16 `json:"maxRetries,omitempty"`
	BlockSlowdown *uint16 `json:"blockSlowdown,omitempty"`
}

type BiometricAccuracyDescriptor struct {
	SelfAttestedFRR *float64 `json:"selfAttestedFRR,omitempty"`
	SelfAttestedFAR *float64 `json:"selfAttestedFAR,omitempty"`
	IAPARThreshold  *float64 `json:"IAPARThreshold,omitempty"`
	MaxTemplates    *uint16  `json:"maxTemplates,omitempty"`
	MaxRetries      *uint16  `json:"maxRetries,omitempty"`
	BlockSlowdown   *uint16  `json:"blockSlowdown,omitempty"`
}

type PatternAccuracyDescriptor struct {
	MinComplexity uint32  `json:"minComplexity"`
	MaxRetries    *uint16 `json:"maxRetries,omitempty"`
	BlockSlowdown *uint16 `json:"blockSlowdown,omitempty"`
}

type RGBPaletteEntry struct {
	R *uint16 `json:"r"`
	G *uint16 `json:"g"`
	B *uint16 `json:"b"`
}

type DisplayPNGCharacteristicsDescriptor struct {
	Width       uint32            `json:"width"`
	Height      uint32            `json:"height"`
	BitDepth    byte              `json:"bitDepth"`
	ColorType   byte              `json:"colorType"`
	Compression byte              `json:"compression"`
	Filter      byte              `json:"filter"`
	Interlace   byte              `json:"interlace"`
	Palette     []RGBPaletteEntry `json:"plte"`
}

type ECDAATrustAnchor struct {
	X       []byte `json:"X"`
	Y       []byte `json:"Y"`
	C       []byte `json:"c"`
	Sx      []byte `json:"sx"`
	Sy      []byte `json:"sy"`
	G1Curve string `json:"G1Curve"`
}

type ExtensionDescriptor struct {
	ID            string `json:"id"`
	Tag           uint16 `json:"tag"`
	Data          string `json:"data"`
	FailIfUnknown bool   `json:"fail_if_unknown"`
}
