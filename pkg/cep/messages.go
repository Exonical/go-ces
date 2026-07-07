// Package cep implements the Certificate Enrollment Policy Web Service
// (MS-XCEP) protocol handler.
package cep

import "encoding/xml"

const (
	NSEnrollmentPolicy = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
	ActionGetPolicies  = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"
	ActionGetPoliciesResponse = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse"
)

// GetPolicies represents the MS-XCEP GetPolicies request element.
type GetPolicies struct {
	XMLName xml.Name `xml:"GetPolicies"`
	Client  Client   `xml:"client"`
	RequestFilter RequestFilter `xml:"requestFilter"`
}

// Client contains information about the requesting client.
type Client struct {
	LastUpdate    string `xml:"lastUpdate,omitempty"`
	PreferredLang string `xml:"preferredLanguage,omitempty"`
}

// RequestFilter specifies which policies to return.
type RequestFilter struct {
	PolicyOIDs    *PolicyOIDs    `xml:"policyOIDs,omitempty"`
	ClientVersion int            `xml:"clientVersion,omitempty"`
	ServerVersion int            `xml:"serverVersion,omitempty"`
}

// PolicyOIDs is a collection of policy OID strings.
type PolicyOIDs struct {
	OID []string `xml:"oid"`
}

// GetPoliciesResponse represents the MS-XCEP GetPoliciesResponse element.
type GetPoliciesResponse struct {
	XMLName  xml.Name      `xml:"GetPoliciesResponse"`
	XMLNS    string        `xml:"xmlns,attr"`
	Response Response      `xml:"response"`
	CAs      CACollection  `xml:"cAs"`
	OIDs     OIDCollection `xml:"oIDs"`
}

// Response contains the certificate enrollment policies.
type Response struct {
	PolicyID string                          `xml:"policyID,omitempty"`
	Policies []CertificateEnrollmentPolicy   `xml:"policies>policy,omitempty"`
}

// CertificateEnrollmentPolicy is an individual policy (template).
type CertificateEnrollmentPolicy struct {
	PolicyOIDReference int               `xml:"policyOIDReference"`
	CAs                CAReferenceCollection `xml:"cAs"`
	Attributes         Attributes        `xml:"attributes"`
}

// CAReferenceCollection holds references to CAs that can issue this policy.
type CAReferenceCollection struct {
	CAReferences []int `xml:"cAReference"`
}

// Attributes holds the detailed attributes of a certificate enrollment policy.
type Attributes struct {
	CommonName               string            `xml:"commonName"`
	PolicySchema             int               `xml:"policySchema"`
	CertificateValidity      CertificateValidity `xml:"certificateValidity"`
	Permission               Permission        `xml:"permission"`
	PrivateKeyAttributes     PrivateKeyAttributes `xml:"privateKeyAttributes"`
	Revision                 Revision          `xml:"revision"`
	SupersededPolicies       *SupersededPolicies `xml:"supersededPolicies,omitempty"`
	PrivateKeyFlags          *uint32           `xml:"privateKeyFlags,omitempty"`
	SubjectNameFlags         *uint32           `xml:"subjectNameFlags,omitempty"`
	EnrollmentFlags          *uint32           `xml:"enrollmentFlags,omitempty"`
	GeneralFlags             *uint32           `xml:"generalFlags,omitempty"`
	HashAlgorithmOIDReference *int             `xml:"hashAlgorithmOIDReference,omitempty"`
	RARequirements           *RARequirements   `xml:"rARequirements,omitempty"`
	KeyArchivalAttributes    *KeyArchivalAttributes `xml:"keyArchivalAttributes,omitempty"`
	Extensions               *Extensions       `xml:"extensions,omitempty"`
}

// CertificateValidity specifies validity period.
type CertificateValidity struct {
	ValidityPeriodSeconds int64 `xml:"validityPeriodSeconds"`
	RenewalPeriodSeconds  int64 `xml:"renewalPeriodSeconds"`
}

// Permission specifies enrollment permissions.
type Permission struct {
	Enroll     bool `xml:"enroll"`
	AutoEnroll bool `xml:"autoEnroll"`
}

// PrivateKeyAttributes specifies key requirements.
type PrivateKeyAttributes struct {
	MinimalKeyLength    int               `xml:"minimalKeyLength"`
	KeySpec             *int              `xml:"keySpec,omitempty"`
	KeyUsageProperty    *uint32           `xml:"keyUsageProperty,omitempty"`
	Permissions         *string           `xml:"permissions,omitempty"`
	AlgorithmOIDReference *int            `xml:"algorithmOIDReference,omitempty"`
	CryptoProviders     *CryptoProviders  `xml:"cryptoProviders,omitempty"`
}

// CryptoProviders is a list of allowed crypto providers.
type CryptoProviders struct {
	Provider []string `xml:"provider"`
}

// Revision tracks the template version.
type Revision struct {
	MajorRevision int `xml:"majorRevision"`
	MinorRevision int `xml:"minorRevision"`
}

// SupersededPolicies lists policies superseded by this one.
type SupersededPolicies struct {
	PolicyOIDs []string `xml:"commonName"`
}

// RARequirements specifies Registration Authority requirements.
type RARequirements struct {
	RASignatures int `xml:"rASignatures"`
}

// KeyArchivalAttributes specifies key archival settings.
type KeyArchivalAttributes struct {
	SymmetricAlgorithmOIDReference int `xml:"symmetricAlgorithmOIDReference"`
	SymmetricAlgorithmKeyLength    int `xml:"symmetricAlgorithmKeyLength"`
}

// Extensions is a collection of policy extensions.
type Extensions struct {
	Extension []Extension `xml:"extension"`
}

// Extension represents a single X.509 extension in the policy.
type Extension struct {
	OIDReference int    `xml:"oIDReference"`
	Critical     bool   `xml:"critical"`
	Value        string `xml:"value,omitempty"` // base64-encoded
}

// CACollection holds the certificate authorities.
type CACollection struct {
	CA []CA `xml:"cA"`
}

// CA represents a certificate authority in the response.
type CA struct {
	URIs                CARICollection `xml:"uris"`
	Certificate         string         `xml:"certificate"` // base64 DER
	EnrollmentPermission bool          `xml:"enrollmentPermission"`
	CAReferenceID       int            `xml:"cAReferenceID"`
}

// CARICollection holds CA URI references.
type CARICollection struct {
	URI []CAURI `xml:"uri"`
}

// CAURI is a single CA endpoint URI.
type CAURI struct {
	Value      string `xml:",chardata"`
	ClientAuth int    `xml:"clientAuthentication,attr"`
	URI        string `xml:"uri,attr,omitempty"`
}

// OIDCollection holds OID definitions.
type OIDCollection struct {
	OID []OID `xml:"oID"`
}

// OID represents an OID definition.
type OID struct {
	Value          string `xml:"value"`
	Group          int    `xml:"group"`
	OIDReferenceID int    `xml:"oIDReferenceID"`
	DefaultName    string `xml:"defaultName"`
}
