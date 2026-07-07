// Package cep implements the Certificate Enrollment Policy Web Service
// (MS-XCEP) protocol handler.
package cep

import "encoding/xml"

const (
	NSEnrollmentPolicy        = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
	ActionGetPolicies         = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"
	ActionGetPoliciesResponse = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse"
)

// GetPolicies represents the MS-XCEP GetPolicies request element.
type GetPolicies struct {
	XMLName       xml.Name      `xml:"GetPolicies"`
	Client        Client        `xml:"client"`
	RequestFilter RequestFilter `xml:"requestFilter"`
}

// Client contains information about the requesting client.
type Client struct {
	LastUpdate    string `xml:"lastUpdate,omitempty"`
	PreferredLang string `xml:"preferredLanguage,omitempty"`
}

// RequestFilter specifies which policies to return.
type RequestFilter struct {
	PolicyOIDs    *PolicyOIDs `xml:"policyOIDs,omitempty"`
	ClientVersion int         `xml:"clientVersion,omitempty"`
	ServerVersion int         `xml:"serverVersion,omitempty"`
}

// PolicyOIDs is a collection of policy OID strings.
type PolicyOIDs struct {
	OID []string `xml:"oid"`
}

// GetPoliciesResponse represents the MS-XCEP GetPoliciesResponse element.
type GetPoliciesResponse struct {
	XMLName  xml.Name      `xml:"GetPoliciesResponse"`
	XMLNS    string        `xml:"xmlns,attr"`
	XMLNSXSI string        `xml:"xmlns:xsi,attr"`
	Response Response      `xml:"response"`
	CAs      CACollection  `xml:"cAs"`
	OIDs     OIDCollection `xml:"oIDs"`
}

// NSXSI is the XML Schema instance namespace, required for xsi:nil attributes.
const NSXSI = "http://www.w3.org/2001/XMLSchema-instance"

// Nillable represents an element that is required by the MS-XCEP schema but
// may carry xsi:nil="true" when it has no value. Windows WWSAPI clients
// reject responses where these elements are omitted entirely.
type Nillable struct {
	Nil   bool   `xml:"xsi:nil,attr,omitempty"`
	Value string `xml:",chardata"`
}

// NilValue returns a Nillable marked xsi:nil="true".
func NilValue() Nillable { return Nillable{Nil: true} }

// Value returns a Nillable carrying the given value.
func Value(v string) Nillable { return Nillable{Value: v} }

// Response contains the certificate enrollment policies.
type Response struct {
	PolicyID           string                        `xml:"policyID"`
	PolicyFriendlyName Nillable                      `xml:"policyFriendlyName"`
	NextUpdateHours    Nillable                      `xml:"nextUpdateHours"`
	PoliciesNotChanged Nillable                      `xml:"policiesNotChanged"`
	Policies           []CertificateEnrollmentPolicy `xml:"policies>policy"`
}

// CertificateEnrollmentPolicy is an individual policy (template).
type CertificateEnrollmentPolicy struct {
	PolicyOIDReference int                   `xml:"policyOIDReference"`
	CAs                CAReferenceCollection `xml:"cAs"`
	Attributes         Attributes            `xml:"attributes"`
}

// CAReferenceCollection holds references to CAs that can issue this policy.
type CAReferenceCollection struct {
	CAReferences []int `xml:"cAReference"`
}

// Attributes holds the detailed attributes of a certificate enrollment policy.
// All nillable elements are required by the MS-XCEP schema and must appear
// with xsi:nil="true" when empty.
type Attributes struct {
	CommonName                string                `xml:"commonName"`
	PolicySchema              int                   `xml:"policySchema"`
	CertificateValidity       CertificateValidity   `xml:"certificateValidity"`
	Permission                Permission            `xml:"permission"`
	PrivateKeyAttributes      PrivateKeyAttributes  `xml:"privateKeyAttributes"`
	Revision                  Revision              `xml:"revision"`
	SupersededPolicies        SupersededPolicies    `xml:"supersededPolicies"`
	PrivateKeyFlags           Nillable              `xml:"privateKeyFlags"`
	SubjectNameFlags          Nillable              `xml:"subjectNameFlags"`
	EnrollmentFlags           Nillable              `xml:"enrollmentFlags"`
	GeneralFlags              Nillable              `xml:"generalFlags"`
	HashAlgorithmOIDReference Nillable              `xml:"hashAlgorithmOIDReference"`
	RARequirements            RARequirements        `xml:"rARequirements"`
	KeyArchivalAttributes     KeyArchivalAttributes `xml:"keyArchivalAttributes"`
	Extensions                Extensions            `xml:"extensions"`
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
	MinimalKeyLength      int             `xml:"minimalKeyLength"`
	KeySpec               Nillable        `xml:"keySpec"`
	KeyUsageProperty      Nillable        `xml:"keyUsageProperty"`
	Permissions           Nillable        `xml:"permissions"`
	AlgorithmOIDReference Nillable        `xml:"algorithmOIDReference"`
	CryptoProviders       CryptoProviders `xml:"cryptoProviders"`
}

// CryptoProviders is a list of allowed crypto providers.
type CryptoProviders struct {
	Nil      bool     `xml:"xsi:nil,attr,omitempty"`
	Provider []string `xml:"provider,omitempty"`
}

// Revision tracks the template version.
type Revision struct {
	MajorRevision int `xml:"majorRevision"`
	MinorRevision int `xml:"minorRevision"`
}

// SupersededPolicies lists policies superseded by this one.
type SupersededPolicies struct {
	Nil        bool     `xml:"xsi:nil,attr,omitempty"`
	PolicyOIDs []string `xml:"commonName,omitempty"`
}

// RARequirements specifies Registration Authority requirements.
type RARequirements struct {
	Nil          bool `xml:"xsi:nil,attr,omitempty"`
	RASignatures *int `xml:"rASignatures,omitempty"`
}

// KeyArchivalAttributes specifies key archival settings.
type KeyArchivalAttributes struct {
	Nil                            bool `xml:"xsi:nil,attr,omitempty"`
	SymmetricAlgorithmOIDReference *int `xml:"symmetricAlgorithmOIDReference,omitempty"`
	SymmetricAlgorithmKeyLength    *int `xml:"symmetricAlgorithmKeyLength,omitempty"`
}

// Extensions is a collection of policy extensions.
type Extensions struct {
	Nil       bool        `xml:"xsi:nil,attr,omitempty"`
	Extension []Extension `xml:"extension,omitempty"`
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
	URIs                 CARICollection `xml:"uris"`
	Certificate          string         `xml:"certificate"` // base64 DER
	EnrollmentPermission bool           `xml:"enrollPermission"`
	CAReferenceID        int            `xml:"cAReferenceID"`
}

// CARICollection holds CA URI references.
type CARICollection struct {
	URI []CAURI `xml:"cAURI"`
}

// CAURI is a single CA endpoint URI. Per MS-XCEP these are child elements,
// not attributes.
type CAURI struct {
	ClientAuthentication int      `xml:"clientAuthentication"`
	URI                  string   `xml:"uri"`
	Priority             Nillable `xml:"priority"`
	RenewalOnly          bool     `xml:"renewalOnly"`
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
