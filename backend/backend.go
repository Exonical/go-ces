// Package backend defines the pluggable interfaces for CA backends
// that power the CEP and CES protocol handlers.
package backend

import (
	"context"
	"crypto/x509"
)

// EnrollmentStatus represents the outcome state of a certificate enrollment.
type EnrollmentStatus int

const (
	// Issued indicates the certificate was successfully signed and returned.
	Issued EnrollmentStatus = iota
	// Pending indicates the request was accepted but requires further action.
	Pending
	// Rejected indicates the request was denied.
	Rejected
)

// EnrollmentResult represents the outcome of a certificate enrollment request.
type EnrollmentResult struct {
	// Status indicates whether the cert was issued, is pending, or was rejected.
	Status EnrollmentStatus
	// Certificate is the signed X.509 certificate (non-nil when Status == Issued).
	Certificate *x509.Certificate
	// CertificateRaw is the DER-encoded certificate bytes.
	CertificateRaw []byte
	// RequestID is an opaque identifier for pending requests (used for polling).
	RequestID string
	// Message is a human-readable description (e.g. rejection reason).
	Message string
}

// Signer handles certificate signing requests — the core CES backend operation.
type Signer interface {
	// Enroll processes a PKCS#10 CSR for the named template.
	// The templateName corresponds to the CertificateTemplateName from the
	// MS-WSTEP AdditionalContext.
	Enroll(ctx context.Context, csr *x509.CertificateRequest, templateName string) (*EnrollmentResult, error)

	// Poll checks the status of a previously pending enrollment request.
	Poll(ctx context.Context, requestID string) (*EnrollmentResult, error)

	// Renew handles certificate renewal given the existing cert and a new CSR.
	Renew(ctx context.Context, oldCert *x509.Certificate, csr *x509.CertificateRequest) (*EnrollmentResult, error)
}

// PolicyProvider returns enrollment policies for the CEP (MS-XCEP) endpoint.
type PolicyProvider interface {
	// GetPolicies returns the certificate enrollment policies, CAs, and OIDs
	// to advertise to Windows clients.
	GetPolicies(ctx context.Context) (*PolicyResponse, error)
}

// PolicyResponse contains the data for a GetPoliciesResponse message.
type PolicyResponse struct {
	Policies []CertificateEnrollmentPolicy
	CAs      []CertificateAuthority
	OIDs     []OIDDefinition
}

// CertificateEnrollmentPolicy represents a single certificate template/policy.
type CertificateEnrollmentPolicy struct {
	PolicyID         string
	CommonName       string
	PolicySchema     int
	OIDReferences    []int
	CAReferences     []int
	Attributes       PolicyAttributes
}

// PolicyAttributes holds the attributes of a certificate enrollment policy.
type PolicyAttributes struct {
	CommonName           string
	HashAlgorithm        string
	HashAlgorithmOIDRef  int
	KeySpec              int // 1=AT_KEYEXCHANGE, 2=AT_SIGNATURE
	KeyLength            int
	CryptoProviders      []string
	PrivateKeyFlags      uint32
	SubjectNameFlags     uint32
	EnrollmentFlags      uint32
	GeneralFlags         uint32
	PermissionEnroll     bool
	PermissionAutoEnroll bool
	Extensions           []PolicyExtension
	PrivateKeySecurityDescriptor string
}

// PolicyExtension represents an X.509 extension in a policy template.
type PolicyExtension struct {
	OIDReference int
	Critical     bool
	Value        []byte
}

// CertificateAuthority represents a CA that can issue certs for a policy.
type CertificateAuthority struct {
	ID          int
	CommonName  string
	DNSName     string
	Certificate []byte   // DER-encoded CA certificate
	URIs        []string // CES endpoint URIs
}

// OIDDefinition represents an OID referenced by policies.
type OIDDefinition struct {
	ReferenceID int
	Value       string // dotted OID, e.g. "1.3.6.1.4.1.311.20.2"
	Group       int
	DefaultName string
}
