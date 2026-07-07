package smallstep

import (
	"context"
	"crypto/x509"
	"encoding/pem"

	"github.com/Exonical/go-ces/backend"
)

// PolicyProvider implements backend.PolicyProvider backed by Smallstep CA.
// It returns a static policy configuration that maps to the step-ca provisioner.
type PolicyProvider struct {
	// Templates lists the certificate templates to advertise to Windows clients.
	Templates []Template
	// CACert is the PEM-encoded CA certificate to include in policy responses.
	CACert []byte
	// CESURL is the URL of the CES endpoint that Windows clients will use for enrollment.
	CESURL string
}

// Template represents a certificate template mapped to step-ca behavior.
type Template struct {
	Name             string
	OID              string // template OID (can use MS-style OID)
	KeyLength        int
	KeySpec          int // 1=AT_KEYEXCHANGE, 2=AT_SIGNATURE
	HashAlgorithm    string
	ValiditySeconds  int64
	AllowAutoEnroll  bool
}

func (p *PolicyProvider) GetPolicies(_ context.Context) (*backend.PolicyResponse, error) {
	resp := &backend.PolicyResponse{}

	// Parse CA cert for the response
	var caDER []byte
	if len(p.CACert) > 0 {
		block, _ := pem.Decode(p.CACert)
		if block != nil {
			caDER = block.Bytes
		}
	}

	// Build CA reference
	ca := backend.CertificateAuthority{
		ID:          0,
		Certificate: caDER,
		URIs:        []string{p.CESURL},
	}
	if len(caDER) > 0 {
		cert, err := x509.ParseCertificate(caDER)
		if err == nil {
			ca.CommonName = cert.Subject.CommonName
		}
	}
	resp.CAs = []backend.CertificateAuthority{ca}

	// OID reference counter
	oidRef := 1

	// Common OIDs
	templateNameOID := backend.OIDDefinition{
		ReferenceID: oidRef,
		Value:       "1.3.6.1.4.1.311.20.2",
		Group:       6,
		DefaultName: "Certificate Template Name",
	}
	resp.OIDs = append(resp.OIDs, templateNameOID)
	oidRef++

	keyUsageOID := backend.OIDDefinition{
		ReferenceID: oidRef,
		Value:       "2.5.29.15",
		Group:       3,
		DefaultName: "Key Usage",
	}
	resp.OIDs = append(resp.OIDs, keyUsageOID)
	oidRef++

	// Hash algorithm OIDs
	sha256OID := backend.OIDDefinition{
		ReferenceID: oidRef,
		Value:       "2.16.840.1.101.3.4.2.1",
		Group:       0,
		DefaultName: "sha256",
	}
	resp.OIDs = append(resp.OIDs, sha256OID)
	hashOIDRef := oidRef
	oidRef++

	// Build policies from templates
	for _, tmpl := range p.Templates {
		// Add template-specific OID
		tmplOID := backend.OIDDefinition{
			ReferenceID: oidRef,
			Value:       tmpl.OID,
			Group:       9,
			DefaultName: tmpl.Name,
		}
		resp.OIDs = append(resp.OIDs, tmplOID)

		keyLength := tmpl.KeyLength
		if keyLength == 0 {
			keyLength = 2048
		}
		keySpec := tmpl.KeySpec
		if keySpec == 0 {
			keySpec = 1
		}

		policy := backend.CertificateEnrollmentPolicy{
			PolicyID:      tmpl.OID,
			CommonName:    tmpl.Name,
			PolicySchema:  3,
			OIDReferences: []int{templateNameOID.ReferenceID, keyUsageOID.ReferenceID, oidRef},
			CAReferences:  []int{0},
			Attributes: backend.PolicyAttributes{
				CommonName:          tmpl.Name,
				HashAlgorithm:       tmpl.HashAlgorithm,
				HashAlgorithmOIDRef: hashOIDRef,
				KeySpec:             keySpec,
				KeyLength:           keyLength,
				PermissionEnroll:    true,
				PermissionAutoEnroll: tmpl.AllowAutoEnroll,
				CryptoProviders: []string{
					"Microsoft Software Key Storage Provider",
					"Microsoft RSA SChannel Cryptographic Provider",
				},
			},
		}
		resp.Policies = append(resp.Policies, policy)
		oidRef++
	}

	return resp, nil
}
