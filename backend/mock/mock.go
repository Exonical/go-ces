// Package mock provides an in-memory mock implementation of the backend
// interfaces for testing.
package mock

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/Exonical/go-ces/backend"
)

// Signer is a mock backend.Signer that issues self-signed certificates.
type Signer struct {
	// IssuerCert is used as the CA certificate for signing.
	IssuerCert *x509.Certificate
	IssuerKey  *ecdsa.PrivateKey

	// PendingRequestIDs tracks requests that should be returned as pending.
	PendingRequestIDs map[string]bool
}

// NewPersistentSigner creates a mock Signer whose CA certificate and key are
// loaded from dir if present, or generated and saved there otherwise. This
// keeps the CA stable across restarts so clients only need to trust it once.
func NewPersistentSigner(dir string) (*Signer, error) {
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		certBlock, _ := pem.Decode(certPEM)
		keyBlock, _ := pem.Decode(keyPEM)
		if certBlock == nil || keyBlock == nil {
			return nil, errors.New("mock: invalid PEM in persisted CA files")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, err
		}
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		return &Signer{
			IssuerCert:        cert,
			IssuerKey:         key,
			PendingRequestIDs: make(map[string]bool),
		}, nil
	}

	s, err := NewSigner()
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(s.IssuerKey)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.IssuerCert.Raw})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certOut, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		return nil, err
	}
	return s, nil
}

// NewSigner creates a mock Signer with a self-signed CA.
func NewSigner() (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "go-ces Mock CA",
			Organization: []string{"go-ces"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &Signer{
		IssuerCert:        cert,
		IssuerKey:         key,
		PendingRequestIDs: make(map[string]bool),
	}, nil
}

func (s *Signer) Enroll(_ context.Context, csr *x509.CertificateRequest, _ string) (*backend.EnrollmentResult, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	subject := csr.Subject
	if subject.CommonName == "" && len(csr.DNSNames) == 0 && len(csr.EmailAddresses) == 0 {
		subject.CommonName = "go-ces User"
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, s.IssuerCert, csr.PublicKey, s.IssuerKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &backend.EnrollmentResult{
		Status:         backend.Issued,
		Certificate:    cert,
		CertificateRaw: certDER,
	}, nil
}

func (s *Signer) Poll(_ context.Context, requestID string) (*backend.EnrollmentResult, error) {
	if s.PendingRequestIDs[requestID] {
		return &backend.EnrollmentResult{
			Status:    backend.Pending,
			RequestID: requestID,
			Message:   "Request is still pending approval",
		}, nil
	}
	return &backend.EnrollmentResult{
		Status:  backend.Rejected,
		Message: "Unknown request ID",
	}, nil
}

func (s *Signer) Renew(ctx context.Context, _ *x509.Certificate, csr *x509.CertificateRequest) (*backend.EnrollmentResult, error) {
	return s.Enroll(ctx, csr, "")
}

// PolicyProvider is a mock backend.PolicyProvider with static policies.
type PolicyProvider struct {
	Policies *backend.PolicyResponse
}

// NewPolicyProvider creates a mock PolicyProvider with a default template.
func NewPolicyProvider() *PolicyProvider {
	return &PolicyProvider{
		Policies: &backend.PolicyResponse{
			Policies: []backend.CertificateEnrollmentPolicy{
				{
					PolicyID:      "{083C7011-1D0A-4855-885D-AC945184658C}",
					CommonName:    "User",
					PolicySchema:  3,
					OIDReferences: []int{1, 2},
					CAReferences:  []int{0},
					Attributes: backend.PolicyAttributes{
						CommonName:           "User",
						HashAlgorithm:        "SHA256",
						HashAlgorithmOIDRef:  3,
						KeySpec:              1,
						KeyLength:            2048,
						PermissionEnroll:     true,
						PermissionAutoEnroll: true,
						CryptoProviders:      []string{"Microsoft Software Key Storage Provider"},
					},
				},
			},
			CAs: []backend.CertificateAuthority{
				{
					ID:         0,
					CommonName: "go-ces Mock CA",
					DNSName:    "ca.example.com",
					URIs:       []string{"https://ca.example.com/CES"},
				},
			},
			OIDs: []backend.OIDDefinition{
				{ReferenceID: 1, Value: "1.3.6.1.4.1.311.20.2", Group: 6, DefaultName: "Certificate Template Name"},
				{ReferenceID: 2, Value: "2.5.29.15", Group: 3, DefaultName: "Key Usage"},
				{ReferenceID: 3, Value: "2.16.840.1.101.3.4.2.1", Group: 1, DefaultName: "sha256"},
			},
		},
	}
}

func (p *PolicyProvider) GetPolicies(_ context.Context) (*backend.PolicyResponse, error) {
	return p.Policies, nil
}
