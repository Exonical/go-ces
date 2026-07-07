// Package smallstep implements a backend.Signer that delegates certificate
// signing to a Smallstep CA (step-ca) instance via its REST API.
package smallstep

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Exonical/go-ces/backend"
)

// Config holds configuration for connecting to a Smallstep CA.
type Config struct {
	// CAURL is the base URL of the step-ca instance (e.g. "https://ca.example.com:9000").
	CAURL string
	// RootCAs is the TLS root certificate pool for connecting to step-ca.
	// If nil, the system pool is used.
	RootCAs *x509.CertPool
	// Provisioner is the name of the step-ca provisioner to use.
	Provisioner string
	// ProvisionerPassword is the password/key for the provisioner (for JWK provisioners).
	ProvisionerPassword string
	// TokenGenerator generates a one-time token for authenticating the sign request.
	// If nil, the Signer will use the Provisioner/ProvisionerPassword to generate tokens.
	TokenGenerator TokenGenerator
}

// TokenGenerator produces a one-time provisioning token for step-ca sign requests.
type TokenGenerator interface {
	Generate(ctx context.Context, subject string) (string, error)
}

// Signer implements backend.Signer backed by a Smallstep CA.
type Signer struct {
	config     Config
	httpClient *http.Client
}

// NewSigner creates a new Smallstep CA signer.
func NewSigner(cfg Config) *Signer {
	tlsConfig := &tls.Config{
		RootCAs: cfg.RootCAs,
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	return &Signer{
		config:     cfg,
		httpClient: client,
	}
}

// signRequest is the JSON body sent to step-ca's /sign endpoint.
type signRequest struct {
	CsrPEM string `json:"csr"`
	OTT    string `json:"ott"`
}

// signResponse is the JSON response from step-ca's /sign endpoint.
type signResponse struct {
	ServerPEM certificateChain `json:"serverPEM"`
	CaPEM     certificateChain `json:"caPEM"`
	CertChain []certPEM        `json:"certChain"`
}

type certificateChain struct {
	Certificate string `json:"certificate"`
}

type certPEM struct {
	Certificate string `json:"certificate"`
}

func (s *Signer) Enroll(ctx context.Context, csr *x509.CertificateRequest, templateName string) (*backend.EnrollmentResult, error) {
	// Generate provisioning token
	subject := csr.Subject.CommonName
	if subject == "" && len(csr.DNSNames) > 0 {
		subject = csr.DNSNames[0]
	}

	token, err := s.getToken(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("smallstep: failed to generate token: %w", err)
	}

	// Encode CSR to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})

	// Build sign request
	reqBody := signRequest{
		CsrPEM: string(csrPEM),
		OTT:    token,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("smallstep: failed to marshal sign request: %w", err)
	}

	// Send to step-ca
	url := s.config.CAURL + "/sign"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("smallstep: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("smallstep: sign request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("smallstep: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("smallstep: sign returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var signResp signResponse
	if err := json.Unmarshal(respBody, &signResp); err != nil {
		return nil, fmt.Errorf("smallstep: failed to parse sign response: %w", err)
	}

	// Extract certificate from response
	certPEMStr := signResp.ServerPEM.Certificate
	if certPEMStr == "" && len(signResp.CertChain) > 0 {
		certPEMStr = signResp.CertChain[0].Certificate
	}
	if certPEMStr == "" {
		return nil, fmt.Errorf("smallstep: no certificate in sign response")
	}

	block, _ := pem.Decode([]byte(certPEMStr))
	if block == nil {
		return nil, fmt.Errorf("smallstep: failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("smallstep: failed to parse certificate: %w", err)
	}

	return &backend.EnrollmentResult{
		Status:         backend.Issued,
		Certificate:    cert,
		CertificateRaw: block.Bytes,
	}, nil
}

func (s *Signer) Poll(_ context.Context, _ string) (*backend.EnrollmentResult, error) {
	// Smallstep CA issues immediately; pending is not supported.
	return &backend.EnrollmentResult{
		Status:  backend.Rejected,
		Message: "Smallstep CA does not support pending requests",
	}, nil
}

func (s *Signer) Renew(ctx context.Context, _ *x509.Certificate, csr *x509.CertificateRequest) (*backend.EnrollmentResult, error) {
	// Smallstep renewal uses the same /sign flow with a new token.
	return s.Enroll(ctx, csr, "")
}

func (s *Signer) getToken(ctx context.Context, subject string) (string, error) {
	if s.config.TokenGenerator != nil {
		return s.config.TokenGenerator.Generate(ctx, subject)
	}
	return "", fmt.Errorf("no token generator configured; set Config.TokenGenerator")
}
