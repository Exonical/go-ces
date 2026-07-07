package smallstep

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Exonical/go-ces/backend"
)

type staticTokenGenerator struct {
	token string
}

func (g *staticTokenGenerator) Generate(_ context.Context, _ string) (string, error) {
	return g.token, nil
}

func TestSigner_Enroll(t *testing.T) {
	// Create a mock step-ca server
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:              pkix.Name{CommonName: "Test CA"},
		NotBefore:            time.Now(),
		NotAfter:             time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                 true,
		BasicConstraintsValid: true,
		KeyUsage:             x509.KeyUsageCertSign,
	}
	_, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	mockCA := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign" {
			http.NotFound(w, r)
			return
		}

		// Parse CSR from request to sign it
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		block, _ := pem.Decode([]byte(req.CsrPEM))
		if block == nil {
			http.Error(w, "invalid CSR PEM", 400)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		// Issue certificate
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		certTmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      csr.Subject,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, certTmpl, caTmpl, csr.PublicKey, caKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

		resp := signResponse{
			ServerPEM: certificateChain{Certificate: string(certPEMBytes)},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockCA.Close()

	// Create signer pointing at mock CA
	signer := NewSigner(Config{
		CAURL:          mockCA.URL,
		RootCAs:        mockCA.TLS.RootCAs,
		Provisioner:    "test",
		TokenGenerator: &staticTokenGenerator{token: "test-token"},
	})
	// Use the mock server's TLS client
	signer.httpClient = mockCA.Client()

	// Generate a CSR
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	// Test enrollment
	result, err := signer.Enroll(context.Background(), csr, "User")
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if result.Status != backend.Issued {
		t.Fatalf("expected Issued, got %d", result.Status)
	}
	if result.Certificate == nil {
		t.Fatal("expected certificate to be non-nil")
	}
	if result.Certificate.Subject.CommonName != "test.example.com" {
		t.Errorf("CN = %q, want %q", result.Certificate.Subject.CommonName, "test.example.com")
	}
}

func TestSigner_Poll(t *testing.T) {
	signer := NewSigner(Config{CAURL: "https://unused"})
	result, err := signer.Poll(context.Background(), "req-123")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != backend.Rejected {
		t.Errorf("expected Rejected, got %d", result.Status)
	}
}

func TestPolicyProvider_GetPolicies(t *testing.T) {
	// Generate a test CA cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Smallstep CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	provider := &PolicyProvider{
		CACert: caPEM,
		CESURL: "https://ces.example.com/CES",
		Templates: []Template{
			{
				Name:            "WebServer",
				OID:             "1.3.6.1.4.1.311.21.8.1",
				KeyLength:       2048,
				KeySpec:         1,
				HashAlgorithm:   "SHA256",
				ValiditySeconds: 365 * 24 * 3600,
				AllowAutoEnroll: false,
			},
			{
				Name:            "User",
				OID:             "1.3.6.1.4.1.311.21.8.2",
				KeyLength:       2048,
				KeySpec:         2,
				HashAlgorithm:   "SHA256",
				ValiditySeconds: 365 * 24 * 3600,
				AllowAutoEnroll: true,
			},
		},
	}

	resp, err := provider.GetPolicies(context.Background())
	if err != nil {
		t.Fatalf("GetPolicies failed: %v", err)
	}

	if len(resp.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(resp.Policies))
	}
	if resp.Policies[0].CommonName != "WebServer" {
		t.Errorf("first policy name = %q, want %q", resp.Policies[0].CommonName, "WebServer")
	}
	if !resp.Policies[1].Attributes.PermissionAutoEnroll {
		t.Error("expected User template to allow auto-enroll")
	}
	if len(resp.CAs) != 1 {
		t.Fatalf("expected 1 CA, got %d", len(resp.CAs))
	}
	if resp.CAs[0].CommonName != "Test Smallstep CA" {
		t.Errorf("CA CN = %q, want %q", resp.CAs[0].CommonName, "Test Smallstep CA")
	}
	if len(resp.OIDs) < 3 {
		t.Errorf("expected at least 3 base OIDs, got %d", len(resp.OIDs))
	}
}
