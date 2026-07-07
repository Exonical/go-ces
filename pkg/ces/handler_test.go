package ces

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Exonical/go-ces/backend/mock"
	"github.com/Exonical/go-ces/pkg/soap"
)

func generateTestCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	return csrDER
}

func buildRSTEnvelope(csrDER []byte) string {
	csrB64 := base64.StdEncoding.EncodeToString(csrDER)
	return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
  <s:Header>
    <a:Action>http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
    <a:MessageID>urn:uuid:test-enroll-001</a:MessageID>
    <a:To>https://ces.example.com/CES</a:To>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:TokenType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/PKCS7</wst:TokenType>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wsse:BinarySecurityToken
        ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
        EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">` + csrB64 + `</wsse:BinarySecurityToken>
      <ac:AdditionalContext>
        <ac:ContextItem Name="CertificateTemplateName">
          <ac:Value>User</ac:Value>
        </ac:ContextItem>
      </ac:AdditionalContext>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`
}

func TestHandler_Enroll(t *testing.T) {
	signer, err := mock.NewSigner()
	if err != nil {
		t.Fatalf("failed to create mock signer: %v", err)
	}
	handler := NewHandler(signer)

	csrDER := generateTestCSR(t)
	reqBody := buildRSTEnvelope(csrDER)

	req := httptest.NewRequest(http.MethodPost, "/CES", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", soap.ContentType)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	// Parse the SOAP envelope
	env, err := soap.ParseEnvelope(body)
	if err != nil {
		t.Fatalf("response is not valid SOAP: %v", err)
	}

	// Verify the response action
	header, err := soap.ParseHeader(env.Header.InnerXML)
	if err != nil {
		t.Fatalf("failed to parse response header: %v", err)
	}
	if header.Action != ActionRSTR {
		t.Errorf("action = %q, want %q", header.Action, ActionRSTR)
	}

	// Unmarshal the RSTR collection
	var collection RequestSecurityTokenResponseCollection
	if err := xml.Unmarshal(env.Body.InnerXML, &collection); err != nil {
		t.Fatalf("failed to unmarshal RSTR collection: %v", err)
	}

	if len(collection.Responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(collection.Responses))
	}

	rstr := collection.Responses[0]
	if rstr.DispositionMessage == nil || rstr.DispositionMessage.Value != "Issued" {
		t.Errorf("disposition = %v, want %q", rstr.DispositionMessage, "Issued")
	}
	if rstr.RequestedSecurityToken == nil {
		t.Fatal("expected RequestedSecurityToken to be non-nil")
	}
	if rstr.RequestedSecurityToken.BinarySecurityToken == nil {
		t.Fatal("expected BinarySecurityToken in response")
	}

	// Verify the RSTR-level certs-only PKCS#7 token is well formed
	if rstr.BinarySecurityToken == nil {
		t.Fatal("expected RSTR-level BinarySecurityToken")
	}
	p7DER, err := base64.StdEncoding.DecodeString(rstr.BinarySecurityToken.Value)
	if err != nil {
		t.Fatalf("failed to decode PKCS#7 token: %v", err)
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(p7DER, &ci); err != nil {
		t.Fatalf("token is not a valid PKCS#7 structure: %v", err)
	}

	// Verify the leaf certificate in RequestedSecurityToken
	certDER, err := base64.StdEncoding.DecodeString(
		rstr.RequestedSecurityToken.BinarySecurityToken.Value)
	if err != nil {
		t.Fatalf("failed to decode cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse issued certificate: %v", err)
	}
	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("cert CN = %q, want %q", cert.Subject.CommonName, "test.example.com")
	}
}

func TestHandler_Poll_Pending(t *testing.T) {
	signer, err := mock.NewSigner()
	if err != nil {
		t.Fatalf("failed to create mock signer: %v", err)
	}
	signer.PendingRequestIDs["req-123"] = true
	handler := NewHandler(signer)

	reqBody := `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
  <s:Header>
    <a:Action>http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
    <a:MessageID>urn:uuid:test-poll-001</a:MessageID>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wst:RequestID>req-123</wst:RequestID>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`

	req := httptest.NewRequest(http.MethodPost, "/CES", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", soap.ContentType)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	body, _ := io.ReadAll(resp.Body)
	env, _ := soap.ParseEnvelope(body)

	var collection RequestSecurityTokenResponseCollection
	if err := xml.Unmarshal(env.Body.InnerXML, &collection); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(collection.Responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(collection.Responses))
	}
	rstr := collection.Responses[0]
	if rstr.DispositionMessage == nil || rstr.DispositionMessage.Value != "Pending" {
		t.Errorf("disposition = %v, want pending", rstr.DispositionMessage)
	}
	if rstr.RequestID == nil || rstr.RequestID.Value != "req-123" {
		t.Errorf("requestID = %v, want %q", rstr.RequestID, "req-123")
	}
}

func TestHandler_WrongMethod(t *testing.T) {
	signer, _ := mock.NewSigner()
	handler := NewHandler(signer)
	req := httptest.NewRequest(http.MethodGet, "/CES", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandler_InvalidSOAP(t *testing.T) {
	signer, _ := mock.NewSigner()
	handler := NewHandler(signer)
	req := httptest.NewRequest(http.MethodPost, "/CES", strings.NewReader("not xml"))
	req.Header.Set("Content-Type", soap.ContentType)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
