package cep

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Exonical/go-ces/backend/mock"
	"github.com/Exonical/go-ces/pkg/soap"
)

func TestHandler_GetPolicies(t *testing.T) {
	provider := mock.NewPolicyProvider()
	handler := NewHandler(provider)

	reqBody := `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action>http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies</a:Action>
    <a:MessageID>urn:uuid:test-001</a:MessageID>
    <a:To>https://ces.example.com/CEP</a:To>
  </s:Header>
  <s:Body>
    <GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
      <client>
        <lastUpdate>2024-01-01T00:00:00Z</lastUpdate>
        <preferredLanguage>en-US</preferredLanguage>
      </client>
      <requestFilter>
        <policyOIDs/>
      </requestFilter>
    </GetPolicies>
  </s:Body>
</s:Envelope>`

	req := httptest.NewRequest(http.MethodPost, "/CEP", strings.NewReader(reqBody))
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

	// Verify it's valid SOAP
	env, err := soap.ParseEnvelope(body)
	if err != nil {
		t.Fatalf("response is not valid SOAP: %v", err)
	}

	// Check the action in header
	header, err := soap.ParseHeader(env.Header.InnerXML)
	if err != nil {
		t.Fatalf("failed to parse response header: %v", err)
	}
	if header.Action != ActionGetPoliciesResponse {
		t.Errorf("action = %q, want %q", header.Action, ActionGetPoliciesResponse)
	}

	// Verify GetPoliciesResponse can be unmarshaled
	var policiesResp GetPoliciesResponse
	if err := xml.Unmarshal(env.Body.InnerXML, &policiesResp); err != nil {
		t.Fatalf("failed to unmarshal GetPoliciesResponse: %v", err)
	}

	if len(policiesResp.Response.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policiesResp.Response.Policies))
	}
	if policiesResp.Response.Policies[0].Attributes.CommonName != "User" {
		t.Errorf("commonName = %q, want %q",
			policiesResp.Response.Policies[0].Attributes.CommonName, "User")
	}
	if len(policiesResp.CAs.CA) != 1 {
		t.Fatalf("expected 1 CA, got %d", len(policiesResp.CAs.CA))
	}
	if len(policiesResp.OIDs.OID) != 3 {
		t.Fatalf("expected 3 OIDs, got %d", len(policiesResp.OIDs.OID))
	}
}

func TestHandler_WrongMethod(t *testing.T) {
	handler := NewHandler(mock.NewPolicyProvider())
	req := httptest.NewRequest(http.MethodGet, "/CEP", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandler_WrongAction(t *testing.T) {
	handler := NewHandler(mock.NewPolicyProvider())
	reqBody := `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action>http://example.com/WrongAction</a:Action>
  </s:Header>
  <s:Body><Foo/></s:Body>
</s:Envelope>`

	req := httptest.NewRequest(http.MethodPost, "/CEP", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", soap.ContentType)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
