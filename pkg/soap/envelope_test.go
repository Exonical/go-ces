package soap

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestParseEnvelope(t *testing.T) {
	raw := `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action>http://example.com/TestAction</a:Action>
    <a:MessageID>urn:uuid:12345</a:MessageID>
    <a:To>http://example.com/endpoint</a:To>
  </s:Header>
  <s:Body>
    <TestElement>hello</TestElement>
  </s:Body>
</s:Envelope>`

	env, err := ParseEnvelope([]byte(raw))
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	if !strings.Contains(string(env.Header.InnerXML), "TestAction") {
		t.Error("expected header to contain Action")
	}
	if !strings.Contains(string(env.Body.InnerXML), "TestElement") {
		t.Error("expected body to contain TestElement")
	}
}

func TestParseHeader(t *testing.T) {
	raw := []byte(`
    <a:Action xmlns:a="http://www.w3.org/2005/08/addressing">http://example.com/Action</a:Action>
    <a:MessageID xmlns:a="http://www.w3.org/2005/08/addressing">urn:uuid:abc</a:MessageID>
    <a:To xmlns:a="http://www.w3.org/2005/08/addressing">http://example.com/to</a:To>
  `)

	h, err := ParseHeader(raw)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Action != "http://example.com/Action" {
		t.Errorf("Action = %q, want %q", h.Action, "http://example.com/Action")
	}
	if h.MessageID != "urn:uuid:abc" {
		t.Errorf("MessageID = %q, want %q", h.MessageID, "urn:uuid:abc")
	}
	if h.To != "http://example.com/to" {
		t.Errorf("To = %q, want %q", h.To, "http://example.com/to")
	}
}

func TestNewEnvelopeAndMarshal(t *testing.T) {
	body := []byte(`<Test>value</Test>`)
	env := NewEnvelope("http://example.com/Action", "urn:uuid:test-123", body)

	out, err := Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "<?xml") {
		t.Error("missing XML declaration")
	}
	if !strings.Contains(s, NS12) {
		t.Error("missing SOAP 1.2 namespace")
	}
	if !strings.Contains(s, "http://example.com/Action") {
		t.Error("missing action in output")
	}
	if !strings.Contains(s, "<Test>value</Test>") {
		t.Error("missing body content")
	}
}

func TestFaultMarshal(t *testing.T) {
	f := NewSenderFault("Invalid request")
	out, err := xml.Marshal(f)
	if err != nil {
		t.Fatalf("xml.Marshal fault: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, FaultCodeSender) {
		t.Error("missing sender fault code")
	}
	if !strings.Contains(s, "Invalid request") {
		t.Error("missing fault reason")
	}
}

func TestMarshalFaultEnvelope(t *testing.T) {
	out, err := MarshalFaultEnvelope("http://example.com/fault", NewReceiverFault("Server error"))
	if err != nil {
		t.Fatalf("MarshalFaultEnvelope: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, FaultCodeReceiver) {
		t.Error("missing receiver fault code")
	}
	if !strings.Contains(s, "Server error") {
		t.Error("missing fault reason text")
	}
}
