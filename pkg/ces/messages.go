// Package ces implements the Certificate Enrollment Web Service
// (MS-WSTEP) protocol handler.
package ces

import "encoding/xml"

const (
	NSWSTrust    = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
	NSWSSecurity = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	NSWSSUtil    = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	NSAuthz      = "http://schemas.xmlsoap.org/ws/2006/12/authorization"
	NSEnrollment = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"

	ActionRST  = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"
	ActionRSTR = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"

	// RequestType values
	RequestTypeIssue = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"

	// TokenType for X.509v3 certificate
	TokenTypeX509v3 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PKCS7"

	// BinarySecurityToken ValueTypes
	ValueTypePKCS10 = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
	ValueTypePKCS7  = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS7"

	// EncodingType
	EncodingTypeBase64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"

	// Disposition values for RequestSecurityTokenResponse
	DispositionIssued  = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#issued"
	DispositionPending = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#pending"
	DispositionDenied  = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#denied"
)

// RequestSecurityToken (RST) is the MS-WSTEP enrollment request.
type RequestSecurityToken struct {
	XMLName            xml.Name            `xml:"RequestSecurityToken"`
	TokenType          string              `xml:"TokenType,omitempty"`
	RequestType        string              `xml:"RequestType"`
	BinarySecurityToken *BinarySecurityToken `xml:"BinarySecurityToken,omitempty"`
	AdditionalContext  *AdditionalContext  `xml:"AdditionalContext,omitempty"`
	RequestID          string              `xml:"RequestID,omitempty"`
}

// BinarySecurityToken carries the PKCS#10 CSR or PKCS#7 renewal request.
type BinarySecurityToken struct {
	XMLName      xml.Name `xml:"BinarySecurityToken"`
	ValueType    string   `xml:"ValueType,attr"`
	EncodingType string   `xml:"EncodingType,attr"`
	Value        string   `xml:",chardata"`
}

// AdditionalContext carries extra enrollment parameters.
type AdditionalContext struct {
	XMLName     xml.Name         `xml:"AdditionalContext"`
	ContextItems []ContextItem   `xml:"ContextItem"`
}

// ContextItem is a name-value pair in AdditionalContext.
type ContextItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"Value"`
}

// RequestSecurityTokenResponseCollection wraps one or more RSTR elements.
type RequestSecurityTokenResponseCollection struct {
	XMLName   xml.Name                     `xml:"RequestSecurityTokenResponseCollection"`
	XMLNS     string                       `xml:"xmlns,attr"`
	Responses []RequestSecurityTokenResponse `xml:"RequestSecurityTokenResponse"`
}

// RequestSecurityTokenResponse (RSTR) is the enrollment response.
type RequestSecurityTokenResponse struct {
	XMLName             xml.Name             `xml:"RequestSecurityTokenResponse"`
	TokenType           string               `xml:"TokenType,omitempty"`
	DispositionMessage  *DispositionMessage  `xml:"DispositionMessage,omitempty"`
	RequestedSecurityToken *RequestedSecurityToken `xml:"RequestedSecurityToken,omitempty"`
	RequestID           string               `xml:"RequestID,omitempty"`
}

// DispositionMessage indicates the enrollment result status.
type DispositionMessage struct {
	XMLName xml.Name `xml:"DispositionMessage"`
	Lang    string   `xml:"xml:lang,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// RequestedSecurityToken wraps the issued certificate.
type RequestedSecurityToken struct {
	XMLName             xml.Name             `xml:"RequestedSecurityToken"`
	BinarySecurityToken *BinarySecurityToken `xml:"BinarySecurityToken"`
}

// GetContextValue extracts a named value from AdditionalContext.
func (rst *RequestSecurityToken) GetContextValue(name string) string {
	if rst.AdditionalContext == nil {
		return ""
	}
	for _, item := range rst.AdditionalContext.ContextItems {
		if item.Name == name {
			return item.Value
		}
	}
	return ""
}
