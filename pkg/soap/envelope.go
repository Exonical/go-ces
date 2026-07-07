// Package soap provides SOAP 1.2 envelope marshaling/unmarshaling helpers
// for the MS-XCEP and MS-WSTEP protocols.
package soap

import "encoding/xml"

const (
	NS12      = "http://www.w3.org/2003/05/soap-envelope"
	NSAddr    = "http://www.w3.org/2005/08/addressing"
	ContentType = "application/soap+xml; charset=utf-8"
)

// Envelope represents a SOAP 1.2 envelope.
type Envelope struct {
	XMLName xml.Name `xml:"s:Envelope"`
	NS      string   `xml:"xmlns:s,attr"`
	NSAddr  string   `xml:"xmlns:a,attr,omitempty"`
	Header  Header   `xml:"s:Header"`
	Body    Body     `xml:"s:Body"`
}

// Header contains WS-Addressing and security elements.
type Header struct {
	Action    string     `xml:"a:Action,omitempty"`
	MessageID string    `xml:"a:MessageID,omitempty"`
	ReplyTo   *ReplyTo  `xml:"a:ReplyTo,omitempty"`
	To        string    `xml:"a:To,omitempty"`
	Security  *Security `xml:"Security,omitempty"`
	Raw       []byte    `xml:"-"`
}

// ReplyTo holds a WS-Addressing ReplyTo element.
type ReplyTo struct {
	Address string `xml:"a:Address"`
}

// Security holds WS-Security elements (for UsernameToken extraction).
type Security struct {
	XMLName       xml.Name       `xml:"Security"`
	UsernameToken *UsernameToken `xml:"UsernameToken,omitempty"`
}

// UsernameToken represents a WS-Security UsernameToken.
type UsernameToken struct {
	Username string `xml:"Username"`
	Password string `xml:"Password"`
}

// Body wraps the raw inner XML of the SOAP body.
type Body struct {
	InnerXML []byte `xml:",innerxml"`
}

// RawEnvelope is used for initial parsing to extract header and body bytes.
type RawEnvelope struct {
	XMLName xml.Name  `xml:"Envelope"`
	Header  RawHeader `xml:"Header"`
	Body    RawBody   `xml:"Body"`
}

// RawHeader captures the raw header XML.
type RawHeader struct {
	InnerXML []byte `xml:",innerxml"`
}

// RawBody captures the raw body XML.
type RawBody struct {
	InnerXML []byte `xml:",innerxml"`
}

// ParseEnvelope parses a SOAP envelope from raw bytes, returning the
// raw header and body content for further protocol-specific parsing.
func ParseEnvelope(data []byte) (*RawEnvelope, error) {
	var env RawEnvelope
	if err := xml.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// ParseHeader extracts WS-Addressing fields from the raw header bytes.
func ParseHeader(raw []byte) (*Header, error) {
	// Wrap in a temporary root for parsing
	wrapped := append([]byte(`<H xmlns:a="`+NSAddr+`" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">`), raw...)
	wrapped = append(wrapped, []byte(`</H>`)...)

	type headerWrap struct {
		XMLName   xml.Name       `xml:"H"`
		Action    string         `xml:"Action,omitempty"`
		MessageID string         `xml:"MessageID,omitempty"`
		To        string         `xml:"To,omitempty"`
		ReplyTo   *ReplyTo       `xml:"ReplyTo,omitempty"`
		Security  *Security      `xml:"Security,omitempty"`
	}

	var h headerWrap
	if err := xml.Unmarshal(wrapped, &h); err != nil {
		return nil, err
	}

	return &Header{
		Action:    h.Action,
		MessageID: h.MessageID,
		To:        h.To,
		ReplyTo:   h.ReplyTo,
		Security:  h.Security,
		Raw:       raw,
	}, nil
}

// NewEnvelope creates a SOAP 1.2 envelope with the given action and body content.
func NewEnvelope(action, messageID string, body []byte) *Envelope {
	return &Envelope{
		NS:     NS12,
		NSAddr: NSAddr,
		Header: Header{
			Action:    action,
			MessageID: messageID,
		},
		Body: Body{InnerXML: body},
	}
}

// Marshal serializes a SOAP envelope to XML bytes with the XML declaration.
func Marshal(env *Envelope) ([]byte, error) {
	out, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}
