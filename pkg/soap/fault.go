package soap

import "encoding/xml"

// Fault codes per WS-Trust and MS-WSTEP specifications.
const (
	FaultCodeSender   = "s:Sender"
	FaultCodeReceiver = "s:Receiver"
)

// Fault represents a SOAP 1.2 fault element.
type Fault struct {
	XMLName xml.Name    `xml:"s:Fault"`
	Code    FaultCode   `xml:"s:Code"`
	Reason  FaultReason `xml:"s:Reason"`
	Detail  *FaultDetail `xml:"s:Detail,omitempty"`
}

// FaultCode contains the fault code value and optional subcode.
type FaultCode struct {
	Value   string     `xml:"s:Value"`
	Subcode *FaultSubcode `xml:"s:Subcode,omitempty"`
}

// FaultSubcode contains a subcode value.
type FaultSubcode struct {
	Value string `xml:"s:Value"`
}

// FaultReason contains a human-readable fault message.
type FaultReason struct {
	Text FaultText `xml:"s:Text"`
}

// FaultText is a language-tagged fault reason string.
type FaultText struct {
	Lang  string `xml:"xml:lang,attr"`
	Value string `xml:",chardata"`
}

// FaultDetail carries protocol-specific fault detail elements.
type FaultDetail struct {
	InnerXML []byte `xml:",innerxml"`
}

// NewFault creates a SOAP fault with the given code and reason.
func NewFault(code, subcode, reason string) *Fault {
	f := &Fault{
		Code: FaultCode{Value: code},
		Reason: FaultReason{
			Text: FaultText{Lang: "en-US", Value: reason},
		},
	}
	if subcode != "" {
		f.Code.Subcode = &FaultSubcode{Value: subcode}
	}
	return f
}

// NewSenderFault creates a SOAP fault indicating a client error.
func NewSenderFault(reason string) *Fault {
	return NewFault(FaultCodeSender, "", reason)
}

// NewReceiverFault creates a SOAP fault indicating a server error.
func NewReceiverFault(reason string) *Fault {
	return NewFault(FaultCodeReceiver, "", reason)
}

// MarshalFaultEnvelope creates a complete SOAP fault envelope.
func MarshalFaultEnvelope(action string, fault *Fault) ([]byte, error) {
	faultBytes, err := xml.Marshal(fault)
	if err != nil {
		return nil, err
	}
	env := NewEnvelope(action, "", faultBytes)
	return Marshal(env)
}
