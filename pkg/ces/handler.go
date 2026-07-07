package ces

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Exonical/go-ces/backend"
	"github.com/Exonical/go-ces/pkg/soap"
)

// Handler serves the MS-WSTEP (CES) SOAP endpoint.
type Handler struct {
	signer backend.Signer
}

// NewHandler creates a new CES handler backed by the given Signer.
func NewHandler(signer backend.Signer) *Handler {
	return &Handler{signer: signer}
}

// ServeHTTP implements http.Handler for the CES SOAP endpoint.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeFault(w, http.StatusBadRequest, "Failed to read request body")
		return
	}
	defer func() { _ = r.Body.Close() }()

	env, err := soap.ParseEnvelope(body)
	if err != nil {
		h.writeFault(w, http.StatusBadRequest, "Invalid SOAP envelope")
		return
	}

	header, err := soap.ParseHeader(env.Header.InnerXML)
	if err != nil {
		h.writeFault(w, http.StatusBadRequest, "Invalid SOAP header")
		return
	}

	if header.Action != ActionRST {
		h.writeFault(w, http.StatusBadRequest,
			fmt.Sprintf("Unsupported action: %s", header.Action))
		return
	}

	var rst RequestSecurityToken
	if err := xml.Unmarshal(env.Body.InnerXML, &rst); err != nil {
		h.writeFault(w, http.StatusBadRequest, "Failed to parse RequestSecurityToken")
		return
	}

	// Determine the operation type
	switch {
	case rst.RequestID != "":
		h.handlePoll(w, r, &rst)
	case rst.BinarySecurityToken != nil:
		h.handleEnroll(w, r, &rst)
	default:
		h.writeFault(w, http.StatusBadRequest, "Missing BinarySecurityToken or RequestID")
	}
}

func (h *Handler) handleEnroll(w http.ResponseWriter, r *http.Request, rst *RequestSecurityToken) {
	// Decode the CSR from the BinarySecurityToken
	csrDER, err := base64.StdEncoding.DecodeString(
		strings.TrimSpace(rst.BinarySecurityToken.Value))
	if err != nil {
		h.writeFault(w, http.StatusBadRequest, "Invalid base64 in BinarySecurityToken")
		return
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		h.writeFault(w, http.StatusBadRequest, "Invalid PKCS#10 certificate request")
		return
	}

	if err := csr.CheckSignature(); err != nil {
		h.writeFault(w, http.StatusBadRequest, "CSR signature verification failed")
		return
	}

	// Extract template name from AdditionalContext
	templateName := rst.GetContextValue("CertificateTemplateName")
	if templateName == "" {
		// Fall back to the CertificateTemplate context item
		templateName = rst.GetContextValue("CertificateTemplate")
	}

	result, err := h.signer.Enroll(r.Context(), csr, templateName)
	if err != nil {
		h.writeFault(w, http.StatusInternalServerError,
			fmt.Sprintf("Enrollment failed: %v", err))
		return
	}

	h.writeResponse(w, result)
}

func (h *Handler) handlePoll(w http.ResponseWriter, r *http.Request, rst *RequestSecurityToken) {
	result, err := h.signer.Poll(r.Context(), rst.RequestID)
	if err != nil {
		h.writeFault(w, http.StatusInternalServerError,
			fmt.Sprintf("Poll failed: %v", err))
		return
	}

	h.writeResponse(w, result)
}

func (h *Handler) writeResponse(w http.ResponseWriter, result *backend.EnrollmentResult) {
	rstr := RequestSecurityTokenResponse{
		TokenType: TokenTypeX509v3,
	}

	switch result.Status {
	case backend.Issued:
		certB64 := base64.StdEncoding.EncodeToString(result.CertificateRaw)
		rstr.RequestedSecurityToken = &RequestedSecurityToken{
			BinarySecurityToken: &BinarySecurityToken{
				ValueType:    ValueTypePKCS7,
				EncodingType: EncodingTypeBase64,
				Value:        certB64,
			},
		}
		rstr.DispositionMessage = &DispositionMessage{
			Lang:  "en-US",
			Value: DispositionIssued,
		}
	case backend.Pending:
		rstr.RequestID = result.RequestID
		rstr.DispositionMessage = &DispositionMessage{
			Lang:  "en-US",
			Value: DispositionPending,
		}
	case backend.Rejected:
		rstr.DispositionMessage = &DispositionMessage{
			Lang:  "en-US",
			Value: DispositionDenied,
		}
	}

	collection := RequestSecurityTokenResponseCollection{
		XMLNS:     NSWSTrust,
		Responses: []RequestSecurityTokenResponse{rstr},
	}

	respBytes, err := xml.Marshal(collection)
	if err != nil {
		h.writeFault(w, http.StatusInternalServerError, "Failed to marshal response")
		return
	}

	soapEnv := soap.NewEnvelope(ActionRSTR, "", respBytes)
	out, err := soap.Marshal(soapEnv)
	if err != nil {
		h.writeFault(w, http.StatusInternalServerError, "Failed to marshal SOAP envelope")
		return
	}

	w.Header().Set("Content-Type", soap.ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func (h *Handler) writeFault(w http.ResponseWriter, status int, reason string) {
	fault := soap.NewSenderFault(reason)
	if status >= 500 {
		fault = soap.NewReceiverFault(reason)
	}
	out, err := soap.MarshalFaultEnvelope(ActionRSTR, fault)
	if err != nil {
		http.Error(w, reason, status)
		return
	}
	w.Header().Set("Content-Type", soap.ContentType)
	w.WriteHeader(status)
	_, _ = w.Write(out)
}
