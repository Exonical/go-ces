package cep

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"

	"github.com/Exonical/go-ces/backend"
	"github.com/Exonical/go-ces/pkg/soap"
)

// Handler serves the MS-XCEP (CEP) SOAP endpoint.
type Handler struct {
	provider backend.PolicyProvider
}

// NewHandler creates a new CEP handler backed by the given PolicyProvider.
func NewHandler(provider backend.PolicyProvider) *Handler {
	return &Handler{provider: provider}
}

// ServeHTTP implements http.Handler for the CEP SOAP endpoint.
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
	defer r.Body.Close()

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

	if header.Action != ActionGetPolicies {
		h.writeFault(w, http.StatusBadRequest,
			fmt.Sprintf("Unsupported action: %s", header.Action))
		return
	}

	policyResp, err := h.provider.GetPolicies(r.Context())
	if err != nil {
		h.writeFault(w, http.StatusInternalServerError, "Failed to retrieve policies")
		return
	}

	resp := h.buildResponse(policyResp)
	respBytes, err := xml.Marshal(resp)
	if err != nil {
		h.writeFault(w, http.StatusInternalServerError, "Failed to marshal response")
		return
	}

	soapEnv := soap.NewEnvelope(ActionGetPoliciesResponse, "", respBytes)
	out, err := soap.Marshal(soapEnv)
	if err != nil {
		h.writeFault(w, http.StatusInternalServerError, "Failed to marshal SOAP envelope")
		return
	}

	w.Header().Set("Content-Type", soap.ContentType)
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

func (h *Handler) buildResponse(pr *backend.PolicyResponse) *GetPoliciesResponse {
	resp := &GetPoliciesResponse{
		XMLNS: NSEnrollmentPolicy,
	}

	for _, p := range pr.Policies {
		policy := CertificateEnrollmentPolicy{
			PolicyOIDReference: findPolicyOIDRef(p, pr.OIDs),
			CAs:                CAReferenceCollection{CAReferences: p.CAReferences},
			Attributes: Attributes{
				CommonName:   p.Attributes.CommonName,
				PolicySchema: p.PolicySchema,
				CertificateValidity: CertificateValidity{
					ValidityPeriodSeconds: 365 * 24 * 3600,
					RenewalPeriodSeconds:  30 * 24 * 3600,
				},
				Permission: Permission{
					Enroll:     p.Attributes.PermissionEnroll,
					AutoEnroll: p.Attributes.PermissionAutoEnroll,
				},
				PrivateKeyAttributes: PrivateKeyAttributes{
					MinimalKeyLength: p.Attributes.KeyLength,
					KeySpec:          intPtr(p.Attributes.KeySpec),
				},
				Revision: Revision{MajorRevision: 100, MinorRevision: 1},
			},
		}
		if len(p.Attributes.CryptoProviders) > 0 {
			policy.Attributes.PrivateKeyAttributes.CryptoProviders = &CryptoProviders{
				Provider: p.Attributes.CryptoProviders,
			}
		}
		if p.Attributes.HashAlgorithmOIDRef > 0 {
			policy.Attributes.HashAlgorithmOIDReference = &p.Attributes.HashAlgorithmOIDRef
		}
		if p.Attributes.PrivateKeyFlags != 0 {
			policy.Attributes.PrivateKeyFlags = &p.Attributes.PrivateKeyFlags
		}
		if p.Attributes.SubjectNameFlags != 0 {
			policy.Attributes.SubjectNameFlags = &p.Attributes.SubjectNameFlags
		}
		if p.Attributes.EnrollmentFlags != 0 {
			policy.Attributes.EnrollmentFlags = &p.Attributes.EnrollmentFlags
		}
		if p.Attributes.GeneralFlags != 0 {
			policy.Attributes.GeneralFlags = &p.Attributes.GeneralFlags
		}
		if len(p.Attributes.Extensions) > 0 {
			exts := &Extensions{}
			for _, e := range p.Attributes.Extensions {
				exts.Extension = append(exts.Extension, Extension{
					OIDReference: e.OIDReference,
					Critical:     e.Critical,
					Value:        base64.StdEncoding.EncodeToString(e.Value),
				})
			}
			policy.Attributes.Extensions = exts
		}
		resp.Response.Policies = append(resp.Response.Policies, policy)
	}

	for _, ca := range pr.CAs {
		uris := CARICollection{}
		for _, u := range ca.URIs {
			uris.URI = append(uris.URI, CAURI{Value: u, ClientAuth: 1})
		}
		resp.CAs.CA = append(resp.CAs.CA, CA{
			URIs:                 uris,
			Certificate:          base64.StdEncoding.EncodeToString(ca.Certificate),
			EnrollmentPermission: true,
			CAReferenceID:        ca.ID,
		})
	}

	for _, oid := range pr.OIDs {
		resp.OIDs.OID = append(resp.OIDs.OID, OID{
			Value:          oid.Value,
			Group:          oid.Group,
			OIDReferenceID: oid.ReferenceID,
			DefaultName:    oid.DefaultName,
		})
	}

	return resp
}

func (h *Handler) writeFault(w http.ResponseWriter, status int, reason string) {
	fault := soap.NewSenderFault(reason)
	if status >= 500 {
		fault = soap.NewReceiverFault(reason)
	}
	out, err := soap.MarshalFaultEnvelope(ActionGetPoliciesResponse, fault)
	if err != nil {
		http.Error(w, reason, status)
		return
	}
	w.Header().Set("Content-Type", soap.ContentType)
	w.WriteHeader(status)
	w.Write(out)
}

func findPolicyOIDRef(p backend.CertificateEnrollmentPolicy, oids []backend.OIDDefinition) int {
	if len(p.OIDReferences) > 0 {
		return p.OIDReferences[0]
	}
	return 0
}

func intPtr(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}
