# Architecture

## Overview

go-ces implements two Microsoft SOAP-based protocols that enable Windows certificate autoenrollment over HTTPS:

```
┌──────────────────────────────────────────────────────┐
│                   go-ces-server                       │
│                                                      │
│  /CEP  ──► pkg/cep.Handler  ──► backend.PolicyProvider │
│  /CES  ──► pkg/ces.Handler  ──► backend.Signer        │
│                                                      │
│  pkg/auth.Middleware (per-endpoint auth)              │
│  pkg/soap (envelope parsing, fault generation)       │
└──────────────────────────────────────────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │   CA Backend        │
              │  (Smallstep, EJBCA, │
              │   Vault PKI, etc.)  │
              └─────────────────────┘
```

## Protocols

### MS-XCEP (Certificate Enrollment Policy)

- **Namespace**: `http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy`
- **Operation**: `GetPolicies` / `GetPoliciesResponse`
- **Purpose**: Windows clients query this endpoint to discover available certificate templates, which CAs can issue them, and cryptographic requirements.
- **Spec**: [MS-XCEP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/08ec4475-32c2-457d-8c27-5a176660a210)

### MS-WSTEP (Certificate Enrollment Service)

- **Namespace**: `http://docs.oasis-open.org/ws-sx/ws-trust/200512`
- **Operation**: `RequestSecurityToken` / `RequestSecurityTokenResponseCollection`
- **Purpose**: Windows clients submit PKCS#10 CSRs wrapped in WS-Trust RST messages. The server returns the signed certificate, a pending status, or a SOAP fault.
- **Spec**: [MS-WSTEP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep/4766a85d-0d18-4fa1-a51f-e5cb98b752ea)

## Package Layout

| Package | Responsibility |
|---------|---------------|
| `pkg/soap` | SOAP 1.2 envelope/fault/WS-Addressing parsing and generation |
| `pkg/cep` | HTTP handler for MS-XCEP, XML message types |
| `pkg/ces` | HTTP handler for MS-WSTEP, XML message types |
| `pkg/auth` | Authentication middleware and authenticator implementations |
| `backend` | `Signer` and `PolicyProvider` interfaces |
| `backend/mock` | In-memory mock (self-signs, static policies) |
| `backend/smallstep` | Smallstep CA integration via REST API |
| `cmd/go-ces-server` | Standalone server binary |

## Enrollment Flow

1. **Policy Discovery** (CEP): Client sends `GetPolicies` SOAP request → server returns templates, CAs, OIDs.
2. **CSR Submission** (CES): Client generates key pair, creates PKCS#10 CSR, sends it in a `RequestSecurityToken` SOAP message with the template name in `AdditionalContext`.
3. **Signing**: Server extracts the CSR, validates it, passes it to the `backend.Signer.Enroll()` method.
4. **Response**: Server returns the signed certificate in a `RequestSecurityTokenResponse` (or a pending/rejected disposition).

## Authentication

Each endpoint URL is configured with one authentication mode:

- **UsernamePassword**: WS-Security `UsernameToken` in SOAP header, or HTTP Basic Auth
- **Certificate**: Mutual TLS client certificate
- **Kerberos**: HTTP Negotiate/SPNEGO (stub for future implementation)

The Windows client determines which mode to use based on the endpoint URL path (e.g., `_CES_UsernamePassword`, `_CES_Kerberos`, `_CES_Certificate`).

## Backend Interface

Implementing a custom CA backend requires two interfaces:

```go
type Signer interface {
    Enroll(ctx context.Context, csr *x509.CertificateRequest, templateName string) (*EnrollmentResult, error)
    Poll(ctx context.Context, requestID string) (*EnrollmentResult, error)
    Renew(ctx context.Context, oldCert *x509.Certificate, csr *x509.CertificateRequest) (*EnrollmentResult, error)
}

type PolicyProvider interface {
    GetPolicies(ctx context.Context) (*PolicyResponse, error)
}
```
