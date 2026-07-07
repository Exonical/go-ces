# go-ces

Go implementation of the Windows Certificate Enrollment Web Services:

- **CEP** — Certificate Enrollment Policy Web Service ([MS-XCEP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/08ec4475-32c2-457d-8c27-5a176660a210))
- **CES** — Certificate Enrollment Web Service ([MS-WSTEP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep/4766a85d-0d18-4fa1-a51f-e5cb98b752ea))

These protocols allow Windows clients to discover available certificate templates and enroll for X.509 certificates over HTTPS/SOAP, enabling autoenrollment scenarios without direct DCOM/RPC access to a Microsoft CA.

## Architecture

```
Windows Client
   │
   ├─► CEP (MS-XCEP): "What templates/CAs are available?"
   │        └─► GetPoliciesResponse
   │
   └─► CES (MS-WSTEP): "Sign this CSR for template X"
            └─► RequestSecurityTokenResponse (cert or pending)
```

The server exposes two SOAP endpoints backed by pluggable interfaces:

- `backend.PolicyProvider` — supplies enrollment policies (templates, CAs, OIDs)
- `backend.Signer` — handles CSR enrollment, polling, and renewal

Any CA can be used as a backend by implementing these interfaces.

## Quick Start

```bash
go install github.com/Exonical/go-ces/cmd/go-ces-server@latest
```

See [docs/deployment.md](docs/deployment.md) for configuration and deployment examples.

## Project Structure

```
pkg/soap/       SOAP 1.2 envelope, fault, WS-Addressing helpers
pkg/cep/        CEP (MS-XCEP) handler and message types
pkg/ces/        CES (MS-WSTEP) handler and message types
pkg/auth/       Authentication middleware (UsernameToken, TLS, Kerberos)
backend/        Signer/PolicyProvider interfaces + implementations
cmd/            Standalone server binary
```

## Authentication

Windows CES/CEP supports three modes (URL-path-based):
- **Username/Password** — WS-Security UsernameToken
- **Client Certificate** — mutual TLS
- **Kerberos/SPNEGO** — HTTP Negotiate (enterprise AD)

## License

MIT
