# Deployment Guide

## Quick Start with Docker Compose

The included `docker-compose.yml` starts go-ces alongside a Smallstep CA for testing:

```bash
docker compose up --build
```

This starts:
- **step-ca** on port 9000 (auto-initialized with a test CA)
- **go-ces-server** on port 8443

## Standalone Binary

```bash
go install github.com/Exonical/go-ces/cmd/go-ces-server@latest

# Run with TLS (recommended for production)
go-ces-server -addr :8443 -tls-cert /path/to/server.crt -tls-key /path/to/server.key

# Run without TLS (development only)
go-ces-server -addr :8080
```

## Windows Client Configuration

### Group Policy (Domain-Joined Machines)

1. Open `gpedit.msc` → Computer Configuration → Windows Settings → Security Settings → Public Key Policies
2. Right-click **Certificate Services Client - Certificate Enrollment Policy** → Properties
3. Add a new enrollment policy server:
   - **URI**: `https://your-server:8443/CEP`
   - **Authentication**: Username and Password (or Certificate)
4. The CES URI is automatically discovered via the CEP response.

### Manual Configuration (Non-Domain)

```powershell
# Add CEP endpoint
certutil -policy -config "https://your-server:8443/CEP" -user

# Or use the Certificates MMC snap-in:
# Action → All Tasks → Request New Certificate → Configure enrollment policy
```

### Registry-Based Configuration

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\PolicyServers\{GUID}]
"URL"="https://your-server:8443/CEP"
"PolicyID"="{GUID}"
"FriendlyName"="Go-CES Policy"
"Flags"=dword:00000010
"AuthFlags"=dword:00000002
"Cost"=dword:00000000
```

AuthFlags values:
- `0x00000001` = Anonymous
- `0x00000002` = Username/Password (Kerberos)
- `0x00000004` = Client Certificate

## TLS Certificate

The server's TLS certificate must be trusted by Windows clients. Options:

1. **Use a certificate from the same CA**: If your step-ca issues the server cert, distribute the root CA via GPO.
2. **Use a publicly trusted cert**: Let's Encrypt or similar.
3. **Manual trust**: Import the CA root into the Windows Trusted Root CA store.

## Production Considerations

- Always enable TLS in production.
- Use client certificate authentication for machine enrollment.
- Place behind a reverse proxy (nginx, Caddy) for TLS termination if needed.
- Monitor the `/health` endpoint for availability checks.
- Configure appropriate firewall rules (port 443 or 8443).

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CES_LISTEN_ADDR` | `:8443` | Listen address |
| `CES_TLS_CERT` | | Path to TLS certificate |
| `CES_TLS_KEY` | | Path to TLS private key |
| `CES_ADVERTISED_URL` | `https://localhost:8443/CES/service.svc/CES` | CES URL advertised in CEP policy responses |
| `CES_CA_URL` | | Smallstep CA URL |
| `CES_CA_ROOT` | | Path to CA root cert (for TLS to step-ca) |
| `CES_PROVISIONER` | | step-ca provisioner name |
