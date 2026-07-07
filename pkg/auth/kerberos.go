package auth

import "net/http"

// KerberosAuthenticator validates Kerberos/SPNEGO credentials from the
// HTTP Negotiate header. This is a stub for future implementation.
type KerberosAuthenticator struct{}

func (a *KerberosAuthenticator) Authenticate(r *http.Request, _ []byte) (*Identity, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 10 {
		return nil, &AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Kerberos authentication required (Negotiate header missing)",
		}
	}

	// TODO: Implement SPNEGO/Kerberos token validation.
	// This requires integration with a KDC (e.g. via gokrb5).
	return nil, &AuthError{
		Code:    http.StatusNotImplemented,
		Message: "Kerberos authentication not yet implemented",
	}
}
