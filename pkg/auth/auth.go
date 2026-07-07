// Package auth provides authentication middleware for the CEP/CES endpoints.
package auth

import (
	"crypto/x509"
	"net/http"
)

// Identity represents the authenticated caller.
type Identity struct {
	Username string
	Domain   string
	Cert     *x509.Certificate
}

// Authenticator validates incoming requests and extracts caller identity.
type Authenticator interface {
	Authenticate(r *http.Request, soapHeader []byte) (*Identity, error)
}

// AuthError is returned when authentication fails.
type AuthError struct {
	Code    int
	Message string
}

func (e *AuthError) Error() string {
	return e.Message
}
