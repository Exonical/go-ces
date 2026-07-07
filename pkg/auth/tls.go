package auth

import "net/http"

// TLSClientCertAuthenticator validates identity via mutual TLS client certificate.
type TLSClientCertAuthenticator struct{}

func (a *TLSClientCertAuthenticator) Authenticate(r *http.Request, _ []byte) (*Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, &AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Client certificate required",
		}
	}

	cert := r.TLS.PeerCertificates[0]
	return &Identity{
		Username: cert.Subject.CommonName,
		Cert:     cert,
	}, nil
}
