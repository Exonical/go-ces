package auth

import (
	"encoding/xml"
	"net/http"
)

// UsernamePasswordAuthenticator validates WS-Security UsernameToken credentials.
type UsernamePasswordAuthenticator struct {
	// Validate is called with the extracted username and password.
	// Return nil error to allow access, or an error to deny.
	Validate func(username, password string) error
}

type usernameTokenHeader struct {
	XMLName       xml.Name `xml:"H"`
	UsernameToken struct {
		Username string `xml:"Username"`
		Password string `xml:"Password"`
	} `xml:"Security>UsernameToken"`
}

func (a *UsernamePasswordAuthenticator) Authenticate(r *http.Request, soapHeader []byte) (*Identity, error) {
	// Try WS-Security UsernameToken from SOAP header
	if len(soapHeader) > 0 {
		wrapped := []byte(`<H>`)
		wrapped = append(wrapped, soapHeader...)
		wrapped = append(wrapped, []byte(`</H>`)...)

		var h usernameTokenHeader
		if err := xml.Unmarshal(wrapped, &h); err == nil && h.UsernameToken.Username != "" {
			if a.Validate != nil {
				if err := a.Validate(h.UsernameToken.Username, h.UsernameToken.Password); err != nil {
					return nil, &AuthError{Code: http.StatusForbidden, Message: err.Error()}
				}
			}
			return &Identity{Username: h.UsernameToken.Username}, nil
		}
	}

	// Fall back to HTTP Basic Auth
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, &AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Missing credentials",
		}
	}

	if a.Validate != nil {
		if err := a.Validate(username, password); err != nil {
			return nil, &AuthError{Code: http.StatusForbidden, Message: err.Error()}
		}
	}

	return &Identity{Username: username}, nil
}
