package auth

import (
	"context"
	"net/http"
)

type contextKey string

const identityKey contextKey = "auth.identity"

// Middleware wraps an http.Handler with authentication.
// If authentication fails, it returns the appropriate HTTP error response.
// On success, the Identity is stored in the request context.
func Middleware(auth Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := auth.Authenticate(r, nil)
		if err != nil {
			if authErr, ok := err.(*AuthError); ok {
				http.Error(w, authErr.Message, authErr.Code)
				return
			}
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), identityKey, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// IdentityFromContext extracts the authenticated Identity from a request context.
// Returns nil if no identity is present (unauthenticated request).
func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey).(*Identity)
	return id
}

// NoOpAuthenticator always succeeds with an anonymous identity.
// Use for testing or endpoints that don't require authentication.
type NoOpAuthenticator struct{}

func (a *NoOpAuthenticator) Authenticate(_ *http.Request, _ []byte) (*Identity, error) {
	return &Identity{Username: "anonymous"}, nil
}
