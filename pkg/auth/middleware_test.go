package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_Success(t *testing.T) {
	authn := &UsernamePasswordAuthenticator{
		Validate: func(_, _ string) error { return nil },
	}

	var gotIdentity *Identity
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotIdentity = IdentityFromContext(r.Context())
	})

	handler := Middleware(authn, inner)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.SetBasicAuth("testuser", "testpass")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if gotIdentity == nil || gotIdentity.Username != "testuser" {
		t.Errorf("expected identity with username 'testuser', got %v", gotIdentity)
	}
}

func TestMiddleware_Failure(t *testing.T) {
	authn := &UsernamePasswordAuthenticator{
		Validate: func(_, _ string) error { return errors.New("bad creds") },
	}

	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler should not be called on auth failure")
	})

	handler := Middleware(authn, inner)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.SetBasicAuth("bad", "creds")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestMiddleware_NoCreds(t *testing.T) {
	authn := &UsernamePasswordAuthenticator{}

	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler should not be called without credentials")
	})

	handler := Middleware(authn, inner)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestNoOpAuthenticator(t *testing.T) {
	authn := &NoOpAuthenticator{}
	identity, err := authn.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Username != "anonymous" {
		t.Errorf("expected 'anonymous', got %q", identity.Username)
	}
}
