// go-ces-server is a standalone Certificate Enrollment Web Services server
// implementing MS-XCEP (CEP) and MS-WSTEP (CES) protocols.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/Exonical/go-ces/backend/mock"
	"github.com/Exonical/go-ces/pkg/cep"
	"github.com/Exonical/go-ces/pkg/ces"
)

// debugLog dumps request and response bodies when CES_DEBUG=1.
func debugLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("CES_DEBUG") != "1" {
			next.ServeHTTP(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		log.Printf("REQUEST %s %s\nHeaders: %v\nBody:\n%s", r.Method, r.URL.Path, r.Header, body)
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("RESPONSE %d\nBody:\n%s", rec.status, rec.buf.String())
	})
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.buf.Write(b)
	return r.ResponseWriter.Write(b)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	addr := flag.String("addr", envOr("CES_LISTEN_ADDR", ":8443"), "Listen address")
	certFile := flag.String("tls-cert", envOr("CES_TLS_CERT", ""), "TLS certificate file (PEM)")
	keyFile := flag.String("tls-key", envOr("CES_TLS_KEY", ""), "TLS private key file (PEM)")
	cesURL := flag.String("ces-url", envOr("CES_ADVERTISED_URL", "https://localhost:8443/CES/service.svc/CES"), "CES endpoint URL advertised in CEP policy responses")
	flag.Parse()

	// Create mock backends for development/testing
	var mockSigner *mock.Signer
	var err error
	if dir := os.Getenv("CES_MOCK_CA_DIR"); dir != "" {
		mockSigner, err = mock.NewPersistentSigner(dir)
	} else {
		mockSigner, err = mock.NewSigner()
	}
	if err != nil {
		log.Fatalf("Failed to create mock signer: %v", err)
	}
	mockPolicy := mock.NewPolicyProvider()
	if len(mockPolicy.Policies.CAs) > 0 {
		mockPolicy.Policies.CAs[0].URIs = []string{*cesURL}
		mockPolicy.Policies.CAs[0].Certificate = mockSigner.IssuerCert.Raw
	}

	// Wire up handlers
	cepHandler := cep.NewHandler(mockPolicy)
	cesHandler := ces.NewHandler(mockSigner)

	mux := http.NewServeMux()
	mux.Handle("/CEP/service.svc/CEP", debugLog(cepHandler))
	mux.Handle("/CES/service.svc/CES", debugLog(cesHandler))

	// Also register without the WCF-style path for flexibility
	mux.Handle("/CEP", debugLog(cepHandler))
	mux.Handle("/CES", debugLog(cesHandler))

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "ok")
	})

	log.Printf("go-ces-server starting on %s", *addr)
	log.Printf("  CEP: %s/CEP", *addr)
	log.Printf("  CES: %s/CES", *addr)

	if *certFile != "" && *keyFile != "" {
		log.Printf("  TLS enabled")
		if err := http.ListenAndServeTLS(*addr, *certFile, *keyFile, mux); err != nil {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
		}
	} else {
		log.Printf("  TLS disabled (use -tls-cert and -tls-key for production)")
		if err := http.ListenAndServe(*addr, mux); err != nil {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
		}
	}
}
