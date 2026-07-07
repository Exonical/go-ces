// go-ces-server is a standalone Certificate Enrollment Web Services server
// implementing MS-XCEP (CEP) and MS-WSTEP (CES) protocols.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Exonical/go-ces/backend/mock"
	"github.com/Exonical/go-ces/pkg/cep"
	"github.com/Exonical/go-ces/pkg/ces"
)

func main() {
	addr := flag.String("addr", ":8443", "Listen address")
	certFile := flag.String("tls-cert", "", "TLS certificate file (PEM)")
	keyFile := flag.String("tls-key", "", "TLS private key file (PEM)")
	flag.Parse()

	// Create mock backends for development/testing
	mockSigner, err := mock.NewSigner()
	if err != nil {
		log.Fatalf("Failed to create mock signer: %v", err)
	}
	mockPolicy := mock.NewPolicyProvider()

	// Wire up handlers
	cepHandler := cep.NewHandler(mockPolicy)
	cesHandler := ces.NewHandler(mockSigner)

	mux := http.NewServeMux()
	mux.Handle("/CEP/service.svc/CEP", cepHandler)
	mux.Handle("/CES/service.svc/CES", cesHandler)

	// Also register without the WCF-style path for flexibility
	mux.Handle("/CEP", cepHandler)
	mux.Handle("/CES", cesHandler)

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
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
