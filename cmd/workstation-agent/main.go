// Command workstation-agent is the on-box service for multi-user Amazon DCV.
//
// It currently serves the DCV external auth-token-verifier endpoint (the DIY,
// no-broker path). The /ensure-session endpoint — which provisions the Linux
// user + home and creates the per-user virtual session — is the next build step
// (see README "Repository layout").
//
// Both surfaces are bound to loopback and reached only over the client's SSM
// port-forward; nothing here is internet-exposed.
package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/vhco-pro/workstation-agent/internal/identity"
	"github.com/vhco-pro/workstation-agent/internal/verifier"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	addr := getenv("WSA_VERIFIER_ADDR", "127.0.0.1:8444")

	client := &http.Client{Timeout: 10 * time.Second}
	v := verifier.NewHandler(client, identity.FromARN, log)

	mux := http.NewServeMux()
	// DCV posts the token here (configured as auth-token-verifier in dcv.conf).
	mux.Handle("/validate-authentication-token", v)
	// Some deployments point auth-token-verifier at the bare URL; accept root too.
	mux.Handle("/", v)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Info("workstation-agent verifier listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
