// Command workstation-agent is the on-box service for multi-user Amazon DCV.
//
// It serves two loopback HTTP surfaces, reached only over the client's SSM
// port-forward (nothing here is internet-exposed):
//
//   - /validate-authentication-token — the DCV auth-token-verifier endpoint
//     (DIY, no-broker path): re-executes the presigned token, maps it to a user.
//   - /ensure-session — provisions the Linux user + home and creates the
//     per-user virtual session, authenticated by the SAME presigned token so it
//     can only ever act for the verified caller.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/vhco-pro/workstation-agent/internal/identity"
	"github.com/vhco-pro/workstation-agent/internal/session"
	"github.com/vhco-pro/workstation-agent/internal/verifier"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	addr := getenv("WSA_ADDR", "127.0.0.1:8444")
	client := &http.Client{Timeout: 10 * time.Second}

	// Verifier: validates a presigned sts:GetCallerIdentity token → username.
	v := verifier.NewHandler(client, identity.FromARN, log)

	// Provisioning backend auto-detected (D1): directory-joined → sssd, else local.
	prov := session.DetectProvisioner(context.Background(), session.DefaultRunner, log)
	mgr := session.NewManager(prov, session.DefaultRunner, log)

	// ensure-session is authenticated by the same token the verifier validates,
	// so a caller can only provision their own session.
	authn := func(ctx context.Context, token string) (string, error) {
		arn, err := verifier.VerifyToken(ctx, client, token)
		if err != nil {
			return "", err
		}
		return identity.FromARN(arn)
	}
	ensure := session.NewHandler(authn, mgr, log)

	mux := http.NewServeMux()
	mux.Handle("/validate-authentication-token", v) // DCV posts the token here
	mux.Handle("/ensure-session", ensure)           // client calls this before connecting
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	// Some deployments point auth-token-verifier at the bare URL; accept root too.
	mux.Handle("/", v)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Info("workstation-agent listening", "addr", addr, "provisioning", prov.Name())
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
