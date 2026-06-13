package session

import (
	"context"
	"fmt"
	"log/slog"
)

// Manager ensures a per-user virtual DCV session exists. A session is named
// after its owner, so each verified user can only ever reach their own.
type Manager struct {
	Prov   Provisioner
	Run    Runner
	Log    *slog.Logger
	Limits Limits // per-user resource caps (MU-10); zero value = unlimited
}

// NewManager wires a Manager. A nil runner uses DefaultRunner; a nil logger
// discards logs.
func NewManager(prov Provisioner, run Runner, log *slog.Logger) *Manager {
	if run == nil {
		run = DefaultRunner
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Manager{Prov: prov, Run: run, Log: log}
}

// EnsureSession provisions the user (via the configured backend) and creates a
// virtual session named after them if one isn't already running. Idempotent —
// safe to call on every connect and after a wake/restart (virtual sessions do
// not survive a dcvserver restart, §12.4). Returns the session id (== username).
func (m *Manager) EnsureSession(ctx context.Context, username string) (string, error) {
	if err := m.Prov.EnsureUser(ctx, username); err != nil {
		return "", err
	}
	// Apply per-user resource caps (MU-10). Non-fatal: a limits hiccup must not
	// block the user from logging in.
	if err := ApplyUserLimits(ctx, m.Run, username, m.Limits); err != nil {
		m.Log.Warn("applying user limits failed (non-fatal)", "user", username, "err", err)
	}
	if m.sessionExists(ctx, username) {
		return username, nil
	}
	// `dcv create-session` must run as root to impersonate the user (§12.4).
	out, err := m.Run(ctx, "dcv", "create-session",
		"--type", "virtual",
		"--owner", username,
		"--user", username,
		username,
	)
	if err != nil {
		return "", fmt.Errorf("create-session for %q: %w (%s)", username, err, out)
	}
	m.Log.Info("created virtual session", "user", username, "backend", m.Prov.Name())
	return username, nil
}

func (m *Manager) sessionExists(ctx context.Context, id string) bool {
	_, err := m.Run(ctx, "dcv", "describe-session", id)
	return err == nil
}
