package session

import (
	"context"
	"fmt"
	"strings"
)

// Limits are per-user resource caps applied to a colleague's systemd user slice
// (`user-<uid>.slice`), so one user's session cannot starve the shared host of
// CPU, memory, or process slots (spec MU-10). Empty fields are left unset.
type Limits struct {
	CPUQuota  string // e.g. "200%" = 2 cores
	MemoryMax string // e.g. "4G"
	TasksMax  string // e.g. "4096"
}

func (l Limits) isEmpty() bool {
	return l.CPUQuota == "" && l.MemoryMax == "" && l.TasksMax == ""
}

// ApplyUserLimits caps the user's systemd slice via `systemctl set-property`.
// No-op when no limits are configured. The user must already exist (we resolve
// their uid first). Persistent (survives until changed), so it sticks across
// reconnects and session restarts.
func ApplyUserLimits(ctx context.Context, run Runner, username string, l Limits) error {
	if l.isEmpty() {
		return nil
	}
	uidOut, err := run(ctx, "id", "-u", username)
	if err != nil {
		return fmt.Errorf("resolve uid for %q: %w", username, err)
	}
	uid := strings.TrimSpace(string(uidOut))

	args := []string{"set-property", fmt.Sprintf("user-%s.slice", uid)}
	if l.CPUQuota != "" {
		args = append(args, "CPUQuota="+l.CPUQuota)
	}
	if l.MemoryMax != "" {
		args = append(args, "MemoryMax="+l.MemoryMax)
	}
	if l.TasksMax != "" {
		args = append(args, "TasksMax="+l.TasksMax)
	}
	if out, err := run(ctx, "systemctl", args...); err != nil {
		return fmt.Errorf("set-property user-%s.slice: %w (%s)", uid, err, strings.TrimSpace(string(out)))
	}
	return nil
}
