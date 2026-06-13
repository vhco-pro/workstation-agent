// Package identity maps a verified AWS caller identity (an STS ARN) to a Linux
// username.
//
// The mapping must be byte-for-byte identical on the client (which targets the
// DCV session named after the user) and in the verifier (which authorizes the
// connection). Keeping it in one place, shared in spirit with the client's rule,
// is deliberate — a mismatch would let a validated user be denied their own
// session. See spec CL-01 / MU-04.
package identity

import (
	"fmt"
	"regexp"
	"strings"
)

// invalidChars matches anything not allowed in the conservative Linux username
// charset we target ([a-z0-9_-]).
var invalidChars = regexp.MustCompile(`[^a-z0-9_-]`)

// maxLen is a safe upper bound for portable Linux usernames.
const maxLen = 32

// FromARN extracts the role-session-name from an STS assumed-role ARN and
// derives a Linux username from it.
//
// For an SSO login the role-session-name is the user's identity, e.g.
//
//	arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_.../alice@example.com
//	                                                          ^^^^^^^^^^^^^^^^^ role-session-name
//
// which Sanitize turns into "alice".
func FromARN(arn string) (string, error) {
	i := strings.LastIndexByte(arn, '/')
	if i < 0 || i == len(arn)-1 {
		return "", fmt.Errorf("identity: ARN has no role-session-name: %q", arn)
	}
	return Sanitize(arn[i+1:])
}

// Sanitize turns a raw SSO username into a valid, stable Linux username.
//
// Default rule (deliberately org-agnostic — no environment-specific assumptions
// are baked in): take the local-part before any '@', lowercase it, drop every
// character outside [a-z0-9_-], and trim to 32 characters. Organisations that
// need a different rule (e.g. stripping an account-type suffix) supply it as
// configuration rather than patching this default.
func Sanitize(raw string) (string, error) {
	s := raw
	if at := strings.IndexByte(s, '@'); at >= 0 {
		s = s[:at]
	}
	s = strings.ToLower(s)
	s = invalidChars.ReplaceAllString(s, "")
	if s == "" {
		return "", fmt.Errorf("identity: %q sanitized to an empty username", raw)
	}
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s, nil
}
