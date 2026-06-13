package authz

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAllowAll(t *testing.T) {
	ok, err := AllowAll{}.Allowed(context.Background(), "anyone")
	if err != nil || !ok {
		t.Fatalf("AllowAll should allow everyone; ok=%v err=%v", ok, err)
	}
}

func TestAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow")
	if err := os.WriteFile(path, []byte("# admins\nalice\ndl6544-a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := Allowlist{Path: path}
	if ok, _ := a.Allowed(context.Background(), "dl6544-a"); !ok {
		t.Error("listed user should be allowed")
	}
	if ok, _ := a.Allowed(context.Background(), "intruder"); ok {
		t.Error("unlisted user must be denied")
	}
	if _, err := (Allowlist{Path: filepath.Join(dir, "nope")}).Allowed(context.Background(), "x"); err == nil {
		t.Error("missing allowlist file should error")
	}
}

func TestGroup(t *testing.T) {
	g := Group{Name: "dcv-users", Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "id" && args[0] == "-nG" && args[1] == "alice" {
			return []byte("alice wheel dcv-users\n"), nil
		}
		return []byte("bob\n"), nil
	}}
	if ok, _ := g.Allowed(context.Background(), "alice"); !ok {
		t.Error("alice is in dcv-users -> allowed")
	}
	if ok, _ := g.Allowed(context.Background(), "bob"); ok {
		t.Error("bob is not in dcv-users -> denied")
	}

	gErr := Group{Name: "x", Run: func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("no such user")
	}}
	if _, err := gErr.Allowed(context.Background(), "ghost"); err == nil {
		t.Error("lookup error should propagate")
	}
}

func TestParse(t *testing.T) {
	run := func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	if _, ok := Parse("", run).(AllowAll); !ok {
		t.Error(`"" -> AllowAll`)
	}
	if _, ok := Parse("ssmIdentity", run).(AllowAll); !ok {
		t.Error(`"ssmIdentity" -> AllowAll`)
	}
	if a, ok := Parse("allowlist:/etc/wsa/allow", run).(Allowlist); !ok || a.Path != "/etc/wsa/allow" {
		t.Error(`"allowlist:..." -> Allowlist with path`)
	}
	if g, ok := Parse("group:dcv-users", run).(Group); !ok || g.Name != "dcv-users" {
		t.Error(`"group:..." -> Group with name`)
	}
}
