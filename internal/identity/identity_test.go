package identity

import "testing"

func TestFromARN(t *testing.T) {
	tests := []struct {
		name    string
		arn     string
		want    string
		wantErr bool
	}{
		{
			name: "sso assumed-role with email session name",
			arn:  "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_abc/alice@example.com",
			want: "alice",
		},
		{
			name: "session name with hyphen suffix is kept (org-agnostic default)",
			arn:  "arn:aws:sts::823091238322:assumed-role/AWSReservedSSO_PowerUserAccess_x/DL6544-A@engie.com",
			want: "dl6544-a",
		},
		{
			name: "instance role session name",
			arn:  "arn:aws:sts::123456789012:assumed-role/workstation-role/i-00c45ce9e5a87cd60",
			want: "i-00c45ce9e5a87cd60",
		},
		{name: "no slash", arn: "not-an-arn", wantErr: true},
		{name: "trailing slash", arn: "arn:aws:sts::1:assumed-role/role/", wantErr: true},
		{name: "session name all symbols", arn: "arn:aws:sts::1:assumed-role/role/@@@", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromARN(tt.arn)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromARN(%q) err = %v, wantErr %v", tt.arn, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("FromARN(%q) = %q, want %q", tt.arn, got, tt.want)
			}
		})
	}
}

func TestSanitizeIsStable(t *testing.T) {
	// The same input must always map to the same username (client and verifier
	// must agree), and the output must be a valid Linux username.
	in := "Alice.Smith+test@example.com"
	a, err := Sanitize(in)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Sanitize(in)
	if a != b {
		t.Fatalf("Sanitize not deterministic: %q vs %q", a, b)
	}
	if a != "alicesmithtest" {
		t.Errorf("Sanitize(%q) = %q, want %q", in, a, "alicesmithtest")
	}
}

func TestSanitizeTruncates(t *testing.T) {
	long := ""
	for i := 0; i < 50; i++ {
		long += "a"
	}
	got, err := Sanitize(long)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxLen {
		t.Errorf("len = %d, want %d", len(got), maxLen)
	}
}
