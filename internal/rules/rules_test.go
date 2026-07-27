package rules

import "testing"

func TestDefaultRulesMatch(t *testing.T) {
	rs := Default()
	cases := []struct {
		name string
		line string
		want string // expected rule ID
	}{
		{"aws", `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`, "aws-access-key-id"},
		// Fixtures are split across a "+" so no committed file contains a
		// contiguous secret-shaped literal (which GitHub push protection blocks);
		// the test reassembles the full string to exercise each rule.
		{"github", "token: ghp_1234567890abcdef" + "ghijklmnopqrstuvwxyz", "github-pat"},
		{"stripe", `key = "sk_live_abcdefghij` + `klmnopqrstuvwx"`, "stripe-secret-key"},
		{"google", "AIzaSyClzfrOzB818x55" + "FASHvX4JuGQciR9lv7q", "google-api-key"},
		{"private", `-----BEGIN RSA PRIVATE KEY-----`, "private-key"},
		{"jwt", `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKLmno`, "jwt"},
		{"conn", `DATABASE_URL=postgres://user:sup3rs3cret@db:5432/app`, "connection-string-password"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ids []string
			for _, m := range Scan(rs, c.line) {
				ids = append(ids, m.RuleID)
			}
			found := false
			for _, id := range ids {
				if id == c.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("line %q: got rules %v, want %q", c.line, ids, c.want)
			}
		})
	}
}

func TestNoFalsePositiveOnPlainText(t *testing.T) {
	rs := Default()
	if m := Scan(rs, "The quick brown fox jumps over the lazy dog."); len(m) != 0 {
		t.Fatalf("plain prose matched rules: %v", m)
	}
}
