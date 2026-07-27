package scan

import "testing"

func TestScannerDedups(t *testing.T) {
	sc := New(DefaultOptions())
	line := `key = "sk_live_abcdefghij` + `klmnopqrstuvwx"` // split literal (see rules_test)
	m := Meta{Source: "fs", Location: "config.py", Line: 1}
	first := sc.Line(line, m)
	if len(first) == 0 {
		t.Fatal("expected a finding on first pass")
	}
	second := sc.Line(line, m) // same secret + location => no new finding
	if len(second) != 0 {
		t.Fatalf("expected dedup, got %d findings", len(second))
	}
}

func TestAllowlistSuppressesUUID(t *testing.T) {
	sc := New(DefaultOptions())
	// A UUID is high-entropy hex-ish but is a classic false positive.
	line := `request_id = "550e8400-e29b-41d4-a716-446655440000"`
	if f := sc.Line(line, Meta{Source: "fs", Location: "log.txt"}); len(f) != 0 {
		t.Fatalf("UUID should be allowlisted, got %v", f)
	}
}

func TestRedactionOn(t *testing.T) {
	sc := New(DefaultOptions())
	f := sc.Line("token: ghp_1234567890abcdef"+"ghijklmnopqrstuvwxyz", Meta{Source: "fs", Location: "x"})
	if len(f) == 0 {
		t.Fatal("expected finding")
	}
	if f[0].Secret == "ghp_1234567890abcdef"+"ghijklmnopqrstuvwxyz" {
		t.Fatal("secret was not redacted")
	}
}

func TestInlineAllowMarker(t *testing.T) {
	sc := New(DefaultOptions())
	line := `charset = "ABCDEFghijkl0123456789+/" // shhscan:allow`
	if f := sc.Line(line, Meta{Source: "fs", Location: "x.go"}); len(f) != 0 {
		t.Fatalf("shhscan:allow line should be skipped, got %v", f)
	}
}

func TestExcludedGlobs(t *testing.T) {
	o := DefaultOptions()
	o.Excludes = []string{"*_test.go", "testdata/*", "scripts/seed.sh"}
	sc := New(o)
	cases := map[string]bool{
		"internal/rules/rules_test.go":  true,
		"testdata/allowlist/hashes.txt": true,
		"scripts/seed.sh":               true,
		"internal/scan/scan.go":         false,
		"main.go":                       false,
	}
	for path, want := range cases {
		if got := sc.Excluded(path); got != want {
			t.Errorf("Excluded(%q) = %v, want %v", path, got, want)
		}
	}
}
