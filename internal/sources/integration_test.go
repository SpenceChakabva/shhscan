package sources

import (
	"testing"

	"github.com/SpenceChakabva/shhscan/internal/scan"
)

// TestAllowlistCasesAreClean scans the committed false-positive fixtures and
// asserts shhscan reports nothing. These files are full of UUIDs, git SHAs,
// sha256 sums, and EXAMPLE placeholders — every one is high-entropy or
// secret-shaped, and every one must be suppressed. This is the regression guard
// for false-positive filtering.
func TestAllowlistCasesAreClean(t *testing.T) {
	sc := scan.New(scan.DefaultOptions())
	findings, err := FS(sc, "../../testdata/allowlist-cases")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(findings) != 0 {
		for _, f := range findings {
			t.Logf("unexpected finding: %s at %s -> %s", f.Description, f.Location, f.Secret)
		}
		t.Fatalf("expected 0 findings in allowlist cases, got %d", len(findings))
	}
}
