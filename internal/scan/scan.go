// Package scan wires the rule and entropy detectors together into a single
// line scanner, and layers on the two things that make the difference between a
// toy and a usable tool: false-positive filtering and de-duplication.
package scan

import (
	"crypto/sha1"
	"encoding/hex"
	"path"
	"regexp"
	"strings"

	"github.com/SpenceChakabva/shhscan/internal/entropy"
	"github.com/SpenceChakabva/shhscan/internal/finding"
	"github.com/SpenceChakabva/shhscan/internal/rules"
)

// Options configures a Scanner.
type Options struct {
	UseRules   bool
	UseEntropy bool
	Redact     bool
	Entropy    entropy.Config
	Allowlist  []*regexp.Regexp // a token matching any of these is ignored
	Excludes   []string         // path globs whose files are skipped entirely
}

// AllowMarker on a line suppresses all findings for that line — the inline
// escape hatch for a value you know is safe (a test fixture, a charset constant).
const AllowMarker = "shhscan:allow"

// DefaultOptions enables both detectors with classic thresholds, redaction on,
// and a built-in allowlist for the usual high-entropy noise.
func DefaultOptions() Options {
	return Options{
		UseRules:   true,
		UseEntropy: true,
		Redact:     true,
		Entropy:    entropy.DefaultConfig(),
		Allowlist:  DefaultAllowlist(),
	}
}

// DefaultAllowlist covers the classic entropy false positives: UUIDs, git object
// hashes, obvious placeholder/example values, and long repeated-character runs.
// These are exactly the cases the search on gitleaks/trufflehog flags as noise.
func DefaultAllowlist() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`), // UUID
		regexp.MustCompile(`(?i)^[0-9a-f]{32}$`),                                                 // md5 / etag
		regexp.MustCompile(`(?i)^[0-9a-f]{40}$`),                                                 // git sha1 / other 40-hex
		regexp.MustCompile(`(?i)^[0-9a-f]{64}$`),                                                 // sha256 hex
		regexp.MustCompile(`(?i)^[0-9a-f]{128}$`),                                                // sha512 hex
		regexp.MustCompile(`(?i)(example|sample|dummy|placeholder|changeme|your[_-]?key|xxxx+|redacted)`),
	}
}

// Scanner scans lines and remembers what it has already reported so the same
// secret in a hundred diffs is surfaced once.
type Scanner struct {
	opts  Options
	rules []rules.Rule
	seen  map[string]bool
}

// New builds a Scanner.
func New(o Options) *Scanner {
	return &Scanner{opts: o, rules: rules.Default(), seen: map[string]bool{}}
}

func (s *Scanner) allowed(tok string) bool {
	for _, re := range s.opts.Allowlist {
		if re.MatchString(tok) {
			return true
		}
	}
	return false
}

// Excluded reports whether a file location should be skipped entirely, per the
// --exclude globs. A glob matches against the full path and the basename, and a
// trailing /* or bare directory name matches everything beneath it.
func (s *Scanner) Excluded(loc string) bool {
	base := path.Base(loc)
	for _, g := range s.opts.Excludes {
		if g == "" {
			continue
		}
		if ok, _ := path.Match(g, loc); ok {
			return true
		}
		if ok, _ := path.Match(g, base); ok {
			return true
		}
		p := strings.TrimSuffix(strings.TrimSuffix(g, "*"), "/")
		if p != "" && (loc == p || strings.HasPrefix(loc, p+"/")) {
			return true
		}
	}
	return false
}

// meta carries the location fields the source knows about.
type Meta struct {
	Source, Location, Commit, Author, Date string
	Line                                   int
}

// Line scans a single line of text and returns de-duplicated findings.
func (s *Scanner) Line(line string, m Meta) []finding.Finding {
	if strings.Contains(line, AllowMarker) {
		return nil
	}
	var out []finding.Finding

	if s.opts.UseRules {
		for _, hit := range rules.Scan(s.rules, line) {
			if s.allowed(hit.Secret) {
				continue
			}
			out = s.add(out, finding.Finding{
				Kind: finding.KindRule, RuleID: hit.RuleID, Description: hit.Description,
				Source: m.Source, Location: m.Location, Line: m.Line,
				Commit: m.Commit, Author: m.Author, Date: m.Date,
				Secret: s.render(hit.Secret),
			}, hit.Secret+m.Location)
		}
	}

	if s.opts.UseEntropy {
		for _, tok := range s.opts.Entropy.Find(line) {
			if s.allowed(tok.Value) {
				continue
			}
			out = s.add(out, finding.Finding{
				Kind: finding.KindEntropy, Description: "High-entropy string",
				Source: m.Source, Location: m.Location, Line: m.Line,
				Commit: m.Commit, Author: m.Author, Date: m.Date,
				Charset: tok.Charset, Entropy: round2(tok.Entropy),
				Secret: s.render(tok.Value),
			}, tok.Value+m.Location)
		}
	}
	return out
}

func (s *Scanner) add(out []finding.Finding, f finding.Finding, dedupKey string) []finding.Finding {
	h := sha1.Sum([]byte(dedupKey))
	k := hex.EncodeToString(h[:])
	if s.seen[k] {
		return out
	}
	s.seen[k] = true
	return append(out, f)
}

func (s *Scanner) render(secret string) string {
	if s.opts.Redact {
		return finding.Redact(secret)
	}
	return secret
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }
