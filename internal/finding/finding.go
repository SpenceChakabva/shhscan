// Package finding defines the result type shared by every scan source and the
// redaction helper that keeps real secrets out of logs and CI output.
package finding

import "strings"

// Kind distinguishes how a finding was detected.
type Kind string

const (
	KindRule    Kind = "rule"    // matched a named provider pattern
	KindEntropy Kind = "entropy" // flagged by high Shannon entropy
)

// Finding is one located secret candidate.
type Finding struct {
	Kind        Kind    `json:"kind"`
	RuleID      string  `json:"rule_id,omitempty"`
	Description string  `json:"description"`
	Source      string  `json:"source"`   // "git" | "fs" | "docker"
	Location    string  `json:"location"` // file path, or "layer/path", or commit short-sha
	Line        int     `json:"line,omitempty"`
	Commit      string  `json:"commit,omitempty"`
	Author      string  `json:"author,omitempty"`
	Date        string  `json:"date,omitempty"`
	Charset     string  `json:"charset,omitempty"`
	Entropy     float64 `json:"entropy,omitempty"`
	Secret      string  `json:"secret"` // already redacted unless --no-redact
}

// Redact masks the middle of a secret, keeping enough on each end to recognise
// it without exposing it. Short secrets are fully masked.
func Redact(s string) string {
	n := len(s)
	if n <= 8 {
		return strings.Repeat("*", n)
	}
	keep := 4
	if n < 16 {
		keep = 2
	}
	return s[:keep] + strings.Repeat("*", n-2*keep) + s[n-keep:]
}
