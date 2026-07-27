// Package rules holds high-signal regular expressions for well-known credential
// formats. Regex catches secrets with a recognisable shape (AWS keys, GitHub
// tokens, private-key headers); the entropy pass in the entropy package catches
// the shapeless high-randomness rest. A good scanner runs both.
package rules

import "regexp"

// Rule is a single named detector.
type Rule struct {
	ID          string
	Description string
	Regex       *regexp.Regexp
	// Group is the capture group holding the secret itself. 0 means the whole
	// match is the secret.
	Group int
}

// Match is a hit produced by a Rule.
type Match struct {
	RuleID      string
	Description string
	Secret      string
	Full        string
}

// Default returns the built-in rule set. These favour precision: each pattern is
// anchored to a provider-specific prefix or structure so it rarely fires on
// ordinary text.
func Default() []Rule {
	return []Rule{
		{ID: "aws-access-key-id", Description: "AWS Access Key ID",
			Regex: regexp.MustCompile(`\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA)[A-Z0-9]{16})\b`), Group: 1},
		{ID: "aws-secret-access-key", Description: "AWS Secret Access Key (contextual)",
			Regex: regexp.MustCompile(`(?i)aws(.{0,20})?(?:secret|sk)(.{0,20})?['"]([A-Za-z0-9/+=]{40})['"]`), Group: 3},
		{ID: "github-pat", Description: "GitHub Personal Access Token",
			Regex: regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b`), Group: 1},
		{ID: "github-fine-grained-pat", Description: "GitHub fine-grained PAT",
			Regex: regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{82})\b`), Group: 1},
		{ID: "gitlab-pat", Description: "GitLab Personal Access Token",
			Regex: regexp.MustCompile(`\b(glpat-[A-Za-z0-9\-_]{20})\b`), Group: 1},
		{ID: "slack-token", Description: "Slack token",
			Regex: regexp.MustCompile(`\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b`), Group: 1},
		{ID: "slack-webhook", Description: "Slack webhook URL",
			Regex: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+`), Group: 0},
		{ID: "stripe-secret-key", Description: "Stripe secret/restricted key",
			Regex: regexp.MustCompile(`\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,99})\b`), Group: 1},
		{ID: "google-api-key", Description: "Google API key",
			Regex: regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`), Group: 1},
		{ID: "google-oauth-id", Description: "Google OAuth client ID",
			Regex: regexp.MustCompile(`\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b`), Group: 1},
		{ID: "sendgrid-key", Description: "SendGrid API key",
			Regex: regexp.MustCompile(`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`), Group: 1},
		{ID: "twilio-key", Description: "Twilio API key",
			Regex: regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`), Group: 1},
		{ID: "npm-token", Description: "npm access token",
			Regex: regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`), Group: 1},
		{ID: "openai-key", Description: "OpenAI API key",
			Regex: regexp.MustCompile(`\b(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b`), Group: 1},
		{ID: "jwt", Description: "JSON Web Token",
			Regex: regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`), Group: 1},
		{ID: "private-key", Description: "Private key block",
			Regex: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), Group: 0},
		{ID: "generic-assignment", Description: "Generic secret assignment",
			Regex: regexp.MustCompile(`(?i)\b(?:api[_\-]?key|secret|passwd|password|token|access[_\-]?key)\b\s*[:=]\s*['"]([^'"\s]{12,80})['"]`), Group: 1},
		{ID: "connection-string-password", Description: "Password inside a connection URI",
			Regex: regexp.MustCompile(`(?i)[a-z]+://[^:@\s]+:([^@\s/]{6,})@`), Group: 1},
	}
}

// Scan runs every rule against line and returns all matches.
func Scan(rs []Rule, line string) []Match {
	var out []Match
	for _, r := range rs {
		for _, m := range r.Regex.FindAllStringSubmatch(line, -1) {
			secret := m[0]
			if r.Group > 0 && r.Group < len(m) {
				secret = m[r.Group]
			}
			out = append(out, Match{RuleID: r.ID, Description: r.Description, Secret: secret, Full: m[0]})
		}
	}
	return out
}
