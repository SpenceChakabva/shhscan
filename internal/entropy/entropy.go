// Package entropy implements Shannon-entropy based detection of high-randomness
// tokens, the technique that lets a scanner catch secrets no regex was written
// for. The approach mirrors the classic trufflehog method: for every contiguous
// run of base64 or hex characters longer than a minimum length, compute the
// Shannon entropy over the relevant character set and flag runs that exceed a
// threshold.
package entropy

import "math"

const (
	base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" // shhscan:allow
	hexChars    = "1234567890abcdefABCDEF"                                            // shhscan:allow

	// MinTokenLen is the shortest run of charset characters worth scoring.
	// Short strings can hit high entropy by chance, so trufflehog uses 20.
	MinTokenLen = 20

	// DefaultBase64Threshold / DefaultHexThreshold are the classic trufflehog
	// defaults (bits per character). Base64 packs ~6 bits/char so real secrets
	// sit high; hex packs ~4 bits/char so its threshold is lower.
	DefaultBase64Threshold = 4.5
	DefaultHexThreshold    = 3.0
)

// Config controls the entropy pass. A zero Config is not useful; use
// DefaultConfig and adjust.
type Config struct {
	Base64Threshold float64
	HexThreshold    float64
	MinLen          int
}

// DefaultConfig returns the classic trufflehog thresholds.
func DefaultConfig() Config {
	return Config{
		Base64Threshold: DefaultBase64Threshold,
		HexThreshold:    DefaultHexThreshold,
		MinLen:          MinTokenLen,
	}
}

// Token is a high-entropy run found inside a line.
type Token struct {
	Value   string
	Entropy float64
	Charset string // "base64" or "hex"
}

// Shannon returns the Shannon entropy of s in bits per character, measured over
// the symbols that actually appear in s. An empty string has zero entropy.
//
//	H = -Σ p(x) * log2(p(x))
func Shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// Find scans one line and returns every high-entropy token in it. It walks the
// line for maximal runs of base64 characters and of hex characters, scores each
// run that clears MinLen, and keeps the ones above the matching threshold.
func (c Config) Find(line string) []Token {
	if c.MinLen == 0 {
		c = DefaultConfig()
	}
	var out []Token
	out = appendRuns(out, line, base64Chars, "base64", c.Base64Threshold, c.MinLen)
	out = appendRuns(out, line, hexChars, "hex", c.HexThreshold, c.MinLen)
	return out
}

func appendRuns(out []Token, line, charset, name string, threshold float64, minLen int) []Token {
	inSet := func(b byte) bool {
		for i := 0; i < len(charset); i++ {
			if charset[i] == b {
				return true
			}
		}
		return false
	}
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= minLen {
			run := line[start:end]
			if h := Shannon(run); h > threshold {
				out = append(out, Token{Value: run, Entropy: h, Charset: name})
			}
		}
		start = -1
	}
	for i := 0; i < len(line); i++ {
		if inSet(line[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(line))
	return out
}
