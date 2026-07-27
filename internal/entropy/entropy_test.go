package entropy

import "testing"

func TestShannon(t *testing.T) {
	if h := Shannon(""); h != 0 {
		t.Fatalf("empty string entropy = %v, want 0", h)
	}
	if h := Shannon("aaaa"); h != 0 {
		t.Fatalf("uniform string entropy = %v, want 0", h)
	}
	// Two equally likely symbols => exactly 1 bit/char.
	if h := Shannon("abab"); h != 1 {
		t.Fatalf("two-symbol entropy = %v, want 1", h)
	}
	// A random-looking secret should score meaningfully higher than a word.
	secret := Shannon("wJalrXUtnFEMI7K7MDENGbPxRfiCYEXAMPLEKEY")
	word := Shannon("passwordpasswordpassword")
	if secret <= word {
		t.Fatalf("secret entropy %v should exceed word entropy %v", secret, word)
	}
}

func TestFindFlagsHighEntropyToken(t *testing.T) {
	cfg := DefaultConfig()
	line := `aws_secret = "wJalrXUtnFEMI7K7MDENGbPxRfiCYzEXAMPLEKEY"`
	toks := cfg.Find(line)
	if len(toks) == 0 {
		t.Fatal("expected a high-entropy token, got none")
	}
	if toks[0].Charset != "base64" {
		t.Fatalf("charset = %q, want base64", toks[0].Charset)
	}
}

func TestFindIgnoresShortAndLowEntropy(t *testing.T) {
	cfg := DefaultConfig()
	if toks := cfg.Find("short = abc123"); len(toks) != 0 {
		t.Fatalf("short token should be ignored, got %v", toks)
	}
	if toks := cfg.Find("value = aaaaaaaaaaaaaaaaaaaaaaaaaaaa"); len(toks) != 0 {
		t.Fatalf("low-entropy repeated run should be ignored, got %v", toks)
	}
}
