// shhscan — a dependency-free secret scanner for git history, filesystems and
// Docker image layers. Combines high-signal regex rules with Shannon-entropy
// detection, redacts what it finds, and exits non-zero on a hit so it drops
// straight into a pre-commit hook or CI gate.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/SpenceChakabva/shhscan/internal/entropy"
	"github.com/SpenceChakabva/shhscan/internal/finding"
	"github.com/SpenceChakabva/shhscan/internal/scan"
	"github.com/SpenceChakabva/shhscan/internal/sources"
)

const usage = `shhscan — find leaked secrets in git history, files, and Docker images

usage:
  shhscan git    [flags] [path]         scan full commit history (default path: .)
  shhscan fs     [flags] <path>         scan a directory tree
  shhscan docker [flags] <image.tar>    scan a 'docker save' tarball

common flags:
  --json                 machine-readable output (for CI)
  --no-redact            print full secrets (use with care)
  --no-regex             disable named provider rules
  --no-entropy           disable entropy detection
  --base64-entropy F     base64 entropy threshold (default 4.5)
  --hex-entropy F        hex entropy threshold (default 3.0)
  --allow RE[,RE...]     extra allowlist regexes (ignore matching tokens)
  --exclude GLOB[,...]   skip files whose path matches a glob
  --max-commits N        (git) limit history depth

exit codes: 0 = clean, 1 = secrets found, 2 = error`

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	sub := os.Args[1]
	if sub == "version" || sub == "--version" || sub == "-v" {
		fmt.Println("shhscan", version)
		return
	}
	fsFlags := flag.NewFlagSet(sub, flag.ExitOnError)
	var (
		asJSON     = fsFlags.Bool("json", false, "")
		noRedact   = fsFlags.Bool("no-redact", false, "")
		noRegex    = fsFlags.Bool("no-regex", false, "")
		noEntropy  = fsFlags.Bool("no-entropy", false, "")
		b64        = fsFlags.Float64("base64-entropy", entropy.DefaultBase64Threshold, "")
		hexT       = fsFlags.Float64("hex-entropy", entropy.DefaultHexThreshold, "")
		allow      = fsFlags.String("allow", "", "")
		exclude    = fsFlags.String("exclude", "", "")
		maxCommits = fsFlags.Int("max-commits", 0, "")
	)
	fsFlags.Usage = func() { fmt.Fprintln(os.Stderr, usage) }

	if sub == "-h" || sub == "--help" || sub == "help" {
		fmt.Println(usage)
		return
	}
	// Go's flag package stops at the first positional arg, so `fs ./path --json`
	// would silently drop --json. Reorder args (flags first) so flag position
	// doesn't matter — the behaviour users expect from a real CLI.
	flagArgs, positionals := splitArgs(os.Args[2:])
	_ = fsFlags.Parse(flagArgs)
	target := ""
	if len(positionals) > 0 {
		target = positionals[0]
	}

	opts := scan.DefaultOptions()
	opts.UseRules = !*noRegex
	opts.UseEntropy = !*noEntropy
	opts.Redact = !*noRedact
	opts.Entropy = entropy.Config{Base64Threshold: *b64, HexThreshold: *hexT, MinLen: entropy.MinTokenLen}
	if extra := parseAllow(*allow); len(extra) > 0 {
		opts.Allowlist = append(opts.Allowlist, extra...)
	}
	for _, g := range strings.Split(*exclude, ",") {
		if g = strings.TrimSpace(g); g != "" {
			opts.Excludes = append(opts.Excludes, g)
		}
	}
	sc := scan.New(opts)

	var (
		findings []finding.Finding
		err      error
	)
	switch sub {
	case "git":
		if target == "" {
			target = "."
		}
		findings, err = sources.Git(sc, target, *maxCommits)
	case "fs":
		if target == "" {
			fail("fs: need a directory path")
		}
		findings, err = sources.FS(sc, target)
	case "docker":
		if target == "" {
			fail("docker: need a path to a 'docker save' tarball")
		}
		findings, err = sources.Docker(sc, target)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fail(err.Error())
	}

	if *asJSON {
		printJSON(findings)
	} else {
		printHuman(findings)
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
}

// valueFlags are the flags that consume the following token as their value.
var valueFlags = map[string]bool{
	"-base64-entropy": true, "--base64-entropy": true,
	"-hex-entropy": true, "--hex-entropy": true,
	"-allow": true, "--allow": true,
	"-exclude": true, "--exclude": true,
	"-max-commits": true, "--max-commits": true,
}

// splitArgs partitions raw args into flag args and positional args, so flags may
// appear in any order relative to the path. Handles both --flag value and
// --flag=value forms.
func splitArgs(args []string) (flags, positionals []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if valueFlags[a] && !strings.Contains(a, "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positionals = append(positionals, a)
	}
	return flags, positionals
}

func parseAllow(s string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if re, err := regexp.Compile(part); err == nil {
			out = append(out, re)
		}
	}
	return out
}

func printJSON(fs []finding.Finding) {
	if fs == nil {
		fs = []finding.Finding{}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(fs)
}

func printHuman(fs []finding.Finding) {
	if len(fs) == 0 {
		fmt.Println("shhscan: no secrets found (clean)")
		return
	}
	for _, f := range fs {
		tag := f.RuleID
		if f.Kind == finding.KindEntropy {
			tag = fmt.Sprintf("entropy %s %.2f", f.Charset, f.Entropy)
		}
		loc := f.Location
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Location, f.Line)
		}
		fmt.Printf("[%s] %s  %s\n", f.Source, tag, loc)
		if f.Commit != "" {
			fmt.Printf("    commit %s  %s  %s\n", f.Commit, f.Author, f.Date)
		}
		fmt.Printf("    %s\n", f.Secret)
	}
	fmt.Printf("\nshhscan: %d finding(s)\n", len(fs))
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "shhscan: "+msg)
	os.Exit(2)
}
