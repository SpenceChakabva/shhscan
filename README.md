# shhscan

A dependency-free secret scanner for **git history**, **filesystems**, and **Docker image layers**. It pairs high-signal regex rules with Shannon-entropy detection, redacts what it finds, and exits non-zero on a hit so it drops straight into a pre-commit hook or CI pipeline.

Single static binary. Zero third-party dependencies — Go standard library only.

**Runs anywhere Go does:** Linux, macOS, and Windows (amd64 and arm64). Pre-built binaries for every platform are attached to each [release](https://github.com/SpenceChakabva/shhscan/releases); download one and run it — no Go toolchain required. Verify the download against `checksums.txt`.

```
$ shhscan git .
[git] aws-access-key-id  config.py:1
    commit 4fa5ef02  tester  Sat Jul 25 17:14:30 2026
    AKIA************NP0Q
[git] entropy base64 5.06  config.py:3
    commit 4fa5ef02  tester  Sat Jul 25 17:14:30 2026
    aB3d****************************3bC6

shhscan: 2 finding(s)
```

## Why this exists

I maintain client environments at an MSP. A secret doesn't have to be in your current code to hurt you — deleting an API key in a later commit leaves it sitting in git history forever, and a key `COPY`'d into an early Docker layer stays in the image even if a later layer removes the file. `shhscan` looks in the three places secrets actually hide: **old commits, image layers, and the working tree.**

## Install

```bash
go install github.com/SpenceChakabva/shhscan@latest
```

Or build from source (works on Linux, macOS, and Windows):

```bash
# Linux / macOS
git clone https://github.com/SpenceChakabva/shhscan
cd shhscan && go build -o shhscan .
```

```powershell
# Windows (PowerShell)
git clone https://github.com/SpenceChakabva/shhscan
cd shhscan; go build -o shhscan.exe .
```

> Rename the module path in `go.mod` to your own GitHub handle before publishing.

### Windows notes

shhscan is pure Go and runs natively on Windows — no WSL required. It shells out to
`git` (install Git for Windows) and, for `docker` scans, uses `tar` (built into
Windows 10 1803+). Use `.\shhscan.exe` and PowerShell paths:

```powershell
.\shhscan.exe git .
.\shhscan.exe fs .\src
.\shhscan.exe docker .\image.tar
```

## Usage

```bash
shhscan git    [path]          # scan full commit history (default: .)
shhscan fs     <path>          # scan a directory tree
shhscan docker <image.tar>     # scan a 'docker save' tarball
```

Scan a Docker image:

```bash
docker save myapp:latest -o image.tar
shhscan docker image.tar
```

### Flags

| Flag | Meaning |
|------|---------|
| `--json` | machine-readable output for CI |
| `--no-redact` | print full secrets (handle with care) |
| `--no-regex` / `--no-entropy` | disable one detector |
| `--base64-entropy F` | base64 entropy threshold (default 4.5) |
| `--hex-entropy F` | hex entropy threshold (default 3.0) |
| `--allow RE[,RE...]` | extra allowlist regexes |
| `--exclude GLOB[,...]` | skip files whose path matches a glob (e.g. `*_test.go,testdata/*`) |
| `--max-commits N` | (git) limit history depth |

Exit codes: `0` clean · `1` secrets found · `2` error.

To silence a single known-safe line inline, add a `shhscan:allow` comment to it.

## How the entropy detection works

Regex only catches secrets whose *shape* you anticipated. Everything else — a random 40-char API secret with no prefix — is caught statistically.

**Shannon entropy** measures per-character randomness in bits:

```
H = -Σ p(x)·log₂(p(x))
```

A repeated string like `aaaa` scores `0`. `password` scores low. A random credential scores high — a base64 secret approaches its theoretical ceiling of ~6 bits/char. For every contiguous run of base64 or hex characters longer than 20 characters, `shhscan` computes entropy over that character set and flags runs above a threshold:

- **base64 → 4.5 bits/char**
- **hex → 3.0 bits/char** (a smaller alphabet packs fewer bits, so its bar is lower)

These are the classic trufflehog defaults, and both are tunable.

## Managing false positives

Entropy detection's weakness is that UUIDs, content hashes, and base64 test fixtures also look random. `shhscan` ships an allowlist that filters:

- UUIDs and 40/64-char hex hashes (git SHAs, sha256)
- obvious placeholders (`EXAMPLE`, `changeme`, `your_key`, …)

Add your own with `--allow`. This is why the canonical AWS *example* keys are **not** reported — they contain `EXAMPLE`.

## Use in CI (GitHub Actions)

```yaml
- name: Scan for secrets
  run: |
    go install github.com/SpenceChakabva/shhscan@latest
    shhscan git . --json
```

The non-zero exit on findings fails the build automatically. As a **pre-commit hook**, drop `scripts/pre-commit` into `.git/hooks/`.

## Try it

```bash
make demo            # Linux / macOS
```

```powershell
.\scripts\demo.ps1   # Windows (PowerShell)
```

This seeds three throwaway fixtures with **freshly generated** random secrets (a git repo with a secret buried in history, a file tree mixing real secrets with false positives, and a synthetic `docker save` tarball) and runs all three scans plus the allowlist check. Nothing sensitive is committed — the seed script generates secrets at runtime, so the repo's own CI self-scan stays green.

`testdata/allowlist-cases/` holds committed false-positive fixtures (UUIDs, git SHAs, sha256/md5 digests, `EXAMPLE` placeholders). The integration test asserts shhscan reports **zero** findings there — the regression guard for false-positive filtering.

## Honest limitations (what I learned building it)

Rebuilding this from scratch — rather than running `gitleaks` — was the point: you understand a detector's blind spots only once you've written one.

- **No live verification.** `shhscan` tells you a string *looks* like a secret; trufflehog additionally calls the provider's API to confirm the credential is live. That's the higher bar, and a good next iteration.
- **Line-oriented.** A secret split across multiple lines or concatenated at runtime evades static line scanning — a known weakness of this whole tool class.
- **Entropy is a blunt instrument.** Newer tools are moving past raw Shannon entropy toward token-efficiency signals that tell a UUID from a real key more reliably.
- **Regex coverage is a curated set**, not exhaustive — it's built for precision over recall.

## License

MIT — see [LICENSE](LICENSE).
