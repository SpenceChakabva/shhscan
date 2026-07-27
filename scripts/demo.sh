#!/usr/bin/env bash
# demo.sh — seed fresh fixtures and run shhscan against all three sources.
# Usage: scripts/demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."

DIR=".demo"
echo "==> seeding test data"
scripts/seed-testdata.sh "$DIR" >/dev/null

echo "==> building shhscan"
go build -o shhscan .
BIN="./shhscan"
line() { printf '\n\033[2m%s\033[0m\n' "────────────────────────────────────────────────────────"; }

line; echo "  1) GIT HISTORY  (secret deleted from working tree, still in history)"; line
"$BIN" git "$DIR/repo" || true

line; echo "  2) FILESYSTEM   (real secrets flagged; UUIDs/SHAs filtered; node_modules skipped)"; line
"$BIN" fs "$DIR/files" || true

line; echo "  3) DOCKER IMAGE (secrets in a layer .env and in the image config)"; line
"$BIN" docker "$DIR/image.tar" || true

line; echo "  4) ALLOWLIST    (false-positive fixtures — expect: no secrets found)"; line
"$BIN" fs testdata/allowlist-cases || true

echo
echo "done. re-run any scan with --json for CI-shaped output."
