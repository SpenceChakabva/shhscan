#!/usr/bin/env bash
# seed-testdata.sh — build throwaway fixtures for exercising shhscan.
#
# Secrets are generated FRESH and RANDOM on every run and written only into the
# target directory (default ./.demo, git-ignored). Nothing sensitive is ever
# committed — this script contains generators, not literal keys — so shhscan's
# own CI self-scan stays green.
#
# Produces three fixtures:
#   <dir>/repo        a git repo with a secret added then "removed" in history
#   <dir>/files       a directory tree mixing real secrets with false positives
#   <dir>/image.tar   a synthetic `docker save` tarball with secrets in a layer
#
# Usage: scripts/seed-testdata.sh [target-dir]
set -eu

DIR="${1:-.demo}"
rm -rf "$DIR"
mkdir -p "$DIR"

# --- random token helpers ---------------------------------------------------
rnd()  { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }   # mixed
rndU() { LC_ALL=C tr -dc 'A-Z0-9'    </dev/urandom | head -c "$1"; }   # upper

AWS_ID="AKIA$(rndU 16)"
AWS_SECRET="$(rnd 40)"
GH_PAT="ghp_$(rnd 36)"
STRIPE="sk_live_$(rnd 24)"
SENDGRID="SG.$(rnd 22).$(rnd 43)"
DB_PASS="$(rnd 18)"

# --- 1) git repo with a secret buried in history ----------------------------
REPO="$DIR/repo"
mkdir -p "$REPO"
(
  cd "$REPO"
  git init -q
  git config user.email demo@example.com
  git config user.name demo
  cat > config.py <<PY
DEBUG = True
AWS_ACCESS_KEY_ID = "$AWS_ID"
AWS_SECRET_ACCESS_KEY = "$AWS_SECRET"
GITHUB_TOKEN = "$GH_PAT"
PY
  git add . && git commit -qm "add service config"
  # "fix" it later — but the secret stays in history
  cat > config.py <<PY
DEBUG = True
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
PY
  git add . && git commit -qm "move creds to environment variables"
)

# --- 2) filesystem tree: real secrets + false positives ---------------------
FILES="$DIR/files"
mkdir -p "$FILES/src" "$FILES/node_modules"
cat > "$FILES/.env" <<ENV
STRIPE_KEY=$STRIPE
DATABASE_URL=postgres://admin:$DB_PASS@db.internal:5432/prod
# these should be IGNORED (false positives):
REQUEST_ID=550e8400-e29b-41d4-a716-446655440000
BUILD_SHA=da39a3ee5e6b4b0d3255bfef95601890afd80709
ENV
echo "const ghToken = \"$GH_PAT\";" > "$FILES/src/app.js"
# a secret inside a skipped dir — proves node_modules is skipped
echo "SENDGRID=$SENDGRID" > "$FILES/node_modules/leaked.txt"

# --- 3) synthetic docker save tarball ---------------------------------------
IMG="$DIR/_img"
mkdir -p "$IMG/rootfs/app"
echo "SENDGRID_API_KEY=$SENDGRID" > "$IMG/rootfs/app/.env"
tar -C "$IMG/rootfs" -cf "$IMG/layer.tar" app
cat > "$IMG/config.json" <<JSON
{"config":{"Env":["PATH=/usr/bin","API_TOKEN=$GH_PAT"]}}
JSON
cat > "$IMG/manifest.json" <<JSON
[{"Config":"config.json","Layers":["layer.tar"]}]
JSON
tar -C "$IMG" -cf "$DIR/image.tar" layer.tar config.json manifest.json
rm -rf "$IMG"

echo "seeded fixtures in $DIR/"
echo "  repo/       git history with a buried secret"
echo "  files/      real secrets + false positives"
echo "  image.tar   docker layer + config secrets"
echo "expected true positives this run:"
echo "  aws id     $AWS_ID"
echo "  github     ${GH_PAT:0:8}...  stripe ${STRIPE:0:12}...  sendgrid ${SENDGRID:0:10}..."
