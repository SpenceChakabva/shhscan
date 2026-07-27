#!/usr/bin/env bash
# build-all.sh — cross-compile shhscan for every supported platform and package
# each into dist/ as a tar.gz (Unix) or zip (Windows), with a checksums file.
#
# Usage: scripts/build-all.sh [version]
set -eu
cd "$(dirname "$0")/.."

VERSION="${1:-dev}"
BIN="shhscan"
LDFLAGS="-s -w -X main.version=${VERSION}"
TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

rm -rf dist && mkdir -p dist
for t in $TARGETS; do
  os="${t%/*}"; arch="${t#*/}"
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  out="${BIN}${ext}"
  echo "building ${os}/${arch}"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$out" .
  name="${BIN}_${VERSION}_${os}_${arch}"
  if [ "$os" = "windows" ]; then
    zip -q "dist/${name}.zip" "$out" README.md LICENSE
  else
    tar -czf "dist/${name}.tar.gz" "$out" README.md LICENSE
  fi
  rm -f "$out"
done

# checksums for verification
( cd dist && (command -v sha256sum >/dev/null && sha256sum * || shasum -a 256 *) > checksums.txt )
echo "---"
ls -la dist
