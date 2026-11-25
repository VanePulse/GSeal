#!/usr/bin/env bash
# Build the release files: one archive per platform and SHA256SUMS.
#
#   tools/release.sh [<out dir>] [<version>]     (defaults: dist, the VERSION file)
#
# Each gseal-<version>-<os>-<arch>.tar.gz holds with-secrets, install.sh,
# uninstall.sh, README.md, SECURITY.md, CHANGELOG.md and LICENSE. Built with
# the vendored modules, no network, CGO disabled (static executables).
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$repo/dist}
version=${2:-$(tr -d ' \n' < "$repo/VERSION")}
case "$out" in /*) ;; *) out=$(pwd)/$out ;; esac
mkdir -p "$out"
cd "$repo"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os=${target%/*} arch=${target#*/}
  name=gseal-$version-$os-$arch
  stage=$(mktemp -d)
  mkdir "$stage/$name"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -mod=vendor -trimpath \
    -ldflags "-s -w -X github.com/VanePulse/GSeal/internal/cli.Version=$version" \
    -o "$stage/$name/with-secrets" ./cmd/with-secrets
  cp install.sh uninstall.sh README.md SECURITY.md CHANGELOG.md LICENSE "$stage/$name/"
  tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
  rm -rf "$stage"
  echo "built $out/$name.tar.gz"
done
cd "$out"
if command -v sha256sum >/dev/null 2>&1; then sum=(sha256sum); else sum=(shasum -a 256); fi
"${sum[@]}" gseal-"$version"-*.tar.gz > SHA256SUMS
echo "wrote $out/SHA256SUMS"
