#!/bin/sh
# Build the softether-webadmin .deb and .rpm for one architecture into dist/.
# Used identically by developers and by CI.
#
#   packaging/build.sh amd64|arm64
#
# Version (also embedded in the binary):
#   on a tag vX.Y.Z (clean tree)  -> X.Y.Z
#   otherwise                     -> <last tag or 0.0.0>~dev.<shortsha>[.dirty]
# The "~" sorts before the release in both dpkg and rpm, which is what we want
# for development builds.
set -eu

arch=${1:?usage: build.sh amd64|arm64}
case $arch in
amd64 | arm64) ;;
*) echo "build.sh: unsupported architecture: $arch" >&2; exit 2 ;;
esac

# Pinned nfpm release; bump deliberately.
NFPM=github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.48.0

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

sha=$(git rev-parse --short=7 HEAD 2>/dev/null || echo unknown)
dirty=
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
	dirty=.dirty
fi
if [ -z "$dirty" ] && tag=$(git describe --tags --exact-match 2>/dev/null); then
	VERSION=${tag#v}
else
	base=$(git describe --tags --abbrev=0 2>/dev/null || echo 0.0.0)
	VERSION=${base#v}~dev.${sha}${dirty}
fi
ARCH=$arch
export VERSION ARCH

# Reproducible mtimes in the packages.
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct 2>/dev/null || date +%s)
export SOURCE_DATE_EPOCH

mkdir -p "$root/build" "$root/dist"

echo "==> softether-webadmin $VERSION ($arch)"
CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
	go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o build/softether-webadmin ./cmd/softether-webadmin

for packager in deb rpm; do
	go run "$NFPM" package --config packaging/nfpm.yaml --packager "$packager" --target "$root/dist/"
done

ls -l "$root/dist"
