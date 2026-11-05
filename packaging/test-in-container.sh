#!/bin/sh
# Run packaging/test-install.sh for one package inside a fresh container.
#
#   packaging/test-in-container.sh <image> <package-file>
#
# The container engine is taken from $CONTAINER_ENGINE (default: docker, else podman).
set -eu

image=${1:?usage: test-in-container.sh <image> <package-file>}
pkg=${2:?usage: test-in-container.sh <image> <package-file>}
here=$(cd "$(dirname "$0")" && pwd)

engine=${CONTAINER_ENGINE:-}
if [ -z "$engine" ]; then
	if command -v docker >/dev/null 2>&1; then engine=docker; else engine=podman; fi
fi

if [ ! -f "$pkg" ]; then
	echo "FAIL: package file not found: $pkg" >&2
	exit 1
fi
pkgdir=$(cd "$(dirname "$pkg")" && pwd)

exec "$engine" run --rm \
	-v "$here/test-install.sh:/test-install.sh:ro" \
	-v "$pkgdir:/pkg:ro" \
	"$image" sh /test-install.sh "/pkg/$(basename "$pkg")"
