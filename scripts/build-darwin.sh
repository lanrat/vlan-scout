#!/bin/bash
set -euo pipefail

version="$(git describe --tags --always --dirty)"
sdk="$(xcrun --sdk macosx --show-sdk-path)"
ldflags="-s -w -X main.version=${version}"
mkdir -p dist

echo "Building darwin/arm64"
GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 \
  CGO_CFLAGS="-isysroot ${sdk}" \
  CGO_LDFLAGS="-isysroot ${sdk}" \
  go build -trimpath -ldflags="${ldflags}" -o dist/vlan-scout .
tar -C dist -czf dist/vlan-scout_darwin_arm64.tar.gz vlan-scout
rm dist/vlan-scout

echo "Building darwin/amd64"
GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 \
  CC="clang -arch x86_64" \
  CGO_CFLAGS="-isysroot ${sdk} -arch x86_64" \
  CGO_LDFLAGS="-isysroot ${sdk} -arch x86_64" \
  go build -trimpath -ldflags="${ldflags}" -o dist/vlan-scout .
tar -C dist -czf dist/vlan-scout_darwin_amd64.tar.gz vlan-scout
rm dist/vlan-scout
