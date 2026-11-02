#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: ci/package.sh <version>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
dist="$root/dist"
rm -rf "$dist" && mkdir -p "$dist"

for arch in amd64 arm64; do
  name="oscompliance-ens-$version-linux-$arch"
  dir="$dist/$name"
  mkdir -p "$dir/bin" "$dir/wazuh" "$dir/agent"
  for part in agent engine; do
    (cd "$root/$part" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
      go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$dir/bin/oscompliance-$part" "./cmd/oscompliance-$part")
  done
  cp "$root"/catalog/wazuh/* "$dir/wazuh/"
  cp "$root/agent/agent.example.json" "$dir/agent/"
  tar -C "$dist" -czf "$dist/$name.tar.gz" "$name"
  rm -rf "$dir"
done

(cd "$dist" && sha256sum ./*.tar.gz | sed 's# \./# #' > SHA256SUMS)
ls -l "$dist"
