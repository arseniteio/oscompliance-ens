#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: ci/package.sh <version>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
dist="$root/dist"
rm -rf "$dist" && mkdir -p "$dist"

notices="$dist/THIRD_PARTY_NOTICES"
{
  echo "The binaries link the Go standard library, $(go env GOVERSION), under the following license."
  echo
  cat "$root/ci/go-LICENSE"
} > "$notices"

release_installer() {
  sed "s/^OSC_RELEASE=\"\${OSC_RELEASE:-}\"\$/OSC_RELEASE=\"\${OSC_RELEASE:-$version}\"/" "$root/install.sh" > "$1"
  grep -q "OSC_RELEASE:-$version}" "$1" || { echo "install.sh: cannot set the release version" >&2; exit 1; }
  chmod 755 "$1"
}

for arch in amd64 arm64; do
  name="oscompliance-ens-$version-linux-$arch"
  dir="$dist/$name"
  mkdir -p "$dir/bin" "$dir/wazuh" "$dir/agent"
  for part in agent engine; do
    (cd "$root/$part" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
      go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$dir/bin/oscompliance-$part" "./cmd/oscompliance-$part")
  done
  cp "$root"/catalog/wazuh/* "$dir/wazuh/"
  cp "$root/agent/agent.example.json" "$root/agent/oscompliance.cron" "$dir/agent/"
  cp "$root/LICENSE" "$notices" "$dir/"
  echo "$version" > "$dir/VERSION"
  release_installer "$dir/install.sh"
  COPYFILE_DISABLE=1 tar --no-xattrs -C "$dist" -czf "$dist/$name.tar.gz" "$name"
  rm -rf "$dir"
done

rm "$notices"
release_installer "$dist/install.sh"
(cd "$dist" && sha256sum ./*.tar.gz ./install.sh | sed 's# \./# #' > SHA256SUMS)
ls -l "$dist"
