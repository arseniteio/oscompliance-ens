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
  yaml="$(cd "$root/engine" && go list -m -f '{{.Dir}}' go.yaml.in/yaml/v3)"
  echo
  echo "oscompliance-policy links go.yaml.in/yaml/v3 under the following licenses."
  echo
  cat "$yaml/LICENSE" "$yaml/NOTICE"
} > "$notices"

# install.sh trusts an unpacked package only when root or the sudo user owns it.
if tar --version | grep -q bsdtar; then
  root_owned=(--uid 0 --gid 0 --uname root --gname root)
else
  root_owned=(--owner=0 --group=0 --numeric-owner)
fi

release_installer() {
  sed "s/^OSC_RELEASE=\"\${OSC_RELEASE:-}\"\$/OSC_RELEASE=\"\${OSC_RELEASE:-$version}\"/" "$root/install.sh" > "$1"
  grep -q "OSC_RELEASE:-$version}" "$1" || { echo "install.sh: cannot set the release version" >&2; exit 1; }
  chmod 755 "$1"
}

release_windows_installer() {
  sed "s/^\$PackagedRelease = ''\$/\$PackagedRelease = '$version'/" "$root/agent/windows/install.ps1" > "$1"
  grep -q "^\$PackagedRelease = '$version'\$" "$1" || { echo "install.ps1: cannot set the release version" >&2; exit 1; }
}

for arch in amd64 arm64; do
  name="oscompliance-ens-wazuh-$version-linux-$arch"
  dir="$dist/$name"
  mkdir -p "$dir/bin" "$dir/wazuh" "$dir/agent"
  for part in agent:agent engine:engine engine:policy; do
    (cd "$root/${part%%:*}" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
      go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$dir/bin/oscompliance-${part#*:}" "./cmd/oscompliance-${part#*:}")
  done
  cp "$root"/catalog/wazuh/* "$dir/wazuh/"
  cp "$root/agent/agent.example.json" "$root/agent/oscompliance.cron" "$dir/agent/"
  cp "$root/LICENSE" "$notices" "$dir/"
  echo "$version" > "$dir/VERSION"
  release_installer "$dir/install.sh"
  COPYFILE_DISABLE=1 tar --no-xattrs "${root_owned[@]}" -C "$dist" -czf "$dist/$name.tar.gz" "$name"
  rm -rf "$dir"
done

name="oscompliance-ens-wazuh-$version-windows-amd64"
dir="$dist/$name"
mkdir -p "$dir/wazuh"
(cd "$root/agent" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$dir/oscompliance-agent.exe" ./cmd/oscompliance-agent)
release_windows_installer "$dir/install.ps1"
cp "$root/agent/windows/agent.example.json" "$dir/"
cp "$root/catalog/wazuh/oscompliance_facts_rules.xml" "$root/catalog/wazuh/agent.conf.windows.fragment.xml" "$dir/wazuh/"
cp "$root/LICENSE" "$notices" "$dir/"
echo "$version" > "$dir/VERSION"
(cd "$dist" && zip -qrX "$name.zip" "$name")
rm -rf "$dir"

rm "$notices"
release_installer "$dist/install.sh"
release_windows_installer "$dist/install.ps1"
(cd "$dist" && sha256sum ./*.tar.gz ./*.zip ./install.sh ./install.ps1 | sed 's# \./# #' > SHA256SUMS)
ls -l "$dist"
