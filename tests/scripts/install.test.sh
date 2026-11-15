#!/usr/bin/env bash
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
failures=0
ok() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; failures=$((failures+1)); }

# shellcheck source=/dev/null
OSC_INSTALL_SOURCED=1 source "$ROOT/install.sh"
set +e

[ "$(arch_of x86_64)" = amd64 ] && [ "$(arch_of aarch64)" = arm64 ] && ok "maps uname -m to the package architecture" || fail "architecture"
r="$( (arch_of riscv64) 2>&1)"; [ $? -ne 0 ] && echo "$r" | grep -q "unsupported architecture" && ok "rejects another architecture" || fail "riscv64 ($r)"

[ "$(plugin_zip_for 1.1.0 2.19.6)" = power-ens-1.1.0-osd-2.19.6.zip ] && ok "picks the plugin zip of the dashboard" || fail "zip for 2.19.6"
r="$( (plugin_zip_for 1.1.0 2.19.4) 2>&1)"; [ $? -ne 0 ] && echo "$r" | grep -q "unsupported OpenSearch Dashboards" && ok "rejects another dashboard version" || fail "zip for 2.19.4 ($r)"

[ "$(OSC_RELEASE=v1.2.3 release_version)" = 1.2.3 ] && ok "takes the release from OSC_RELEASE without the v" || fail "OSC_RELEASE"

mkdir -p "$T/sums" && echo good > "$T/sums/a.tar.gz" && echo other > "$T/sums/b.tar.gz"
(cd "$T/sums" && sha256sum a.tar.gz > SHA256SUMS)
(verify_checksum "$T/sums" a.tar.gz) >/dev/null 2>&1 && ok "accepts a file that matches its checksum" || fail "matching checksum"
echo tampered > "$T/sums/a.tar.gz"
r="$( (verify_checksum "$T/sums" a.tar.gz) 2>&1)"; [ $? -ne 0 ] && echo "$r" | grep -q "checksum mismatch" && ok "stops on a changed file" || fail "changed file ($r)"
r="$( (verify_checksum "$T/sums" b.tar.gz) 2>&1)"; [ $? -ne 0 ] && echo "$r" | grep -q "not listed" && ok "stops on a file missing from SHA256SUMS" || fail "unlisted file ($r)"

mkdir -p "$T/pkg/bin" && touch "$T/pkg/bin/oscompliance-agent" && chmod +x "$T/pkg/bin/oscompliance-agent"
cp "$ROOT/install.sh" "$T/pkg/" && echo 1.1.0 > "$T/pkg/VERSION"
r="$(cd "$T" && OSC_INSTALL_SOURCED=1 bash -c 'source pkg/install.sh; fetch_package; echo "$PKG $(package_version)"')"
[ "$r" = "$T/pkg 1.1.0" ] && ok "uses the package it was unpacked from without downloading" || fail "local package ($r)"

OSSEC="$T/ossec" CONF_DIR="$T/etc"; mkdir -p "$OSSEC/etc"
echo '<ossec_config></ossec_config>' > "$OSSEC/etc/ossec.conf"
audit_manager_config; audit_manager_config
[ "$(grep -c "$BLOCK_BEGIN" "$OSSEC/etc/ossec.conf")" = 1 ] && ok "adds the manager localfiles once" || fail "localfile block count"
grep -q "\"wazuh_shared_conf\": \"$GROUP_CONF\"" "$CONF_DIR/agent.json" && ok "points the manager's agent at the ens group configuration" || fail "agent.json"
sed -i.bak "\|$BLOCK_BEGIN|,\|$BLOCK_END|d" "$OSSEC/etc/ossec.conf"
[ "$(cat "$OSSEC/etc/ossec.conf")" = '<ossec_config></ossec_config>' ] && ok "the uninstall expression removes exactly that block" || fail "block removal"

[ $failures -eq 0 ] && echo "ALL OK" || { echo "$failures FAILURES"; exit 1; }
