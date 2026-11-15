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

mkdir -p "$T/loose/bin" && cp "$ROOT/install.sh" "$T/loose/" && touch "$T/loose/bin/oscompliance-agent" && chmod +x "$T/loose/bin/oscompliance-agent"
unpacked_package "$T/loose" && fail "a folder without VERSION is a package" || ok "a script next to a planted bin/ without VERSION is not a package"
mkdir -p "$T/shared" && cp -R "$T/pkg/." "$T/shared/" && chmod o+w "$T/shared/bin"
unpacked_package "$T/shared" && fail "a writable package is trusted" || ok "a package others can write to is not trusted"

OSSEC="$T/ossec" CONF_DIR="$T/etc"; mkdir -p "$OSSEC/etc"
echo '<ossec_config></ossec_config>' > "$OSSEC/etc/ossec.conf"
audit_manager_config; audit_manager_config
[ "$(grep -c "$BLOCK_BEGIN" "$OSSEC/etc/ossec.conf")" = 1 ] && ok "adds the manager localfiles once" || fail "localfile block count"
grep -q "\"wazuh_shared_conf\": \"$GROUP_CONF\"" "$CONF_DIR/agent.json" && ok "points the manager's agent at the ens group configuration" || fail "agent.json"
sed -i.bak "\|$BLOCK_BEGIN|,\|$BLOCK_END|d" "$OSSEC/etc/ossec.conf"
[ "$(cat "$OSSEC/etc/ossec.conf")" = '<ossec_config></ossec_config>' ] && ok "the uninstall expression removes exactly that block" || fail "block removal"

cluster_conf() { printf '<ossec_config>\n  <cluster>\n    <node_type>%s</node_type>\n    <disabled>%s</disabled>\n  </cluster>\n</ossec_config>\n' "$1" "$2" > "$OSSEC/etc/ossec.conf"; }
mkdir -p "$OSSEC/bin" && touch "$OSSEC/bin/wazuh-analysisd" && chmod +x "$OSSEC/bin/wazuh-analysisd"
DASHBOARD="$T/dashboard"
cluster_conf worker no; [ "$(cluster_role)" = worker ] && [ "$(detect_components)" = worker ] && ok "a worker manager only reloads the rules" || fail "worker ($(detect_components))"
cluster_conf master no; [ "$(detect_components)" = "rules audit engine" ] && ok "a master manager gets the rules, the audit and the engine" || fail "master ($(detect_components))"
cluster_conf worker yes; [ "$(cluster_role)" = master ] && ok "a manager with the cluster disabled is a single node" || fail "disabled cluster"
mkdir -p "$DASHBOARD" && echo '{"version": "2.19.6"}' > "$DASHBOARD/package.json"
[ "$(detect_components)" = "rules audit engine plugin" ] && ok "an all-in-one server gets everything" || fail "all-in-one ($(detect_components))"
rm "$OSSEC/bin/wazuh-analysisd"; [ "$(detect_components)" = plugin ] && ok "a dashboard node only gets the plugin" || fail "dashboard ($(detect_components))"
rm -r "$DASHBOARD"; [ -z "$(detect_components)" ] && ok "an indexer node gets nothing" || fail "indexer node"

[ "$(parse_components engine,plugin)" = "engine plugin" ] && ok "takes a component list from --only" || fail "--only list"
r="$( (parse_components engine,indexer) 2>&1)"; [ $? -ne 0 ] && echo "$r" | grep -q "unknown component: indexer" && ok "rejects an unknown component" || fail "unknown component ($r)"

FILEBEAT_CONF="$T/filebeat.yml"
printf 'output.elasticsearch:\n  hosts:\n  - 10.0.0.1:9200\n  - "https://10.0.0.2:9200"\n  protocol: https\n' > "$FILEBEAT_CONF"
[ "$(filebeat_indexers)" = "https://10.0.0.1:9200,https://10.0.0.2:9200" ] && ok "reads the indexers of a Filebeat host list" || fail "filebeat list ($(filebeat_indexers))"
printf 'output.elasticsearch.hosts: ["idx-01:9200", "idx-02:9200", '"'"'idx-03:9200'"'"']\n' > "$FILEBEAT_CONF"
[ "$(filebeat_indexers)" = "https://idx-01:9200,https://idx-02:9200,https://idx-03:9200" ] && ok "reads the indexers of an inline Filebeat array" || fail "filebeat array ($(filebeat_indexers))"
FILEBEAT_CONF="$T/none.yml"; [ -z "$(filebeat_indexers)" ] && ok "no Filebeat means no indexers" || fail "no filebeat"

valid_group ens && valid_group web_servers.prod-1 && ok "accepts Wazuh group names" || fail "valid group"
! valid_group 'ens;rm' && ! valid_group '' && ok "rejects other group names" || fail "invalid group"

echo '<ossec_config></ossec_config>' > "$OSSEC/etc/ossec.conf"
append_block "$OSSEC/etc/ossec.conf" "$(facts_localfile)"; append_block "$OSSEC/etc/ossec.conf" "$(facts_localfile)"
[ "$(grep -c "<location>$FACTS</location>" "$OSSEC/etc/ossec.conf")" = 1 ] && ok "adds the agent's facts localfile once" || fail "agent localfile"
remove_block "$OSSEC/etc/ossec.conf"; [ "$(cat "$OSSEC/etc/ossec.conf")" = '<ossec_config></ossec_config>' ] && ok "removes the agent's block" || fail "agent block removal"

rm -f "$CONF_DIR/agent.json"; request_group ens
[ "$(cat "$CONF_DIR/agent.json")" = '{"wazuh_group": "ens"}' ] && ok "writes the requested group" || fail "agent.json group"
echo '{"collectors": ["identity"]}' > "$CONF_DIR/agent.json"; request_group ens
[ "$(cat "$CONF_DIR/agent.json")" = '{"wazuh_group": "ens", "collectors": ["identity"]}' ] && ok "adds the group to an existing agent.json" || fail "agent.json insert ($(cat "$CONF_DIR/agent.json"))"
request_group web; [ "$(cat "$CONF_DIR/agent.json")" = '{"wazuh_group": "web", "collectors": ["identity"]}' ] && ok "replaces a previous group" || fail "agent.json replace ($(cat "$CONF_DIR/agent.json"))"

PKG="$T/pkg" RULES_FILE="$OSSEC/etc/rules/oscompliance_facts_rules.xml"; mkdir -p "$PKG/wazuh" "$OSSEC/etc/rules"; echo new > "$PKG/wazuh/oscompliance_facts_rules.xml"; echo old > "$RULES_FILE"
rules_synced && fail "old rules count as synced" || ok "a worker waits for the rules of its release"
echo new > "$RULES_FILE"; rules_synced && ok "a worker sees the rules of its release" || fail "synced rules"

r="$( (main agent --only engine) 2>&1)"; [ $? -ne 0 ] && echo "$r" | grep -q usage && ok "--only belongs to server" || fail "agent --only"
r="$( (main server --group ens) 2>&1)"; [ $? -ne 0 ] && echo "$r" | grep -q usage && ok "--group belongs to agent" || fail "server --group"

[ $failures -eq 0 ] && echo "ALL OK" || { echo "$failures FAILURES"; exit 1; }
