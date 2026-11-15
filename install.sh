#!/usr/bin/env bash
set -euo pipefail

OSC_RELEASE="${OSC_RELEASE:-}"
OSC_REPO_URL="${OSC_REPO_URL:-https://github.com/arseniteio}"
OSC_WAIT_SECONDS="${OSC_WAIT_SECONDS:-900}"
OSSEC="${OSSEC:-/var/ossec}"
DASHBOARD="${DASHBOARD:-/usr/share/wazuh-dashboard}"

PREFIX=/usr/local/bin
CONF_DIR=/etc/oscompliance
LOG_DIR=/var/log/oscompliance
STATE_DIR=/var/lib/oscompliance
FACTS="$LOG_DIR/facts.ndjson"
CRON_FILE=/etc/cron.d/oscompliance
UNIT_FILE=/etc/systemd/system/oscompliance-engine.service
RULES_FILE="$OSSEC/etc/rules/oscompliance_facts_rules.xml"
GROUP_CONF="$OSSEC/etc/shared/ens/agent.conf"
BLOCK_BEGIN='<!-- oscompliance begin -->'
BLOCK_END='<!-- oscompliance end -->'

usage() {
  cat >&2 <<'EOF'
usage: install.sh server | agent | uninstall

  server     install the rules, the engine, its users and the Power ENS plugin on an
             all-in-one Wazuh server installed from packages, and audit the manager
  agent      install the agent on a machine with a Wazuh agent
  uninstall  remove whatever this script installed on this machine

Run it again with a newer release to upgrade.
EOF
  exit 1
}

say() { echo "oscompliance: $*"; }
die() { echo "oscompliance: $*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" = 0 ] || die "run this as root"
}

require_tools() {
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null || die "$tool is not installed: install it and run this again"
  done
}

arch_of() {
  case "$1" in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *) die "unsupported architecture: $1" ;;
  esac
}

plugin_zip_for() {
  case "$2" in
    2.19.5 | 2.19.6) echo "power-ens-$1-osd-$2.zip" ;;
    *) die "unsupported OpenSearch Dashboards version: $2 (Wazuh 4.14.7, 4.14.8 or 4.14.9 is required)" ;;
  esac
}

release_version() {
  if [ -n "$OSC_RELEASE" ]; then
    echo "${OSC_RELEASE#v}"
    return
  fi
  local latest
  latest="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$OSC_REPO_URL/oscompliance-ens/releases/latest")"
  case "$latest" in
    */tag/v*) echo "${latest##*/tag/v}" ;;
    *) die "cannot find the latest release: set OSC_RELEASE, for example OSC_RELEASE=1.0.0" ;;
  esac
}

verify_checksum() {
  local dir="$1" file="$2"
  grep -q " $file\$" "$dir/SHA256SUMS" || die "$file is not listed in SHA256SUMS"
  (cd "$dir" && grep " $file\$" SHA256SUMS | sha256sum -c --quiet -) || die "checksum mismatch for $file"
}

download() {
  local repo="$1" version="$2" dir="$3"
  shift 3
  local url="$OSC_REPO_URL/$repo/releases/download/v$version" file
  curl -fsSL -o "$dir/SHA256SUMS" "$url/SHA256SUMS"
  for file in "$@"; do
    curl -fsSL -o "$dir/$file" "$url/$file"
    verify_checksum "$dir" "$file"
  done
}

script_dir() {
  local source="${BASH_SOURCE[0]:-}"
  [ -n "$source" ] && [ -f "$source" ] && (cd "$(dirname "$source")" && pwd)
}

fetch_package() {
  local here
  here="$(script_dir || true)"
  if [ -n "$here" ] && [ -x "$here/bin/oscompliance-agent" ]; then
    PKG="$here"
    return
  fi

  VERSION="$(release_version)"
  local name
  name="oscompliance-ens-$VERSION-linux-$(arch_of "$(uname -m)")"
  say "downloading $name"
  download oscompliance-ens "$VERSION" "$WORK" "$name.tar.gz"
  tar -xzf "$WORK/$name.tar.gz" -C "$WORK"
  PKG="$WORK/$name"
}

fetch_plugin() {
  local osd zip
  osd="$(grep -m1 '"version"' "$DASHBOARD/package.json" | cut -d'"' -f4)"
  zip="$(plugin_zip_for "$VERSION" "$osd")"

  if [ -f "$PKG/$zip" ] && [ -f "$PKG/deploy-plugin.sh" ]; then
    PLUGIN_ZIP="$PKG/$zip"
    DEPLOY="$PKG/deploy-plugin.sh"
    return
  fi

  say "downloading $zip"
  download power-ens "$VERSION" "$WORK" "$zip" deploy-plugin.sh
  PLUGIN_ZIP="$WORK/$zip"
  DEPLOY="$WORK/deploy-plugin.sh"
}

package_version() {
  cat "$PKG/VERSION"
}

wait_for() {
  local what="$1" seconds="$2"
  shift 2
  local waited=0
  until "$@"; do
    [ "$waited" -lt "$seconds" ] || return 1
    [ $((waited % 60)) -ne 0 ] || say "waiting for $what"
    sleep 5
    waited=$((waited + 5))
  done
}

api_is_up() {
  [ "$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:55000/)" != 000 ]
}

group_conf_arrived() {
  grep -qs facts.ndjson "$OSSEC/etc/shared/agent.conf"
}

with_terminal() {
  if [ -n "${API_ADMIN_PASSWORD:-}" ] && [ -n "${OSC_INDEXER_PASSWORD:-}" ] && [ -n "${OSC_WAZUH_API_PASSWORD:-}" ]; then
    "$@" </dev/null
  elif [ -r /dev/tty ]; then
    "$@" </dev/tty
  else
    die "no terminal to ask for passwords: export API_ADMIN_PASSWORD, OSC_INDEXER_PASSWORD and OSC_WAZUH_API_PASSWORD"
  fi
}

install_agent_files() {
  install -m 755 "$PKG/bin/oscompliance-agent" "$PREFIX/"
  install -m 644 "$PKG/agent/oscompliance.cron" "$CRON_FILE"
  install -d -m 750 "$LOG_DIR"
  install -d -m 700 "$STATE_DIR"
  touch "$FACTS"
  if command -v selinuxenabled >/dev/null && selinuxenabled; then
    restorecon -R "$PREFIX/oscompliance-agent" "$CRON_FILE" "$LOG_DIR"
  fi
}

warn_missing_services() {
  systemctl is-active -q auditd || say "warning: auditd is not active, the audit evidences will not be evaluable"
  systemctl is-active -q cron || systemctl is-active -q crond || say "warning: no cron service is active, the agent will not run on its own"
}

install_rules() {
  local clash
  clash="$(grep -rlE 'id="11900[0-4]"' "$OSSEC/etc/rules/" | grep -v "$RULES_FILE" || true)"
  [ -z "$clash" ] || die "rule IDs 119000 to 119004 are already used in: $clash"
  install -o wazuh -g wazuh -m 660 "$PKG/wazuh/oscompliance_facts_rules.xml" "$RULES_FILE"
  "$OSSEC/bin/wazuh-analysisd" -t || die "wazuh-analysisd rejected the rules"
}

audit_manager_config() {
  install -d -m 755 "$CONF_DIR"
  [ -f "$CONF_DIR/agent.json" ] ||
    echo "{\"paths\": {\"wazuh_shared_conf\": \"$GROUP_CONF\", \"wazuh_client_keys\": \"\"}}" > "$CONF_DIR/agent.json"

  grep -qF "$BLOCK_BEGIN" "$OSSEC/etc/ossec.conf" && return
  cat >> "$OSSEC/etc/ossec.conf" <<EOF
$BLOCK_BEGIN
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>$FACTS</location>
  </localfile>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</ossec_config>
$BLOCK_END
EOF
}

create_group() {
  [ -d "$OSSEC/etc/shared/ens" ] || "$OSSEC/bin/agent_groups" -a -g ens -q >/dev/null
}

install_engine() {
  install -m 755 "$PKG/bin/oscompliance-engine" "$PREFIX/"
  install -m 644 "$PKG/wazuh/oscompliance-engine.service" "$UNIT_FILE"
  systemctl daemon-reload
  systemctl enable -q oscompliance-engine
  systemctl restart oscompliance-engine
}

server() {
  require_tools curl jq unzip sha256sum tar systemctl
  [ -x "$OSSEC/bin/wazuh-analysisd" ] || die "no Wazuh manager in $OSSEC"
  [ -f "$DASHBOARD/package.json" ] || die "no Wazuh dashboard in $DASHBOARD: on Docker or a distributed deployment, follow docs/en/install-docker.md or docs/en/install.md"

  fetch_package
  VERSION="${VERSION:-$(package_version)}"
  fetch_plugin

  say "installing the rules and auditing the manager"
  install_rules
  install_agent_files
  audit_manager_config
  systemctl restart wazuh-manager
  wait_for "the Wazuh API" 300 api_is_up || die "the Wazuh API did not start"
  create_group

  if [ -f "$CONF_DIR/engine.env" ]; then
    say "engine users already exist, keeping them"
  else
    say "creating the engine users"
    with_terminal bash "$PKG/wazuh/engine-users.sh" create
  fi

  say "installing the Power ENS plugin"
  bash "$DEPLOY" "$PLUGIN_ZIP"

  say "starting the engine"
  install_engine
  "$PREFIX/oscompliance-agent" -full

  cat <<EOF

Done. Next steps:
  1. In the dashboard, open Power ENS, Configuración, Organización, fill in Cliente and press
     Guardar configuración global.
  2. Add each machine to audit to the ens group, with its ID from $OSSEC/bin/agent_control -l:
       $OSSEC/bin/agent_groups -a -i <id> -g ens -q
  3. On each of those machines, run this script with the agent argument.
The first verdicts appear within 15 minutes of the first save.
EOF
}

agent() {
  require_tools curl sha256sum tar systemctl
  [ -f "$OSSEC/etc/client.keys" ] || die "no Wazuh agent in $OSSEC"
  [ ! -x "$OSSEC/bin/wazuh-analysisd" ] || die "this is the Wazuh manager: use the server argument"

  fetch_package
  warn_missing_services
  install_agent_files

  if ! group_conf_arrived; then
    local id
    id="$(cut -d' ' -f1 "$OSSEC/etc/client.keys" | head -n1)"
    say "waiting for the ens group configuration. If this machine is not in the group yet, run on the manager:"
    say "  $OSSEC/bin/agent_groups -a -i $id -g ens -q"
    if ! wait_for "the group configuration" "$OSC_WAIT_SECONDS" group_conf_arrived; then
      say "the group configuration has not arrived yet. The agent is installed and cron runs it every hour."
      say "For a complete first pass, run 'oscompliance-agent -full' once $OSSEC/etc/shared/agent.conf mentions facts.ndjson."
      return
    fi
  fi

  systemctl restart wazuh-agent
  sleep 30
  "$PREFIX/oscompliance-agent" -full
  say "done. The machine appears in Power ENS after the next engine pass, within 15 minutes."
}

uninstall_server() {
  say "removing the engine, the plugin and the rules"
  with_terminal bash "$PKG/wazuh/engine-users.sh" remove || say "warning: the engine users could not be removed"
  systemctl disable -q --now oscompliance-engine || true
  rm -f "$UNIT_FILE" "$PREFIX/oscompliance-engine"
  systemctl daemon-reload
  if [ -d "$DASHBOARD/plugins/powerEns" ]; then
    sudo -u wazuh-dashboard "$DASHBOARD/bin/opensearch-dashboards-plugin" remove powerEns
    systemctl restart wazuh-dashboard
  fi
  rm -f "$RULES_FILE"
  [ ! -f "$GROUP_CONF" ] || sed -i '/<!-- oscompliance begin/,/<!-- oscompliance end -->/d' "$GROUP_CONF"
  sed -i "\|$BLOCK_BEGIN|,\|$BLOCK_END|d" "$OSSEC/etc/ossec.conf"
  systemctl restart wazuh-manager
  say "the indices oscompliance-* and wazuh-ens-configuration are kept: delete them from Dev Tools when no longer needed"
}

uninstall() {
  if [ -f "$UNIT_FILE" ]; then
    require_tools curl jq sha256sum tar systemctl
    fetch_package
    uninstall_server
  fi

  say "removing the agent"
  rm -f "$CRON_FILE" "$PREFIX/oscompliance-agent"
  rm -rf "$CONF_DIR" "$LOG_DIR" "$STATE_DIR"
  if command -v augenrules >/dev/null; then augenrules --load >/dev/null; fi
  say "done"
}

main() {
  [ $# -eq 1 ] || usage
  require_root
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  case "$1" in
    server) server ;;
    agent) agent ;;
    uninstall) uninstall ;;
    *) usage ;;
  esac
}

if [ "${OSC_INSTALL_SOURCED:-}" != 1 ]; then
  main "$@"
fi
