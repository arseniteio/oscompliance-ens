#!/usr/bin/env bash
set -euo pipefail

OSC_RELEASE="${OSC_RELEASE:-}"
OSC_REPO_URL="${OSC_REPO_URL:-https://github.com/arseniteio}"
OSC_WAIT_SECONDS="${OSC_WAIT_SECONDS:-900}"
OSC_INDEXER_URLS="${OSC_INDEXER_URLS:-}"
OSC_INDEXER_CA="${OSC_INDEXER_CA:-}"
OSSEC="${OSSEC:-/var/ossec}"
DASHBOARD="${DASHBOARD:-/usr/share/wazuh-dashboard}"
FILEBEAT_CONF="${FILEBEAT_CONF:-/etc/filebeat/filebeat.yml}"
INDEXER_CERTS="${INDEXER_CERTS:-/etc/wazuh-indexer/certs}"

PREFIX=/usr/local/bin
CONF_DIR=/etc/oscompliance
LOG_DIR=/var/log/oscompliance
STATE_DIR=/var/lib/oscompliance
FACTS="$LOG_DIR/facts.ndjson"
CRON_FILE=/etc/cron.d/oscompliance
UNIT_FILE=/etc/systemd/system/oscompliance-engine.service
ENGINE_CONF="$CONF_DIR/engine.conf"
RULES_FILE="$OSSEC/etc/rules/oscompliance_facts_rules.xml"
GROUP_CONF="$OSSEC/etc/shared/ens/agent.conf"
BLOCK_BEGIN='<!-- oscompliance begin -->'
BLOCK_END='<!-- oscompliance end -->'
COMPONENTS="rules audit engine plugin worker"

usage() {
  cat >&2 <<'EOF'
usage: install.sh server [--only <components>]
       install.sh agent [--group <name>]
       install.sh uninstall

  server     install what this Wazuh server node needs. Run it on every manager and
             dashboard node, the master first. It detects the node:
               master manager (or single node)  rules, manager audit, engine
               worker manager                   reloads the rules the master syncs
               dashboard                        Power ENS plugin
             --only replaces the detection with a comma-separated list of
             rules, audit, engine, plugin and worker.
  agent      install the agent on a machine with a Wazuh agent. --group asks the
             engine to add the machine to that Wazuh group, such as ens.
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

valid_group() {
  [[ "$1" =~ ^[A-Za-z0-9._-]{1,255}$ ]]
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

owned_and_locked() {
  local dir="$1" owner="${SUDO_UID:-$(id -u)}"
  [ -z "$(find "$dir" \( -perm -g+w -o -perm -o+w \) -print -quit)" ] &&
    [ -z "$(find "$dir" ! -uid 0 ! -uid "$owner" -print -quit)" ]
}

unpacked_package() {
  local dir="$1"
  [ -n "$dir" ] && [ -f "$dir/VERSION" ] && [ -x "$dir/bin/oscompliance-agent" ] && owned_and_locked "$dir"
}

fetch_package() {
  local here
  here="$(script_dir || true)"
  if unpacked_package "$here"; then
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

rules_synced() {
  cmp -s "$RULES_FILE" "$PKG/wazuh/oscompliance_facts_rules.xml"
}

with_terminal() {
  if (: </dev/tty) 2>/dev/null; then
    "$@" </dev/tty
  else
    "$@" </dev/null
  fi
}

is_manager() {
  [ -x "$OSSEC/bin/wazuh-analysisd" ]
}

is_dashboard() {
  [ -f "$DASHBOARD/package.json" ]
}

cluster_role() {
  awk '
    /<cluster>/ { inside = 1 }
    inside && /<disabled>/ { value = $0; gsub(/.*<disabled>|<\/disabled>.*|[ \t]/, "", value); disabled = value }
    inside && /<node_type>/ { value = $0; gsub(/.*<node_type>|<\/node_type>.*|[ \t]/, "", value); type = value }
    /<\/cluster>/ { inside = 0 }
    END { print (disabled == "no" && type == "worker") ? "worker" : "master" }
  ' "$OSSEC/etc/ossec.conf"
}

detect_components() {
  local found=()
  if is_manager; then
    if [ "$(cluster_role)" = worker ]; then
      found+=(worker)
    else
      found+=(rules audit engine)
    fi
  fi
  if is_dashboard; then
    found+=(plugin)
  fi
  echo "${found[*]:-}"
}

parse_components() {
  local list="${1//,/ }" item
  for item in $list; do
    [[ " $COMPONENTS " == *" $item "* ]] || die "unknown component: $item (use $COMPONENTS)"
  done
  echo "$list"
}

has() {
  [[ " $SELECTED " == *" $1 "* ]]
}

filebeat_indexers() {
  [ -f "$FILEBEAT_CONF" ] || return 0
  awk '
    /^([ \t]*|.*\.)hosts:/ {
      line = $0
      sub(/^[^:]*:[ \t]*/, "", line)
      if (line != "") {
        gsub(/\[|\]|["\047 ]/, "", line)
        n = split(line, hosts, ",")
        for (i = 1; i <= n; i++) if (hosts[i] != "") print hosts[i]
        exit
      }
      list = 1
      next
    }
    list && /^[ \t]*-/ { value = $0; sub(/^[ \t]*-[ \t]*/, "", value); gsub(/["\047 ]/, "", value); print value; next }
    list { exit }
  ' "$FILEBEAT_CONF" | sed '/:\/\//!s#^#https://#' | paste -sd, -
}

indexer_ca() {
  local candidate
  for candidate in /etc/filebeat/certs/root-ca.pem "$INDEXER_CERTS/root-ca.pem"; do
    if [ -f "$candidate" ]; then
      echo "$candidate"
      return
    fi
  done
}

resolve_indexer() {
  if [ -z "$OSC_INDEXER_URLS" ] && [ -f "$ENGINE_CONF" ]; then
    OSC_INDEXER_URLS="$(sed -n 's/^OSC_INDEXER_URLS=//p' "$ENGINE_CONF")"
    OSC_INDEXER_CA="${OSC_INDEXER_CA:-$(sed -n 's/^OSC_INDEXER_CA=//p' "$ENGINE_CONF")}"
  fi
  OSC_INDEXER_URLS="${OSC_INDEXER_URLS:-$(filebeat_indexers)}"
  OSC_INDEXER_CA="${OSC_INDEXER_CA:-$(indexer_ca)}"

  [ -n "$OSC_INDEXER_URLS" ] || die "cannot read the indexers from $FILEBEAT_CONF: set OSC_INDEXER_URLS, such as OSC_INDEXER_URLS=https://10.0.0.1:9200,https://10.0.0.2:9200"
  [ -f "$OSC_INDEXER_CA" ] || die "no indexer CA certificate found: set OSC_INDEXER_CA to the root-ca.pem the indexers are signed with"
}

write_engine_conf() {
  install -d -m 755 "$CONF_DIR"
  printf 'OSC_INDEXER_URLS=%s\nOSC_INDEXER_CA=%s\n' "$OSC_INDEXER_URLS" "$OSC_INDEXER_CA" > "$ENGINE_CONF"
  chmod 644 "$ENGINE_CONF"
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

append_block() {
  local file="$1" body="$2"
  grep -qF "$BLOCK_BEGIN" "$file" && return
  printf '%s\n<ossec_config>\n%s\n</ossec_config>\n%s\n' "$BLOCK_BEGIN" "$body" "$BLOCK_END" >> "$file"
}

remove_block() {
  local file="$1"
  [ -f "$file" ] || return 0
  sed -i.oscompliance-bak "\|$BLOCK_BEGIN|,\|$BLOCK_END|d" "$file"
  rm -f "$file.oscompliance-bak"
}

facts_localfile() {
  cat <<EOF
  <localfile>
    <log_format>json</log_format>
    <location>$FACTS</location>
  </localfile>
EOF
}

audit_manager_config() {
  install -d -m 755 "$CONF_DIR"
  [ -f "$CONF_DIR/agent.json" ] ||
    echo "{\"paths\": {\"wazuh_shared_conf\": \"$GROUP_CONF\", \"wazuh_client_keys\": \"\"}}" > "$CONF_DIR/agent.json"

  append_block "$OSSEC/etc/ossec.conf" "$(facts_localfile)
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>"
}

request_group() {
  local group="$1" config="$CONF_DIR/agent.json"
  install -d -m 755 "$CONF_DIR"
  if [ ! -s "$config" ]; then
    printf '{"wazuh_group": "%s"}\n' "$group" > "$config"
  elif grep -q '"wazuh_group"' "$config"; then
    sed -E "s/\"wazuh_group\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"wazuh_group\": \"$group\"/" "$config" > "$config.new"
    mv "$config.new" "$config"
  else
    awk -v group="$group" '!done && sub(/\{/, "{\"wazuh_group\": \"" group "\", ") { done = 1 } { print }' "$config" > "$config.new"
    mv "$config.new" "$config"
  fi
}

create_group() {
  [ -d "$OSSEC/etc/shared/ens" ] || "$OSSEC/bin/agent_groups" -a -g ens -q >/dev/null
}

create_engine_users() {
  if [ -f "$CONF_DIR/engine.env" ]; then
    say "engine users already exist, keeping them; updating their permissions"
  else
    say "creating the engine users"
  fi
  INDEXER_URL="${OSC_INDEXER_URLS%%,*}" INDEXER_CA="$OSC_INDEXER_CA" CERTS="$INDEXER_CERTS" \
    KEEP_PASSWORDS="$([ -f "$CONF_DIR/engine.env" ] && echo 1 || echo 0)" \
    with_terminal bash "$PKG/wazuh/engine-users.sh" create
}

install_engine() {
  write_engine_conf
  install -m 755 "$PKG/bin/oscompliance-engine" "$PREFIX/"
  install -m 644 "$PKG/wazuh/oscompliance-engine.service" "$UNIT_FILE"
  systemctl daemon-reload
  systemctl enable -q oscompliance-engine
  systemctl restart oscompliance-engine
}

reload_synced_rules() {
  say "worker node: the rules and the group configuration come from the master"
  wait_for "the rules of release $VERSION from the master" "$OSC_WAIT_SECONDS" rules_synced ||
    die "the rules of release $VERSION have not arrived from the master: run install.sh server on the master, then this again"
  systemctl restart wazuh-manager
  say "rules loaded on this worker"
}

server_next_steps() {
  echo
  echo "Done on this node. Next steps:"
  if has engine; then
    echo "  1. Run this script with the server argument on every other manager and dashboard node."
    echo "  2. On each machine to audit, run this script with: agent --group ens"
    echo "The engine judges with the default configuration (level MEDIO, group ens) until one is saved"
    echo "in Power ENS. The first verdicts appear within 15 minutes."
  fi
}

server() {
  require_tools curl sha256sum tar systemctl
  if [ -n "$ONLY" ]; then
    SELECTED="$(parse_components "$ONLY")"
  else
    SELECTED="$(detect_components)"
  fi
  [ -n "${SELECTED// /}" ] || die "no Wazuh manager or dashboard on this host: indexer nodes need nothing"
  if has rules || has audit || has engine || has worker; then
    is_manager || die "no Wazuh manager in $OSSEC"
  fi
  if has plugin; then
    is_dashboard || die "no Wazuh dashboard in $DASHBOARD"
    require_tools unzip
  fi
  if has engine; then
    require_tools jq
    resolve_indexer
  fi
  say "installing on this node: $SELECTED"

  fetch_package
  VERSION="${VERSION:-$(package_version)}"

  if has worker; then
    reload_synced_rules
  fi

  if has rules || has audit; then
    say "installing the rules and auditing the manager"
    if has rules; then install_rules; fi
    if has audit; then
      install_agent_files
      audit_manager_config
    fi
    systemctl restart wazuh-manager
    wait_for "the Wazuh API" 300 api_is_up || die "the Wazuh API did not start"
  fi

  if has rules; then
    create_group
  fi

  if has engine; then
    wait_for "the Wazuh API" 300 api_is_up || die "the Wazuh API did not start"
    create_engine_users
    say "starting the engine"
    install_engine
  fi

  if has plugin; then
    fetch_plugin
    say "installing the Power ENS plugin"
    bash "$DEPLOY" "$PLUGIN_ZIP"
  fi

  if has audit; then
    "$PREFIX/oscompliance-agent" -full
  fi

  server_next_steps
}

agent_in_group() {
  local group="$1"
  request_group "$group"
  append_block "$OSSEC/etc/ossec.conf" "$(facts_localfile)"
  systemctl restart wazuh-agent
  sleep 30
  "$PREFIX/oscompliance-agent" -full
  say "done. The engine adds this machine to the group $group within 15 minutes, and its configuration follows."
}

agent_waiting_for_group() {
  if ! group_conf_arrived; then
    local id
    id="$(cut -d' ' -f1 "$OSSEC/etc/client.keys" | head -n1)"
    say "waiting for the ens group configuration. If this machine is not in the group yet, run on the manager:"
    say "  $OSSEC/bin/agent_groups -a -i $id -g ens -q"
    say "or run this script again with: agent --group ens"
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

agent() {
  require_tools curl sha256sum tar systemctl
  [ -f "$OSSEC/etc/client.keys" ] || die "no Wazuh agent in $OSSEC"
  ! is_manager || die "this is a Wazuh manager: use the server argument"
  [ -z "$GROUP" ] || valid_group "$GROUP" || die "not a Wazuh group name: $GROUP"

  fetch_package
  warn_missing_services
  install_agent_files

  if [ -n "$GROUP" ]; then
    agent_in_group "$GROUP"
  else
    agent_waiting_for_group
  fi
}

remove_engine() {
  say "removing the engine"
  INDEXER_URL="$(sed -n 's/^OSC_INDEXER_URLS=//p' "$ENGINE_CONF" 2>/dev/null | cut -d, -f1)" \
    INDEXER_CA="$(sed -n 's/^OSC_INDEXER_CA=//p' "$ENGINE_CONF" 2>/dev/null)" CERTS="$INDEXER_CERTS" \
    with_terminal bash "$PKG/wazuh/engine-users.sh" remove || say "warning: the engine users could not be removed"
  systemctl disable -q --now oscompliance-engine || true
  rm -f "$UNIT_FILE" "$PREFIX/oscompliance-engine"
  systemctl daemon-reload
}

remove_plugin() {
  say "removing the Power ENS plugin"
  sudo -u wazuh-dashboard "$DASHBOARD/bin/opensearch-dashboards-plugin" remove powerEns
  systemctl restart wazuh-dashboard
}

remove_manager_parts() {
  say "removing the rules and the manager audit"
  if [ "$(cluster_role)" = master ]; then
    rm -f "$RULES_FILE"
    remove_block "$GROUP_CONF"
  fi
  remove_block "$OSSEC/etc/ossec.conf"
  systemctl restart wazuh-manager
  say "the indices oscompliance-* and wazuh-ens-configuration are kept: delete them from Dev Tools when no longer needed"
}

remove_agent_parts() {
  grep -qsF "$BLOCK_BEGIN" "$OSSEC/etc/ossec.conf" || return 0
  remove_block "$OSSEC/etc/ossec.conf"
  systemctl restart wazuh-agent || say "warning: wazuh-agent did not restart"
}

uninstall() {
  if [ -f "$UNIT_FILE" ]; then
    require_tools curl jq sha256sum tar systemctl
    fetch_package
    remove_engine
  fi
  if [ -d "$DASHBOARD/plugins/powerEns" ]; then
    remove_plugin
  fi
  if is_manager; then
    remove_manager_parts
  else
    remove_agent_parts
  fi

  say "removing the agent"
  rm -f "$CRON_FILE" "$PREFIX/oscompliance-agent"
  rm -rf "$CONF_DIR" "$LOG_DIR" "$STATE_DIR"
  if command -v augenrules >/dev/null; then augenrules --load >/dev/null; fi
  say "done"
}

main() {
  [ $# -ge 1 ] || usage
  local command="$1"
  shift
  ONLY=""
  GROUP=""
  while [ $# -gt 0 ]; do
    case "$command:$1" in
      server:--only) [ $# -ge 2 ] || usage; ONLY="$2"; shift 2 ;;
      agent:--group) [ $# -ge 2 ] || usage; GROUP="$2"; shift 2 ;;
      *) usage ;;
    esac
  done

  require_root
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  case "$command" in
    server) server ;;
    agent) agent ;;
    uninstall) uninstall ;;
    *) usage ;;
  esac
}

if [ "${OSC_INSTALL_SOURCED:-}" != 1 ]; then
  main "$@"
fi
