# Installation

This guide installs OSCompliance ENS on an existing Wazuh deployment. Plan
for about one hour on the manager and a few minutes per audited machine. Every
step can be undone, and nothing here changes how Wazuh itself collects or
alerts.

| Where | What | Section |
|---|---|---|
| Wazuh manager | rules, ENS group, engine users, engine service | [1](#1-manager) |
| Wazuh dashboard | Power ENS plugin | [2](#2-dashboard) |
| Every audited Linux machine | `oscompliance-agent`, auditd | [3](#3-audited-machines) |
| The manager as an audited machine | `oscompliance-agent` | [4](#4-the-manager-as-an-audited-machine) |

## Requirements

| Component | Requirement |
|---|---|
| Wazuh | 4.14.x manager, indexer and dashboard |
| Dashboard | OpenSearch Dashboards 2.19.5 (the one Wazuh 4.14 ships) |
| Audited machines | Linux on amd64 or arm64 with a Wazuh agent enrolled in the manager; systemd recommended |
| auditd | on audited machines, for op.acc.2 EV-06, op.acc.3 and op.acc.4 EV-04 and EV-07 |
| Access | root on every host; Wazuh API administrator and indexer admin certificate on the manager, once |

The binaries are static (Go, `CGO_ENABLED=0`) and have no runtime
dependencies. Nothing is compiled on the target hosts.

## 0. Build the packages

There are no published packages yet. Build them from this repository on any
machine with Go:

```bash
VERSION=0.10.0
make dist VERSION="$VERSION"
tar xzf "dist/oscompliance-ens-$VERSION-linux-amd64.tar.gz"
cd "oscompliance-ens-$VERSION-linux-amd64"
```

`make dist` writes one package per architecture and a checksum file to `dist/`:

```
oscompliance-ens-<version>-linux-amd64.tar.gz
oscompliance-ens-<version>-linux-arm64.tar.gz
SHA256SUMS
```

The package holds:

| Path | Content |
|---|---|
| `bin/oscompliance-agent` | the agent |
| `bin/oscompliance-engine` | the engine |
| `wazuh/oscompliance_facts_rules.xml` | rules 119000-119004 |
| `wazuh/agent.conf.fragment.xml` | the facts localfile, for a manual group configuration |
| `wazuh/engine-role.yml` | least-privilege indexer role of the engine |
| `wazuh/engine-api-role.json` | least-privilege Wazuh API policy of the engine |
| `agent/agent.example.json` | every agent setting with its default |

Run `make check` first: it runs gofmt, `go vet` and the full test suite.

## 1. Manager

All commands run as root on the manager.

### 1.1 Rules

```bash
install -o wazuh -g wazuh -m 660 wazuh/oscompliance_facts_rules.xml /var/ossec/etc/rules/
/var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager
```

The rules use IDs 119000 to 119004. They index only lines read from
`/var/log/oscompliance/facts.ndjson` (facts), the agent's authentication probe,
JSON service logs declared for op.acc.5, and auditd records carrying an
`oscompliance_*` key. They raise nothing above level 3.

### 1.2 ENS group

The engine configures agents per Wazuh group. Create one and add the machines
to audit:

```bash
/var/ossec/bin/agent_groups -a -g ens -q
/var/ossec/bin/agent_groups -a -i <agent_id> -g ens -q
```

An agent can belong to other groups as well. The engine only writes its own
marked region of this group's `agent.conf` and leaves the rest untouched.

### 1.3 Indexer user

The engine reads Wazuh's indices and writes its own three. It needs no admin
rights. Create its role, user and mapping with the indexer's security API,
using the admin certificate:

```bash
OS="https://127.0.0.1:9200"
CERTS=/etc/wazuh-indexer/certs
os() { curl -s --cacert $CERTS/root-ca.pem --cert $CERTS/admin.pem --key $CERTS/admin-key.pem \
  -H 'Content-Type: application/json' "$@"; }

os -X PUT "$OS/_plugins/_security/api/roles/oscompliance_engine" -d '{
  "cluster_permissions": ["cluster_composite_ops_ro",
    "cluster:admin/opendistro/ism/managedindex/explain", "cluster:admin/opendistro/ism/policy/get"],
  "index_permissions": [
    {"index_patterns": ["wazuh-alerts-*", "wazuh-monitoring-*", "wazuh-states-inventory-*",
                        "wazuh-states-vulnerabilities-*", "wazuh-ens-configuration"],
     "allowed_actions": ["read"]},
    {"index_patterns": ["oscompliance-verdicts", "oscompliance-identity-history", "oscompliance-config-history"],
     "allowed_actions": ["create_index", "manage_mapping", "crud", "indices:admin/get",
                         "indices:admin/refresh*", "indices:data/write/bulk*"]}]}'

read -rsp 'Password for the oscompliance indexer user: ' OSC_PW; echo
os -X PUT "$OS/_plugins/_security/api/internalusers/oscompliance" \
  -d "{\"password\": \"$OSC_PW\"}"
os -X PUT "$OS/_plugins/_security/api/rolesmapping/oscompliance_engine" \
  -d '{"users": ["oscompliance"]}'
```

The same role in `roles.yml` format is `wazuh/engine-role.yml`, for
installations managed with `securityadmin.sh`.

### 1.4 Wazuh API user

The engine reads the manager's configuration, rules and inventory through the
Wazuh API, and writes the group configuration. Create a policy, a role and a
user with the API itself:

```bash
API="https://127.0.0.1:55000"
TOKEN=$(curl -sk -u wazuh-wui -X POST "$API/security/user/authenticate?raw=true")
api() { curl -sk -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }

POLICY=$(api -X POST "$API/security/policies" -d "$(jq '.policy' wazuh/engine-api-role.json)" \
  | jq '.data.affected_items[0].id')
ROLE=$(api -X POST "$API/security/roles" -d '{"name": "oscompliance_engine"}' \
  | jq '.data.affected_items[0].id')
api -X POST "$API/security/roles/$ROLE/policies?policy_ids=$POLICY"

read -rsp 'Password for the oscompliance API user: ' OSC_API_PW; echo
USER_ID=$(api -X POST "$API/security/users" \
  -d "{\"username\": \"oscompliance\", \"password\": \"$OSC_API_PW\"}" | jq '.data.affected_items[0].id')
api -X POST "$API/security/users/$USER_ID/roles?role_ids=$ROLE"
```

The policy grants `group:read`, `group:create`, `group:update_config`, `agent:read`,
`syscollector:read`, `manager:read` and `rules:read`. Wazuh requires API
passwords of 8 to 64 characters with upper and lower case, a digit and a
symbol.

The API user is optional. Without it the engine judges everything it can read
from the indexer, leaves the manager's own configuration NOT_EVALUABLE by
COLLECTION, and does not write the group configuration: add
`wazuh/agent.conf.fragment.xml` to the group's `agent.conf` by hand instead.

### 1.5 Engine

```bash
install -m 755 bin/oscompliance-engine /usr/local/bin/
install -d -m 700 /etc/oscompliance
umask 077
cat > /etc/oscompliance/engine.env <<EOF
OSC_INDEXER_USER=oscompliance
OSC_INDEXER_PASSWORD=$OSC_PW
OSC_WAZUH_API_USER=oscompliance
OSC_WAZUH_API_PASSWORD=$OSC_API_PW
EOF
unset OSC_PW OSC_API_PW
```

Passwords are read only from the environment, never from the command line,
so they do not appear in `ps` or in the journal.

Run one pass by hand before installing the service. Without `-interval` the
engine runs once and exits; without `-sync-apply` it only logs the group
configuration it would write:

```bash
set -a; . /etc/oscompliance/engine.env; set +a
oscompliance-engine \
  -indexer https://127.0.0.1:9200 -user "$OSC_INDEXER_USER" \
  -ca /etc/wazuh-indexer/certs/root-ca.pem \
  -wazuh-api https://127.0.0.1:55000 -wazuh-api-user "$OSC_WAZUH_API_USER" \
  -wazuh-api-ca /var/ossec/api/configuration/ssl/server.crt -wazuh-api-server-name localhost
```

A good pass ends with a line like:

```json
{"level":"INFO","msg":"pass","verdicts":4410,"seconds":5.8,"requests":381}
```

Then install the service:

```bash
cat > /etc/systemd/system/oscompliance-engine.service <<'EOF'
[Unit]
Description=OSCompliance ENS engine
After=network-online.target wazuh-indexer.service wazuh-manager.service
Wants=network-online.target

[Service]
EnvironmentFile=/etc/oscompliance/engine.env
ExecStart=/usr/local/bin/oscompliance-engine \
  -indexer https://127.0.0.1:9200 -user ${OSC_INDEXER_USER} \
  -ca /etc/wazuh-indexer/certs/root-ca.pem \
  -wazuh-api https://127.0.0.1:55000 -wazuh-api-user ${OSC_WAZUH_API_USER} \
  -wazuh-api-ca /var/ossec/api/configuration/ssl/server.crt -wazuh-api-server-name localhost \
  -interval 15m -sync-apply
Restart=on-failure
RestartSec=60
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now oscompliance-engine
```

Adjust the URLs and certificates to the installation. `-wazuh-api-server-name`
is needed when the API certificate does not name the host in the URL; the
default Wazuh certificate names `localhost`. Every flag is described in
[configuration](configuration.md#engine).

## 2. Dashboard

Build the Power ENS plugin from its repository (see its README), install the
zip with `config/deploy-plugin.sh` and grant its administrator role with
`config/create-admin-role.sh`:

```bash
bash deploy-plugin.sh powerEns-2.19.5.zip
bash create-admin-role.sh --map <dashboard_user>
```

`deploy-plugin.sh` validates the zip, keeps a copy of the plugin it replaces in
`/var/backups/power-ens`, installs and restarts the dashboard, and tells how to
roll back if anything fails.

In Power ENS > Configuración:

1. Alcance: select the `ens` group, the ENS category (BAJO, MEDIO or
   ALTO) and the system type of each machine.
2. Each control: fill its parameters. Each control page in
   [controls](controls/README.md) lists them and says which evidence each one
   feeds.
3. Save. The engine applies the change on its next pass.

A control whose parameters are not set shows NOT_EVALUABLE by CONFIGURATION:
it is never judged against a default nobody chose.

## 3. Audited machines

As root on every machine of the `ens` group:

```bash
install -m 755 bin/oscompliance-agent /usr/local/bin/
install -d -m 750 /var/log/oscompliance
install -d -m 700 /var/lib/oscompliance
cat > /etc/cron.d/oscompliance <<'EOF'
# oscompliance-agent: one collection pass per hour, the file system sweep daily.
17 * * * * root /usr/local/bin/oscompliance-agent >/dev/null 2>&1
23 3 * * * root /usr/local/bin/oscompliance-agent -collect sweep >/dev/null 2>&1
EOF
```

Install and enable auditd with the distribution's package (`auditd` on
Debian and Ubuntu, `audit` on RHEL). The agent adds its own watches at
runtime with `auditctl`, tagged `oscompliance_*`, on every pass. It never
removes a rule and never writes to `/etc/audit`.

The agent reads `/etc/shadow`, `sshd -T` and the sudoers files, so it runs as
root. It needs no configuration file on a standard system; see
[configuration](configuration.md#agent) when files live elsewhere.

Wait until the machine receives the group's `agent.conf` (a minute or two
after the engine's first `-sync-apply` pass), then send a full pass:

```bash
grep -q oscompliance /var/ossec/etc/shared/agent.conf && /usr/local/bin/oscompliance-agent -full
```

Rolling out to many machines is the same three commands; use the
configuration management tool already in place (Ansible, Salt, Puppet).

## 4. The manager as an audited machine

The manager is judged like every other machine. It belongs to no group, so it
reads the group configuration from the ENS group's directory and its own
`ossec.conf`:

```bash
install -m 755 bin/oscompliance-agent /usr/local/bin/
install -d -m 750 /var/log/oscompliance
install -d -m 700 /var/lib/oscompliance /etc/oscompliance
cat > /etc/oscompliance/agent.json <<'EOF'
{"paths": {"wazuh_shared_conf": "/var/ossec/etc/shared/ens/agent.conf", "wazuh_client_keys": ""}}
EOF
```

Add the facts file and the audit log to `/var/ossec/etc/ossec.conf`, inside
`<ossec_config>`, and restart the manager:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/oscompliance/facts.ndjson</location>
</localfile>
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

Then install the same cron file and auditd as in section 3.

## 5. Verify

| Check | Command | Expected |
|---|---|---|
| Agent writes facts | `tail -n 3 /var/log/oscompliance/facts.ndjson` | JSON lines with `"oscompliance":"1"` |
| Facts are indexed | Discover on `wazuh-alerts-*`: `rule.id:119001` | facts of every machine |
| Auth log reaches Wazuh | Discover: `rule.id:119002` | one probe per machine and pass |
| Engine passes | `journalctl -u oscompliance-engine -n 5` | `"msg":"pass"` lines with no `error` |
| Group configuration | `journalctl -u oscompliance-engine \| grep 'group configuration'` | `"applied":true` |
| Verdicts | Power ENS dashboard | every machine with a verdict per control |

The first full picture needs one agent pass and one engine pass after it: at
most about 75 minutes, or a few minutes with `-full` on the agent.

## Upgrade

1. Check the repository history for changes to rules or roles.
2. Manager: install the new rules if they changed and restart the manager;
   apply role changes with the commands of 1.3 and 1.4 (`PUT` replaces).
3. Engine: keep the running binary, install the new one, restart.

   ```bash
   cp /usr/local/bin/oscompliance-engine /usr/local/bin/oscompliance-engine.prev
   install -m 755 bin/oscompliance-engine /usr/local/bin/
   systemctl restart oscompliance-engine
   ```

4. Agents: install the new binary. The next cron run uses it; nothing needs a
   restart.
5. Plugin: build Power ENS from the matching commit and install it.

The engine reads facts from older agents: fact schemas only grow. Upgrade the
engine first, then the agents.

To roll back, put the `.prev` binary back and restart the engine. Verdicts
already written stay; the next pass replaces them.

## Uninstall

```bash
# audited machines
rm -f /etc/cron.d/oscompliance /usr/local/bin/oscompliance-agent
rm -rf /var/lib/oscompliance /var/log/oscompliance /etc/oscompliance
augenrules --load   # reloads rules.d, dropping the runtime watches the agent added

# manager
systemctl disable --now oscompliance-engine
rm -f /etc/systemd/system/oscompliance-engine.service /usr/local/bin/oscompliance-engine
rm -f /var/ossec/etc/rules/oscompliance_facts_rules.xml && systemctl restart wazuh-manager
```

Remove the engine's marked region from the group `agent.conf`, the indexer
user and role, the API user, role and policy, and, if the history is no
longer needed, the indices `oscompliance-verdicts`,
`oscompliance-identity-history` and `oscompliance-config-history`.
