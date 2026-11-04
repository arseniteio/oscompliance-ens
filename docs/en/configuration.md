# Configuration

Three things are configured, in three places. The operator sets the engine's connection and timing once, with flags and `/etc/oscompliance/engine.env` on the manager. The operator sets agent paths in `/etc/oscompliance/agent.json`, only on non-standard machines. The security officer sets the ENS policy (level, scope and every control parameter) in Power ENS at any time. It is stored in `wazuh-ens-configuration`.

Policy never lives on the machines. Agents hold paths only; every value that
decides compliance is a parameter in Power ENS, and the engine reloads it on
every pass.

## Engine

`oscompliance-engine` writes JSON logs to standard error. Without
`-interval` it runs one pass and exits.

| Flag | Default | Purpose |
|---|---|---|
| `-indexer` | `https://wazuh.indexer:9200` | indexer URL |
| `-user` | `admin` | indexer user; password in `OSC_INDEXER_PASSWORD` |
| `-ca` | system roots | CA certificate of the indexer (PEM) |
| `-wazuh-api` | empty | Wazuh API URL; empty disables everything read from or written to the API |
| `-wazuh-api-user` | `oscompliance` | API user; password in `OSC_WAZUH_API_PASSWORD` |
| `-wazuh-api-ca` | system roots | certificate the API is trusted with (PEM) |
| `-wazuh-api-server-name` | URL host | name checked in the API certificate |
| `-interval` | `0` | time between passes; `0` runs once |
| `-window` | `26h` | events newer than this count |
| `-lookback` | `168h` | agents with facts this recent are judged |
| `-sync-interval` | `15m` | minimum time between two group configuration syncs |
| `-sync-apply` | off | write the group configuration; without it changes are only logged and recorded |
| `-controls` | empty | comma-separated controls to judge; empty judges all of them |
| `-alerts-index` | `wazuh-alerts-*` | alerts index pattern |
| `-monitoring-index` | `wazuh-monitoring-*` | agent keepalive index pattern |
| `-states-prefix` | `wazuh-states-` | prefix of Wazuh's inventory and vulnerability indices |
| `-config-index` | `wazuh-ens-configuration` | Power ENS configuration index |
| `-verdicts-index` | `oscompliance-verdicts` | verdicts |
| `-history-index` | `oscompliance-identity-history` | per-account history |
| `-config-history-index` | `oscompliance-config-history` | group configuration changes |

| Environment variable | Purpose |
|---|---|
| `OSC_INDEXER_PASSWORD` | indexer password |
| `OSC_WAZUH_API_PASSWORD` | Wazuh API password |

The window is 26 hours so that an hourly agent and a daily sweep always have
a pass inside it, with margin for a late cron run.

## Group configuration

With `-wazuh-api` and `-sync-apply`, the engine keeps a marked region in the
`agent.conf` of every Wazuh group named in the ENS scope:

```xml
<!-- oscompliance begin: written by oscompliance-engine from the ENS configuration, do not edit -->
<agent_config>
  <!-- oscompliance {"acl_paths":["/srv/data"],"audit_watches":["/srv/data"],"exec_watches":["/usr/bin/git"]} -->
  <localfile><log_format>json</log_format><location>/var/log/oscompliance/facts.ndjson</location></localfile>
  <localfile><log_format>audit</log_format><location>/var/log/audit/audit.log</location></localfile>
</agent_config>
<agent_config name="sede-01">
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/sede/auth.json</location>
    <label key="oscompliance_service">sede</label>
  </localfile>
</agent_config>
<!-- oscompliance end -->
```

| Content | From |
|---|---|
| `acl_paths` | op.acc.2 P-08, op.exp.2 P-08 |
| `audit_watches` | op.acc.2 P-06, op.acc.3 P-03 paths and the security paths, op.acc.4 P-07 |
| `exec_watches` | op.acc.3 P-03 binaries |
| `backup_sources`, `backup_keys` | op.exp.3 P-07, mp.info.6 P-04 and P-08 |
| `key_stores` | op.exp.10 P-02 |
| FIM `<directories>` | op.acc.2 P-02 paths outside Wazuh's defaults |
| service localfiles | op.acc.5 P-02 |

What most machines of the group share goes to every agent; a machine that
needs other paths or has services of its own gets a block with its name.
Everything outside the markers is left untouched. Every change is recorded in
`oscompliance-config-history` with the region before and after; without
`-sync-apply` the change is recorded but not written.

## Control groups

With the option on in Power ENS (`scope.controlGroups`), the engine creates one
Wazuh group per control, `ens-excluir-<control>`, on its next group sync. It
needs `-wazuh-api`, `-sync-apply` and `group:create` in its API role. To take a
machine out of a control, add it to that group. Turning the option off ignores
the groups and deletes none of them. See [verdicts](verdicts.md).

## Agent

`/etc/oscompliance/agent.json` is optional. Without it the agent uses the
defaults; with it only the keys present change. An unknown key stops the
agent with an error. The file is read on every run.

| Key | Default | Purpose |
|---|---|---|
| `output` | `/var/log/oscompliance/facts.ndjson` | file the facts are appended to |
| `host` | system host name | host name written in every fact |
| `state` | `/var/lib/oscompliance/state.json` | what each collector last sent, to send only changes |
| `collectors` | all except `sweep` | collectors of the hourly pass |
| `sweep_timeout` | `15m` | time limit of the daily file system sweep |
| `paths.passwd` | `/etc/passwd` | account database |
| `paths.shadow` | `/etc/shadow` | password aging and locking |
| `paths.group` | `/etc/group` | group database |
| `paths.sshd` | `/usr/sbin/sshd` | sshd binary, asked for its effective configuration |
| `paths.sudoers` | `/etc/sudoers` | main sudoers file; includes are followed |
| `paths.pam_dir` | `/etc/pam.d` | PAM configuration |
| `paths.wazuh_shared_conf` | `/var/ossec/etc/shared/agent.conf` | group configuration the engine writes |
| `paths.wazuh_client_keys` | `/var/ossec/etc/client.keys` | the agent's key, which names the machine in that configuration; empty on the manager |

`agent/agent.example.json` holds every key with its default.

| Flag | Purpose |
|---|---|
| `-config path` | read another file; it must exist |
| `-collect a,b` | run these collectors instead of the configured ones |
| `-full` | send everything, even what did not change |

Collectors: `identity`, `groups`, `umask`, `sudoers`, `config`, `pam`,
`authprobe`, `listening`, `services`, `wazuh`, `acl`, `audit`, `firewall`,
`neighbours`, `virtualization`, `packages`, `units`, `backups`, `updates`,
`transactions`, `snapshots`, `malware`, `timesync`, `keys`, `device` and
`sweep`. What each one reads is in [facts](facts.md).

Removing a collector from the list leaves the evidences that need it
NOT_EVALUABLE by COLLECTION. It never makes them pass.

## ENS policy

Set in Power ENS > Configuración and stored in the document
`ACTIVE_CONFIGURATION` of `wazuh-ens-configuration`.

| Setting | Effect |
|---|---|
| ENS category | BAJO, MEDIO or ALTO; requirements outside it are NOT_APPLICABLE |
| Scope | the Wazuh groups audited |
| System type of each machine | picks its built-in parameter template |
| Control enabled | a disabled control is NOT_APPLICABLE everywhere |
| Control parameters | listed on each [control page](controls/README.md) |

Every parameter has a class that decides where its value comes from:

| Class | Value |
|---|---|
| `organisation` | the control's common value; per-machine values are ignored |
| `system` | the machine's own value, else its template, else the common value |
| `platform` | as `system`; built-in templates per system type ship values for it |

Templates: the one assigned to the machine, built-in (`catalog/templates/`)
or custom; `none` disables it; with none assigned, the built-in template of the
machine's system type. The system type is the one set by hand, else the one
Wazuh's inventory platform implies (`catalog/system-types.json`).

Lists compare ignoring case. A parameter marked as a regular expression uses
RE2, matches the whole value, is case-sensitive and at most 512 characters
long. Tables are rows of cells separated by `|`.

A parameter that is not set gives NOT_EVALUABLE by CONFIGURATION on the
evidences that need it. The engine never applies a value nobody chose, except
the two product defaults that op.acc.1 documents (lowest UID of a person and
privileged groups), and the verdict says when it does.
