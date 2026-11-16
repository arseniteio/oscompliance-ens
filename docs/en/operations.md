# Operations

## What runs, and when

Every audited machine runs an agent pass each hour at minute 17, and the file system sweep each day at 03:23, limited by `sweep_timeout` (15 minutes). The engine runs a pass every 15 minutes. It syncs the group configuration at most every 15 minutes, and only when something changed.

## Engine logs

The engine logs JSON to the journal:

```bash
journalctl -u oscompliance-engine -f
```

| Message | Fields | Meaning |
|---|---|---|
| `pass` | `verdicts`, `seconds`, `requests` | one pass done |
| `pass` with `error` | same, plus `error` | the pass failed; verdicts already written stay |
| `parameters` | `error` | the ENS configuration could not be read; the pass continues with what was read |
| `inventory platforms` | `error` | system types could not be derived from the inventory |
| `group configuration` | `group`, `agents`, `applied` | the region of a group was synced (`applied: false` without `-sync-apply`) |
| `group configuration` | `error` | the sync failed; the next pass tries again |

`requests` should grow linearly with the fleet, about 0.7 per agent. A pass
that takes several times its usual time points at the indexer: heap, disk
or a long garbage collection.

## Checking a machine

On the machine:

```bash
tail -n 5 /var/log/oscompliance/facts.ndjson | jq -c '{fact, ts, status}'
grep -c oscompliance /var/ossec/etc/shared/agent.conf
auditctl -l | grep -c oscompliance_
```

In Discover, on `wazuh-alerts-*`, for that agent:

| Query | Shows |
|---|---|
| `rule.id:119001` | its facts |
| `rule.id:119002` | its authentication probes: the auth log reaches Wazuh |
| `rule.id:119004` | its audited accesses |

Its verdicts, on `oscompliance-verdicts`:

```
agent.name:"web-01" and scope:evidence and status:NOT_EVALUABLE
```

## Troubleshooting

No alerts 119001 from a machine. The Wazuh agent has not received the facts localfile, or the rules are not loaded. Check that `/var/ossec/etc/shared/agent.conf` on the machine mentions `facts.ndjson`, and run `wazuh-analysisd -t` on the manager. If the file arrived after the first pass, run `touch /var/log/oscompliance/facts.ndjson`, restart `wazuh-agent` and run `oscompliance-agent -full`.

Everything is NOT_EVALUABLE by COLLECTION on one machine. There was no agent pass in the window. Check `/etc/cron.d/oscompliance`, and run the agent by hand to read its error. With SELinux enforcing, run `restorecon` as in the installation guide.

Login evidences are NOT_EVALUABLE by COLLECTION. The authentication log does not reach Wazuh, so there is no 119002 alert. Add `/var/log/auth.log`, `/var/log/secure` or journald to the agent's localfiles, then log in over SSH.

op.acc.2 EV-06, op.acc.3 or op.acc.4 EV-07 are NOT_EVALUABLE by COLLECTION. auditd is not running, its watches are not loaded, or the audit log is not read. Install auditd and check `auditctl -l`. The engine's block in the group configuration adds the audit localfile.

A control is NOT_EVALUABLE by CONFIGURATION. A parameter is not set. The verdict names it: set it in Power ENS.

The engine logs `the ENS scope has never been read`. The engine could not read the configuration index since it started. The `parameters` line before it names the error, usually the indexer connection. Without a saved configuration the engine uses the catalog default and does not log this.

The engine gets 401 or 403 from the indexer. The password is wrong or the role lacks a permission. Check `engine.env` and compare the role with `engine-role.json`. The error names the action.

The engine gets 401 or 403 from the Wazuh API. The password is wrong or the policy lacks an action. Compare the policy with `engine-api-role.json`.

The engine logs a certificate error. The CA is wrong, or the API certificate names another host. Check `-ca`, `-wazuh-api-ca` and `-wazuh-api-server-name`.

The engine logs HTTP 429. The indexer is under pressure. The engine retries. If it happens often, raise the indexer heap or `-interval`.

The group configuration is not applied. `-sync-apply` is missing, or the scope names no Wazuh group. The `group configuration` log line says which.

`agent_groups` returns error 1017. The manager is starting. Wait one minute and repeat. Error 1751 means the agent is already in the group, and nothing needs doing.

The manager has no verdicts. The agent is not installed on it, or its `ossec.conf` lacks the facts localfile. See [installation, section 8](install.md#8-audit-the-manager).

A new machine shows nothing. It is not in the ENS group, or its first pass ran before it received the group configuration. Add it to the group and repeat [section 7 of the installation](install.md#7-install-the-agent-on-the-audited-machines).

A machine installed with `--group` does not join the group. The group is not in the ENS scope, the engine lacks `group:modify_assignments` or `agent:modify_group`, or no `agent_pass` with `requested_group` is in the window. The `group configuration` and `group requests` log lines say which. After an upgrade from 1.1.0, run `engine-users.sh create` again to add the two actions.

The Wazuh agent logs warning 1958 for `facts.ndjson`. The file is declared in `ossec.conf` and in the group configuration. Wazuh reads it once, and nothing needs doing.

Power ENS does not appear in the dashboard. On packages, read the output of `deploy-plugin.sh` and `journalctl -u wazuh-dashboard`. On Docker, check the image of the `wazuh.dashboard` service. If the zip was built for another version, the dashboard refuses it: build it again for your version. A blank page after an upgrade goes away after closing the tab and logging in again.

Docker cannot pull images. The host needs access to Docker Hub. Without it, pull `wazuh/wazuh-dashboard` for your version and `alpine:3.20` from a network with access, and move them with `docker save` and `docker load`.

## Before installing on a machine

`oscompliance-doctor` ([arseniteio/oscompliance-agent-doctor-ens](https://github.com/arseniteio/oscompliance-agent-doctor-ens)) checks a machine before and after the installation: the Wazuh agent is installed, enrolled, connected and in the ENS group; auditd, auditctl, cron, the syslog socket and the authentication log are in place; and, once the agent is installed, its cron file, directories, configuration and last pass. On the manager it checks the facts localfile in `ossec.conf` instead of the group. It exits 0 when the machine is ready and 1 with each problem otherwise.

## Capacity

A pass makes about 0.7 requests per agent. It takes 6 to 8 seconds for 1,000 agents and 100 to 130 seconds for 10,000, measured on a single-node lab indexer with a 1 GB heap.

Each agent sends about 115 facts per day in steady state, a small fraction of what Wazuh's own modules send. Verdicts are written per pass, so set an ISM policy on `oscompliance-verdicts` to the retention the audit requires.

`oscompliance-fleetsim` loads a synthetic fleet, copied from a real agent,
into separate indices, to measure the engine on the target indexer before
rollout:

```bash
oscompliance-fleetsim -indexer https://127.0.0.1:9200 -user admin -ca root-ca.pem \
  -agent 001 -agents 10000 -quiet
oscompliance-engine -indexer https://127.0.0.1:9200 -user admin -ca root-ca.pem \
  -alerts-index wazuh-alerts-4.x-fleetsim -monitoring-index wazuh-monitoring-fleetsim \
  -verdicts-index oscompliance-verdicts-fleetsim
```

## Backups

Everything OSCompliance needs to recover lives in the indexer: the ENS
configuration (`wazuh-ens-configuration`) and the history indices. Include
them in the indexer's snapshot policy. Agents hold no state that cannot be
rebuilt: a lost `/var/lib/oscompliance` only makes the next pass a full one.
