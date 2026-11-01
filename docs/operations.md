# Operations

## What runs, and when

| What | Where | When |
|---|---|---|
| agent pass | every audited machine | hourly, minute 17 |
| file system sweep | every audited machine | daily at 03:23, capped by `sweep_timeout` (15 min) |
| engine pass | manager host | every 15 minutes; 6 to 8 s per 1,000 agents |
| group configuration sync | manager host | at most every 15 minutes, only when something changed |

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

| Symptom | Cause | Fix |
|---|---|---|
| No alerts 119001 from a machine | the Wazuh agent has not received the facts localfile, or the rules are not loaded | check the group's `agent.conf` on the machine; `wazuh-analysisd -t` on the manager |
| Everything NOT_EVALUABLE by COLLECTION on one machine | no agent pass in the window | `/etc/cron.d/oscompliance`, run the agent by hand and read its error |
| Login evidences NOT_EVALUABLE by COLLECTION | the authentication log does not reach Wazuh: no 119002 alert | add the auth log (`/var/log/auth.log` or `/var/log/secure`) or journald to the agent's localfiles |
| op.acc.2 EV-06, op.acc.3, op.acc.4 EV-07 NOT_EVALUABLE by COLLECTION | auditd not running, watches not loaded, or the audit log not read | install auditd; check `auditctl -l`; the region adds the audit localfile |
| A control NOT_EVALUABLE by CONFIGURATION | a parameter is not set | the verdict names it; set it in Power ENS |
| Engine: 401 or 403 from the indexer | wrong password, or the role lacks a permission | `engine.env`; compare the role with `engine-role.yml`; the error names the action |
| Engine: 401 or 403 from the Wazuh API | wrong password, or the policy lacks an action | compare the policy with `engine-api-role.json` |
| Engine: certificate error | wrong CA, or the API certificate names another host | `-ca`, `-wazuh-api-ca`, `-wazuh-api-server-name` |
| Engine: HTTP 429 in the log | indexer under pressure | the engine retries; if frequent, raise the indexer heap or `-interval` |
| Group configuration not applied | `-sync-apply` missing, or the scope names no Wazuh group | the `group configuration` log line says which |
| The manager has no verdicts | the agent is not installed on it, or its `ossec.conf` lacks the facts localfile | [installation, section 4](install.md#4-the-manager-as-an-audited-machine) |
| A new machine shows nothing | it is not in the ENS group, or the first pass ran before it got the group configuration | add it to the group; run `oscompliance-agent -full` |

## Before installing on a machine

`oscompliance-doctor` ([arseniteio/oscompliance-agent-doctor-ens](https://github.com/arseniteio/oscompliance-agent-doctor-ens))
checks that auditd is installed and running, and that the Wazuh agent is
installed, enrolled and connected to the manager. It exits 0 when the machine
is ready and 1 with each problem otherwise.

## Capacity

| Fleet | Requests per pass | Engine pass |
|---|---|---|
| 1,000 agents | about 760 | 6 to 8 s |
| 10,000 agents | about 7,200 | 100 to 130 s |

Measured on a single-node lab indexer with a 1 GB heap.

Each agent sends about 115 facts per day in steady state, a small fraction of
what Wazuh's own modules send. Verdicts are written per pass; set an ISM
policy on `oscompliance-verdicts` to the retention the audit requires.

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
