# Architecture

OSCompliance ENS measures the controls of the Esquema Nacional de Seguridad
(Real Decreto 311/2022, Annex II) on an existing Wazuh deployment. It adds two
binaries and five Wazuh rules. It does not replace any Wazuh component and
does not run its own collection channel, database or message bus.

On the audited machine, `oscompliance-agent` writes `facts.ndjson` and the
Wazuh agent ships it with the authentication and audit logs, FIM, SCA and
inventory. On the manager host, rules 119000-119004 index the facts. Every 15
minutes `oscompliance-engine` reads the indexer, writes verdicts back to it and
updates the group `agent.conf` through the Wazuh API. The Power ENS plugin in
the dashboard shows the verdicts.

## Components

`oscompliance-agent` runs on every audited Linux machine, the manager included. It reads local state and appends facts to `/var/log/oscompliance/facts.ndjson`. It does not judge, keeps no policy and opens no network connection.

The Wazuh agent ships that file with the authentication and audit logs, inventory, FIM and SCA. Nothing in it is specific to OSCompliance.

Wazuh rules 119000 to 119004 run on the manager. They index facts, the authentication probe, service events and audited accesses. They carry no verdict.

`oscompliance-engine` runs next to the indexer, usually on the manager host. It judges every evidence, requirement and control and writes the verdicts. It changes nothing on the audited machines except through the group configuration.

The Power ENS plugin runs in the Wazuh dashboard. It stores the organisation's parameters and shows verdicts and reports. It does not judge.

## Data flow

1. Collect. Cron runs the agent every hour, and the file system sweep once
   a day. Each collector reads one area (accounts, PAM, sshd, sudoers,
   listeners, packages, backups and others) and emits facts. A collector whose
   output did not change emits nothing; every fact is sent again at least
   every three days. Each pass ends with an `agent_pass` fact.
2. Ship. The Wazuh agent reads `facts.ndjson` as a JSON localfile. Rule
   119001 indexes every valid fact in `wazuh-alerts-*`. The rules accept a fact
   only from that file, so a local user cannot forge one through syslog.
3. Read. The engine reads, per pass: the facts of every machine in the
   window, Wazuh's own alerts (authentication, sudo, FIM, SCA, audit,
   antimalware, vulnerability detection), Wazuh's inventory
   (`wazuh-states-inventory-*`, `wazuh-states-vulnerabilities-*`), agent
   keepalives (`wazuh-monitoring-*`), the manager's configuration through the
   Wazuh API, DNS records for mail controls, and the parameters the plugin
   stores in `wazuh-ens-configuration`.
4. Judge. Each control's judge turns sources and parameters into one
   verdict per machine and evidence. Evidences add up to requirements and
   requirements to a control score ([verdicts](verdicts.md)).
5. Write. Verdicts go to `oscompliance-verdicts`; the per-account
   identity history to `oscompliance-identity-history`.
6. Configure. Some parameters name paths the agents must read or watch
   (ACL paths, audit watches, service logs, FIM directories). The engine
   writes them into a marked region of each ENS group's `agent.conf` through
   the Wazuh API, and records every change in `oscompliance-config-history`.
   Wazuh distributes the file to the agents.
7. Show. The plugin reads the latest pass of each machine and the last
   control verdict of each day, and renders reasons from their codes in the
   user's language.

## Design principles

- Agents emit facts, never verdicts. The machine being audited does not
  decide whether it complies. A compromised or misconfigured agent can stop
  reporting; it cannot report compliance.
- What cannot be proven does not comply. Missing data is
  NOT_EVALUABLE, and a requirement with a NOT_EVALUABLE evidence is
  NON_COMPLIANT, not evidenced. Silence is never read as compliance: a control
  that judges logins first proves that the authentication log reaches Wazuh.
- Wazuh first. If Wazuh already collects something (logins, FIM, SCA,
  inventory, vulnerabilities, auditd), the engine reads it from the index.
  The agent covers only what Wazuh does not see.
- One definition per control. `catalog/controls/ens/<control>.json` holds
  requirements, levels, evidences, parameters and report fields. The engine
  embeds it; the plugin vendors a copy and its tests fail on drift.
- Policy lives in one place. Agents hold paths only. Every policy value is
  a parameter in the plugin, read by the engine on every pass.
- Stateless judging. Each pass judges the current state from the index.
  Rerunning a pass gives the same verdicts.

## The manager is audited

The manager is a machine like any other and receives every control. It runs
the agent with its own `ossec.conf` reading `facts.ndjson`, and reads the
paths the engine writes from the `agent.conf` of an ENS group. Its inventory
and configuration come from the Wazuh API. Measures that the regulation
requires somewhere in the system, rather than on every machine, are judged
on the manager: when no machine holds them, the manager carries the failure.

## Scale

Measured with `oscompliance-fleetsim`, which loads a synthetic fleet into a Wazuh indexer and runs real passes. A pass over 1,000 agents makes about 760 requests and takes 6 to 8 seconds. A pass over 10,000 agents makes about 7,200 requests and takes 100 to 130 seconds.

The engine reads in chunks of 500 agents with composite aggregations, runs controls side by side, keeps at most four requests in flight and retries on HTTP 429. Cost grows linearly with the fleet. The default 15-minute interval leaves wide headroom at 10,000 agents.

On the agent side, a pass reads local files and runs a few commands
(`sshd -T`, `systemctl`, the package manager); unchanged collectors send
nothing. A steady machine sends about 115 facts per day.

## Repository layout

| Path | Holds |
|---|---|
| `catalog/controls/ens/` | control definitions |
| `catalog/schemas/facts/`, `catalog/fact/` | fact schemas and their Go types |
| `catalog/schemas/verdicts/` | verdict schema |
| `catalog/messages/` | reason texts, English and Spanish |
| `catalog/templates/`, `catalog/system-types.json` | built-in parameter values per system type |
| `catalog/wazuh/` | rules, agent.conf fragment, indexer and API roles |
| `agent/` | `oscompliance-agent` and its collectors |
| `engine/` | `oscompliance-engine`, sources, judges, aggregation, group configuration; `oscompliance-fleetsim` |
| `docs/` | this documentation, in `en/` and `es/` |
| `ci/`, `.github/workflows/` | packaging and CI |

## Adding a control

1. `catalog/`: the control definition, fact schemas and Go types, reason
   messages in both languages, templates.
2. `agent/`: collectors for what Wazuh does not already collect.
3. `engine/internal/controls/ens/<control>`: the judge, with tests.
4. `docs/en/controls/<control>.md` and `docs/es/controls/<control>.md`: the page, with the sections every control has.
5. power-ens: `npx tsx config/sync-catalog.ts` to vendor the catalog.
6. Lab: facts arrive, the engine writes verdicts, the plugin shows them.
