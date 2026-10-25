# oscompliance-core

Compliance agent, engine and catalog for OS Compliance. First framework: ENS
(Spain, RD 311/2022).

## Architecture

| Component | Location | Role |
|---|---|---|
| Agent | `agent/` | Runs on the audited host. Observes and emits facts to Wazuh. Never judges compliance. |
| Engine | `engine/` | Runs server-side. Reads facts, applies the policy parameters, writes evidence, requirement and control verdicts to an index. |
| Plugin | separate repository | Wazuh dashboard plugin. Displays verdicts, edits policy parameters, produces reports. Never evaluates. |
| Catalog | `catalog/` | Single source of truth: controls, requirements, evidences, facts, parameters, schemas. |

Data flow: agent → Wazuh → engine → state index → plugin.

## Layout

```
catalog/            Go module .../catalog: embeds controls/ and templates/
  docs/contracts/   per-control fact contracts
  docs/adr/         architecture decision records
  schemas/facts/    JSON schemas, one per fact type, with examples
  schemas/verdicts/ JSON schema of the verdicts index
  fact/             fact types shared by agent and engine; its tests validate
                    the schemas
  wazuh/            manager side: <localfile> fragment and generic fact rules
  controls/ens/     per control: evidences with levels and requirements,
                    parameter classes
  templates/        built-in parameter templates by system type
agent/              Go module github.com/OpenSourceCompliance/oscompliance-core/agent
  cmd/oscompliance-agent/
  internal/controls/ens/opacc1/, opacc2/   collectors of those controls
  internal/sysconf/ configuration, PAM, sockets, ACLs, audit watches, the
                    Wazuh agent's own configuration, shared by every control
  internal/emit/    fact output (the agent keeps no state between passes)
engine/             Go module github.com/OpenSourceCompliance/oscompliance-core/engine
  cmd/oscompliance-engine/
  internal/controls/ens/opacc1/ ... opacc6/   judges, one package per control
  internal/source/  facts read from wazuh-alerts-*
  internal/store/   verdicts index
  internal/params/  policy parameters from the plugin configuration
  internal/history/ per-account identity history (EV-08)
  internal/run/     one evaluation pass
```

## Status

Pre-alpha. op.acc.1 to op.acc.6 run end to end on Linux: agent, Wazuh rules,
engine, verdicts. Contracts: `catalog/docs/contracts/`. Pending work:
`docs/roadmap.md`.

## Prerequisites

On every audited machine (the manager included):

| Requirement | Why |
|---|---|
| Linux, root | The agent reads shadow, sudoers, /proc and every file system. |
| Wazuh agent 4.x, enrolled in a group | It ships the facts and the logs; the group's shared configuration carries the paths that come from parameters. |
| auditd, running | op.acc.2 EV-06, op.acc.3 and op.acc.4 EV-04 and EV-07 judge audited accesses. The agent loads its own watches and rules; Wazuh reads `/var/log/audit/audit.log` (localfile with `log_format audit`). Without it those evidences are NOT_EVALUABLE by COLLECTION. |
| An authentication log Wazuh reads (auth.log or journald) | Logins, failures, sudo and su come from Wazuh's own rules. |
| systemd (optional) | Whether a listening service starts at boot (op.acc.6 EV-08). |

On the manager: the rules of `catalog/wazuh/oscompliance_facts_rules.xml`
(119000-119004) and the facts `<localfile>` of
`catalog/wazuh/agent.conf.fragment.xml` in each group.

## Development

Requires Go 1.27. Each module has its own `go.mod`; agent and engine import
`catalog` through a `replace` directive.

```bash
make check   # gofmt, go vet and go test on every module, schemas included
```

End-to-end testing uses
[wazuh-lab-docker](https://github.com/OpenSourceCompliance/wazuh-lab-docker),
which builds both binaries from this repository.

## License

Not yet chosen.
