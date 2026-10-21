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
catalog/
  docs/contracts/   per-control fact contracts
  docs/adr/         architecture decision records
  schemas/facts/    JSON schemas, one per fact type
  controls/         control definitions
agent/              Go module github.com/OpenSourceCompliance/oscompliance-core/agent
  cmd/oscompliance-agent/
  internal/controls/ens/opacc1/
  internal/source/  data sources (accounts, auth log, ...)
  internal/emit/    fact output
  internal/state/   offsets, cursors, snapshots
  internal/fact/    fact types
engine/
```

## Status

Pre-alpha. In progress: the op.acc.1 fact contract
(`catalog/docs/contracts/op.acc.1.md`). No code yet.

## Development

Requires Go 1.27. End-to-end testing uses
[wazuh-lab-docker](https://github.com/OpenSourceCompliance/wazuh-lab-docker).

## License

Not yet chosen.
