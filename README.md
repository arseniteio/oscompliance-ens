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
  internal/controls/ens/opacc1/   collectors
  internal/source/  data sources (accounts, auth log, ...)
  internal/emit/    fact output
  internal/state/   offsets, cursors, snapshots
engine/             Go module github.com/OpenSourceCompliance/oscompliance-core/engine
  cmd/oscompliance-engine/
  internal/controls/ens/opacc1/   judges
  internal/source/  facts read from wazuh-alerts-*
  internal/store/   verdicts index
  internal/params/  policy parameters from the plugin configuration
  internal/history/ per-account identity history (EV-08)
  internal/run/     one evaluation pass
```

## Status

Pre-alpha. op.acc.1 (EV-01 to EV-08) runs end to end on Linux: agent, Wazuh
rules, engine, verdicts. Contract: `catalog/docs/contracts/op.acc.1.md`.

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
