# Control pipeline

How one ENS control goes from its definition to the screen. Every control the plugin shows follows this
path; a control that skips a step is not finished.

```
catalog ──► agent ──► Wazuh ──► engine ──► oscompliance-verdicts ──► power-ens
   ▲                              │
   └────── power-ens configuration (wazuh-ens-configuration)
```

## 1. Catalog (`catalog/`)

The single definition of the control. Nothing else defines it.

| File | Holds |
| --- | --- |
| `controls/ens/<control>.json` | Requirements, levels, evidences, parameters with their class (`organisation`, `system`, `platform`), types, columns and patterns |
| `docs/contracts/<control>.md` | What each evidence reads and when it passes |
| `schemas/facts/` and `fact/` | The facts the agent emits for it |
| `messages/{en,es}.json` | The text of every reason the engine writes, by code |
| `templates/*.json` | Built-in values per system type |
| `wazuh/oscompliance_facts_rules.xml` | Rules 119000-119004 that turn facts into alerts |

## 2. Agent (`agent/`)

`oscompliance-agent` runs on the machine, collects what the contract asks and appends facts to
`/var/log/oscompliance/facts.ndjson`. It holds no policy: the paths it reads come from the group
configuration the engine writes (step 4).

## 3. Wazuh

The group `agent.conf` reads `facts.ndjson` (`log_format json`) and the audit log. Rule 119001 indexes each
fact in `wazuh-alerts-*`. Authentication events come from Wazuh's own rules (sshd 5715 and others).

## 4. Engine (`engine/`)

`oscompliance-engine` runs next to the indexer, every `-interval`:

1. Reads the active configuration from `wazuh-ens-configuration` and resolves each parameter per machine:
   own value, assigned template, built-in template of its type, common value.
2. Reads the facts of each machine in the window, and the inventory from `wazuh-monitoring-*`.
3. Judges every evidence, requirement and control and writes the verdicts to `oscompliance-verdicts`
   (one document per scope, `reason_code` and `reason_args` for the text).
4. Keeps the group `agent.conf` in line with the parameters (`-wazuh-api`, `-sync-apply`), recording every
   change in `oscompliance-config-history`.

## 5. Plugin (`power-ens`)

The plugin judges nothing.

- Its catalog is a copy of step 1 (`config/sync-catalog.ts`; `tests/catalog/engine-catalog.test.ts` fails on
  any drift).
- Configuración writes the parameters the engine reads (step 4.1).
- Every screen and report is built from the latest pass of each machine in `oscompliance-verdicts`, and
  the daily series from the last control verdict of each day. Reasons are rendered from `reason_code`.

## Adding a control

1. Catalog entry, contract, fact schemas, messages and templates in `catalog/`.
2. Collectors in `agent/`, judge in `engine/internal/controls/ens/<control>`.
3. `npx tsx config/sync-catalog.ts` in power-ens, plus its report model in `public/ens/reports/`.
4. Lab: facts arrive, the engine writes verdicts, the plugin shows them.
