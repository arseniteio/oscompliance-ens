# op.acc.1 fact contract

## 1. Vocabulary

## 2. Current facts inventory

Source: runbook `op.acc.1-identification` (v1, bash) and its manager rules
`ensfacil_op_acc_1_json_rules.xml`. Lab counts: `wazuh-lab-docker`, one Ubuntu
24.04 agent, 2026-10-21.

Every line carries the envelope `ensfacil`, `event`, `ts`, `host`. Lines from
`score.py` and the watchdog also carry `emisor`.

Type: **fact** = observation only; **verdict** = carries a compliance judgement;
**diagnostic** = about the collection itself. Verdict fields are the ones the
agent should stop emitting.

| Event | Emitter | Evidences | Payload fields | Verdict fields | Rule | Type | Lab |
|---|---|---|---|---|---|---|---|
| `account_active` | lib | EV-01, EV-07 | `usuario`, `uid`, `tipo`, `requisito` | `estado` (always CUMPLE), `nivel` | 106811 | fact | 12 |
| `account_inventory` | lib | EV-01 | `total_cuentas`, `uids_duplicados`, `fuente`, `requisito` | `estado` (NO_CUMPLE if duplicates), `nivel` | 106809, 106810 | fact + verdict | 4 |
| `account_created` | lib | EV-02 | `usuario`, `requisito` | `estado` (always CUMPLE), `nivel` | 106812 | fact | 0 |
| `account_modified` | lib | EV-02 | `usuario`, `antes`, `despues`, `requisito` | `estado` (always CUMPLE), `nivel` | 106813 | fact | 0 |
| `account_deleted` | lib | EV-02, EV-08 | `usuario`, `dias_retenida`, `requisito` | `estado`, `nivel`, `retencion_min` | 106818 | fact + verdict | 0 |
| `account_authenticated` | lib | EV-03, EV-05 | `usuario`, `origen`, `requisito` | none | 106873 | fact | 0 |
| `account_disabled` | lib | EV-04 | `usuario`, `dias_desde_baja`, `requisito` | `estado`, `nivel`, `plazo_max` | 106815 | verdict | 0 |
| `account_offboarding` | lib | EV-04 | `usuario`, `dias_desde_baja`, `requisito` | `estado` (vs `plazo_max`), `nivel`, `plazo_max` | 106816, 106817 | verdict | 0 |
| `retention_violation` | lib | EV-08 | `usuario`, `dias_retenida`, `requisito` | `estado` (NO_CUMPLE), `nivel`, `retencion_min` | 106819 | verdict | 0 |
| `multi_role_inventory` | lib | EV-06 | `grupos`, `sufijo`, `requisito` | `nivel` | none | fact | 0 |
| `multi_role_account` | lib | EV-06 | `usuario`, `grupo`, `motivo`, `requisito` | `estado` (NO_CUMPLE), `nivel` | none | verdict | 0 |
| `multi_role_usage` | lib | EV-06 | `usuario`, `origen`, `motivo`, `requisito` | `estado` (NO_CUMPLE), `nivel` | 106807 | verdict | 0 |
| `privilege_use` | lib | EV-06 | `usuario`, `comando`, `privilegio`, `requisito` | `estado` (always CUMPLE), `nivel` | 106808 | fact | 0 |
| `evidence_state` | lib, score.py, watchdog | EV-01, 02, 04, 06, 08 | `evidence_id`, `requisito`, `motivo`, `causa` | `estado`, `nivel` | 106850–106853 | verdict | 18 |
| `control_state` | score.py | per requirement | `control`, `evidencias`, `delegadas`, `motivo` | `estado`, `nivel`, `no_evidenciado`, `sin_evidencia` | 106860–106863, 106869 | verdict | 16 |
| `score_snapshot` | score.py | all | `control`, `lineas_corruptas`, `requisitos_aplicables`, `requisitos_medidos`, `requisitos_sin_medir`, `requisitos_delegados`, `motivo`, `config_ajuste` | `estado`, `nivel`, `score` | 106870–106872, 106890 | verdict | 6 |
| `collector_run` | collect.sh | none | `version`, `resultado`, `evidencias_emitidas`, `evidencias_cubiertas` | none | 106891 | diagnostic | 4 |
| `collector_warning` | collect.sh, lib | none | `parametro`, `valor`, `motivo`, `rc` | none | 106830 | diagnostic | 4 |
| `collector_missing` | watchdog | all | `control`, `detalle`, `ventana_horas`, `ventana_configurada_horas`, `config_ajuste` | `estado` (NO_CUMPLE), `nivel` | 106831 | diagnostic + verdict | 0 |

Findings:

- `multi_role_inventory` and `multi_role_account` have no rule: they only match
  the level-0 base rule 106800 and never reach the index.
- Rules with no emitter in v1: 106801 `generic_account_login`, 106802
  `auth_success`, 106805 `service_account_interactive`, 106806
  `interactive_login`, 106824/106825 `authorized_list_check`, 106826
  `unauthorized_user`.
- `account_authenticated` is the only fact with no verdict field.
- Lab gaps: no authentication source in the container, so EV-03, EV-05 and
  EV-06 emit nothing; no `bajas.tsv`, so EV-04 is `NO_EVALUABLE`
  (CONFIGURATION).

## 3. Requirements and evidences

## 4. Envelope v2

Schema: [`envelope.v1.json`](../../schemas/facts/envelope.v1.json). The file
version tracks the schema; this section keeps the name "v2" to set it apart
from the v1 runbook envelope.

| Field | Type | Meaning |
|---|---|---|
| `oscompliance` | `"1"` | Envelope version and decoder marker. Replaces `ensfacil`. |
| `fact` | string | Fact type. Replaces `event`. |
| `ts` | RFC 3339, UTC, `Z` | Observation time. |
| `host` | string | Observed system. |
| `agent_version` | string | Emitting agent version. |
| `run_id` | UUID | One collection pass. Replaces the `collector_run` heartbeat. |

Payload fields sit at the top level, next to the envelope. A fact carries no
`estado`, `nivel`, `evidence_id` or `requisito`: the catalog maps facts to
evidences and the engine judges them.

## 5. Fact catalogue

EV-01 and EV-02 are defined so far. Examples in
[`examples/`](../../schemas/facts/examples/).

### `account_record`

Schema: [`account_record.v1.json`](../../schemas/facts/account_record.v1.json).
One per local account with `uid >= uid_min`, any shell. Fields: `account_name`, `uid`,
`gid`, `shell`, `login_enabled`. `login_enabled` is false when the shell ends in
`/nologin` or `/false`; an empty shell counts as enabled.

Differences with v1 `account_active`: accounts without login are emitted too,
flagged by `login_enabled`; `tipo=persona` is dropped (classification belongs
to the engine).

### `account_inventory_snapshot`

Schema: [`account_inventory_snapshot.v1.json`](../../schemas/facts/account_inventory_snapshot.v1.json).
One per pass, emitted after every `account_record` of the same `run_id`.

| Field | When | Meaning |
|---|---|---|
| `source`, `source_path` | always | Account database read (`passwd`). |
| `source_status` | always | `read`, `unreadable`, `implausible` (no UID 0 entry). |
| `source_error` | not `read` | Why the read failed. |
| `uid_min` | always | Threshold applied to `account_record`. |
| `entries_total` | `read` | Entries with a numeric UID, any UID. |
| `records_emitted` | `read` | `account_record` facts in this `run_id`. |
| `duplicate_uids` | `read` | `[{uid, account_names[]}]` over all entries; empty when none. |

Differences with v1 `account_inventory`: no `estado`; the unreadable and
implausible cases are a fact instead of an `evidence_state`; duplicates carry
the users that share each UID; `records_emitted` lets the engine detect an
incomplete pass.

### `identity_record` (EV-02)

Schema: [`identity_record.v1.json`](../../schemas/facts/identity_record.v1.json).
One per entry of `passwd`, at any UID, joined with its `shadow` entry. Fields:
`account_name`, `uid`, `gid`, `shell`, `password_state` (`set`, `locked`,
`empty`, `missing`, `other`), `account_expires` (date, optional). Never a
password hash.

### `identity_snapshot` (EV-02)

Schema: [`identity_snapshot.v1.json`](../../schemas/facts/identity_snapshot.v1.json).
One per pass, after every `identity_record` of the same `run_id`.

| Field | When | Meaning |
|---|---|---|
| `passwd_path`, `passwd_status` | always | `read`, `unreadable`, `implausible`. |
| `passwd_error` | not `read` | Why. |
| `shadow_path`, `shadow_status` | always | `read`, `unreadable`. |
| `shadow_error` | not `read` | Why. |
| `records_emitted` | both `read` | `identity_record` facts in this `run_id`. |

Differences with v1 `account_created`, `account_modified`, `account_deleted`:
the agent keeps no baseline and emits no changes. It reports the whole identity
table on every pass and the engine compares two passes. A lost or corrupt
baseline on the host can no longer hide or invent changes, and a reinstalled
agent needs no first pass to set one.

## 6. Parameters

| Parameter | Owner | Default | Use |
|---|---|---|---|
| `uid_min` | agent | 1000 | Lowest UID emitted as `account_record`. Reported in the snapshot. |
| `passwd_path` | agent | `/etc/passwd` | Source path. Reported as `source_path` (EV-01) and `passwd_path` (EV-02). |
| `shadow_path` | agent | `/etc/shadow` | EV-02. Reported as `shadow_path`. |

## 7. Evidence judgement

EV-01, as the engine must compute it to match v1 (`score.py`), over the latest
`account_inventory_snapshot` per host in the window:

1. No snapshot: `NO_EVALUABLE`, cause `COLLECTION`.
2. `source_status` is not `read`: `NO_EVALUABLE`, cause `COLLECTION`, reason
   `source_error`.
   A read snapshot without `records_emitted` breaks the schema:
   `NOT_EVALUABLE`, cause `EVIDENCE`.
3. Fewer `account_record` received for that `run_id` than `records_emitted`:
   `NO_EVALUABLE`, cause `COLLECTION`. New in v2.
4. `duplicate_uids` not empty: `NO_CUMPLE`.
5. Otherwise: `CUMPLE`.

Active accounts for EV-01 and EV-07 are the `account_record` with
`login_enabled = true`.

EV-02 over the latest `identity_snapshot` per host in the window (the
current pass) and the newest complete pass before it (the previous pass: both
files read, every record received; up to 10 earlier passes are tried):

1. No snapshot: `NOT_EVALUABLE`, cause `COLLECTION`.
2. `passwd_status` or `shadow_status` is not `read`: `NOT_EVALUABLE`, cause
   `COLLECTION`, reason the error.
   Both read but no `records_emitted`: `NOT_EVALUABLE`, cause `EVIDENCE`.
3. Fewer `identity_record` received than `records_emitted`: `NOT_EVALUABLE`,
   cause `COLLECTION`.
4. Otherwise `COMPLIANT`: identity changes are being recorded. The reason
   lists what changed against the previous pass, by `account_name`: created,
   deleted, and modified (any field of `identity_record` differs). With no
   previous pass in the lookback, the reason says the current pass is the
   baseline.

Same result as v1, where the change facts are always `CUMPLE` and the evidence
fails only when collection fails. The change list itself is what EV-08
(retention) and the plugin will read; where it is stored is open (section 10).

Verdicts follow [`verdict.v1.json`](../../schemas/verdicts/verdict.v1.json)
and go to the `oscompliance-verdicts` index. Status values are in English; v1
equivalents: `COMPLIANT` = `CUMPLE`, `NON_COMPLIANT` = `NO_CUMPLE`,
`NOT_EVALUABLE` = `NO_EVALUABLE`. Causes keep their v1 names.

Engine parameters: `window` 26 h (v1 `OPACC1_VENTANA_HORAS`), `lookback` 7
days (agents with facts this recent are judged even when the window is empty).
Records of a pass are matched by `run_id`, not by the window.

## 8. Wazuh rules

Files: [`catalog/wazuh/`](../../wazuh/). Installed on the manager only; the
agent runs and writes, nothing else.

- `agent.conf.fragment.xml`: one `<localfile>` (`log_format json`,
  `/var/log/oscompliance/facts.ndjson`) for every control, delivered through
  the group `agent.conf`.
- `oscompliance_facts_rules.xml`, range 119000-119099, apart from v1
  (106800-106899) and from every band the plugin uses or reserves (up to
  112899; 112000-112099 is mp.eq.4). 119000 matches the envelope at level 0;
  119001 matches any fact with a valid `fact` and `run_id` at level 3, so it
  is indexed. A new fact type needs no new rule.

What the engine reads from `wazuh-alerts-*` (`rule.id: 119001`), checked in
the lab:

- Every payload field sits under `data.`.
- Scalars arrive as strings: `"1000"`, `"true"`. Arrays of objects
  (`duplicate_uids`) keep their JSON types. The engine converts scalars back
  using the schemas.
- Wazuh renames static field names (`user` became `dstuser`); hence
  `account_name`. The envelope schema lists the names to avoid.
- A line with the envelope but an invalid `fact` or `run_id` stops at 119000
  and is not indexed.


## 9. Parity and migration

EV-01, checked in `wazuh-lab-docker` on 2026-10-21: v1 (`collect.sh` +
`score.py`) and v2 (agent + engine) run over the same `passwd`, verdicts read
from the index.

| Case | v1 | v2 |
|---|---|---|
| Normal `passwd` | `CUMPLE` | `COMPLIANT` |
| Two accounts with UID 1001 | `NO_CUMPLE` | `NON_COMPLIANT`, names both accounts |
| No UID 0 entry | `NO_EVALUABLE` `COLLECTION` | `NOT_EVALUABLE` `COLLECTION` |
| Missing file | `NO_EVALUABLE` `COLLECTION` | `NOT_EVALUABLE` `COLLECTION` |
| Normal again, right after the duplicate | `NO_CUMPLE` | `COMPLIANT` |

Divergence in the last row: v1 rule 2 keeps any non-compliant fact for the
whole window (26 h), so a fixed duplicate stays `NO_CUMPLE` until it ages out.
v2 judges the latest pass only; the earlier `NON_COMPLIANT` verdict stays in
`oscompliance-verdicts` as history. Decided 2026-10-21: v2 keeps judging the
current state.


## 10. Open decisions

- EV-02 changes: only in the verdict reason, or also as documents of their own
  (one per change) that EV-08 and the plugin can query.


