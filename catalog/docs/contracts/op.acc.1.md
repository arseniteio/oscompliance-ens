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

Data: [`controls/ens/op.acc.1.json`](../../controls/ens/op.acc.1.json),
generated from the plugin catalog. Levels decide applicability (section 7).

| Evidence | Requirements | Levels | Judged from |
|---|---|---|---|
| EV-01 Account inventory, unique UIDs | 1.3, 1.4, r1.2, r1.3 | all | identity pass, P-10 |
| EV-02 Identity changes recorded | 1.3, 1.4 | all | identity passes (current and previous) |
| EV-03 No generic account logins | 1.1, 1.3 | all | Wazuh login alerts, P-04 |
| EV-04 Offboarded accounts disabled in time | 1.4 | all | identity pass, P-05, P-09, P-10 |
| EV-05 No service account logins | 1.2, 1.3 | all | Wazuh login alerts, P-03 |
| EV-06 One identity per role | 1.2, r1.2 | all | group pass, identity pass, logins, P-11, P-12 |
| EV-07 Active accounts authorized | r1.3 | MEDIO, ALTO | identity pass, P-07, P-10 |
| EV-08 Accounts retained before deletion | 1.4 | all | identity history, P-06, P-09, P-10 |

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
evidences and the engine judges them. The agent keeps no state between passes.

## 5. Fact catalogue

Examples in [`examples/`](../../schemas/facts/examples/). Every snapshot fact
is emitted after the records of its `run_id`, even when its source could not
be read, and carries `records_emitted` so the engine can tell a complete pass.

### `identity_record` and `identity_snapshot`

Schemas: [`identity_record.v1.json`](../../schemas/facts/identity_record.v1.json),
[`identity_snapshot.v1.json`](../../schemas/facts/identity_snapshot.v1.json).

One `identity_record` per entry of `passwd`, at any UID, joined with its
`shadow` entry: `account_name`, `uid`, `gid`, `shell`, `password_state`
(`set`, `locked`, `empty`, `missing`, `other`), `account_expires` (date,
optional), `authorized_keys` (how many public keys sshd would accept; absent
when it cannot be known). Never a password hash nor a key.

| `identity_snapshot` field | When | Meaning |
|---|---|---|
| `passwd_path`, `passwd_status` | always | `read`, `unreadable`, `implausible` (no UID 0 entry). |
| `passwd_error` | not `read` | Why. |
| `shadow_path`, `shadow_status` | always | `read`, `unreadable`. |
| `shadow_error` | not `read` | Why. |
| `records_emitted` | both `read` | `identity_record` facts in this `run_id`. |
| `sshd_status` | always | `read` (from `sshd -T`), `absent` (no sshd: 0 keys for everyone), `command` (an `AuthorizedKeysCommand` decides: keys unknown), `error`. |
| `sshd_error` | `error` | Why. |
| `authorized_keys_files` | `read` | Global `AuthorizedKeysFile` patterns. Each account's count uses `sshd -T -C user=<account>,host=localhost,addr=127.0.0.1`: `Match User` and `Match Group` apply exactly, `Match Address` and `Match Host` as for a local connection. |

Replaces v1 `account_active`, `account_inventory`, `account_created`,
`account_modified` and `account_deleted`. The agent applies no UID threshold
and emits no changes: it reports the whole identity table on every pass and
the engine applies P-10 and compares passes. A lost or corrupt baseline on
the host can no longer hide or invent changes.

### `group_record` and `group_snapshot`

Schemas: [`group_record.v1.json`](../../schemas/facts/group_record.v1.json),
[`group_snapshot.v1.json`](../../schemas/facts/group_snapshot.v1.json).
One `group_record` per line of the group file (`group_name`, `gid`,
`members`), then one `group_snapshot` (`group_path`, `group_status` `read`,
`unreadable` or `implausible` (no GID 0), `group_error`, `records_emitted`).

Replaces v1 `multi_role_inventory`, `multi_role_account`, `multi_role_usage`
and `privilege_use`: the agent no longer knows which groups grant privilege
nor the admin suffix; P-11 and P-12 are applied by the engine.

### Wazuh login alerts (EV-03, EV-05, EV-06)

No fact of ours. Wazuh collects the authentication log and its own decoders
and rules produce the alerts the engine reads:

| What | Query on `wazuh-alerts-*` | Fields used |
|---|---|---|
| sshd login | `rule.groups: authentication_success`, `decoder.parent: sshd` (rule 5715 and children) | `data.dstuser`, `data.srcip` |
| Console, su and graphical login | `rule.groups: authentication_success`, `decoder.parent: pam`, `predecoder.program_name` in `login`, `su`, `gdm-password`, `lightdm`, `sddm` (rule 5501) | `data.dstuser` |
| Authentication log reaches Wazuh | `rule.groups` in `authentication_success`, `authentication_failed`, `sudo`, in the lookback | `agent.id` |

The PAM session of sshd is not counted (5715 already is) nor `sudo` (privilege
use, not a login). Replaces v1 `account_authenticated`, which only saw sshd:
the agent keeps no offset or cursor and parses no log.

## 6. Parameters

Agent parameters are paths only; every policy parameter lives in the plugin's
configuration (`wazuh-ens-configuration`, document `ACTIVE_CONFIGURATION`)
and the engine reloads it every pass.

| Parameter | Owner | Default | Use |
|---|---|---|---|
| `passwd_path` | agent | `/etc/passwd` | Identity facts, groups (admin accounts). |
| `shadow_path` | agent | `/etc/shadow` | Identity facts. |
| `sshd_path` | agent | `/usr/sbin/sshd` | `sshd -T` for key files. |
| `group_path` | agent | `/etc/group` | Group facts. |
| P-03 `cuentas_servicio_definidas` | plugin, platform | template | EV-05. List or regex. |
| P-04 `cuentas_genericas_prohibidas` | plugin, organisation | none | EV-03. List or regex. |
| P-05 `plazo_max_deshabilitar_dias` | plugin, organisation | none | EV-04. Number. |
| P-06 `periodo_retencion_cuentas_dias` | plugin, organisation | none | EV-08. Number. |
| P-07 `lista_usuarios_autorizados` | plugin, system | none | EV-07. Table `usuario \| sistema \| rol`; only `usuario` is compared. |
| P-09 `bajas_declaradas` | plugin, organisation | none | EV-04, EV-08. Table `usuario \| fecha_baja` (YYYY-MM-DD); an unreadable row is a configuration error. Replaces v1 `bajas.tsv` on the host. |
| P-10 `uid_minimo_persona` | plugin, platform | template, else 1000 (product default) | EV-01, EV-04, EV-07, EV-08. Replaces the agent's v1 `OPACC1_UID_MIN`. |
| P-11 `grupos_privilegiados` | plugin, platform | template, else `sudo, wheel, admin` (product default, said in the reason) | EV-06. List. |
| P-12 `sufijo_admin` | plugin, organisation | none: nobody is excluded | EV-06. First entry. |

Resolution, as the plugin's `configuration-resolver.ts`, with the classes of
[`controls/ens/op.acc.1.json`](../../controls/ens/op.acc.1.json):

1. `organisation`: the control's common value only; an agent value is
   ignored.
2. `system` and `platform`: the agent's own value; else its template (the
   assigned one, built-in from [`templates/`](../../templates/) or custom
   from the configuration; `none` disables it; with none assigned or found,
   the built-in default of its system type, `typeOverride` before
   `detectedType`); else the common value.
3. The match mode (`regex`) is the one stored with the value, at its level.
   A regex is RE2 (Go `regexp`, the plugin's engine), matches the whole name,
   at most 512 characters, case-sensitive; a list compares ignoring case.
   Parameters that take no regex reject one with `CONFIGURATION`.

Union parameters (read whole across agents) do not occur in op.acc.1.

## 7. Evidence judgement

Before any judgement, applicability: with `global.ensLevel` set, an evidence
whose levels do not include it is `NOT_APPLICABLE` (EV-07 at BAJO); a control
with `enabled: false` gives `NOT_APPLICABLE` for all its evidences. Without a
level nothing is ruled out. The engine decides it, not the plugin.

Shared checks:

- Identity pass usable: the newest `identity_snapshot` in the window exists,
  both files `read`, `records_emitted` present (else `EVIDENCE`), and at least
  that many `identity_record` received for its `run_id` (more is fine: Wazuh
  can deliver a line twice). Otherwise `NOT_EVALUABLE`, cause `COLLECTION`.
- A parameter missing or unusable gives `NOT_EVALUABLE`, cause
  `CONFIGURATION`. Never a default the auditor did not set, except P-10 and
  P-11 where the plugin itself documents a product default.
- Disabled account: no-login shell, expired, or no usable password (`locked`
  or `missing`) and `authorized_keys` = 0. Unknown when the password is
  unusable and `authorized_keys` is absent. v1 counted a locked password with
  keys as disabled, though sshd still accepts the key. Active: UID >= P-10 and
  not disabled.

**EV-01**: identity pass usable and P-10 usable; a UID held by more than one
entry, at any UID (as v1): `NON_COMPLIANT`; otherwise `COMPLIANT`.

**EV-02**: identity pass usable; then `COMPLIANT`, with the changes against
the newest complete earlier pass (up to 10 tried) in the reason: created,
deleted, modified (any field of `identity_record`, compared by value). With
no earlier pass, the reason says the current one is the baseline. As v1, the
evidence fails only when collection fails.

**EV-03, EV-05**: the logins in the window against P-04 (generic) or P-03
(service). List unusable: `CONFIGURATION`. No authentication event in the
lookback: `NOT_EVALUABLE`, `COLLECTION` (silence from a log that does not
reach Wazuh is not compliance). A login whose account matches:
`NON_COMPLIANT`, each account with its count. Otherwise `COMPLIANT`, with the
logins by method.

**EV-04**: identity pass usable, P-05, P-09, P-10 usable. An account with UID
>= P-10 and an offboarding date (its P-09 row, else its `account_expires`)
not disabled more than P-05 days after it: `NON_COMPLIANT`; if only its keys
could tell and they are unknown: `NOT_EVALUABLE`, `EVIDENCE`. No date at all
and P-09 empty: `NOT_EVALUABLE`, `CONFIGURATION`. Otherwise `COMPLIANT`; a
declared account that no longer exists counts as handled.

**EV-06**: group pass usable (as the identity pass), identity table for admin
accounts, P-11 and P-12 usable. A member of a P-11 group, not itself named
`<x><suffix>`, with no `<member><suffix>` account, or a login by such a
member: `NON_COMPLIANT` (as v1). No finding and no authentication event in
the lookback: `NOT_EVALUABLE`, `COLLECTION`; v1 gave that whenever its auth
source failed, v2 keeps a structural finding. Otherwise `COMPLIANT`.

**EV-07**: identity pass usable, P-07 (`usuario` column) and P-10 usable. An
active account not in P-07, compared literally and with case as the plugin:
`NON_COMPLIANT`. Not listed and state unknown: `NOT_EVALUABLE`, `EVIDENCE`.
Otherwise `COMPLIANT`. v1 called active any account with a login shell.

**EV-08**: over the per-account history the engine keeps in
`oscompliance-identity-history` (one document per agent and account:
`first_seen`, `last_seen`, `disabled_since`, `disabled_observed`,
`state_unknown`, `deleted_at`, last `account_expires`), moved forward by each
complete current identity pass; applying a pass twice changes nothing. It
replaces v1 `deshabilitadas.tsv` on the host. P-06, P-09, P-10 unusable:
`CONFIGURATION`; no complete current pass: `COLLECTION`. An account with UID
>= P-10 deleted in the window less than P-06 days after its start date (P-09
row, else last expiry, else the observed day it was disabled), or deleted
while still enabled (zero days; v1 did not track these): `NON_COMPLIANT`.
Deleted with no start date or with its last state unknown: `NOT_EVALUABLE`,
`EVIDENCE`. Otherwise `COMPLIANT`.

Verdicts follow [`verdict.v1.json`](../../schemas/verdicts/verdict.v1.json)
in `oscompliance-verdicts`, one per agent, evidence and pass (judging the same
pass again replaces it). Status values in English; v1 equivalents:
`COMPLIANT` = `CUMPLE`, `NON_COMPLIANT` = `NO_CUMPLE`, `NOT_EVALUABLE` =
`NO_EVALUABLE`, `NOT_APPLICABLE` = `NO_APLICA`. Causes keep their v1 names.

Engine parameters: `window` 26 h (v1 `OPACC1_VENTANA_HORAS`), `lookback` 7
days (agents with facts this recent are judged even when the window is
empty). Records of a pass are matched by `run_id`, not by the window.

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
- Scalars arrive as strings: `"1000"`, `"true"`. Arrays keep their JSON
  types. The engine converts scalars back using the Go fact types.
- Wazuh renames static field names (`user` became `dstuser`); hence
  `account_name`. The envelope schema lists the names to avoid.
- A line with the envelope but an invalid `fact` or `run_id` stops at 119000
  and is not indexed.

## 9. Parity and migration

Checked in `wazuh-lab-docker` on 2026-10-21 for EV-01: v1 (`collect.sh` +
`score.py`) and v2 over the same `passwd`, verdicts read from the index.

| Case | v1 | v2 |
|---|---|---|
| Normal `passwd` | `CUMPLE` | `COMPLIANT` |
| Two accounts with UID 1001 | `NO_CUMPLE` | `NON_COMPLIANT`, names both accounts |
| No UID 0 entry | `NO_EVALUABLE` `COLLECTION` | `NOT_EVALUABLE` `COLLECTION` |
| Missing file | `NO_EVALUABLE` `COLLECTION` | `NOT_EVALUABLE` `COLLECTION` |
| Normal again, right after the duplicate | `NO_CUMPLE` | `COMPLIANT` |

v1 keeps any non-compliant fact for the whole window (26 h); v2 judges the
current state and keeps earlier verdicts as history (decided 2026-10-21).

Deliberate differences with v1, each decided on 2026-10-22: a locked password
with SSH keys is not disabled; EV-07 counts active accounts by that
definition, not by shell; EV-08 counts accounts deleted while enabled; EV-03,
EV-05 and EV-06 also see console, su and graphical logins; the engine
decides `NOT_APPLICABLE` by level; templates and parameter classes are
applied as the plugin does.

## 10. Open decisions

- The plugin still reads its own copy of the templates and evidence levels
  (TypeScript). It should read `controls/` and `templates/` when it is
  changed.
- Showing identity changes in the plugin: from the EV-02 verdict reason or
  from `oscompliance-identity-history`.
