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

## 5. Fact catalogue

## 6. Parameters

## 7. Evidence judgement

## 8. Wazuh rules

## 9. Parity and migration

## 10. Open decisions
