# op.mon.1 Detección de intrusión

op.mon.1 (intrusion detection) judges the Wazuh manager as the intrusion
detection system: whether it runs and loads rules, whether those rules
cover the risk analysis, are current and silenced only with approval,
whether each machine is under it and produces detections, and whether the
network detection the risk analysis asks for reaches it.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.7.1. Definition: [`catalog/controls/ens/op.mon.1.json`](../../catalog/controls/ens/op.mon.1.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 1.1 detection tools | B/M/A | EV-01 to EV-05 |
| r1.1 rule based detection | M/A | EV-01, EV-08 |
| r2.1 alert response procedures | A | attestation (P-ATT) |
| r3.1 automatic actions | none | EV-07 |

## Sources

| Source | Content | Used by |
|---|---|---|
| Wazuh API `/manager/status` | manager processes | EV-01 |
| Wazuh API `/rules?status=enabled` | loaded rules: id, level, file, directory | EV-01, EV-04, EV-08 |
| Wazuh API `/manager/configuration` | `ruleset` (rule_exclude), `active-response` | EV-07, EV-08 |
| Wazuh API `/syscollector/000/packages` | version and install time of `wazuh-manager` | EV-08 |
| `wazuh-monitoring-*` | last keepalive of each machine | EV-02 |
| `wazuh_agent_config` fact ([op.acc.2](op.acc.2.md)) | FIM and SCA enabled | EV-02 |
| alerts, OSCompliance's own left out | newest alert of each machine in 90 days | EV-03 |
| alerts in groups `ids`, `suricata`, `snort`, `zeek`, `nids` | network intrusion alerts of the fleet | EV-05 |
| active response alerts | responses run on the machine | EV-07 |

The engine reads the manager with its API user (`-wazuh-api`); the role
needs `manager:read` and `rules:read` (catalog/wazuh/engine-api-role.json).
Without the API, EV-01, EV-04, EV-07 and EV-08 are NOT_EVALUABLE. The
manager is read once and judged for every machine.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 network detection `necesaria \| producto \| justificacion` | one row | EV-05 |
| P-02 rule sets `conjunto \| descripcion \| minimo_reglas` | `wazuh`, `propias` or a rule file | EV-01 |
| P-03 compromise situations `situacion \| ambito \| reglas` | rule ids and ranges | EV-04 |
| P-04 alert response procedures | documentary | |
| P-05 approved silencing `regla \| motivo \| aprobador` | | EV-08 |
| P-06 automatic responses `accion \| reglas \| alcance \| timeout` | | EV-07 |
| P-07 maximum age of the rules in days | | EV-08 |
| P-08 days without detections | | EV-03, EV-05 |
| P-09 hours without reporting | | EV-02 |
| P-ATT documentary attestations | r2.1 | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opmon1`.

- EV-01 detection running. `wazuh-analysisd`, `wazuh-remoted`,
  `wazuh-db` and `wazuh-modulesd` running, rules of level 1 or more loaded,
  and every rule set of P-02 with at least `minimo_reglas` of them.
- EV-02 coverage. The machine's last keepalive within P-09 hours, and
  neither FIM nor SCA disabled in its agent configuration. Wazuh keeps no
  keepalive of the manager: it reports while `wazuh-analysisd` runs.
- EV-03 detections. An alert of the machine within P-08 days.
- EV-04 risk analysis. Every situation of P-03 has a loaded rule of
  level 1 or more among its rules.
- EV-05 network detection. When P-01 says `sí`, a network intrusion
  alert within P-08 days; otherwise COMPLIANT with its justification.
- EV-07 automatic responses. Every action of P-06 configured and not
  disabled in the manager's active response.
- EV-08 rules current. The `wazuh-manager` package installed within
  P-07 days, and every excluded rule file and every Wazuh rule rewritten to
  level 0 in `etc/rules` (id under 100000) in P-05 with reason and approver.

## Not measured

- Procedures applied. Op.exp.7 judges the handling of each alert; r2.1 stays an attestation.
