# op.exp.7 Gestión de incidentes

op.exp.7 (incident management) sets Wazuh's detections against the incident
register the organisation keeps in Configuración: relevant alerts become
incidents, incidents are escalated, contained and closed within their
deadlines, the right people and bodies are told, evidence is preserved and
lessons are recorded. op.exp.9 judges the same register for its records.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.3.7. Definition: [`catalog/controls/ens/op.exp.7.json`](../../catalog/controls/ens/op.exp.7.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 7.1 incident management process | B/M/A | EV-01, EV-02, EV-04 |
| 7.2 incidents with personal data | B/M/A | EV-07 |
| r1.1 notification to CCN-CERT | M/A | EV-08 |
| r2.1 urgent measures and evidence | M/A | EV-05, EV-06 |
| r2.2 resources to investigate and resolve | M/A | EV-03 |
| r2.3 information to those responsible | M/A | EV-04 |
| r2.4 measures against repetition | M/A | EV-12 |
| r3.1 dynamic reconfiguration | A | EV-09 |
| r3.2 CCN-CERT advisories | A | EV-10 |
| r4.1 automatic prevention and response | none | EV-11 |

## Sources

| Source | Content | Used by |
|---|---|---|
| Wazuh alerts of the machine | counts by hour at or above the levels of P-01 | EV-01, EV-02 |
| active response alerts (`rule.groups: active_response`) | containment executed on the machine | EV-06, EV-09 |
| `wazuh_agent_config` of the manager, new fields | days whose alert logs are sealed (`.sum`), CDB lists and their dates | EV-05, EV-10 |
| `wazuh_agent_config`, `malware_protection` | active responses sent and installed ([op.exp.6](op.exp.6.md)) | EV-11 |
| P-13 | the incident register | EV-02 to EV-09, EV-12 |

### `wazuh_agent_config`, new fields

`sealed_days`: the days of the last 400 whose alert log has its signature
(`logs/alerts/<year>/<month>/ossec-alerts-<day>.log.sum`); `lists`: the CDB
lists of `etc/lists` with `name` and `modified`. Both are empty off the
manager.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 classification `categoria \| severidad \| nivel_minimo \| notificable_ccn_cert \| criterio` | the lowest Wazuh level of each severity | EV-01, EV-02, EV-08 |
| P-02 escalation `severidad \| destinatario \| plazo_horas \| canal` | | EV-02, EV-04 |
| P-03 incident management system | documentary | |
| P-04 owners of information and service `sistema \| responsable_informacion \| responsable_servicio` | | EV-04 |
| P-05 response deadlines `severidad \| contencion_horas \| resolucion_horas` | | EV-03 |
| P-06 CCN-CERT single window | documentary | |
| P-07 systems with personal data `sistema \| tratamientos` | | EV-07 |
| P-08 evidence to preserve | documentary | |
| P-09 automatic response actions | documentary | |
| P-10 elements of dynamic reconfiguration | documentary | |
| P-11 CCN-CERT advisories `canal \| responsable \| lista_cdb \| plazo_dias` | | EV-10 |
| P-12 rules not reconciled `regla \| motivo` | | EV-02 |
| P-13 incident register | one row per phase | EV-02 to EV-09, EV-12 |

P-13 columns: `incidente | fase | fecha | severidad | sistemas | clasificacion |
escalado_a | notificado_a | datos_personales | notificacion_ccn_cert |
relevancia_juridica | medidas_mejora | referencia | revision_eventos`. `fase`
is `inicial`, `intermedio` or `final`; `sistemas` are agent names separated
by commas; dates as in op.exp.5 (Europe/Madrid unless they carry a zone).
## How each evidence is judged

Judges are in `engine/internal/controls/ens/opexp7`. An incident is the rows
that share `incidente`; it involves the machine when `sistemas` names it.
Incidents of the last 90 days are judged.

- **EV-01 detection.** Alerts of the machine at or above the lowest level of
  P-01 in the window, by severity: COMPLIANT. P-01 empty: NOT_EVALUABLE.
- **EV-02 reconciliation.** Every hour with an alert at or above a severity's
  level, outside P-12, needs an incident of the machine opened within that
  severity's `plazo_horas` of P-02: otherwise NON_COMPLIANT.
- **EV-03 times.** The intermediate phase within `contencion_horas` and the
  final within `resolucion_horas` of the initial one, per severity of P-05;
  an open incident past them fails too.
- **EV-04 escalation and information.** `escalado_a` must hold the recipient
  of P-02 for the severity, and `notificado_a` the owners of P-04 of every
  system.
- **EV-05 evidence preserved.** Every day of an incident of the machine must
  have its alert log sealed on the manager.
- **EV-06 urgent measures.** A high or critical incident needs an active
  response on the machine between its initial and final phases, or an
  intermediate phase.
- **EV-07 personal data.** An incident on a system of P-07 must fill
  `datos_personales`; when `si`, `notificado_a` must be filled within 72
  hours of the initial phase.
- **EV-08 CCN-CERT.** An incident whose classification P-01 marks
  notifiable must carry a `notificacion_ccn_cert` date.
- **EV-09 dynamic reconfiguration.** A critical incident needs an active
  response on the machine between its initial and final phases.
- **EV-10 advisories.** The CDB list of P-11 must exist on the manager and be
  modified within `plazo_dias`.
- **EV-11 automatic response.** As op.exp.6 EV-11.
- **EV-12 improvement.** A closed incident must fill `medidas_mejora`.
