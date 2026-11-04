# op.exp.9 Registro de la gestión de incidentes

op.exp.9 (record of incident management) judges the records of each
incident of op.exp.7's register: the events that caused it, its reports,
emergency actions and the system changes it brought, evidence able to stand
in court, and the review of auditable events afterwards.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.3.9. Definition: [`catalog/controls/ens/op.exp.9.json`](../../../catalog/controls/ens/op.exp.9.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 9.1 reports, actions and changes recorded | B/M/A | EV-01 to EV-04, EV-09 |
| 9.2 evidence with legal value | B/M/A | EV-05, EV-07, EV-09 |
| 9.3 auditable events reviewed after incidents | B/M/A | EV-08, EV-09 |

## Sources

The incident register is op.exp.7 P-13 ([op.exp.7](op.exp.7.md)). Besides:

| Source | Content | Used by |
|---|---|---|
| Wazuh alerts of the machine | alerts in the hours before each incident and on each of its days | EV-01, EV-07 |
| active response alerts | emergency actions | EV-03 |
| FIM alerts and `package_transaction` ([op.exp.5](op.exp.5.md)), op.exp.5 P-10 | changes during each incident and their requests | EV-04 |
| sealed alert logs of the manager ([op.exp.7](op.exp.7.md)) | | EV-05 |

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 incident register system | documentary; the register is op.exp.7 P-13 | |
| P-02 report phases `fase \| contenido_minimo \| exigible_desde_horas` | | EV-02 |
| P-03 composition of legal evidence | documentary | |
| P-04 criteria of legal relevance | documentary; the register marks `relevancia_juridica` | |
| P-05 evidence custody | documentary | |
| P-06 evidence retention | documentary | |
| P-07 review of auditable events `severidad \| plazo_dias \| procedimiento` | | EV-08 |
| P-08, P-09 | documentary | |
| P-ATT documentary attestations | | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opexp9`; incidents of the last
90 days that involve the machine.

- EV-01 originating events. The alerts of the machine in the 24 hours
  before each initial phase must still be in the index.
- EV-02 reports. A closed incident must have every phase of P-02 its
  duration makes due (`exigible_desde_horas`).
- EV-03 emergency actions. As op.exp.7 EV-06.
- EV-04 system changes. The changes of the machine between the initial
  and final phases must be covered by requests of op.exp.5 P-10.
- EV-05 sealed evidence. An incident with `relevancia_juridica` `si`
  must carry `referencia` and have every day sealed on the manager.
- EV-07 records of the period kept. Every day of an incident with legal
  relevance, or still open, must keep alerts of the machine in the index.
- EV-08 auditable events reviewed. A closed incident whose severity has a
  row in P-07 must fill `revision_eventos` within `plazo_dias` of its close.
- EV-09 complete record. An incident must carry `referencia`, its initial
  phase and, once closed, its final one.

## Not measured

- Chain of custody. Accesses to the custody repository leave no fact. It stays declared in P-05.
