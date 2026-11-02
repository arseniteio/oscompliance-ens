# op.exp.5 Gestión de cambios

op.exp.5 (change management) sets the changes that really happen on each
machine against the change register the organisation keeps in Configuración:
every change needs an approved request, requests carry enough information,
high-risk ones are approved beforehand by the security manager, the service
stays up, documentation follows and, at ALTA, a reversion point exists.

Levels: MEDIO, ALTO. Annex II section 4.3.5. Definition: [`catalog/controls/ens/op.exp.5.json`](../../catalog/controls/ens/op.exp.5.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 5.1 requests registered and numbered | M/A | EV-01, EV-02 |
| 5.2 enough information to authorise | M/A | EV-03 |
| 5.3 tests in equivalent pre-production | M/A | EV-05 |
| 5.4 prior approval of high-risk changes | M/A | EV-04 |
| 5.5 acceptance tests and documentation | M/A | EV-06, EV-07 |
| r1.1 reversion foreseen | A | EV-07, EV-09 |
| r1.2 failures reported to the security manager | A | attestation (P-ATT) |
| r1.3 changes documented with their security impact | A | EV-03 |

## Sources

| Source | Content | Used by |
|---|---|---|
| FIM alerts (`syscheck`, [op.acc.2](op.acc.2.md)) | files changed, when | EV-01, EV-02, EV-07, EV-09 |
| `package_transaction` records ([op.exp.4](op.exp.4.md)) | software changes, when and by whom | EV-01, EV-02, EV-05, EV-07, EV-09 |
| `wazuh_agent_config` | FIM enabled on the machine | EV-01 |
| `unit_snapshot` ([op.exp.3](op.exp.3.md)), field `failed` | services failed now | EV-07 |
| dpkg alerts, rule 2902 | versions installed on the pre-production machine | EV-05 |
| `snapshot_list` ([op.exp.4](op.exp.4.md)) | reversion points | EV-09 |
| P-10 | the change register | EV-02 to EV-04, EV-06, EV-07 |

A change is a FIM alert or an apt transaction of the window. Its time is
the alert's or the transaction's start.

### `unit_snapshot`, new field

`failed`: the services `systemctl list-units --type=service --state=failed`
lists.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 change management system `herramienta \| ubicacion \| prefijo_referencia` | | EV-03 |
| P-02 columns a request must fill | | EV-03 |
| P-03 high-risk criteria | documentary | |
| P-04 security manager `nombre \| cuenta` | | EV-04 |
| P-06 configuration documents `documento \| ubicacion \| plazo_dias` | | EV-06 |
| P-07 failure reporting channel | documentary | |
| P-09 hours after a change in which a failure is its effect | | EV-07 |
| P-10 change register | one request per row, columns below | EV-02 to EV-04, EV-06, EV-07 |
| op.exp.4 P-06 pre-production pairs | the same declaration | EV-05 |
| op.exp.4 P-07 reversion mechanism | the same declaration | EV-09 |
| P-ATT documentary attestations | r1.2 | |

P-10 columns: `peticion | fecha_registro | sistema | descripcion | riesgo |
aprobado_por | fecha_aprobacion | ventana_inicio | ventana_fin | estado |
documentacion | impacto_seguridad`. `sistema` is an agent name or `*`;
`estado` is `registrada`, `aprobada`, `implantada`, `revertida` or
`rechazada`; `riesgo` is `alto`, `medio` or `bajo`. Dates and times are
`2026-10-20 06:00` (Europe/Madrid) or RFC 3339. An empty `ventana_fin`
leaves the window open: a standard change.

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opexp5`. A source missing is
NOT_EVALUABLE by COLLECTION; a parameter missing or unusable is
NOT_EVALUABLE by CONFIGURATION. A request covers a change when its
`sistema` is the machine or `*`, its `estado` is `aprobada`, `implantada`
or `revertida`, it was approved before the change, and its window contains
the change.

- EV-01 real changes. FIM enabled and the apt history read: COMPLIANT
  with the changes of the window. FIM disabled: NON_COMPLIANT.
- EV-02 changes without a request. A change no request covers:
  NON_COMPLIANT with the changes.
- EV-03 request information. Every authorised request of the machine
  whose window touches the last 90 days must fill the columns of P-02, its
  `peticion` must start with the prefix of P-01 when it has one, and at ALTA
  it must fill `impacto_seguridad`: otherwise NON_COMPLIANT.
- EV-04 high-risk approval. Every high-risk request of the machine
  implanted in the last 90 days must be approved by the account of P-04
  before its window opens: otherwise NON_COMPLIANT.
- EV-05 pre-production. As op.exp.4 EV-08 over the software of the
  window, with the pairs of op.exp.4 P-06.
- EV-06 documentation. Every request implanted more than its document's
  `plazo_dias` ago must name in `documentacion` the documents of P-06 it
  updated: otherwise NON_COMPLIANT.
- EV-07 stability. A service failed now, with a change in the P-09 hours
  before, whose covering request is not `revertida`: NON_COMPLIANT. Without
  systemd: NOT_EVALUABLE by COLLECTION.
- EV-09 reversion point. As op.exp.4 EV-09, over every change of the
  window, with op.exp.4 P-07.

op.exp.3 EV-05 judges the edits of the security configuration (FIM changes
under op.exp.3 P-04) against the same register.

## Not measured

- Failures reported to the security manager. The communication leaves no fact. r1.2 is accredited by attestation.
