# op.cont.2 Plan de continuidad

op.cont.2 (continuity plan) judges what of the plan leaves a record: its
current approval, the contracts of its alternative means and the training of
its people; and, as a reinforcement no category requires, whether each
machine checks its integrity when it comes back from an outage.

Levels: ALTO. Annex II section 4.6.2. Definition: [`catalog/controls/ens/op.cont.2.json`](../../../catalog/controls/ens/op.cont.2.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 2.1 functions and activities | A | EV-01 |
| 2.2 coordination of alternative means | A | EV-01 |
| 2.3 alternative means under contract | A | EV-01, EV-04 |
| 2.4 training of the people | A | EV-01, EV-06 |
| 2.5 integration with other plans | A | EV-01 |
| r1.1 emergency and contingency plan | none | |
| r2.1 integrity after an outage | none | EV-03 |

## Sources

| Source | Content | Used by |
|---|---|---|
| P-01, P-03, P-04, P-05 | registers of the plan | EV-01, EV-04, EV-06 |
| `wazuh_agent_config` fact | FIM directories and `scan_on_start` | EV-03 |

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 approvals `referencia \| version \| fecha_aprobacion \| aprobado_por \| responsable` | | EV-01 |
| P-02 essential services, P-06 other plans | documentary | |
| P-03 functions `funcion \| responsable \| suplente \| actividades` | | EV-06 |
| P-04 alternative means `medio \| proveedor \| contrato \| vigencia_hasta \| activacion` | | EV-04 |
| P-05 training `persona \| formacion \| fecha \| vigente_hasta` | | EV-06 |
| P-07 paths checked after an outage | system | EV-03 |
| P-08 months between reviews of the plan | | EV-01 |
| P-ATT documentary attestations | | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opcont2`.

- EV-01 plan. The newest `fecha_aprobacion` of P-01, not in the future,
  within P-08 months.
- EV-04 contracts. Every means of P-04 with a `contrato` and
  `vigencia_hasta` not past.
- EV-06 training. Every `responsable` and `suplente` of P-03 with a row
  of P-05 whose `vigente_hasta` is not past; names compared without case or
  accents.
- EV-03 integrity after an outage. FIM enabled with `scan_on_start`, and
  every path of P-07 under a FIM directory.

## Not measured

- EV-02, EV-05, EV-07 and EV-08: no source produces a verdict for them.
