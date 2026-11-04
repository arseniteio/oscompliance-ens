# op.mon.2 Sistema de métricas

op.mon.2 (metrics system) judges the data the organisation collects to
measure its security: the cycles of metrics it consolidates and validates,
the data its incident indicators need, the resources it records, and
whether the measurement of each machine is reliable.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.7.2. Definition: [`catalog/controls/ens/op.mon.2.json`](../../../catalog/controls/ens/op.mon.2.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 2.1 implementation data and article 32 report | B/M/A | EV-02, EV-04 |
| r1.1 incident management data | M/A | EV-03 |
| r2.1 efficiency: hours and budget | M/A | EV-06 |

## Sources

| Source | Content | Used by |
|---|---|---|
| P-06 cycle register | | EV-02, EV-06 |
| op.exp.7 P-13 incident register ([op.exp.7](op.exp.7.md)) | | EV-03 |
| `wazuh-monitoring-*` | agent status | EV-04 |
| `agent_pass` fact | the machine's newest OSCompliance pass | EV-04 |

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 statement of applicability | documentary | |
| P-02 days of a cycle | | EV-02, EV-03, EV-06 |
| P-03 margin days after a cycle | | EV-02, EV-06 |
| P-04 incident indicators | `incidentes_por_tipo`, `incidentes_por_severidad`, `tiempo_medio_contencion`, `tiempo_medio_resolucion`, `notificados_ccn_cert`, `notificados_aepd` | EV-03 |
| P-05 validators `responsable \| rol \| ambito` | `metricas`, `recursos` or `ambos` | EV-02, EV-06 |
| P-06 cycles `fecha_consolidacion \| periodo \| implantacion_global \| validado_por \| horas_internas \| horas_externas \| presupuesto` | | EV-02, EV-06 |
| P-07 resource criteria | documentary | |
| P-ATT documentary attestations | | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opmon2`.

- EV-02 cycles. The newest row of P-06 validated by a person of P-05
  for `metricas` must be within P-02 plus P-03 days.
- EV-03 incident data. Every incident of op.exp.7 opened within P-02
  days must carry what each indicator of P-04 needs: `clasificacion`,
  `severidad`, an intermediate or final phase, its initial phase,
  `notificacion_ccn_cert` or `datos_personales`.
- EV-04 reliable measurement. The machine's agent active (the manager
  while its analysis runs) and an `agent_pass` within the window.
- EV-06 resources. As EV-02, for a validator of `recursos` and a row
  with the three resource columns filled.
