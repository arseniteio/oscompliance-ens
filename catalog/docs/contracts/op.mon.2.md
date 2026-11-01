# op.mon.2 fact contract

op.mon.2 (metrics system) judges the data the organisation collects to
measure its security: the cycles of metrics it consolidates and validates,
the data its incident indicators need, the resources it records, and
whether the measurement of each machine is reliable.

## 1. Requirements and evidences

| Requirement | Levels | Evidences |
|---|---|---|
| 2.1 implementation data and article 32 report | B/M/A | EV-02, EV-04 |
| r1.1 incident management data | M/A | EV-03 |
| r2.1 efficiency: hours and budget | M/A | EV-06 |

## 2. Sources

| Source | Content | Used by |
|---|---|---|
| P-06 cycle register | | EV-02, EV-06 |
| op.exp.7 P-13 incident register (op.exp.7 contract) | | EV-03 |
| `wazuh-monitoring-*` | agent status | EV-04 |
| `agent_pass` fact | the machine's newest OSCompliance pass | EV-04 |

## 3. Parameters

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

## 4. Evidence judgement

Judges are in `engine/internal/controls/ens/opmon2`.

- **EV-02 cycles.** The newest row of P-06 validated by a person of P-05
  for `metricas` must be within P-02 plus P-03 days.
- **EV-03 incident data.** Every incident of op.exp.7 opened within P-02
  days must carry what each indicator of P-04 needs: `clasificacion`,
  `severidad`, an intermediate or final phase, its initial phase,
  `notificacion_ccn_cert` or `datos_personales`.
- **EV-04 reliable measurement.** The machine's agent active (the manager
  while its analysis runs) and an `agent_pass` within the window.
- **EV-06 resources.** As EV-02, for a validator of `recursos` and a row
  with the three resource columns filled.

## 5. Parity with v1 and deliberate differences

Kept: the requirements and EV-02 to EV-04, EV-06.

Changed on purpose:

- EV-01, EV-05 and EV-07 were outputs of the v1 engine without a verdict;
  the implementation degree is the verdicts themselves.
- EV-04 judges each machine; v1 judged the coverage of the fleet against a
  target, which the control score of every machine already shows.
- The cycle register is a parameter (P-06); v1 read a file on the manager.
