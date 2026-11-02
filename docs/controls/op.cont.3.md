# op.cont.3 Pruebas periódicas

op.cont.3 (periodic tests) judges the tests of the continuity plan: that
they exercise the alternative means, come as often as planned for every kind
and scenario, that each machine taking part came back within its RTO as
Wazuh's monitoring saw it, and that the deficiencies they reveal are
corrected.

Levels: ALTO. Annex II section 4.6.3. Definition: [`catalog/controls/ens/op.cont.3.json`](../../catalog/controls/ens/op.cont.3.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 3.1 periodic tests and corrections | A | EV-01 to EV-05 |

## Sources

| Source | Content | Used by |
|---|---|---|
| P-04 test register, P-05 deficiency register | | EV-01, EV-02, EV-05 |
| `wazuh-monitoring-*` | agent status every few minutes during each test and the day after | EV-03, EV-04 |

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 months between tests | | EV-01, EV-02 |
| P-02 kinds `tipo \| descripcion \| periodicidad_meses` | | EV-01, EV-02 |
| P-03 scenarios `escenario \| sistemas` | | EV-02 |
| P-04 tests `inicio \| fin \| tipo \| escenario \| sistemas \| resultado \| deficiencias \| informe` | `sistemas` are agent names | EV-01 to EV-05 |
| P-05 deficiencies `deficiencia \| prueba \| responsable \| plazo \| estado \| cierre \| version_plan` | `prueba` is the test's date | EV-05 |
| P-06 planned windows | documentary | |
| P-07 RTO `sistema \| rto_horas \| tolerancia_min` | | EV-04 |
| P-ATT documentary attestations | | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opcont3`. A partial test or a
full drill (`parcial`, `simulacro`) is one that exercises the alternative
means.

- EV-01 tests recorded. P-02 plans a partial test or a drill, and one
  took place within P-01 months.
- EV-02 periodicity. The newest test, the newest of each kind of P-02
  (its own months or P-01) and of each scenario of P-03 within P-01 months.
- EV-03 measured. Monitoring records of the machine in every partial
  test or drill of the period it took part in; none: NOT_EVALUABLE.
- EV-04 RTO. In those tests, the longest span the machine was not
  `active`, from `inicio` to a day after `fin`, within `rto_horas` plus
  `tolerancia_min`, and the machine active at the end. A machine no test
  involved: COMPLIANT.
- EV-05 deficiencies. No open deficiency past its `plazo` or older than
  the newest test, and every test with at least its `deficiencias` in P-05.

## Not measured

- EV-06 to EV-08: no source produces a verdict for them.
