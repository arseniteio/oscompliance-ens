# mp.sw.2 fact contract

mp.sw.2 (acceptance and entry into service) judges the machines of each
application: every install of its packages preceded by an accepted act and,
at MEDIO, by the same version installed in pre-production, and the security
of the machine not worse after it: no SCA regression, no undeclared port, no
critical or high vulnerability in its packages.

## 1. Requirements and evidences

| Requirement | Levels | Evidences |
|---|---|---|
| 2.1 acceptance criteria met without harm | B/M/A | EV-01 to EV-05 |
| r1.1 tests in an isolated pre-production | M/A | EV-07 |
| r2.1 source code audit | none | |

A machine where no application of P-01 is deployed: every evidence and
requirement NOT_APPLICABLE. When no machine of P-01 reports to Wazuh, the
manager carries the control and every evidence is NON_COMPLIANT there.

## 2. Sources

| Source | Content | Used by |
|---|---|---|
| dpkg alerts, rule 2902 (`data.package`, `data.version`) | installs of the last 90 days, the first time of each version | EV-01, EV-02, EV-03, EV-07 |
| `wazuh-states-inventory-packages-*` (`package.installed`) | rpm installs of the last 90 days: rpm keeps the install time, dpkg does not | EV-01, EV-02, EV-03, EV-07 |
| SCA alerts, rule 19007 (op.exp.3 contract) | checks that passed and now fail | EV-03 |
| `listening_snapshot`, `listening_socket` (op.acc.6 contract) | ports open | EV-04 |
| `wazuh-states-vulnerabilities-*` | open critical and high vulnerabilities by package | EV-05 |
| `wazuh-monitoring-*` | agent names, to find the pre-production machine | EV-07 |

## 3. Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 applications `aplicacion \| maquinas \| paquetes \| responsable \| origen` | machines and packages separated by commas | scope, EV-01, EV-02, EV-05 |
| P-02 acceptance criteria, P-07 code audits | documentary | |
| P-03 pre-production `produccion \| preproduccion \| aislamiento` | | EV-07 |
| P-04 days after a deployment watched | | EV-03 |
| P-05 expected ports `aplicacion \| puerto \| servicio` | `*` for every machine | EV-04 |
| P-06 acceptance acts `fecha \| aplicacion \| version \| resultado \| aceptado_por` | | EV-02 |
| P-ATT documentary attestations | | |

## 4. Evidence judgement

Judges are in `engine/internal/controls/ens/mpsw2`. A deployment is an
install of a package of an application of the machine in the last 90 days.

- **EV-01 deployments seen.** Every application of the machine has its
  `paquetes`.
- **EV-02 acceptance.** Every deployment has an act of its application,
  `aceptada`, with `aceptado_por`, dated no later, whose `version` is empty
  or a prefix of the deployed one.
- **EV-03 configuration.** No SCA regression within P-04 days after a
  deployment.
- **EV-04 exposure.** Every port open beyond loopback is in P-05 for an
  application of the machine or for `*`.
- **EV-05 vulnerabilities.** No open critical or high vulnerability in a
  package of the machine's applications.
- **EV-07 pre-production.** Every deployed version installed earlier on the
  machine P-03 pairs with this one.

## 5. Parity with v1 and deliberate differences

Kept: the requirements and EV-01 to EV-05, EV-07.

Changed on purpose:

- Deployments are read from dpkg installs and from the install time rpm
  keeps in the inventory; v1 diffed the software inventory.
- EV-06 (acceptance criteria checked automatically) is EV-03 to EV-05.
- EV-08 (isolation of pre-production) and EV-09 (stability after a
  deployment) are out: no common source tells them.
- EV-10 (code audit findings) is out: r2.1 applies to no category.
