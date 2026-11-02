# mp.s.2 Protección de servicios y aplicaciones web

mp.s.2 (protection of web services and applications) judges the machines
that serve the web applications: their logs in Wazuh, the attacks the
requirement lists watched by loaded rules, the age of the critical and high
vulnerabilities of the platform, and the audits of each application with
their findings solved.

Levels: BAJO, MEDIO, ALTO. Annex II section 5.8.2. Definition: [`catalog/controls/ens/mp.s.2.json`](../../catalog/controls/ens/mp.s.2.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 2.1 no access bypassing authentication | B/M/A | EV-01 to EV-06 |
| 2.2 privilege escalation | B/M/A | EV-01, EV-07 |
| 2.3 cross site scripting | B/M/A | EV-01, EV-08 |
| r1.1 black box audits | B/M | EV-11 |
| r1.2 audit frequency defined | B/M | EV-11 |
| r2.1 white box audits | B/M/A | EV-11 |
| r2.2 methodologies and automatic tools | B/M/A | EV-10, EV-11 |
| r2.3 vulnerabilities found solved | B/M/A | EV-12 |
| r3.1 proxies and caches | A | attestation (P-ATT) |

A machine that is not a `maquina` of P-01: every evidence and requirement
NOT_APPLICABLE. When no machine of P-01 reports to Wazuh, the manager carries
every application: EV-10 is NON_COMPLIANT there. A system without web
services disables the control. P-07 picks black box (r1) or white box (r2) audits: the
reinforcements of the other are NOT_APPLICABLE; at ALTO white box applies
whatever P-07 says.

## Sources

| Source | Content | Used by |
|---|---|---|
| alerts of each `fuente` of P-01 | hours with alerts, a week back | EV-01 |
| Wazuh API rules ([op.mon.1](op.mon.1.md)) | rules of the indicators of P-03 | EV-02 to EV-08 |
| `wazuh-states-vulnerabilities-*` | open vulnerabilities by severity and day of detection | EV-10 |
| P-08, P-12 | audits and their findings | EV-11, EV-12 |

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 applications `aplicacion \| maquina \| fuente \| url \| exposicion` | | scope, EV-01, EV-11, EV-12 |
| P-02 authenticated resources, P-04 forbidden ways, P-05 cookie attributes, P-06 audit procedure, P-13 proxies and caches | documentary | |
| P-03 attack indicators `ataque \| indicador \| fuente \| reglas` | `ataque` one of the seven of the requirement | EV-02 to EV-08 |
| P-07 audit modality | caja negra, caja blanca | EV-11, decisions |
| P-08 audits `fecha \| aplicacion \| modalidad \| metodologia \| herramientas \| hallazgos` | | EV-11 |
| P-09 days a critical or high vulnerability may stay open | | EV-10 |
| P-10 days between audits | | EV-11 |
| P-11 hours without web logs | | EV-01 |
| P-12 findings `hallazgo \| aplicacion \| severidad \| responsable \| plazo \| estado` | | EV-12 |
| P-ATT documentary attestations | r3.1 | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/mps2`.

- EV-01 logs. As mp.com.1 EV-01 over the sources of the machine's
  applications.
- EV-02 to EV-08 attacks. As mp.com.3 EV-04 for access without
  authentication, alternative ways, URL manipulation, cookie manipulation,
  injection, privilege escalation and XSS.
- EV-10 vulnerabilities. No critical or high vulnerability of the
  machine detected more than P-09 days ago and still open.
- EV-11 audits. Every application of the machine with an audit of the
  modality in force within P-10 days; a white box one with `metodologia`
  and `herramientas`.
- EV-12 findings. Every finding of the machine's applications
  `resuelto`, `cerrado` or within its `plazo`.

## Not measured

- Attempt against success. The web logs Wazuh decodes do not tell a successful attack apart.
- Proxies and caches. R3.1 is an attestation.
