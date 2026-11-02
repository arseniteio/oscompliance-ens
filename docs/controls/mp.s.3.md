# mp.s.3 Protección de la navegación web

mp.s.3 (protection of web browsing) judges the browsing filter through its
logs and the rules behind each of its functions, the DNS servers and the
antimalware of every machine, how long the browsing records are kept, and
the awareness of users and training of administrators.

Levels: BAJO, MEDIO, ALTO. Annex II section 5.8.3. Definition: [`catalog/controls/ens/mp.s.3.json`](../../catalog/controls/ens/mp.s.3.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 3.1 rules of use | B/M/A | attestation (P-ATT) |
| 3.2 awareness | B/M/A | EV-12 |
| 3.3 administrators trained | B/M/A | EV-13 |
| 3.4 name resolution and connections | B/M/A | EV-05, EV-11 |
| 3.5 problems arriving by browsing | B/M/A | EV-01, EV-02, EV-04, EV-06, EV-11 |
| 3.6 malicious code and active content | B/M/A | EV-01 to EV-04, EV-06 |
| 3.7 cookie policy | B/M/A | attestation (P-ATT) |
| r1.1 browsing recorded and kept | A | EV-08 |
| r1.2 inspection of encrypted channels | A | attestation (P-ATT) |
| r1.3 blacklist | A | EV-10 |
| r2.1 whitelist | none | |

## Sources

| Source | Content | Used by |
|---|---|---|
| alerts of each `fuente` of P-02 | hours with alerts, a week back | EV-01 |
| Wazuh API rules ([op.mon.1](op.mon.1.md)) | rules of the indicators of P-03 | EV-02 to EV-04, EV-10, EV-11 |
| `device_security` fact ([mp.eq.2](mp.eq.2.md)) | `dns_resolvers` | EV-05 |
| `malware_protection` fact ([op.exp.6](op.exp.6.md)) | antimalware running | EV-06 |
| ISM policy of the alerts index ([op.exp.8](op.exp.8.md)) | retention in days | EV-08 |

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 rules of use, P-05 cookie policy, P-11 TLS inspection, P-13 whitelist | documentary | |
| P-02 browsing filters `filtro \| maquina \| fuente` | | EV-01 |
| P-03 indicators `filtro \| indicador \| fuente \| reglas` | `filtro` categorías, descargas y contenido activo, reputación, lista negra, evasión | EV-02 to EV-04, EV-10, EV-11 |
| P-04 authorised DNS servers | addresses or CIDR | EV-05 |
| P-06 awareness `fecha \| actividad \| alcance \| participacion` | | EV-12 |
| P-07 administrator training `fecha \| persona \| formacion` | | EV-13 |
| P-08 retention days of browsing records | | EV-08 |
| P-09, P-10 days between awareness activities and trainings | | EV-12, EV-13 |
| P-12 hours without logs of the filter | | EV-01 |
| op.exp.6 P-02 expected antimalware | | EV-06 |
| P-ATT documentary attestations | 3.1, 3.7, r1.2 | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/mps3`. The filter and the
registers are the organisation's: they are judged the same on every machine.

- EV-01 logs. As mp.com.1 EV-01 over the sources of P-02 and P-12.
- EV-02 to EV-04, EV-10, EV-11 filter functions. As mp.com.3 EV-04 for
  categories, downloads and active content, reputation, blacklist and
  evasion.
- EV-05 DNS. Every server of `dns_resolvers` within an entry of P-04;
  `*` is no entry. No server: NON_COMPLIANT.
- EV-06 workstation. As op.exp.6 EV-01.
- EV-08 retention. The retention of the alerts index at least P-08
  days; no retention policy: NON_COMPLIANT.
- EV-12, EV-13. The newest row of P-06 within P-09 days, of P-07 within
  P-10 days.

## Not measured

- EV-07 (cookies) and EV-09 (TLS inspection): neither leaves a record. Requirements 3.7 and r1.2 are judged by attestation.
