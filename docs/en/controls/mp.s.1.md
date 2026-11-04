# mp.s.1 Protección del correo electrónico

mp.s.1 (protection of e-mail) judges the machines of the mail platform: the
platform's logs in Wazuh, its spam, malware and mobile code filters backed
by loaded rules, TLS in transit, SPF, DKIM and DMARC of the own domains,
changes to its configuration under change control, and the awareness of its
users.

Levels: BAJO, MEDIO, ALTO. Annex II section 5.8.1. Definition: [`catalog/controls/ens/mp.s.1.json`](../../../catalog/controls/ens/mp.s.1.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 1.1 body and attachments protected | B/M/A | EV-06, EV-09 |
| 1.2 routing and connections protected | B/M/A | EV-06, EV-07, EV-09 |
| 1.3 spam | B/M/A | EV-01, EV-02, EV-09 |
| 1.4 malicious code | B/M/A | EV-01, EV-03, EV-09 |
| 1.5 mobile code | B/M/A | EV-01, EV-05, EV-09 |
| 1.6 limits to private use | B/M/A | attestation (P-ATT) |
| 1.7 awareness and training | B/M/A | EV-10 |

A machine that is not a `maquina` of P-01: every evidence and requirement
NOT_APPLICABLE. When no machine of P-01 reports to Wazuh, the manager carries
the control: the organisation's evidences are judged there and EV-06 and
EV-09 are NON_COMPLIANT. A system without e-mail disables the control.

## Sources

| Source | Content | Used by |
|---|---|---|
| alerts of each `fuente` of P-01 | hours with alerts, a week back | EV-01 |
| Wazuh API rules ([op.mon.1](op.mon.1.md)) | rules of the indicators of P-03 | EV-02, EV-03, EV-05 |
| `config_file` of `/etc/postfix/main.cf` | `smtpd_tls_security_level`, `smtp_tls_security_level`, the four `*_tls_*protocols`, `smtpd_tls_cert_file` | EV-06 |
| DNS TXT records, read by the engine | `<dominio>`, `_dmarc.<dominio>`, `<selector>._domainkey.<dominio>` | EV-07 |
| FIM alerts, op.exp.5 P-10 ([op.exp.5](op.exp.5.md)) | | EV-09 |

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 platform `plataforma \| maquina \| fuente` | | scope, EV-01 |
| P-02 own domains `dominio \| selector_dkim \| politica_dmarc` | | EV-07 |
| P-03 filters `filtro \| indicador \| fuente \| reglas` | `filtro` antispam, antimalware or código móvil | EV-02, EV-03, EV-05 |
| P-04 TLS requirements, P-05 content encryption, P-06 rules of use | documentary | |
| P-07 awareness `fecha \| actividad \| alcance \| participacion` | | EV-10 |
| P-08 days between awareness activities | | EV-10 |
| P-09 mail configuration | system; built-in per system type | EV-09 |
| P-10 hours without logs of the platform | | EV-01 |
| P-ATT documentary attestations | 1.6 | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/mps1`.

- EV-01 logs. As mp.com.1 EV-01 over the sources of P-01 and P-10.
- EV-02, EV-03, EV-05 filters. As mp.com.3 EV-04 for the indicators of
  `antispam`, `antimalware` and `código móvil` of P-03.
- EV-06 TLS. `smtpd_tls_security_level` may or encrypt,
  `smtp_tls_security_level` set and not none, and every protocol list
  excluding SSLv2, SSLv3, TLSv1 and TLSv1.1 (by `!` or a `>=TLSv1.2`
  floor). No Postfix on the machine: NON_COMPLIANT.
- EV-07 domains. Every domain of P-02 with an SPF record ending in an
  `all` that is not `+all` or `?all`, a TXT record under its DKIM selector,
  and a DMARC record with `p=quarantine` or `p=reject`.
- EV-09 configuration. As mp.com.3 EV-10 over P-09.
- EV-10 awareness. The newest activity of P-07 within P-08 days.

## Not measured

- EV-04 (every message scanned) and EV-08 (spoofing of the own domain): no common log tells them. DMARC (EV-03) covers spoofing.
- Mail TLS is read from Postfix only. Other mail servers are NOT_EVALUABLE by COLLECTION for EV-06.
