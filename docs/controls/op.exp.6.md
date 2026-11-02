# op.exp.6 Protección frente a código dañino

op.exp.6 (protection against malicious code) judges that every machine runs
its antimalware with current signatures and the right settings, that
detections are resolved, that the whole system is scanned regularly, that
critical paths are checked at start, and, at ALTA, the allowlist and the EDR
layer Wazuh provides: reputation, content rules, rootkit detection and
automatic containment. Wazuh is not the antimalware: it shows that one
exists, works and is well set.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.3.6. Definition: [`catalog/controls/ens/op.exp.6.json`](../../catalog/controls/ens/op.exp.6.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 6.1 prevention and reaction | B/M/A | EV-01, EV-04, EV-10, EV-11 |
| 6.2 antimalware on every machine | B/M/A | EV-01 |
| 6.3 external files analysed before use | B/M/A | EV-12 |
| 6.4 detection bases up to date | B/M/A | EV-02 |
| 6.5 right settings and real-time protection | B/M/A | EV-03 |
| r1.1 periodic full scan | M/A | EV-05 |
| r2.1 critical functions checked at start | M/A | EV-06 |
| r3.1 application allowlist | A | EV-07 |
| r4.1 EDR | A | EV-08 to EV-11 |
| r5.1, r5.2 | none | EV-12, EV-03 |

## Sources

| Source | Content | Used by |
|---|---|---|
| `malware_protection` fact | products and whether they run, ClamAV signatures, settings and last full scan, fapolicyd, active response scripts, YARA | EV-01 to EV-03, EV-05, EV-07, EV-09, EV-11 |
| ClamAV alerts, rules 52502 and 52511 | detections, and the same detection repeated | EV-04 |
| `wazuh_agent_config` | FIM paths and `scan_on_start`, rootcheck, integrations of the manager, active responses the manager sends | EV-06, EV-08, EV-10, EV-11 |
| VirusTotal alerts, rule 87105 | files VirusTotal flags | EV-08 |
| USB alerts, rule 81101 | removable storage attached | EV-12 |

Wazuh decodes ClamAV from syslog: `LogSyslog` must be on for EV-04 to see
detections.

### `malware_protection`

One per pass: `products` (`product`, `running`) among clamav, mdatp,
falcon-sensor, sophos-spl, eset, sentinelone and trendmicro-ds;
`signatures`, the build time of ClamAV's daily database; `enabled_settings`, the
ones switched on (`proteccion_tiempo_real`: clamonacc running or `OnAccessIncludePath` set;
`actualizacion_automatica_firmas`: freshclam running; `analisis_comprimidos`:
`ScanArchive` not off; `registro_syslog`: `LogSyslog` on); `last_scan`, the
newest `End Date` of a clamscan summary in `/var/log/clamav/*.log`;
`allowlist`, fapolicyd as `enforcing`, `permissive`, `stopped` or `absent`;
`responses`, the scripts in `/var/ossec/active-response/bin`; `yara`, the
YARA script and binary present.

### `wazuh_agent_config`, new fields

`syscheck_scan_on_start`, `rootcheck_disabled`, `integrations` (on the
manager's own fact: virustotal and others) and `active_responses` (scripts of
`shared/ar.conf`, Wazuh's restarts left out).

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 antimalware product by kind of machine | documentary | |
| P-02 antimalware expected running | system; built-in per system type | EV-01 |
| P-03 hours the signatures may be old | | EV-02 |
| P-04 expected settings `ajuste \| valor` | `si` or `no` | EV-03 |
| P-05 entry paths of external files | documentary | |
| P-06 days between full scans | | EV-05 |
| P-07 critical paths checked at start | system; built-in per system type | EV-06 |
| P-08 allowlisted applications | documentary | |
| P-09 EDR capabilities `capacidad \| activada \| alcance` | `virustotal`, `yara`, `rootcheck`, `active_response` | EV-08 to EV-11 |
| P-10 removable devices policy | `bloqueados`, `analisis` or `lectura` | EV-12 |
| P-ATT documentary attestations | | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opexp6`. A source missing is
NOT_EVALUABLE by COLLECTION; a parameter missing or unusable is
NOT_EVALUABLE by CONFIGURATION.

- EV-01 antimalware present. Every product of P-02 must run: otherwise
  NON_COMPLIANT. No antimalware at all: NON_COMPLIANT.
- EV-02 signatures. ClamAV's daily database must be built within P-03
  hours. Another product: NOT_EVALUABLE by COLLECTION, its signatures are
  not read.
- EV-03 settings. Each row of P-04 must match what is observed.
- EV-04 detections. A detection repeated (rule 52511) in the window:
  NON_COMPLIANT, the infection was not resolved. Other detections are
  listed. ClamAV not logging to syslog: NOT_EVALUABLE by COLLECTION.
- EV-05 full scan. The last full scan must have ended within P-06 days.
- EV-06 checks at start. FIM must scan on start and cover every path of
  P-07, and rootcheck must run.
- EV-07 allowlist. fapolicyd must be enforcing.
- EV-08 reputation. When P-09 activates `virustotal`, the manager must
  have the VirusTotal integration and the machine FIM on. Flagged files of
  the window are listed.
- EV-09 content rules. When P-09 activates `yara`, its script and binary
  must be on the machine.
- EV-10 suspicious activity. When P-09 activates `rootcheck`, it must run.
- EV-11 containment. When P-09 activates `active_response`, the manager
  must send at least one and each script must be on the machine.
- EV-12 external files. USB storage attached in the window with P-10
  `bloqueados`: NON_COMPLIANT. With `analisis`, real-time protection must be
  on. Otherwise COMPLIANT.

A capability P-09 does not activate leaves its evidence NON_COMPLIANT: R4
asks for all of them.

## Not measured

- Antimalware of mail gateways (amavis): the agent reads the machine's own antimalware only.
