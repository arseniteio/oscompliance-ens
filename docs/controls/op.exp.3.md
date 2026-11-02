# op.exp.3 Gestión de la configuración de seguridad

op.exp.3 (management of the security configuration) adds time to op.exp.2:
the baseline holds without regressions, only authorised accounts edit the
security configuration, nothing unauthorised is installed, only authorised
services run, the configuration is backed up and it is verified
periodically.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.3.3. Definition: [`catalog/controls/ens/op.exp.3.json`](../../catalog/controls/ens/op.exp.3.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 3.1 minimum functionality kept | B/M/A | EV-01, EV-04, EV-10 |
| 3.2 least privilege kept | B/M/A | EV-01, EV-10 |
| 3.3 changes authorised beforehand | B/M/A | EV-05 |
| 3.4 reaction to notified vulnerabilities | B/M/A | EV-06 |
| 3.5 reaction to incidents | B/M/A | EV-07 |
| 3.6 only authorised staff edit the configuration | B/M/A | EV-02 |
| r1.1 authorised baseline | M/A | attestation (P-ATT) |
| r1.2 periodic verification against the baseline | M/A | EV-03, EV-11 |
| r1.3 list of authorised services | M/A | EV-04 |
| r2.1 very few administrators | A | EV-08 |
| r3.1 configuration backups | A | EV-09 |
| r4.1, r5.1 | none | |

## Sources

| Source | Content | Used by |
|---|---|---|
| SCA summary alerts ([op.exp.2](op.exp.2.md)) | every score in the window, and the newest | EV-01 |
| SCA check alerts, rule 19007 with `data.sca.check.previous_result: passed` | checks that went from passed to failed | EV-10 |
| audited writes, rule 119004 key `oscompliance_write` | who wrote under the paths of P-04 | EV-02, EV-08 |
| FIM alerts (`syscheck`) and op.exp.5 P-10 | edits under P-04 and the change register | EV-05 |
| `wazuh-states-vulnerabilities-*` and op.exp.4 P-01 | open vulnerabilities and their deadlines | EV-06 |
| op.exp.7 P-13 | the incident register | EV-07 |
| `audit_watch_snapshot`, `wazuh_agent_config` ([op.acc.2](op.acc.2.md)) | the audit chain | EV-02, EV-08 |
| `identity_snapshot`, `identity_record` ([op.acc.1](op.acc.1.md)) | the account behind an audit uid | EV-02, EV-08 |
| dpkg alerts, rule 2901 (`data.package`) | packages newly installed | EV-03 |
| `package_selection` fact | packages installed on request, not as dependencies | EV-03 |
| `unit_snapshot` fact | systemd services running | EV-04 |
| `listening_snapshot`, `listening_socket` ([op.acc.6](op.acc.6.md)) | processes listening outside a unit | EV-04 |
| `backup_snapshot` fact | the newest copy of each source of P-07 | EV-09 |

The paths of P-04 reach auditd with the audit watches of the group
configuration (`audit_watches`); the sources of P-07 reach the agent as
`backup_sources`.

### `package_selection`

One per pass: `manager` (`apt`, `dnf`, `none`), `status` (`read`, `error`)
and `packages`, the names `apt-mark showmanual` or `dnf repoquery
--userinstalled` list. Emitted only when it changes.

### `unit_snapshot`

One per pass: `status` (`read`, `absent` when there is no systemd, `error`)
and `units`, the services `systemctl list-units --type=service
--state=running` lists. Emitted only when it changes.

### `backup_snapshot`

One per pass, `sources` with `source`, `status` (`read`, `absent`,
`error`) and `newest`, the time of the newest copy. A source is
`git:<directory>` (time of its last commit, as etckeeper keeps `/etc`) or a
file pattern (time of the newest file it matches). The rest of the fact is
in the [mp.info.6](mp.info.6.md).

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 software authorised on top of the baseline (package names) | system | EV-03 |
| P-02 authorised services (unit or process names) | system; built-in per system type | EV-04 |
| P-03 accounts authorised to edit the security configuration | | EV-02 |
| P-04 paths of the security configuration | platform; built-in per system type | EV-02, EV-08 |
| P-05 days between verifications | | EV-11 |
| P-06 change authorisation procedure | documentary; the register is op.exp.5 P-10 | |
| P-07 configuration copies `alcance \| fuente \| destino` | system | EV-09 |
| P-08 accepted deviation (%) | documentary | |
| P-09 maximum number of effective administrators | | EV-08 |
| P-10 hours a copy may be old | | EV-09 |
| P-11 register of verifications `fecha \| alcance \| responsable` | | EV-11 |
| P-12 days of the score series | | EV-01 |
| P-ATT documentary attestations | 3.3, 3.4, 3.5, r1.1 | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opexp3`. A source missing is
NOT_EVALUABLE by COLLECTION; a parameter missing or unusable is
NOT_EVALUABLE by CONFIGURATION. The audit chain is op.acc.4's: auditd
running, every P-04 path watched and the audit log read by Wazuh.

- EV-01 baseline kept. Every summary of the op.exp.2 P-01 policies in
  the last P-12 days, and the newest, must be at least op.exp.2 P-05;
  otherwise NON_COMPLIANT with the lowest. The SCA freshness of op.exp.2
  EV-01 applies.
- EV-02 who edits. Every successful write of the window under P-04 must
  be by an account of P-03: otherwise NON_COMPLIANT. Writes whose account
  cannot be named: NOT_EVALUABLE by EVIDENCE. None, with the chain
  complete: COMPLIANT.
- EV-03 unauthorised software. Each package newly installed in the
  window that the machine keeps on request must be in P-01: otherwise
  NON_COMPLIANT. Dependencies are not judged. On a machine with dnf:
  NOT_EVALUABLE by COLLECTION, since Wazuh does not decode the package of a
  yum or dnf line.
- EV-04 authorised services. Every running unit, and every listening
  process outside a unit, must be in P-02 (`getty@.service` covers every
  `getty@tty1.service`): otherwise NON_COMPLIANT. Without systemd only the
  listening processes are judged.
- EV-05 authorised edits. Every FIM change of the window under P-04
  must be covered by an approved request of op.exp.5 P-10
  ([op.exp.5](op.exp.5.md)): otherwise NON_COMPLIANT.
- EV-06 reaction to vulnerabilities. op.exp.4 EV-02 with the deadlines of
  op.exp.4 P-01 ([op.exp.4](op.exp.4.md)).
- EV-07 reaction to incidents. op.exp.7 EV-12 over the register of
  op.exp.7 P-13: every closed incident of the machine records its measures.
- EV-08 administrators. The accounts that wrote under P-04 in the
  window must be at most P-09: otherwise NON_COMPLIANT.
- EV-09 configuration copies. The newest copy of every source of P-07
  must be within P-10 hours: otherwise NON_COMPLIANT. A source with no
  copy: NON_COMPLIANT.
- EV-10 regressions. A check that went from passed to failed in the
  last P-12 days: NON_COMPLIANT with the checks. None: COMPLIANT.
- EV-11 periodic verification. The newest date of P-11 not in the
  future must be within P-05 days.

## Not measured

- Package installs on rpm machines for EV-03 need a decoder for `/var/log/dnf.rpm.log`; until then those machines are NOT_EVALUABLE by COLLECTION.
