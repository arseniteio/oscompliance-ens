# op.acc.2 Requisitos de acceso

op.acc.2 (access requirements) judges that resources are protected by access
control: nothing critical is writable by everyone, operating system files do
not change unnoticed, nobody escalates without a grant, declared rights are
the applied ones and, at ALTO, every privilege is individual and every
access is of a permitted type.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.2.2. Definition: [`catalog/controls/ens/op.acc.2.json`](../../catalog/controls/ens/op.acc.2.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 2.1 resources protected by access control | B/M/A | EV-01, EV-03, EV-07 |
| 2.2 rights as the resource owner decides | B/M/A | EV-03, EV-04 |
| 2.3 operating system files protected | B/M/A | EV-02, EV-03, EV-07 |
| r1.1 privileges kept individually | A | EV-05 |
| r1.2 privileges restrict the type of access | A | EV-05, EV-06 |

## Sources

| Source | Content | Used by |
|---|---|---|
| `file_sweep_snapshot`, `special_file` (`sweep`, daily) | world-writable entries, SUID and SGID files, entries without owner or group | EV-01, EV-07 |
| `umask_snapshot` (`umask`) | every umask declaration of login.defs, /etc/profile, /etc/bash.bashrc and /etc/profile.d | EV-01 |
| `identity_*`, `group_*` ([op.acc.1](op.acc.1.md)) | accounts and groups | EV-03, EV-05, EV-06 |
| `sudoers_snapshot`, `sudo_grant` (`sudoers`) | user specifications with aliases expanded, NOPASSWD commands, Defaults; includes followed | EV-03, EV-05 |
| `wazuh_agent_config` (`wazuh`) | FIM directories, ignores and frequency; localfiles | EV-02, EV-06 |
| `acl_snapshot`, `acl_record` (`acl`) | mode, owner and POSIX ACL of each path of P-08 | EV-04 |
| `audit_watch_snapshot` (`audit`) | auditd state and the watches loaded | EV-06 |
| `auth_log_probe` and rule 119002 | the authentication log reaches Wazuh | EV-03 |
| FIM alerts, group `syscheck` | file changes | EV-02 |
| sudo alerts 5401 to 5407, su sessions (5501) | elevations and refusals | EV-03 |
| rule 119004, auditd records with an `oscompliance_*` key | audited accesses and their kind | EV-06 |

The sweep walks `/` and every other local file system, never network or
pseudo file systems, and does not follow symlinks. It has a time and a record
limit; reaching either marks the sweep partial instead of hiding what is
left.

The paths of P-08 and P-06 reach the agents through the group configuration
the engine writes (`acl_paths`, `audit_watches`). For each audited path the
agent loads four auditd watches, one per permission (`oscompliance_read`,
`_write`, `_exec`, `_attr`), so every audited access carries its kind. It
never removes a rule.

FIM is Wazuh's own. By default it watches /etc, /usr/bin, /usr/sbin, /bin,
/sbin and /boot; a P-02 path elsewhere needs a `<directories>` entry in the
group configuration.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 systems in scope | system | |
| P-02 critical paths | platform | EV-01 (scope), EV-02 |
| P-03 world-writable allowed when sticky | | EV-01 |
| P-04 access policy reference | documentary | |
| P-05 privilege model | presence | EV-05 |
| P-06 `perfil \| recurso \| tipos_permitidos` | system | EV-06 |
| P-07 minimum umask | | EV-01 |
| P-08 `recurso \| modo \| propietario_grupo \| acl_esperada` | system | EV-04 |
| P-09 `usuario \| perfil \| privilegios` | system | EV-05, EV-06 |
| P-10 authorised SUID and SGID binaries | platform | EV-07 |
| P-11 world-writable exceptions | platform | EV-01 |
| P-12 privileged groups | platform | EV-03, EV-05 |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opacc2`. A source missing is
NOT_EVALUABLE by COLLECTION; a parameter missing or unusable is
NOT_EVALUABLE by CONFIGURATION.

- **EV-01 world-writable and umask.** A world-writable entry under a P-02 path
  that is not a P-11 exception (nor, with P-03, a sticky directory), or a
  declared umask that does not cover every bit of P-07: NON_COMPLIANT. A
  partial sweep, an unreadable umask source or no umask declared:
  NOT_EVALUABLE by COLLECTION. The umask is never assumed.
- **EV-02 critical files.** A FIM alert of the window on or under a P-02 path:
  NON_COMPLIANT; every change is reported. A P-02 path FIM does not watch in
  time (not covered, ignored, FIM off, or scans further apart than the window
  without real time): NOT_EVALUABLE by COLLECTION.
- **EV-03 escalations.** Privileged accounts are UID 0, members of a P-12
  group and accounts a sudo grant names. A sudo run or su session that makes
  an unprivileged account a privileged one: NON_COMPLIANT. Becoming an
  ordinary account is lateral and accepted; refusals are the control working
  and are only reported. An elevation by a non-local account or with sudoers
  blind spots, or no elevation while the probe does not come back:
  NOT_EVALUABLE by COLLECTION.
- **EV-04 declared rights.** For each P-08 row: mode compared as octal, owner
  when declared, every declared ACL entry present and every applied named
  entry declared. A difference: NON_COMPLIANT. A path missing or unreadable:
  NOT_EVALUABLE by COLLECTION.
- **EV-05 individual privileges (ALTO).** A privileged account (as EV-03,
  without UID 0) not in P-09: NON_COMPLIANT. Sudoers blind spots or grants to
  groups or UIDs that do not exist: NOT_EVALUABLE by COLLECTION.
- **EV-06 type of access (ALTO).** For each successful audited access, the
  person (audit UID, else UID) gives a profile through P-09; the profile and
  the longest P-06 path containing the resource give the permitted types. A
  type not permitted: NON_COMPLIANT. An account without a profile is counted,
  not judged. An access with no person or no row: NOT_EVALUABLE by EVIDENCE.
  Silence needs auditd running, every P-06 path watched and the audit log
  read by Wazuh; otherwise NOT_EVALUABLE by COLLECTION.
- **EV-07 SUID, SGID and ownerless files.** An entry without owner or group,
  or a SUID or SGID file not in P-10: NON_COMPLIANT. A partial sweep with
  nothing found: NOT_EVALUABLE by COLLECTION.

## Not measured

- **Machines without auditd**, such as most containers: EV-06 is
  NOT_EVALUABLE by COLLECTION there.
- **auditd refusals** are not read; refused sudo runs are reported only.
