# op.acc.2 fact contract

op.acc.2 (access requirements) on Linux. The agent reports the file system,
the umask declarations, sudoers, the ACLs and audit watches the manager asks
for, and what the Wazuh agent watches. Wazuh reports file changes (FIM), sudo
and su, and audited accesses. The engine judges against the plugin
parameters.

## 1. Requirements and evidences

| Requirement | Levels | Evidences |
|---|---|---|
| 2.1 resources protected by access control | B/M/A | EV-01, EV-03, EV-07 |
| 2.2 rights as the policy declares | B/M/A | EV-03, EV-04 |
| 2.3 OS resources protected from change | B/M/A | EV-02, EV-03, EV-07 |
| r1.1 individual privileges (R1) | A | EV-05 |
| r1.2 access limited to the type permitted (R1) | A | EV-05, EV-06 |

Aggregation follows op.acc.1 (section 7 there).

## 2. Facts

| Fact | Collector | Used by |
|---|---|---|
| `special_file`, `file_sweep_snapshot` | `sweep` (daily) | EV-01, EV-07 |
| `umask_snapshot` | `umask` | EV-01 |
| `identity_record`, `identity_snapshot`, `group_record`, `group_snapshot` | `identity`, `groups` | EV-03, EV-05, EV-06 |
| `sudo_grant`, `sudoers_snapshot` | `sudoers` | EV-03, EV-05 |
| `wazuh_agent_config` | `wazuh` | EV-02, EV-06 |
| `acl_record`, `acl_snapshot` | `acl` | EV-04 |
| `audit_watch_snapshot` | `audit` | EV-06 |
| `auth_log_probe` | `authprobe` | EV-03 |

Schemas: `catalog/schemas/facts`.

- **sweep**: one walk of the local file systems (`/` always, other local
  mounts, no network or pseudo file systems, symlinks not followed) reporting
  world-writable entries, SUID and SGID files, and entries without owner or
  group. A time limit and a record limit mark the sweep partial instead of
  hiding what is left.
- **umask**: every `umask` declaration of login.defs, /etc/profile,
  /etc/bash.bashrc and /etc/profile.d/*.sh, anywhere in a line.
- **sudoers**: user specifications with their subjects (aliases expanded,
  groups and uids left for the engine) and NOPASSWD commands, and every
  Defaults setting; `@include`, `#include` and `@includedir` followed.
- **wazuh**: the FIM directories, ignores and frequency, and the localfiles,
  of the agent's ossec.conf and of the shared blocks that apply to it.
- **acl**, **audit**: they read `/var/ossec/etc/shared/oscompliance.json`,
  which the manager places in the group's shared files (section 3). `acl`
  reports mode, owner and POSIX ACL of each `acl_paths` entry. `audit` loads,
  for each `audit_watches` entry, four auditd watches, one per permission
  (r, w, x, a) with keys `oscompliance_read`, `_write`, `_exec`, `_attr`, so
  every audited access carries its kind; it never removes a rule.

Wazuh alerts used as they are:

| Alerts | Used as | Evidence |
|---|---|---|
| group `syscheck` with `syscheck.path` | file changes | EV-02 |
| sudo 5402, 5403, 5407 (run) and 5401, 5404, 5405, 5406 (refused); PAM sessions of su (5501) | elevations | EV-03 |
| rule 119004: auditd records with an `oscompliance_*` key | audited accesses | EV-06 |

Wazuh's audit rules leave unknown keys at level 0; rule 119004 indexes ours.

## 3. Paths from parameters

Some paths come from parameters the agent cannot read: P-08 (rights to
check) and P-06 (resources to audit). The manager writes them to a shared
file of the group, which Wazuh copies to every agent of the group:

```json
{"acl_paths": ["/srv/datos"], "audit_watches": ["/srv/datos"]}
```

The FIM paths (P-02) need no file: Wazuh FIM already watches /etc, /usr/bin,
/usr/sbin, /bin, /sbin and /boot by default, and the engine checks that each
P-02 path is covered. A P-02 path elsewhere needs a `<directories>` entry in
the group configuration. The audit log reaches Wazuh through a localfile
with `log_format audit` in the group configuration. Writing the shared file
and those entries from the parameters belongs to the manager side (plugin or
installer); the lab writes its own in `scripts/manager-setup.sh`.

## 4. Parameters

| ID | Class | Used by |
|---|---|---|
| P-02 critical paths | platform | EV-01 (scope), EV-02 |
| P-03 world-writable allowed (sticky) | organisation | EV-01 |
| P-05 privilege model | organisation | EV-05 (presence) |
| P-06 `perfil \| recurso \| tipos_permitidos` | system | EV-06 |
| P-07 minimum umask | organisation | EV-01 |
| P-08 `recurso \| modo \| propietario_grupo \| acl_esperada` | system | EV-04 |
| P-09 `usuario \| perfil \| privilegios` | system | EV-05, EV-06 |
| P-10 authorised SUID and SGID | platform | EV-07 |
| P-11 world-writable exceptions | platform | EV-01 |
| P-12 privileged groups | platform | EV-03, EV-05 |

## 5. Evidence judgement

Judges are in `engine/internal/controls/ens/opacc2`.

- **EV-01 world-writable and umask.** A world-writable entry under a P-02
  path that is not a P-11 exception (nor, with P-03, a sticky directory), or
  a declared umask that does not cover every bit of P-07: NON_COMPLIANT. A
  partial sweep, an unreadable umask source or no umask declared:
  NOT_EVALUABLE by COLLECTION. The umask is never assumed.
- **EV-02 critical files.** A FIM alert of the window on a P-02 path or
  under a P-02 directory: NON_COMPLIANT, as v1, every change is reported. A
  P-02 path FIM does not watch in time (no directory covers it, it is
  ignored, FIM is off, or scheduled scans are further apart than the window
  and the directory is not real time): NOT_EVALUABLE by COLLECTION.
- **EV-03 escalations.** Privileged: UID 0, members of a P-12 group (primary
  group included) and accounts a sudo grant names. A sudo run or su session
  that makes an unprivileged local account a privileged one: NON_COMPLIANT.
  Becoming an ordinary account is lateral and fine; refusals are the control
  working and only reported. An elevation by an account that is not local, or
  with sudoers blind spots: NOT_EVALUABLE by COLLECTION. No elevation while
  the auth log probe does not come back: NOT_EVALUABLE by COLLECTION.
- **EV-04 declared rights.** For each P-08 row: mode compared as octal
  numbers, owner when declared, every declared ACL entry present and every
  applied named entry declared (base entries are the mode's). A difference:
  NON_COMPLIANT. A path missing, unreadable or not sent to the agent:
  NOT_EVALUABLE by COLLECTION, a gap and not a deviation.
- **EV-05 individual privileges (ALTO).** A privileged account (as EV-03,
  without UID 0) not in P-09: NON_COMPLIANT. Sudoers blind spots or grants to
  groups or uids that do not exist: NOT_EVALUABLE by COLLECTION.
- **EV-06 type of access (ALTO).** Each successful audited access: the person
  (audit uid, else uid) gives a profile through P-09, the profile and the
  longest P-06 path containing the resource give the permitted types. A type
  not permitted: NON_COMPLIANT. An account without a profile is counted, not
  judged, as v1. An access with no person or no row: NOT_EVALUABLE by
  EVIDENCE. Silence needs auditd running, every P-06 path watched and the
  audit log read by Wazuh: otherwise NOT_EVALUABLE by COLLECTION.
- **EV-07 SUID, SGID and ownerless files.** An entry without owner or group,
  or a SUID or SGID file not in P-10: NON_COMPLIANT. A partial sweep with
  nothing found: NOT_EVALUABLE by COLLECTION.

## 6. Parity with v1 and deliberate differences

Kept: the parameters and their meaning, every change of a critical file
being reported, the privileged set, accounts without a profile not judged.

Changed on purpose:

- The agent keeps no state. FIM is Wazuh's own; the baseline, the hashes and
  the comparison of v1 are gone.
- EV-02 proves silence by FIM coverage of each P-02 path instead of a
  heartbeat.
- EV-03 reads Wazuh's sudo and su alerts instead of parsing the auth log, and
  proves silence with the auth log probe; auditd refusals, which v1 only
  counted, are not read.
- EV-06 learns the kind of access from the watch key (one watch per
  permission) instead of decoding syscalls and open flags, so new syscalls
  (openat2) are not blind spots.
- Paths that come from parameters reach the agent through a shared file of
  the group instead of files maintained on every machine; v1 regenerated
  audit rules from local files every pass.
- The umask is read anywhere in a line, not only as the first word.
- The sweep always includes `/` whatever its file system type (an overlay
  root was skipped).

## 7. Open points

- The manager side must write `oscompliance.json`, the FIM directories for
  P-02 paths outside the default ones, and the audit localfile.
- Containers without auditd leave EV-06 NOT_EVALUABLE by COLLECTION.
