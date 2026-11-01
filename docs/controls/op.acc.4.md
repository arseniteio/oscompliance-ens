# op.acc.4 Proceso de gestión de derechos de acceso

op.acc.4 (management of access rights) judges what is open to anyone, who
holds which privileges against the access matrix of P-01, who changes
rights, who reaches need-to-know resources, who logs in remotely, and
whether rights are reviewed.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.2.4. Definition: [`catalog/controls/ens/op.acc.4.json`](../../catalog/controls/ens/op.acc.4.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 4.1 access denied unless authorised | B/M/A | EV-01, EV-02 |
| 4.2 least privilege | B/M/A | EV-02, EV-03, EV-08 |
| 4.3 need to know | B/M/A | EV-07 |
| 4.4 only competent staff grant rights | B/M/A | EV-03, EV-04, EV-05 |
| 4.5 remote access policy | B/M/A | EV-06 |

## Sources

| Source | Content | Used by |
|---|---|---|
| `firewall_snapshot` (`firewall`) | packet filter chains and their default policy | EV-01 |
| `config_snapshot`, `config_file` | smb.conf, vsftpd.conf, login.defs | EV-01, EV-08 |
| `sudoers_snapshot`, `sudo_grant` ([op.acc.2](op.acc.2.md)) | sudo grants | EV-02, EV-08 |
| `identity_*`, `group_*` ([op.acc.1](op.acc.1.md)) | accounts and groups | EV-03, EV-04, EV-07, EV-08 |
| `audit_watch_snapshot`, `wazuh_agent_config` ([op.acc.2](op.acc.2.md)) | auditd state, watches, audit log read by Wazuh | EV-04, EV-07 |
| rule 119004, audited accesses | changes of rights (`oscompliance_perm`) and accesses | EV-04, EV-07 |
| sshd logins, rule 5715 and children | remote logins | EV-06 |
| `auth_log_probe` and rule 119002 | the authentication log reaches Wazuh | EV-06 |

The paths of P-07 reach auditd through the group configuration the engine
writes (`audit_watches`). Changes of mode, owner and attributes, and writes
to the account and sudo files, are audited with key `oscompliance_perm`.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 access matrix `rol \| recurso \| acceso,acceso` | system; roles are accounts or sudoers subjects (`%group`, `#uid`, `%#gid`) | EV-01, EV-02, EV-03, EV-08 |
| P-02 accounts competent to change rights | first column | EV-04 |
| P-03 days between reviews | | EV-05 |
| P-04 permitted remote access channels | platform; see [op.acc.6](op.acc.6.md) | |
| P-05 accounts allowed remote access | system; up to the first `\|` | EV-06 |
| P-06 privileged groups | platform | EV-03 |
| P-07 need-to-know resources `recurso \| perfiles` | system; profiles are groups | EV-07 |
| P-08 review register `fecha \| alcance \| responsable` | | EV-05 |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opacc4`. A source missing is
NOT_EVALUABLE by COLLECTION; a parameter missing or unusable is
NOT_EVALUABLE by CONFIGURATION. Silence on a machine whose audit chain is
incomplete (auditd not running, rules not loaded, audit log not read) is
NOT_EVALUABLE by COLLECTION; a breach found stands.

- **EV-01 deny by default.** Openings are a packet filter chain that accepts
  by default, no input chain, no packet filter at all, a Samba share with
  `guest ok` or `public`, and vsftpd with `anonymous_enable`. An opening whose
  resource is not in the `recurso` column of P-01: NON_COMPLIANT. A packet
  filter with no rules is an opening.
- **EV-02 sudo against the matrix.** Each grant is looked up as `subject |
  sudo` in P-01, and every part of what it grants must be among the row's
  accesses. A grant without a row or beyond its accesses: NON_COMPLIANT. A row
  without accesses: NOT_EVALUABLE by CONFIGURATION. sudo not installed:
  COMPLIANT. Grants to subjects the agent cannot name leave silence
  NOT_EVALUABLE by COLLECTION.
- **EV-03 privileged groups.** Every member of a P-06 group, primary group
  included, must be a role of P-01; otherwise NON_COMPLIANT.
- **EV-04 who changes rights.** Every successful `oscompliance_perm` change of
  the window must be by an account of P-02; otherwise NON_COMPLIANT. Changes
  whose account cannot be named: NOT_EVALUABLE by EVIDENCE.
- **EV-05 periodic review.** The newest date of P-08 not in the future must
  be within P-03 days; otherwise NON_COMPLIANT. No usable date: NOT_EVALUABLE
  by CONFIGURATION.
- **EV-06 remote access.** Every sshd login of the window must be by an
  account of P-05; otherwise NON_COMPLIANT. No login is COMPLIANT only when
  the probe proves the log reaches Wazuh.
- **EV-07 need to know.** Each audited access under a P-07 resource (the
  longest that contains it) must be by an account with one of its profiles
  among its groups; otherwise NON_COMPLIANT. Silence needs every P-07
  resource watched by auditd.
- **EV-08 privileges above the minimum.** Sudo grants of every command, and
  system accounts (UID below `UID_MIN` of login.defs, not root) with a login
  shell, must be roles of P-01; otherwise NON_COMPLIANT.

## Not measured

- **Rights inside applications and directories.** The control reads the
  operating system: packet filter, file sharing, sudo, groups and audited
  file accesses.
- **Remote access by channels other than sshd** for EV-06; the channels
  themselves are judged by [op.acc.6](op.acc.6.md) EV-07 and EV-08.
