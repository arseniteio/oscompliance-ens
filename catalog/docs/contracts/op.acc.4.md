# op.acc.4 fact contract

op.acc.4 (management of access rights) judges what is open to anyone, who
holds which privileges against the access matrix of P-01, who changes
rights, who reaches need-to-know resources, and whether rights are
reviewed.

## 1. Requirements and evidences

| Requirement | Levels | Evidences |
|---|---|---|
| 4.1 access denied unless authorised | B/M/A | EV-01, EV-02 |
| 4.2 least privilege | B/M/A | EV-02, EV-03, EV-08 |
| 4.3 need to know | B/M/A | EV-07 |
| 4.4 only competent staff grant rights | B/M/A | EV-03, EV-04, EV-05 |
| 4.5 remote access policy | B/M/A | EV-06 |

Levels and evidence lists are in `controls/ens/op.acc.4.json`.

## 2. Facts

op.acc.4 reads facts other controls also use; none is specific to it.

| Fact | Source | Used by |
|---|---|---|
| `firewall_snapshot` | agent, `firewall` collector | EV-01 |
| `config_snapshot`, `config_file` (smb.conf, vsftpd.conf, login.defs) | agent, `config` collector (op.acc.6 contract) | EV-01, EV-08 |
| `sudoers_snapshot`, `sudo_grant` | agent, `sudoers` collector (op.acc.2 contract) | EV-02, EV-08 |
| `identity_snapshot`, `identity_record`, `group_snapshot`, `group_record` | agent (op.acc.1 contract) | EV-03, EV-04, EV-07, EV-08 |
| `audit_watch_snapshot`, `wazuh_agent_config` | agent (op.acc.2 contract) | EV-04, EV-07 |
| audited accesses, rule 119004 | auditd through Wazuh | EV-04, EV-07 |
| sshd logins, rule 5715 and children | Wazuh | EV-06 |
| `auth_log_probe` and rule 119002 | agent and Wazuh | EV-06 |

The paths of P-07 reach auditd through the shared `oscompliance.json`
(`audit_watches`); changes of mode, owner and attributes, and writes to the
account and sudo files, are audited with key `oscompliance_perm`.

## 3. Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 access matrix `rol \| recurso \| acceso,acceso` | roles are accounts or sudoers subjects (`%group`, `#uid`, `%#gid`) | EV-01, EV-02, EV-03, EV-08 |
| P-02 accounts competent to change rights (first column) | | EV-04 |
| P-03 days between reviews | | EV-05 |
| P-05 accounts allowed remote access (up to the first `\|`) | | EV-06 |
| P-06 privileged groups | | EV-03 |
| P-07 need-to-know resources `recurso \| perfiles` | profiles are groups | EV-07 |
| P-08 register of reviews `fecha \| alcance \| responsable` | | EV-05 |

P-08 is new: v1 read the register from a file on every machine. The plugin
must offer it (open point).

## 4. Evidence judgement

Judges are in `engine/internal/controls/ens/opacc4`. A fact missing or
unreadable is NOT_EVALUABLE by COLLECTION; a parameter missing or unusable is
NOT_EVALUABLE by CONFIGURATION. The audit chain of a machine is complete when
auditd runs, the rules needed are loaded and Wazuh reads the audit log;
silence with an incomplete chain is NOT_EVALUABLE by COLLECTION, a breach
found stands.

- **EV-01 deny by default.** Openings are a packet filter chain that
  accepts by default, no input chain or no packet filter at all, a Samba
  share with `guest ok` or `public`, and vsftpd with `anonymous_enable`. An
  opening whose resource is not in the recurso column of P-01:
  NON_COMPLIANT. No opening: COMPLIANT.
- **EV-02 sudo against the matrix.** Each sudo grant is looked up as
  `subject | sudo` in P-01, and every part of what it grants must be among
  the row's accesses. A grant without a row or beyond its accesses:
  NON_COMPLIANT. A row without accesses: NOT_EVALUABLE by CONFIGURATION.
  sudo not installed: COMPLIANT. Grants to subjects the agent cannot name
  leave silence NOT_EVALUABLE by COLLECTION.
- **EV-03 privileged groups.** Every member of a P-06 group, primary group
  included, must be a role of P-01; otherwise NON_COMPLIANT.
- **EV-04 who changes rights.** Every successful `oscompliance_perm` change
  of the window must be by an account of P-02: otherwise NON_COMPLIANT.
  Changes whose account cannot be named: NOT_EVALUABLE by EVIDENCE.
- **EV-05 periodic review.** The newest date of P-08 not in the future must
  be within P-03 days: otherwise NON_COMPLIANT. No usable date:
  NOT_EVALUABLE.
- **EV-06 remote access.** Every sshd login of the window must be by an
  account of P-05: otherwise NON_COMPLIANT. No login is COMPLIANT only when
  the auth log probe proves the log reaches Wazuh.
- **EV-07 need to know.** Each audited access under a P-07 resource (the
  longest that contains it) must be by an account with one of its profiles
  among its groups: otherwise NON_COMPLIANT. Silence needs every P-07
  resource watched by auditd.
- **EV-08 privileges above the minimum.** Sudo grants of every command and
  system accounts (UID below UID_MIN of login.defs, not root) with a login
  shell must be roles of P-01: otherwise NON_COMPLIANT. None: COMPLIANT.

## 5. Parity with v1 and deliberate differences

Kept: the eight evidences, the matrix of P-01 and the parameters' meaning.

Changed on purpose:

- A packet filter with no rules is an opening; v1 passed a machine with an
  empty ruleset.
- A sudo grant without a P-01 row is NON_COMPLIANT; v1 left it
  NOT_EVALUABLE.
- Accesses are split on commas outside parentheses, so a grant with a
  comma matches the same text in P-01; v1 never matched it.
- EV-08 passes a machine with no finding; v1 required at least one.
- P-05 lines are read up to the first `|`, so an annotation does not turn an
  authorised account into an offender.
- P-07 resources cover what is under them, and profiles are checked against
  every group of the account; v1 compared the exact path and the primary
  group only.
- The review register is a parameter (P-08); a date in the future is left
  out instead of hiding the real ones.

## 6. Open points

- The plugin must offer P-08.
- The manager side must write the P-07 paths to `audit_watches`.
