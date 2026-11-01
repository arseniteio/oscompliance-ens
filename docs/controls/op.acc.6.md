# op.acc.6 Mecanismo de autenticación (usuarios de la organización)

op.acc.6 (authentication mechanism, organisation users) judges how staff
authenticate on each Linux machine: the factors each channel demands by zone,
lockout, credential age and quality, disablement after a notice, remote
channels, re-authentication at critical points, suspension after non-use and
what is exposed before authenticating.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.2.6. Definition: [`catalog/controls/ens/op.acc.6.json`](../../catalog/controls/ens/op.acc.6.json).

## Requirements

| Requirement | Levels | Evidences | Proven by |
|---|---|---|---|
| 6.1, 6.2, 6.3, 6.9 | B/M/A | | P-ATT |
| 6.4 periodic credential change | B/M/A | EV-05 | P-04 |
| 6.5, 6.6 disablement on compromise or leaving | B/M/A | EV-06 | P-06, P-12 |
| 6.7 nothing revealed before authenticating | B/M/A | EV-12 | P-11 |
| 6.8 attempt limit with lockout | B/M/A | EV-03, EV-04 | P-05 |
| r1.1 password only from controlled zones (R1) | B/M/A | EV-02 | P-01, P-02 |
| r1.2 password quality (R1, R2) | B/M/A | EV-11 | P-01, P-10 |
| r2.1 second factor (R2) | B/M/A | EV-02 | P-01 |
| r3.1, r3.2, r4.1, r4.2 certificates (R3, R4) | B/M/A | | P-01, P-ATT |
| r5.1 logging of accesses | M/A | EV-01 | P-03 |
| r5.2 notice of last access | M/A | | P-ATT |
| r6.1 re-authentication at critical points | A | EV-09 | P-08 |
| r7.1 suspension after non-use | A | EV-10 | P-09 |
| r8.1 two factors from uncontrolled zones | B/M/A | EV-02 | P-02 |
| r9.1 interconnection ITS | B/M/A | | P-ATT |
| r9.2 remote access authorised and encrypted | B/M/A | EV-07, EV-08 | P-07 |

## Sources

| Source | Content | Used by |
|---|---|---|
| `identity_*` (`identity`) | accounts, last password change, maximum and inactive days, newest change of the key files, last login from wtmp and lastlog | EV-05, EV-06, EV-10 |
| `config_snapshot`, `config_file` (`config`) | login.defs, faillock.conf, pwquality.conf and drop-ins, pwhistory.conf, sshd_config and drop-ins, `sshd -T`, `ssh -V` | EV-01, EV-02, EV-03, EV-05, EV-11, EV-12 |
| `pam_snapshot`, `pam_rule` (`pam`) | auth and password stacks of sshd, login, greeters, su, sudo and passwd, includes and substacks resolved | EV-02, EV-03, EV-09, EV-11 |
| `sudoers_snapshot`, `sudo_grant` (`sudoers`) | NOPASSWD commands and Defaults | EV-09 |
| `listening_snapshot`, `listening_socket` (`listening`) | non-loopback listeners with process, systemd unit, socket unit and whether they start at boot | EV-02, EV-08 |
| `auth_log_probe` and rule 119002 | the authentication log reaches Wazuh | EV-01, EV-02, EV-04, EV-07 |
| `authentication_success`: sshd (5715) and PAM sessions of login and greeters (5501) | logins, with sshd method and key type | EV-02, EV-07, EV-10 |
| `authentication_failed` with `data.dstuser`, not `invalid_login` | failures against existing accounts | EV-04 |
| pam_faillock and pam_tally2 lockout lines | lockouts | EV-04 |
| `oscompliance-identity-history` ([op.acc.1](op.acc.1.md)) | when an account was disabled or deleted | EV-06 |

Only the keys the controls judge are sent from configuration files, which can
hold secrets. PAM is resolved the same way on Debian (`common-*`) and RHEL
(`system-auth`, `password-auth`); a rule whose module is not installed is
marked.

The agent writes `auth log probe <run_id>` to syslog (authpriv, tag
`oscompliance-agent`) on every pass. Rule 119002 for that line proves the
authentication log reaches Wazuh whether or not anybody logged in. A probe
written more than ten minutes ago that never came back proves it does not.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 mechanism: R1, R2, R3 or R4 | one, not cumulative | decisions on r1.x to r4.x |
| P-02 controlled zones: CIDR, address or `local` | | EV-02 |
| P-03 sources whose accesses must be logged | platform | EV-01 |
| P-04 days between credential changes | | EV-05 |
| P-05 maximum failed attempts | | EV-03, EV-04 |
| P-06 hours to disable after a notice | | EV-06 |
| P-07 `canal \| cifrado \| autoriza \| uso_constante` | platform | EV-07, EV-08 |
| P-08 critical points: `sudo`, `su`, `sudo:/path` | platform | EV-09 |
| P-09 days of non-use before suspension | | EV-10 |
| P-10 `criterio \| minimo` | | EV-11 |
| P-11 exposures allowed, or `ninguna` | platform | EV-12 |
| P-12 register `usuario \| fecha \| motivo` | dates RFC 3339 or a day | EV-06 |
| P-ATT documentary attestations | | documentary requirements |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opacc6`. A source missing or
incomplete is NOT_EVALUABLE by COLLECTION; a parameter missing or unusable is
NOT_EVALUABLE by CONFIGURATION, never a product default.

- **EV-01 logging.** P-03 without `local`: COMPLIANT, directory sources are
  measured on their own servers. Otherwise NON_COMPLIANT when the probes do
  not come back or sshd `LogLevel` is QUIET, FATAL or ERROR.
- **EV-02 factors by zone.** Factors: publickey 1 (2 for a `-SK` key with
  `verify-required`), password 1, keyboard-interactive 2 when the sshd auth
  stack requires a second-factor module (google_authenticator, oath, u2f,
  duo, radius_auth, yubico, totp; not optional, not sufficient), the console
  likewise from the login stack. `AuthenticationMethods` raises the count to
  its weakest list. A channel listening on an address outside P-02 is
  exposed; a wildcard address is every address of the machine. A one-factor
  result under a `Match` block: NOT_EVALUABLE by EVIDENCE. Judged once per
  requirement (see below).
- **EV-03 lockout configuration.** Each password path in use (sshd with
  password or keyboard-interactive, login and the greeters) needs a
  pam_faillock or pam_tally2 auth rule that is not optional, with `deny` at
  most P-05 and no automatic unlock. pam_faillock settings come from the rule,
  then faillock.conf, then its defaults (3, 600). No path accepting passwords:
  COMPLIANT.
- **EV-04 failures without lockout.** Per existing account, the most failures
  within any 15 minutes, all origins together. Above P-05 with no lockout of
  the account in the window: NON_COMPLIANT. No failure: COMPLIANT when the log
  reaches Wazuh.
- **EV-05 credential age.** Accounts that can log in, any UID. A password
  older than P-04, without a maximum or with a maximum above P-04; key files
  unchanged for more than P-04; login.defs giving new accounts a maximum above
  P-04 or none: NON_COMPLIANT. A forced change at the next login counts as
  fresh.
- **EV-06 disablement after a notice.** For each P-12 row of an account the
  identity history knows on this machine: the hours from the notice to the
  first pass that saw it disabled or deleted, or, still enabled, the hours so
  far. Above P-06: NON_COMPLIANT. An account already disabled when first seen
  after the notice gives only an upper bound: within P-06 it is on time,
  beyond it NOT_EVALUABLE by EVIDENCE. No row for this machine: COMPLIANT.
- **EV-07 remote channel used.** Remote logins of the window by channel (sshd
  is `ssh`). A channel not in the `canal` column of P-07: NON_COMPLIANT. No
  remote login: COMPLIANT when the log reaches Wazuh.
- **EV-08 listening channels.** Authentication channels: sshd (ssh), slapd
  (ldap, ldaps), xrdp (rdp), vnc, telnetd, vsftpd, proftpd and pure-ftpd
  (ftp), cockpit-ws (cockpit), webmin; transport channels: openvpn,
  tailscaled. No P-07 row, not encrypted, or enabled at boot while its row
  says `uso_constante` no: NON_COMPLIANT. Boot state unknown where the row
  needs it: NOT_EVALUABLE by EVIDENCE. No channel listening: COMPLIANT.
- **EV-09 re-authentication (ALTO).** Point `sudo`: NOPASSWD for ALL,
  `!authenticate`, or `timestamp_timeout` below 0. Point `sudo:<command>`:
  NOPASSWD for that command. Point `su`: pam_wheel with `trust`. root's own
  grants are left out. A finding at a point of P-08: NON_COMPLIANT. An
  undefined Cmnd_Alias under NOPASSWD: NOT_EVALUABLE by COLLECTION.
- **EV-10 non-use (ALTO).** Accounts that can log in, any UID. Last use is the
  newest of wtmp, lastlog and the login alerts (key logins without a terminal
  are not in wtmp); never used, the newest credential date. Idle longer than
  P-09: NON_COMPLIANT. No use and no credential date: NOT_EVALUABLE by
  EVIDENCE.
- **EV-11 password quality.** The password stack of passwd: pam_pwquality
  (rule, then pwquality.conf and drop-ins; defaults minlen 8, dictcheck 1),
  else pam_cracklib (minlen 9, dictionary always), else pam_unix (minlen 6
  with obscure, else 1). Classes: minclass or the number of negative credits,
  whichever is larger. History: pam_pwhistory (default 10) or pam_unix
  `remember`. A criterion below its P-10 minimum: NON_COMPLIANT.
- **EV-12 exposure before authenticating.** From the configuration, no
  connection opened. sshd not installed: COMPLIANT. Exposures:
  `sshd:version_software` always, `sshd:version_distribucion` with
  DebianBanner on, `sshd:version_addendum`, `sshd:banner_previo`. One not in
  P-11: NON_COMPLIANT.

## Requirement decisions

op.acc.6 decides some requirements itself, only where the requirement
applies by level; a decision replaces the aggregation of its evidences and
any attestation.

- **P-01** not set or not R1 to R4: the seven mechanism requirements are
  NOT_EVALUABLE by CONFIGURATION and count against; no attestation proves a
  reinforcement nobody chose. Set: the requirements of the other mechanisms
  are NOT_APPLICABLE.
- **EV-02 per requirement.** r8.1: a login from outside P-02 with one factor,
  or an exposed channel accepting one factor, fails. r1.1: the same for logins
  and channels that use a password. r2.1: any login or channel with one
  factor fails. The EV-02 verdict is the worst of the requirements that apply.

## Not measured

- **Certificates (R3, R4) and the last access notice (r5.2)** leave no record
  on the machine; they are judged by attestation.
- **Directory and application authentication.** The control reads each
  machine's PAM, sshd and sudo; directory servers are measured as machines of
  their own.
