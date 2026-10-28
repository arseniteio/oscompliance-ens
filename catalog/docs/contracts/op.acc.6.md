# op.acc.6 fact contract

op.acc.6 (authentication mechanism, organisation users) on Linux. The agent
reports configuration and state; Wazuh reports authentication events from its
own decoders; the engine judges both against the plugin parameters.

## 1. Requirements and evidences

| Requirement | Levels | Evidences | Proven by |
|---|---|---|---|
| 6.1, 6.2, 6.3, 6.9 | B/M/A | – | P-ATT |
| 6.4 periodic credential change | B/M/A | EV-05 | P-04 |
| 6.5, 6.6 disablement on compromise or leaving | B/M/A | EV-06 | P-06, register |
| 6.7 nothing revealed before authenticating | B/M/A | EV-12 | P-11 |
| 6.8 attempt limit with lockout | B/M/A | EV-03, EV-04 | P-05 |
| r1.1 password only from controlled zones (R1) | B/M/A | EV-02 | P-01, P-02 |
| r1.2 password quality (R1, R2) | B/M/A | EV-11 | P-01, P-10 |
| r2.1 second factor (R2) | B/M/A | EV-02 | P-01 |
| r3.1, r3.2, r4.1, r4.2 certificates (R3, R4) | B/M/A | – | P-01, P-ATT |
| r5.1 logging of accesses | M/A | EV-01 | P-03 |
| r5.2 notice of last access | M/A | – | P-ATT |
| r6.1 re-authentication at critical points | A | EV-09 | P-08 |
| r7.1 suspension after non-use | A | EV-10 | P-09 |
| r8.1 two factors from uncontrolled zones | B/M/A | EV-02 | P-02 |
| r9.1 interconnection ITS | B/M/A | – | P-ATT |
| r9.2 remote access authorized and encrypted | B/M/A | EV-07, EV-08 | P-07 |

Levels and evidence lists are in `controls/ens/op.acc.6.json`.

## 2. Facts

Agent facts are shared by every control that needs them; none is specific to
op.acc.6. Each pass emits its records first and a snapshot last with
`records_emitted`. A collector whose records and snapshot did not change
sends nothing, and everything every 3 days; the pass ends with `agent_pass`,
which names the snapshot that still holds. The engine uses the newest
complete pass in the window, or the older one the newest `agent_pass` holds.

| Fact | Collector | Used by |
|---|---|---|
| `identity_record`, `identity_snapshot` | `identity` | EV-05, EV-06 (through the op.acc.1 history), EV-10 |
| `config_file`, `config_snapshot` | `config` | EV-01, EV-02, EV-03, EV-05, EV-11, EV-12 |
| `pam_rule`, `pam_snapshot` | `pam` | EV-02, EV-03, EV-09, EV-11 |
| `sudo_grant`, `sudoers_snapshot` | `sudoers` | EV-09 |
| `listening_socket`, `listening_snapshot` | `listening` | EV-02, EV-08 |
| `auth_log_probe` | `authprobe` | EV-01, EV-02, EV-04, EV-07 |

Schemas: `catalog/schemas/facts`. What each collector reads:

- **identity**: passwd and shadow (never the hash), the keys sshd would accept,
  the last password change, the maximum and inactive days, the newest change
  of the key files, and the last login from wtmp, wtmp.1 and lastlog.
- **config**: login.defs, faillock.conf, pwquality.conf and its drop-ins,
  pwhistory.conf, sshd_config and its drop-ins (Match lines), `sshd -T` and
  `ssh -V`. Only the keys the controls judge are sent: configuration files
  can hold secrets.
- **pam**: the auth and password stacks of sshd, login, the graphical
  greeters, su, su-l, sudo and passwd, with `@include`, `include` and
  `substack` resolved, so Debian (`common-*`) and RHEL (`system-auth`,
  `password-auth`) read the same. Only the judged arguments are sent, and a
  rule whose module is not installed is marked.
- **sudoers**: every user specification with the commands it runs without a
  password (tags carried over, Cmnd_Alias expanded) and every Defaults setting.
- **listening**: TCP sockets in LISTEN and UDP sockets without a peer, loopback
  left out, matched to their process through `/proc`, with the systemd unit,
  the socket unit (socket activation) and `systemctl is-enabled` of both.
- **authprobe**: writes `auth log probe <run_id>` to syslog, facility authpriv,
  tag `oscompliance-agent`. When Wazuh raises rule 119002 for it, the
  authentication log of the machine reaches Wazuh, whether or not anybody
  logged in. Wazuh ignores cron sessions (rule 5521, level 0), so the absence
  of other events proves nothing.

Wazuh alerts used as they are:

| Alerts | Used as | Evidences |
|---|---|---|
| group `authentication_success`, sshd (5715) and PAM sessions of login, gdm-password, lightdm, sddm (5501) | logins, with the sshd method and key type from `full_log` | EV-02, EV-07, EV-10 |
| group `authentication_failed` with `data.dstuser`, not `invalid_login` | failed attempts against existing accounts | EV-04 |
| `full_log` with pam_faillock "account temporarily locked" or pam_tally2 "tally N, deny M" | lockouts | EV-04 |
| rule 119002 | the probe came back | EV-01, EV-02, EV-04, EV-07 |

## 3. Parameters

| ID | Class | Type | Used by |
|---|---|---|---|
| P-01 mechanism, R1 to R4 | organisation | select | decisions on r1.x to r4.x |
| P-02 controlled zones: CIDR, address or `local`, comment after a blank | organisation | list | EV-02 |
| P-03 sources whose accesses must be logged | platform | list | EV-01 |
| P-04 days | organisation | number | EV-05 |
| P-05 attempts | organisation | number | EV-03, EV-04 |
| P-06 hours | organisation | number | EV-06 |
| P-07 `canal \| cifrado \| autoriza \| uso_constante` | platform | table | EV-07 (canal), EV-08 |
| P-08 `sudo`, `su`, `sudo:/path` | platform | list | EV-09 |
| P-09 days | organisation | number | EV-10 |
| P-10 `criterio \| minimo` | organisation | table | EV-11 |
| P-11 exposures allowed, or `ninguna` | platform | list | EV-12 |
| P-12 register `usuario \| fecha \| motivo` | organisation | table | EV-06 |
| P-ATT | organisation | table | documentary requirements |

P-12 is not in the plugin yet. v1 read a file maintained on every machine
(`/etc/power-ens/opacc6-incidencias.tsv`). Until the plugin offers it, EV-06 is
NOT_EVALUABLE by CONFIGURATION. Dates are RFC 3339 or a day (00:00 UTC).

A parameter that is not set gives NOT_EVALUABLE by CONFIGURATION on the
evidences that need it, never a product default.

## 4. Evidence judgement

Every judge is in `engine/internal/controls/ens/opacc6`. A fact read that is
missing or incomplete gives NOT_EVALUABLE by COLLECTION. "The log reaches
Wazuh" means a probe of the window came back; a probe written more than ten
minutes ago that never came back means it does not.

- **EV-01 logging.** P-03 without `local`: COMPLIANT, directory sources are
  measured on their own servers. Otherwise NON_COMPLIANT when the probes do
  not come back or sshd `LogLevel` is QUIET, FATAL or ERROR; COMPLIANT when
  the probe came back and sshd logs at INFO or more.
- **EV-02 factors by zone.** Judged once per requirement (section 5). Factors:
  publickey 1 (2 for a `-SK` key with `PubkeyAuthOptions verify-required`),
  password 1, keyboard-interactive 2 when the sshd auth stack requires a
  second-factor module (google_authenticator, oath, u2f, duo, radius_auth,
  yubico, totp; not optional, not sufficient), the console likewise from the
  login stack. `AuthenticationMethods` raises the count to its weakest list.
  Channels are the authentication channels listening (EV-08 mapping); one on
  an address outside P-02 is exposed, a wildcard address is every address of
  the machine. A one-factor result under a Match block in sshd_config is
  NOT_EVALUABLE by EVIDENCE: Match can change it per user.
- **EV-03 lockout configuration.** The password paths in use: sshd when
  `PasswordAuthentication` or `KbdInteractiveAuthentication` (with UsePAM) is
  yes; login and the greeters when they have a PAM file. Each needs a
  pam_faillock or pam_tally2 auth rule that is not optional, with `deny` at
  most P-05 and no automatic unlock (`unlock_time` 0 or never). pam_faillock
  settings come from the rule, then faillock.conf, then its defaults (3, 600).
  No path accepting passwords: COMPLIANT.
- **EV-04 failures without lockout.** Per existing account, the most failures
  within any 15 minutes, all origins together. More than P-05 with no lockout
  of the account in the window: NON_COMPLIANT. No failure: COMPLIANT when the
  log reaches Wazuh.
- **EV-05 credential age.** Accounts that can log in (op.acc.1 rule: not a
  no-login shell, not expired, a usable password or a key), any UID. A
  password older than P-04, without a maximum or with a maximum above P-04;
  keys whose files have not changed for more than P-04; login.defs giving new
  accounts a maximum above P-04 or none: NON_COMPLIANT. A forced change at the
  next login counts as fresh.
- **EV-06 disablement after a notice.** For each P-12 row of an account the
  op.acc.1 history knows on this machine: the hours from the notice to the
  first pass that saw the account disabled or deleted, or, still enabled, the
  hours since the notice. More than P-06: NON_COMPLIANT. An account already
  disabled when first seen after the notice gives only an upper bound: within
  P-06 it counts as on time, beyond it NOT_EVALUABLE by EVIDENCE. No row for
  this machine: COMPLIANT.
- **EV-07 remote channel used.** Remote logins of the window by channel (sshd
  is `ssh`). A channel not in the canal column of P-07, compared without case:
  NON_COMPLIANT. No remote login: COMPLIANT when the log reaches Wazuh.
- **EV-08 listening channels.** Process or unit to channel: sshd ssh, slapd
  ldap or ldaps (636), xrdp rdp, any vnc, telnetd telnet, vsftpd, proftpd and
  pure-ftpd ftp, cockpit-ws cockpit, miniserv.pl webmin (authentication);
  openvpn and tailscaled (transport). Other listeners are not access channels.
  NON_COMPLIANT: no P-07 row, not encrypted, or enabled at boot while its row
  says `uso_constante` no. `uso_constante` si allows both states. Enablement
  unknown where the row needs it (no systemd): NOT_EVALUABLE by EVIDENCE. No
  channel listening: COMPLIANT.
- **EV-09 re-authentication (ALTO).** Point `sudo`: NOPASSWD for ALL,
  `!authenticate`, or `timestamp_timeout` below 0. Point `sudo:<command>`:
  NOPASSWD for that command. Point `su`: pam_wheel with `trust`. root's own
  grants are left out. A finding at a point of P-08 is NON_COMPLIANT; a
  `sudo` finding reaches any listed sudo point. An undefined Cmnd_Alias under
  NOPASSWD: NOT_EVALUABLE by COLLECTION.
- **EV-10 non-use (ALTO).** Accounts that can log in, any UID. Last use: the
  newest of the last login (wtmp, lastlog) and the newest login alert (logins
  without a terminal are not in wtmp). Never used: the newest credential date
  counts. Idle longer than P-09: NON_COMPLIANT. No use and no credential date:
  NOT_EVALUABLE by EVIDENCE.
- **EV-11 password quality.** The password stack of passwd. pam_pwquality
  (rule, then pwquality.conf and its drop-ins, the last value wins; defaults
  minlen 8, dictcheck 1), else pam_cracklib (minlen 9, dictionary always),
  else pam_unix (minlen 6 with obscure, else 1). Classes: minclass or the
  number of negative credits, whichever is larger. History: pam_pwhistory
  (rule, then pwhistory.conf, default 10) or pam_unix `remember`. A criterion
  below its P-10 minimum: NON_COMPLIANT.
- **EV-12 exposure before authenticating.** From the configuration, no
  connection opened. sshd not installed: COMPLIANT. Exposures:
  `sshd:version_software` always, `sshd:version_distribucion` with
  DebianBanner on (the default of Debian and Ubuntu builds),
  `sshd:version_addendum`, `sshd:banner_previo`. One not in P-11:
  NON_COMPLIANT.

## 5. Requirement decisions

op.acc.6 decides some requirements itself (`evaluator.Decider`); a decision
applies only where the requirement applies by level and replaces the
aggregation of its evidences and any P-ATT row.

- **P-01.** Not set or not R1 to R4: the seven mechanism requirements are
  NOT_EVALUABLE by CONFIGURATION and count against; no P-ATT row proves a
  reinforcement nobody chose. Set: the requirements of other mechanisms are
  NOT_APPLICABLE. The chosen ones are proven by their evidences (r1.1, r1.2,
  r2.1) or by P-ATT (r3.x, r4.x).
- **EV-02.** r8.1: a login from outside P-02 with one factor, or an exposed
  channel accepting one factor, fails. r1.1: the same for logins and channels
  that use a password. r2.1: any login or channel with one factor fails. The
  EV-02 evidence verdict is the worst of the requirements that apply.

Requirement and control aggregation follow op.acc.1 (section 7 there).

## 6. Wazuh rules

`catalog/wazuh/oscompliance_facts_rules.xml`: 119001 indexes every fact,
119002 indexes the probe line. No rule per evidence and no verdict in a rule.
Fact fields avoid the objects of the Wazuh alerts template (`data.port`,
`data.process` and others); `catalog/fact` tests it.

## 7. Parity with v1 and deliberate differences

Kept: the parameters and their meaning, the exposure and point names of P-08
and P-11, the factor model, the defaults of pam_faillock, pwquality and
cracklib, the P-01 gate, the EV-02 variants per requirement.

Changed on purpose:

- EV-01 proves collection with the probe instead of a local log reader with
  offsets and a dead-source grep.
- EV-03 reads every password path (sshd, login, greeters), resolves RHEL
  `include` and `substack`, and ignores optional lockout rules.
- EV-04 counts per account in any 15 minutes across origins, not per origin
  and per hourly run, which a spread or slow attack escaped.
- EV-05 reads login.defs (declared but never read in v1).
- EV-06 measures from the op.acc.1 history, accepts an upper bound within
  P-06, and takes the register from a parameter instead of a file per machine.
- EV-07 compares channels without case.
- EV-08 fails a channel without a P-07 row (v1: NOT_EVALUABLE, against what
  P-07 itself says), fails any unencrypted channel, lets `uso_constante` si
  allow a disabled unit, and is COMPLIANT on a machine with no channel.
- EV-09 reads every NOPASSWD command, expands aliases, follows every include
  and reads Defaults by key, not by substring.
- EV-10 adds login alerts to wtmp and lastlog, so key logins without a
  terminal count as use.
- EV-11 reads pwhistory.conf, applies the pwquality drop-ins after the main
  file, counts classes without adding minclass and credits, and reads the
  passwd stack, so RHEL and Debian read the same.
- A P-ATT row for R3 or R4 no longer proves anything while P-01 is unset.

## 8. Open points

- P-12, the register of compromised and departed accounts, must be added to
  the plugin as an organisation table.
- The manager (agent 000) needs the agent installed and the localfile in its
  own ossec.conf to be judged like any machine.
