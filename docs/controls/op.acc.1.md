# op.acc.1 Identificación

op.acc.1 (identification) judges that every person and process has its own
identifier: UIDs are unique, identity changes are recorded, generic and
service accounts do not log in, administrators use a separate account,
departed users are disabled in time and kept before deletion, and every
active account is authorised.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.2.1. Definition: [`catalog/controls/ens/op.acc.1.json`](../../catalog/controls/ens/op.acc.1.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 1.1 valid unique identifier | B/M/A | EV-03 |
| 1.2 separate identifiers per role | B/M/A | EV-05, EV-06 |
| 1.3 one identifier per entity | B/M/A | EV-01, EV-02, EV-03, EV-05 |
| 1.4 account life cycle | B/M/A | EV-01, EV-02, EV-04, EV-08 |
| 1.5 identification in electronic communications (eIDAS) | B/M/A | P-ATT |
| r1.1 the person behind the identifier | M/A | P-ATT |
| r1.2 identification drives privileges | M/A | EV-01, EV-06 |
| r1.3 up-to-date list of authorised users | M/A | EV-01, EV-07 |

## Sources

| Source | Content | Used by |
|---|---|---|
| `identity_snapshot`, `identity_record` (`identity` collector) | every passwd entry joined with shadow: name, UID, GID, shell, password state, expiry, number of keys sshd accepts | EV-01, EV-02, EV-04, EV-06, EV-07, EV-08 |
| `group_snapshot`, `group_record` (`groups` collector) | every group and its members | EV-06 |
| sshd logins, rule 5715 and children | `data.dstuser`, `data.srcip` | EV-03, EV-05, EV-06 |
| console, su and graphical logins, rule 5501 (`login`, `su`, `gdm-password`, `lightdm`, `sddm`) | `data.dstuser` | EV-03, EV-05, EV-06 |
| any `authentication_success`, `authentication_failed` or `sudo` alert in the lookback | the authentication log reaches Wazuh | EV-03, EV-05, EV-06 |
| `oscompliance-identity-history` (engine index) | per agent and account: first and last seen, disabled since, deleted at, last expiry | EV-08, op.acc.6 EV-06 |

The agent sends the whole identity table on every pass and never a password
hash or a key. It applies no UID threshold and computes no change: the engine
compares passes, so a lost or tampered baseline on the machine cannot hide or
invent a change.

The number of keys per account comes from `sshd -T -C user=<account>`, so
`Match User` and `Match Group` blocks apply exactly. When an
`AuthorizedKeysCommand` decides, the number is unknown.

A pass is usable when passwd and shadow were read and every record of its
`run_id` arrived. Otherwise the evidences that need it are NOT_EVALUABLE by
COLLECTION.

Disabled account: no-login shell, expired, or no usable password
(`locked` or `missing`) and no SSH key. A locked password with keys is not
disabled: sshd still accepts the key. Active account: UID at least P-10
and not disabled.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 identity source | documentary | |
| P-02 systems in scope | system | |
| P-03 service accounts | platform; list or regex | EV-05 |
| P-04 forbidden generic accounts | list or regex | EV-03 |
| P-05 days to disable a departed account | | EV-04 |
| P-06 days to keep a disabled account before deletion | | EV-08 |
| P-07 authorised users `usuario \| sistema \| rol` | system; only `usuario` is compared | EV-07 |
| P-08 HR integration | documentary | |
| P-09 declared departures `usuario \| fecha_baja` (YYYY-MM-DD) | | EV-04, EV-08 |
| P-10 lowest UID of a person | platform; product default 1000 | EV-01, EV-04, EV-07, EV-08 |
| P-11 privileged groups | platform; product default `sudo, wheel, admin` | EV-06 |
| P-12 suffix of administrative accounts | first entry; none excludes nobody | EV-06 |
| P-ATT documentary attestations | | 1.5, r1.1 |

Regular expressions are RE2, match the whole name, are case-sensitive and at
most 512 characters long. Lists compare ignoring case. P-10 and P-11 are the
only parameters with a product default, and the verdict says when it is used.

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opacc1`. A source missing is
NOT_EVALUABLE by COLLECTION; a parameter missing or unusable is
NOT_EVALUABLE by CONFIGURATION.

- EV-01 account inventory. A UID held by more than one entry, at any UID:
  NON_COMPLIANT, naming every account. Otherwise COMPLIANT.
- EV-02 identity changes recorded. Compared with the newest complete
  earlier pass (up to ten are tried): accounts created, deleted and modified
  in any field are listed in the verdict. COMPLIANT whenever the pass is
  usable; the first pass is the baseline. It fails only when collection
  fails.
- EV-03 generic accounts. A login in the window by an account that
  matches P-04: NON_COMPLIANT, with each account and its count. No
  authentication event in the lookback: NOT_EVALUABLE by COLLECTION, because
  silence from a log that does not reach Wazuh is not compliance.
- EV-04 departures disabled in time. An account with UID at least P-10
  and a departure date (its P-09 row, else its expiry) not disabled within
  P-05 days of it: NON_COMPLIANT. When only its keys could tell and they are
  unknown: NOT_EVALUABLE by EVIDENCE. No date anywhere and P-09 empty:
  NOT_EVALUABLE by CONFIGURATION. A declared account that no longer exists
  counts as handled.
- EV-05 service accounts. As EV-03, against P-03.
- EV-06 one identity per role. A member of a P-11 group (primary group
  included) that is not itself an administrative account `<x><P-12>` and has
  no `<member><P-12>` account, or a login by such a member: NON_COMPLIANT. No
  finding and no authentication event in the lookback: NOT_EVALUABLE by
  COLLECTION.
- EV-07 active accounts authorised. An active account not in the
  `usuario` column of P-07: NON_COMPLIANT. Not listed and state unknown:
  NOT_EVALUABLE by EVIDENCE.
- EV-08 retention before deletion. From the identity history. An account
  with UID at least P-10 deleted in the window less than P-06 days after its
  start date (P-09 row, else last expiry, else the day it was seen disabled),
  or deleted while still enabled: NON_COMPLIANT. Deleted with no start date or
  with its last state unknown: NOT_EVALUABLE by EVIDENCE.

## Not measured

- eIDAS identification (1.5) and the person behind each identifier
  (r1.1). No machine records them. They are judged by attestation.
- Directory accounts. Accounts that exist only in LDAP, Active Directory
  or another directory are not read: the control judges the local identity
  table of each machine.
