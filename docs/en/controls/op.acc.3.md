# op.acc.3 Segregación de funciones y tareas

op.acc.3 (segregation of duties) judges what people do: the binaries they run
and the paths they touch, classified into functions with P-03, against the
pairs of functions P-02 forbids one person to hold and the critical tasks
P-04 requires several people for.

Levels: MEDIO, ALTO. Annex II section 4.2.3. Definition: [`catalog/controls/ens/op.acc.3.json`](../../../catalog/controls/ens/op.acc.3.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 3.1 development and operation apart | M/A | EV-01, EV-06 |
| 3.2 authorisation and control apart, critical tasks shared | M/A | EV-02, EV-03, EV-06 |
| r1.1 configuration and maintenance apart (R1) | A | EV-04, EV-06 |
| r1.2 audit accounts with no other function (R1) | A | EV-05 |
| r2.1 controlled audit accounts (R2) | none | P-ATT |
| r3.1 access to security information (R3) | none | EV-07 |

## Sources

An action is an account running a binary or touching a path.

| Source | Content | Used by |
|---|---|---|
| auditd through Wazuh's audit decoder, rule 119004 | `audit.auid` (the login, kept across su and sudo), `audit.exe`, `audit.file.name`, `audit.key` | every evidence |
| sudo alerts 5402, 5403, 5407 | `data.srcuser`, `data.command` (whole command line) | every evidence |
| `audit_watch_snapshot` ([op.acc.2](op.acc.2.md)) | auditd state and the watches loaded | silence |
| `identity_*` ([op.acc.1](op.acc.1.md)) | names for audit UIDs | every evidence |

The engine derives the auditd watches from P-03 and writes them into the
group configuration: binaries in a bin or sbin directory become execution
watches (`exec_watches`, key `oscompliance_exec`); P-03 paths and the
security paths (/var/ossec/etc, /etc/audit, /var/log/audit) become
`audit_watches`. A change to P-03 reaches every agent without touching a
machine.

Actions are pooled by account name across every machine over the last P-06
days: the same name is the same person. An audit UID that cannot be named is
reported and never pooled.

The audit chain of a machine is complete when auditd runs, every P-03 path
indicator is watched (exactly or under a watched directory) and Wazuh reads
the audit log.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 functions per person | documentary | |
| P-02 incompatible pairs `a \| b`; `b` may be `*` | | EV-01, EV-02, EV-04, EV-05 |
| P-03 `funcion \| indicador \| ...` | platform | every evidence |
| P-04 `tarea \| personas \| indicador ...` | | EV-03 |
| P-05 audit accounts | | EV-05 |
| P-06 correlation window, days | | every evidence |
| P-ATT documentary attestations | | r2.1 |

Function names are compared without case or accents ("Operación" is
"operacion"). Indicators match as substrings of the binary, the command line
or the path, without case. Each pair evidence judges one pair, found in P-02
in either order: EV-01 `desarrollo | operacion`, EV-02 `autorizacion |
control`, EV-04 `configuracion | mantenimiento`, EV-05 `auditoria | *`.

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opacc3`. P-02, P-03 or P-06
unusable: every evidence NOT_EVALUABLE by CONFIGURATION. Silence on a machine
with an incomplete audit chain is NOT_EVALUABLE by COLLECTION; a breach found
stands.

- EV-01, EV-02, EV-04 incompatible pairs. A person who acted on this
  machine and holds both functions of the pair, here or on any other machine:
  NON_COMPLIANT, with one action of each function. The pair not in P-02:
  NOT_EVALUABLE by CONFIGURATION.
- EV-03 critical tasks. A task run on this machine by fewer different
  people than P-04 requires, over the window: NON_COMPLIANT. A task not run
  is not a failure. A row without a number of people (2 or more) or a
  command: NOT_EVALUABLE by CONFIGURATION.
- EV-05 audit accounts. With `auditoria | *` in P-02, a person holding
  auditoria and anything else; for each P-05 account, any function other than
  auditoria or supervision: NON_COMPLIANT. Neither declared: NOT_EVALUABLE by
  CONFIGURATION.
- EV-06 actions per account. The accounts that acted on this machine and
  their functions. Actions whose account cannot be named: NOT_EVALUABLE by
  EVIDENCE.
- EV-07 security information. Who read or changed the security paths.
  Reported only: r3.1 applies at no level.

## Not measured

- Functions held on paper (P-01). The control judges what people did,
  not what the organisation chart says; P-01 stays as documentation.
- Actions outside auditd and sudo, such as work done through an
  application's own interface.
