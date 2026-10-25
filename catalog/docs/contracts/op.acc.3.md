# op.acc.3 fact contract

op.acc.3 (segregation of duties) judges what people do: the binaries they
run and the paths they touch, classified into functions with P-03, against
the pairs of functions P-02 forbids one person to hold, and the critical
tasks P-04 asks several people for.

## 1. Requirements and evidences

| Requirement | Levels | Evidences |
|---|---|---|
| 3.1 development and operation apart | M/A | EV-01, EV-06 |
| 3.2 authorisation and control apart, critical tasks shared | M/A | EV-02, EV-03, EV-06 |
| r1.1 configuration and maintenance apart (R1) | A | EV-04, EV-06 |
| r1.2 audit accounts with no other function (R1) | A | EV-05 |
| r2.1 controlled audit accounts (R2) | none | P-ATT |
| r3.1 access to security information (R3) | none | EV-07 |

## 2. Actions

An action is an account running a binary or touching a path:

| Source | What it gives | Rule |
|---|---|---|
| auditd, through Wazuh's audit decoder | `audit.auid` (the login, kept across su and sudo), `audit.exe`, `audit.file.name`, `audit.key` | 119004 |
| Wazuh's sudo alerts | `data.srcuser`, `data.command` (the whole command line) | 5402, 5403, 5407 |

The auditd watches come from the manager: the shared `oscompliance.json`
lists the P-03 binaries in `exec_watches` (one execution watch each, key
`oscompliance_exec`) and the P-03 paths and the security paths
(/var/ossec/etc, /etc/audit, /var/log/audit) in `audit_watches`. The agent's
`audit` collector loads them and reports what is loaded in
`audit_watch_snapshot` (op.acc.2 contract, section 2). The audit log reaches
Wazuh through a localfile with `log_format audit` in the group
configuration.

Actions are pooled by account name across every machine over the last P-06
days, as v1: the same name is the same person. An audit uid is named with
the identity facts of its machine; one that cannot be named is reported
(EV-06) and never pooled.

## 3. Parameters

| ID | Class | Used by |
|---|---|---|
| P-02 incompatible pairs `a \| b`, `b` may be `*` | organisation | EV-01, EV-02, EV-04, EV-05 |
| P-03 `funcion \| indicador \| ...` | platform | every evidence |
| P-04 `tarea \| personas \| indicador ...` | organisation | EV-03 |
| P-05 audit accounts | organisation | EV-05 |
| P-06 correlation window, days | organisation | every evidence |
| P-01 functions per person | organisation | documentary, not read |

Function names are compared without case or accents everywhere ("Operación"
is "operacion"). Indicators match as substrings of the binary or command
line and the path, without case. P-04 carries the command of each task as
its third and later cells: v1 kept them in a file on every machine. The
plugin's P-04 must gain that column (open point).

Each evidence judges one pair, as the plugin's policy: EV-01 desarrollo |
operacion, EV-02 autorizacion | control, EV-04 configuracion |
mantenimiento, EV-05 auditoria | \*. A pair is found in P-02 in either order.

## 4. Evidence judgement

Judges are in `engine/internal/controls/ens/opacc3`. P-02, P-03 or P-06
unusable: every evidence NOT_EVALUABLE by CONFIGURATION. The audit chain of a
machine is complete when auditd runs, every P-03 indicator that is a path is
watched (exactly or under a watched directory) and Wazuh reads the audit log.
Silence on a machine with an incomplete chain is NOT_EVALUABLE by
COLLECTION; a breach found stands.

- **EV-01, EV-02, EV-04 pairs.** A person who acted on this machine and holds
  both functions of the pair, here or on another machine: NON_COMPLIANT, with
  an action of each function. The pair not in P-02: NOT_EVALUABLE by
  CONFIGURATION.
- **EV-03 critical tasks.** A task run on this machine by fewer different
  people than P-04 asks, over the window: NON_COMPLIANT. As v1, people are
  counted over the window, not per run. A task not run is not a failure. A
  P-04 row without its number of people (2 or more) or its command:
  NOT_EVALUABLE by CONFIGURATION.
- **EV-05 audit accounts.** With `auditoria | *` in P-02, a person holding
  auditoria and anything else; for each P-05 account, any function other
  than auditoria or supervision: NON_COMPLIANT. Neither declared:
  NOT_EVALUABLE by CONFIGURATION (v1 passed it by vacuity).
- **EV-06 actions per account.** The accounts that acted on this machine and
  their functions. Actions whose account cannot be named: NOT_EVALUABLE by
  EVIDENCE.
- **EV-07 security information.** Who read or changed the security paths;
  reported, since r3.1 applies at no level.

## 5. Parity with v1 and deliberate differences

Kept: the requirement pairs, the substring indicators, pooling by name, the
window-wide count of people per task, accounts with actions of no function
counted in the inventory.

Changed on purpose:

- Actions come from Wazuh's audit and sudo alerts: the binary, the path and
  the command line are all there. v1's parser lost the path (PATH records
  were not read) and the arguments, so path indicators never matched, and a
  numeric uid filter after `ausearch -i` left EV-03 always empty.
- The watched binaries follow P-03 through the manager's shared file instead
  of a fixed template that had to be reloaded by hand.
- Silence is proven per machine by its audit chain, not by any heartbeat of
  any machine in the last 24 hours.
- Accents are ignored on every side, so a pair written with them still
  matches.
- `* | auditoria` is the wildcard pair; v1 accepted it and never matched.
- r1.2 without P-05 and without the wildcard is NOT_EVALUABLE, not
  COMPLIANT.
- P-06 is the window, as its description says; v1 used a fixed 30 days.

## 6. Open points

- The plugin's P-04 must carry each task's command (third column).
- The manager side must write `exec_watches` and `audit_watches` from P-03
  and the audit localfile.
