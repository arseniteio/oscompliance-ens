# op.acc.5 fact contract

op.acc.5 (authentication mechanism, external users) judges the services
where people outside the organisation log in: an e-office, a citizen portal,
a public API, a supplier extranet. No system file says which service that is
or how it authenticates, so the service writes its own authentication log in
the contract below, Wazuh reads it, and the engine judges the events.

## 1. Requirements and evidences

| Requirement | Levels | Evidences | Proven by |
|---|---|---|---|
| 5.1, 5.2, 5.3, 5.9 | B/M/A | – | P-ATT |
| 5.4 periodic credential change | B/M/A | EV-04 | P-05 |
| 5.5, 5.6 disablement on compromise or end of relationship | B/M/A | EV-05 | P-06 |
| 5.7 rejection reveals nothing | B/M/A | EV-06 | – |
| 5.8 attempt limit and reactivation | B/M/A | EV-02, EV-03 | P-03, P-04 |
| r1.1 password (R1) | B/M/A | EV-07 | P-01 |
| r1.2 password complexity (R1) | B/M/A | EV-02 | P-01 |
| r2.1 password and OTP (R2) | B/M/A | EV-07 | P-01 |
| r3.1, r4.1 certificate validation (R3, R4) | B/M/A | EV-08 | P-01, P-07 |
| r3.2, r4.2 second factor on the certificate | B/M/A | EV-07 | P-01 |
| r3.3, r4.3 qualified registration | B/M/A | – | P-01, P-ATT |
| r5.1 access log kept and continuous | M/A | EV-01, EV-09 | P-08 |
| r5.2 last access notice | M/A | – | P-09, P-ATT |
| r6.1, r7.1 | none | – | always NOT_APPLICABLE |

## 2. How the log reaches Wazuh

Each P-02 row (`servicio | host | log`, a system parameter: per machine) is a
`<localfile>` in the group configuration, inside an `<agent_config>` block
naming the machine, with a label naming the service:

```xml
<agent_config name="lab-agent-01">
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/sede/autenticacion.json</location>
    <label key="oscompliance_service">sede</label>
  </localfile>
</agent_config>
```

Wazuh adds the label to every event; rule 119003 indexes any JSON event with
`oscompliance_service` and `tipo`. The agent installs nothing: the manager
distributes the localfile, and the agent's `services` collector reads the same
shared configuration to watch the file (section 3). The engine writes these
blocks from P-02 through the Wazuh API.

The contract, one JSON line per event, `ts` (RFC 3339) and `tipo` mandatory:

```json
{"ts":"…","tipo":"autenticacion","usuario":"u","origen":"203.0.113.7","resultado":"exito","factores":["password","otp"]}
{"ts":"…","tipo":"autenticacion","usuario":"u","origen":"203.0.113.7","resultado":"fallo","mensaje":"text shown to the user"}
{"ts":"…","tipo":"autenticacion","usuario":"u","resultado":"exito","factores":["certificado","pin"],"certificado_emisor":"FNMT-RCM","revocacion":"ocsp"}
{"ts":"…","tipo":"bloqueo","usuario":"u"}
{"ts":"…","tipo":"desbloqueo","usuario":"u","modo":"intervencion"}
{"ts":"…","tipo":"cambio_credencial","usuario":"u"}
{"ts":"…","tipo":"notificacion_compromiso","usuario":"u","referencia":"INC-12"}
{"ts":"…","tipo":"fin_relacion","usuario":"u","referencia":"BAJA-7"}
{"ts":"…","tipo":"inhabilitacion","usuario":"u"}
{"ts":"…","tipo":"politica","bloqueo":"activado","max_intentos":5,"reactivacion":"intervencion","longitud_minima":12,"complejidad":"activada"}
```

Factors: `password`, `otp`, `certificado`, `tarjeta`, `pin`, `biometria`. The
contract is v1's, unchanged, so services that already write it need nothing
new. Event times are the alert's: Wazuh reads new lines as they are written.

## 3. Agent facts

| Fact | Collector | Used by |
|---|---|---|
| `service_log`, `service_log_snapshot` | `services` | EV-01, EV-03, EV-09 |

The collector reads `/var/ossec/etc/shared/agent.conf`, keeps the
`agent_config` blocks that apply to this agent (no attribute, its own name in
`name`, Linux in `os`; `profile` blocks are left out) and, for each localfile
labelled `oscompliance_service`, reports the file (inode, size, modification
time), its rotated copies (`path.*`, `path-*`) and the `ts` of the first
contract line of the oldest copy, compressed or not.

## 4. Parameters

| ID | Class | Type | Used by |
|---|---|---|---|
| P-01 mechanism, R1 to R4 | organisation | select | decisions, EV-07, EV-08 |
| P-02 `servicio \| host \| log` | system | table | the services of the machine |
| P-03 attempts | organisation | number | EV-02, EV-03 |
| P-04 reactivation procedure | organisation | string | decision on 5.8 |
| P-05 days | organisation | number | EV-04 |
| P-06 hours | organisation | number | EV-05 |
| P-07 `ac \| validacion` | organisation | table | EV-08 |
| P-08 days | organisation | number | EV-01 |
| P-09 last access notice | organisation | yes/no | decision on r5.2 |
| P-ATT, P-DA | organisation | table | documentary requirements, exclusion |

The services of a machine are its P-02 rows, the labelled localfiles its agent
reads and the services with events from it.

## 5. Evidence judgement

Judges are in `engine/internal/controls/ens/opacc5`. A machine with no service
leaves every evidence NOT_EVALUABLE by CONFIGURATION (P-DA excludes the
control there, section 6). The window is the engine's (26 hours); "as far
back as the index goes" means every event Wazuh keeps.

- **EV-01 retention.** Per service, the log reaches back to the older of its
  oldest event in Wazuh and the first line of its oldest copy on disk. Less
  than P-08 days: NON_COMPLIANT, so a new service fails until it has logged
  for P-08 days, as in v1.
- **EV-02 lockout.** The newest `politica` of each service: lockout off (or
  `max_intentos` 0), more attempts than P-03, or `reactivacion automatica`:
  NON_COMPLIANT. A run of failures of one account longer than P-03 in the
  window, not cut by a success, a lockout or an unlock: NON_COMPLIANT;
  failures while the account is locked do not count. No policy declared:
  NOT_EVALUABLE by EVIDENCE.
- **EV-03 failures by origin.** Per service and origin, the most failures
  within any 15 minutes; more than P-03: NON_COMPLIANT. The index gives an
  upper bound per origin and the exact count is taken only where the bound is
  above P-03. No failure from a service whose newest line is not in Wazuh:
  NOT_EVALUABLE by COLLECTION.
- **EV-04 credential age.** Accounts that logged in or changed their
  credential and were not disabled afterwards. A last change older than P-05:
  NON_COMPLIANT. No change recorded: the credential is at least as old as the
  oldest event of the service; beyond P-05 that is NON_COMPLIANT, otherwise
  NOT_EVALUABLE by EVIDENCE.
- **EV-05 disablement delay.** Each `notificacion_compromiso` or
  `fin_relacion` closes with the next `inhabilitacion` of the same account and
  service; an open one counts the hours so far. More than P-06:
  NON_COMPLIANT. No notice ever: NOT_EVALUABLE by EVIDENCE, as v1, since a
  service that does not log notices would otherwise pass.
- **EV-06 rejection messages.** A message of the window that says the account
  does not exist, that only the password was wrong, the state of the account,
  or technical detail (exceptions, SQL states, server versions):
  NON_COMPLIANT. "Usuario o contraseña incorrectos" reveals nothing. A
  service that never logged a message: NOT_EVALUABLE by EVIDENCE.
- **EV-07 mechanism used.** Each successful login by its factors: R4 card
  with PIN or biometrics, R3 certificate with PIN or biometrics, R2 password
  with OTP, R1 password alone. One that is not P-01: NON_COMPLIANT. Logins
  without factors: NOT_EVALUABLE by EVIDENCE; none in the window:
  NOT_EVALUABLE by COLLECTION.
- **EV-08 certificate validation.** Only with P-01 R3 or R4, otherwise
  NOT_APPLICABLE. An issuer that is not a P-07 row, or a revocation check that
  is not one its row demands: NON_COMPLIANT. None in the window:
  NOT_EVALUABLE by COLLECTION.
- **EV-09 continuity.** Each read of the logs against the one before: the log
  disappeared, was replaced with no rotated copy keeping the old inode (or a
  compressed copy written since), or shrank without rotating; the file was
  written after the newest event Wazuh has of it; a P-02 service the agent
  does not read. Any of them: NON_COMPLIANT. Fewer than two reads:
  NOT_EVALUABLE by COLLECTION.

## 6. Requirement decisions

op.acc.5 decides some requirements itself (`evaluator.Decider`), applied only
where the requirement applies by level:

- **P-DA** with a reason, a reference and a usable link, on a machine with no
  service: every requirement NOT_APPLICABLE. With a service the declaration is
  contradicted and ignored.
- **P-01** unusable: the nine reinforcement requirements NOT_EVALUABLE by
  CONFIGURATION, and no P-ATT row proves r3.3 or r4.3. Another mechanism's
  requirements: NOT_APPLICABLE. R1 above BAJO: r1.1 and r1.2 NON_COMPLIANT,
  the ENS only allows a password alone at BAJO.
- **r1.2** under R1: a declared policy with complexity off or no minimum
  length is NON_COMPLIANT; none declared is NOT_EVALUABLE; otherwise EV-02.
- **5.8**: P-04 not set is NOT_EVALUABLE, unless EV-02 or EV-03 already
  failed.
- **r5.2**: P-09 no is NON_COMPLIANT; not set NOT_EVALUABLE; yes leaves it to
  P-ATT.

## 7. Parity with v1 and deliberate differences

Kept: the contract, the parameters, the factor classes, the P-01 gate, the
.8, r1.2 and r5.2 rules, the regex families of EV-06.

Changed on purpose:

- The agent keeps no state and parses nothing: the log goes through Wazuh, and
  streaks, ages and delays are computed from the index. v1 kept offsets,
  streaks, open notices and account lists on every machine.
- The services come from the manager (labelled localfiles from P-02), not from
  a variable on every machine that had to match P-02 by hand.
- EV-01 counts what Wazuh keeps as well as what the disk keeps.
- EV-02 ignores failures while an account is locked.
- EV-03 counts within 15 minutes, not per hourly run.
- EV-04 dates a credential with no recorded change by the age of the index.
- EV-08 fails an issuer that P-07 does not admit (v1: NOT_EVALUABLE).
- EV-09 also catches lines written but never delivered, and a declared
  service the agent does not read.
- No P-ATT row proves r3.3 or r4.3 while P-01 is unset.

## 8. Open points

- Failures without an origin are counted for EV-03 only as an upper bound and
  never accuse.
