# op.acc.5 Mecanismo de autenticación (usuarios externos)

op.acc.5 (authentication mechanism, external users) judges the services where
people outside the organisation log in: an e-office, a citizen portal, a
public API, a supplier extranet. No system file says which service that is
or how it authenticates, so each service writes its authentication events in
the contract below, Wazuh collects them, and the engine judges the events.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.2.5. Definition: [`catalog/controls/ens/op.acc.5.json`](../../catalog/controls/ens/op.acc.5.json).

## Requirements

| Requirement | Levels | Evidences | Proven by |
|---|---|---|---|
| 5.1, 5.2, 5.3, 5.9 | B/M/A | | P-ATT |
| 5.4 periodic credential change | B/M/A | EV-04 | P-05 |
| 5.5, 5.6 disablement on compromise or end of relationship | B/M/A | EV-05 | P-06 |
| 5.7 rejection reveals nothing | B/M/A | EV-06 | |
| 5.8 attempt limit and reactivation | B/M/A | EV-02, EV-03 | P-03, P-04 |
| r1.1 password (R1) | B/M/A | EV-07 | P-01 |
| r1.2 password complexity (R1) | B/M/A | EV-02 | P-01 |
| r2.1 password and OTP (R2) | B/M/A | EV-07 | P-01 |
| r3.1, r4.1 qualified certificate (R3, R4) | B/M/A | EV-08 | P-01, P-07 |
| r3.2, r4.2 second factor on the certificate | B/M/A | EV-07 | P-01 |
| r3.3, r4.3 qualified registration | B/M/A | | P-01, P-ATT |
| r5.1 access log kept and continuous | M/A | EV-01, EV-09 | P-08 |
| r5.2 last access notice | M/A | | P-09, P-ATT |
| r6.1, r7.1 | none | | always NOT_APPLICABLE |

## Sources

Each P-02 row (`servicio | host | log`) becomes a `<localfile>` in the group
configuration, inside an `<agent_config>` block naming the machine, with a
label naming the service. The engine writes these blocks through the Wazuh
API:

```xml
<agent_config name="sede-01">
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/sede/autenticacion.json</location>
    <label key="oscompliance_service">sede</label>
  </localfile>
</agent_config>
```

Rule 119003 indexes every JSON event with `oscompliance_service` and `tipo`.
The service writes one JSON line per event; `ts` (RFC 3339) and `tipo` are
mandatory:

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

Factors: `password`, `otp`, `certificado`, `tarjeta`, `pin`, `biometria`.

| Source | Content | Used by |
|---|---|---|
| rule 119003 | the service's authentication events | EV-01 to EV-08 |
| `service_log_snapshot`, `service_log` (`services`) | for each labelled localfile that applies to the agent: inode, size, modification time, rotated copies and the `ts` of the oldest line on disk | EV-01, EV-03, EV-09 |

The services of a machine are its P-02 rows, the labelled localfiles its
agent reads and the services with events from it.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 mechanism: R1, R2, R3 or R4 | one, not cumulative | decisions, EV-07, EV-08 |
| P-02 `servicio \| host \| log` | system | the services of each machine |
| P-03 maximum failed attempts | | EV-02, EV-03 |
| P-04 reactivation procedure | | decision on 5.8 |
| P-05 days between credential changes | | EV-04 |
| P-06 hours to disable a credential | | EV-05 |
| P-07 admitted authorities `ac \| validacion` | | EV-08 |
| P-08 days the access log is kept | | EV-01 |
| P-09 last access notice, yes or no | | decision on r5.2 |
| P-ATT documentary attestations | | documentary requirements |
| P-DA declaration of applicability | | exclusion |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opacc5`. A machine with no
service leaves every evidence NOT_EVALUABLE by CONFIGURATION, unless P-DA
excludes the control there.

- **EV-01 retention.** Per service, the log reaches back to the older of its
  oldest event in Wazuh and its oldest line on disk. Less than P-08 days:
  NON_COMPLIANT, so a new service fails until it has logged for P-08 days.
- **EV-02 lockout.** The newest `politica` of each service: lockout off,
  `max_intentos` 0 or above P-03, or automatic reactivation: NON_COMPLIANT. A
  run of failures of one account longer than P-03 in the window, not cut by a
  success, a lockout or an unlock: NON_COMPLIANT. Failures while the account
  is locked do not count. No policy declared: NOT_EVALUABLE by EVIDENCE.
- **EV-03 failures by origin.** Per service and origin, the most failures
  within any 15 minutes; above P-03: NON_COMPLIANT. No failure from a service
  whose newest line is not in Wazuh: NOT_EVALUABLE by COLLECTION.
- **EV-04 credential age.** Accounts that logged in or changed their
  credential and were not disabled afterwards. A last change older than P-05:
  NON_COMPLIANT. No change recorded: the credential is at least as old as the
  oldest event of the service; beyond P-05 that is NON_COMPLIANT, otherwise
  NOT_EVALUABLE by EVIDENCE.
- **EV-05 disablement delay.** Each `notificacion_compromiso` or
  `fin_relacion` closes with the next `inhabilitacion` of the same account and
  service; an open one counts the hours so far. Above P-06: NON_COMPLIANT. No
  notice ever: NOT_EVALUABLE by EVIDENCE, since a service that does not log
  notices would otherwise pass.
- **EV-06 rejection messages.** A message that says the account does not
  exist, that only the password was wrong, the state of the account, or
  technical detail (exceptions, SQL states, server versions): NON_COMPLIANT.
  "Usuario o contraseña incorrectos" reveals nothing. A service that never
  logged a message: NOT_EVALUABLE by EVIDENCE.
- **EV-07 mechanism used.** Each successful login is classed by its factors:
  R4 card with PIN or biometrics, R3 certificate with PIN or biometrics, R2
  password with OTP, R1 password alone. One that is not P-01: NON_COMPLIANT.
  Logins without factors: NOT_EVALUABLE by EVIDENCE; no login in the window:
  NOT_EVALUABLE by COLLECTION.
- **EV-08 certificate validation.** Only with R3 or R4, otherwise
  NOT_APPLICABLE. An issuer not in P-07, or a revocation check its row does
  not admit: NON_COMPLIANT. None in the window: NOT_EVALUABLE by COLLECTION.
- **EV-09 continuity.** Each read of the logs against the one before: the log
  disappeared, was replaced with no rotated copy keeping the old inode, or
  shrank without rotating; the file was written after the newest event Wazuh
  has of it; or a P-02 service the agent does not read. Any of them:
  NON_COMPLIANT. Fewer than two reads: NOT_EVALUABLE by COLLECTION.

## Requirement decisions

op.acc.5 decides some requirements itself, only where the requirement
applies by level:

- **P-DA** with a reason, a reference and a usable link, on a machine with no
  service: every requirement NOT_APPLICABLE. On a machine with a service the
  declaration is contradicted and ignored.
- **P-01** unusable: the nine mechanism requirements are NOT_EVALUABLE by
  CONFIGURATION, and no attestation proves r3.3 or r4.3. The requirements of
  the mechanisms not chosen: NOT_APPLICABLE. R1 above BAJO: r1.1 and r1.2
  NON_COMPLIANT; the ENS allows a password alone only at BAJO.
- **r1.2** under R1: a declared policy with complexity off or no minimum
  length is NON_COMPLIANT; none declared is NOT_EVALUABLE; otherwise EV-02.
- **5.8**: P-04 not set is NOT_EVALUABLE, unless EV-02 or EV-03 already
  failed.
- **r5.2**: P-09 no is NON_COMPLIANT; not set NOT_EVALUABLE; yes leaves it to
  P-ATT.

## Not measured

- **Services that do not write the contract.** The control cannot see inside
  an application. A service without the log is NOT_EVALUABLE, never
  COMPLIANT.
- **Failures without an origin** count for EV-03 only as an upper bound and
  never accuse.
