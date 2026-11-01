# op.nub.1 fact contract

op.nub.1 (cloud services) judges the cloud services the organisation uses:
whether their logs reach Wazuh, who administers them, and their record of
certification, ENS conformity, penetration tests, encryption and data
jurisdiction.

## 1. Requirements and evidences

| Requirement | Levels | Evidences |
|---|---|---|
| 1.1 measures of the service provided | B/M/A | attestation (P-ATT) |
| 1.2 conformity of third-party services | B/M/A | EV-01, EV-04, EV-09 |
| r1.1 certified third-party services | M/A | EV-08 |
| r1.2 security services under op.pl.5 | M/A | attestation (P-ATT) |
| r2.1 configuration by the CCN-STIC guide | A | EV-02 |

P-01 decides what applies: `usuario` the requirements of third-party
services, `prestador` 1.1, `ambos` both, `ninguna` nothing; r2.1 applies to
every position but `ninguna`.

## 2. Sources

| Source | Content | Used by |
|---|---|---|
| alerts of the cloud modules, by rule group | newest record of each module, a week back | EV-01 |
| CloudTrail through `aws-s3` | `data.aws.readOnly` false, no `errorCode`: actor `userIdentity.arn` | EV-04 |
| Office 365 through `office365` | `RecordType` 1 or 8, not failed: actor `UserId` | EV-04 |
| Azure activity log through `azure-logs` | `CategoryValue` Administrative, `ActivityStatusValue` Succeeded: actor `Caller` | EV-04 |
| Entra ID directory audits through `ms-graph` | `result` success: actor `initiatedBy.user.userPrincipalName` | EV-04 |
| Google Admin Activity audit log through `gcp-pubsub` or `gcp-bucket` | no `status.code`: actor `protoPayload.authenticationInfo.principalEmail` | EV-04 |
| alerts of the rule group of each row of P-07 | posture findings of a week, and those at or above P-14 | EV-02 |
| P-02 to P-12 | | EV-08, EV-09 |

Rule groups by module: `aws-s3` amazon or aws, `azure-logs` azure,
`gcp-pubsub` and `gcp-bucket` gcp, `office365`, `ms-graph`, `github`.

## 3. Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 position | `usuario`, `prestador`, `ambos`, `ninguna` | all |
| P-02 services `servicio \| modelo \| proveedor \| informacion \| criticidad \| uso` | `uso` utilizado or prestado | EV-08, EV-09 |
| P-03 ENS conformity `servicio \| conformidad \| alcance \| vigencia \| referencia` | | EV-09 |
| P-04 certification `servicio \| metodologia \| certificado \| vigencia` | | EV-08 |
| P-05 security services | documentary | |
| P-07 configuration guides `servicio \| guia \| estandar \| grupo_reglas` | | EV-02 |
| P-06 Wazuh integrations `servicio \| modulo \| ambito` | | EV-01, EV-04 |
| P-08 jurisdiction `servicio \| ubicacion \| copias \| jurisdiccion` | | EV-09 |
| P-09 encryption `servicio \| cifrado \| gestion_claves` | | EV-09 |
| P-10 provider pentests `servicio \| informe \| fecha \| alcance` | | EV-09 |
| P-11 administrators `servicio \| identidad` | | EV-04 |
| P-12 months of a provider pentest | | EV-09 |
| P-13 hours without cloud logs | | EV-01 |
| P-14 level of a serious posture finding | | EV-02 |
| P-ATT documentary attestations | 1.1, r1.2 | |

## 4. Evidence judgement

Judges are in `engine/internal/controls/ens/opnub1`. The control is judged
the same on every machine: its data is the organisation's.

- **EV-01 logs.** Every service of P-06 with a module must have a record of
  that module within P-13 hours; no module at all: NON_COMPLIANT.
- **EV-02 posture.** Every row of P-07 with a `grupo_reglas` has alerts of
  that group in the last week, none of level P-14 or above. No such row:
  NON_COMPLIANT. The provider judges its tenant against its standard (AWS
  Security Hub, Microsoft Defender for Cloud, Google Security Command
  Center); Wazuh brings the findings in and the engine judges them.
- **EV-04 administrators.** Every actor of a successful administrative
  operation of the window in `aws-s3`, `office365`, `azure-logs`,
  `ms-graph`, `gcp-pubsub` or `gcp-bucket` must be in P-11 for the service
  of that module. A service integrated with `github`: NOT_EVALUABLE.
- **EV-08 certification.** Every used service of P-02 with a `certificado`
  in P-04 whose `vigencia` is not past.
- **EV-09 record.** Every used service with a conformity of P-03 in force, a
  pentest of P-10 within P-12 months, a row of P-09 and a row of P-08.
  Services compare without case or accents.

## 5. Parity with v1 and deliberate differences

Kept: the requirements and EV-01, EV-02, EV-04, EV-08, EV-09.

Changed on purpose:

- EV-03, EV-05, EV-06 and EV-07 gave no verdict in v1 and are out.
