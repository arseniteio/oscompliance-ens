# mp.eq.3 Protección de dispositivos portátiles

mp.eq.3 (portable devices) judges every portable device: inventoried with
its responsible, its custody checked regularly, its losses handled in time,
no dispensable remote access key on it and, at ALTO, its disk encrypted
when it holds information of MEDIO or above.

Levels: BAJO, MEDIO, ALTO. Annex II section 5.3.3. Definition: [`catalog/controls/ens/mp.eq.3.json`](../../../catalog/controls/ens/mp.eq.3.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 3.1 inventory, responsible and custody | B/M/A | EV-01, EV-02 |
| 3.2 losses reported | B/M/A | EV-06 |
| 3.3 remote access limited | B/M/A | attestation (P-ATT) |
| 3.4 no dispensable remote access keys | B/M/A | EV-03 |
| r1.1 disk encryption | A | EV-04 |
| r2.1 use in protected places | A | attestation (P-ATT) |

A machine that is neither in P-01 nor portable by its chassis: every
evidence and requirement NOT_APPLICABLE.

## Sources

| Source | Content | Used by |
|---|---|---|
| `device_security` fact ([mp.eq.2](mp.eq.2.md)) | chassis, root encryption | scope, EV-04 |
| `wazuh-monitoring-*` | last keepalive | EV-02 |
| `key_snapshot`, `key_record` ([op.exp.10](op.exp.10.md)) | private keys on disk | EV-03 |
| P-01, P-09, P-10 | inventory, custody checks, losses | EV-01, EV-02, EV-06 |

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 inventory `dispositivo \| tipo \| responsable \| nivel_confidencialidad` | `dispositivo` the agent name | scope, EV-01, EV-04 |
| P-02 days between custody checks | | EV-02 |
| P-03 loss procedure, P-04 remote access profile, P-07 rules for use outside | documentary | |
| P-05 indispensable keys | paths, globs | EV-03 |
| P-08 hours to react to a loss | | EV-06 |
| P-09 custody checks `fecha \| dispositivo \| responsable \| resultado` | | EV-02 |
| P-10 losses `fecha \| dispositivo \| incidente \| acciones_completadas` | | EV-06 |
| P-ATT documentary attestations | 3.3, r2.1 | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/mpeq3`.

- EV-01 inventory. The machine in P-01 with a `responsable`.
- EV-02 custody. A keepalive within P-02 days and the newest check of
  the device in P-09 within P-02 days.
- EV-03 remote access keys. No private key under `/home` or `/root`
  outside P-05.
- EV-04 encryption. With `nivel_confidencialidad` MEDIO or ALTO, the
  root filesystem on dm-crypt.
- EV-06 losses. Every loss of the device in P-10 with its `incidente`
  and `acciones_completadas` within P-08 hours.

## Not measured

- Secure boot, firmware password. No source reads it.
