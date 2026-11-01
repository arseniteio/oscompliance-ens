# mp.eq.3 fact contract

mp.eq.3 (portable devices) judges every portable device: inventoried with
its responsible, its custody checked regularly, its losses handled in time,
no dispensable remote access key on it and, at ALTO, its disk encrypted
when it holds information of MEDIO or above.

## 1. Requirements and evidences

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

## 2. Sources

| Source | Content | Used by |
|---|---|---|
| `device_security` fact (mp.eq.2 contract) | chassis, root encryption | scope, EV-04 |
| `wazuh-monitoring-*` | last keepalive | EV-02 |
| `key_snapshot`, `key_record` (op.exp.10 contract) | private keys on disk | EV-03 |
| P-01, P-09, P-10 | inventory, custody checks, losses | EV-01, EV-02, EV-06 |

## 3. Parameters

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

## 4. Evidence judgement

Judges are in `engine/internal/controls/ens/mpeq3`.

- **EV-01 inventory.** The machine in P-01 with a `responsable`.
- **EV-02 custody.** A keepalive within P-02 days and the newest check of
  the device in P-09 within P-02 days.
- **EV-03 remote access keys.** No private key under `/home` or `/root`
  outside P-05.
- **EV-04 encryption.** With `nivel_confidencialidad` MEDIO or ALTO, the
  root filesystem on dm-crypt.
- **EV-06 losses.** Every loss of the device in P-10 with its `incidente`
  and `acciones_completadas` within P-08 hours.

## 5. Parity with v1 and deliberate differences

Kept: the requirements and EV-01 to EV-04, EV-06.

Changed on purpose:

- A device is portable by its SMBIOS chassis or because P-01 lists it; v1
  also guessed by battery and model.
- EV-05 (services reached from untrusted networks) and EV-07 (use outside
  protected places) are out: neither leaves a record a verdict can rest on;
  3.3 and r2.1 are attestations.
- EV-08 (secure boot, firmware password) is out: no source reads it.
