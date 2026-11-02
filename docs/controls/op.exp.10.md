# op.exp.10 Protección de claves criptográficas

op.exp.10 (protection of cryptographic keys) judges what of the key life
cycle lives on the machines: who reads the key stores, where private keys
are and how they are protected, whether keys are generated where they are
used, whether retired keys are still there, which algorithms services
accept and use, and the validity of certificates.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.3.10. Definition: [`catalog/controls/ens/op.exp.10.json`](../../catalog/controls/ens/op.exp.10.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 10.1 keys protected their whole life | B/M/A | EV-01, EV-02, EV-07, EV-08 |
| 10.2 generation apart from operation | B/M/A | EV-05 |
| 10.3 retired keys archived off operation | B/M/A | EV-06 |
| r1.1 algorithms authorised by the CCN | M/A | EV-03, EV-04, EV-07 |
| r2.1 ciphers conforming to CCN-STIC | none | attestation (P-ATT) |

## Sources

| Source | Content | Used by |
|---|---|---|
| audited accesses, rule 119004 ([op.acc.2](op.acc.2.md)) | reads and writes under the stores of P-02, and executions of key tools | EV-01, EV-05 |
| `audit_watch_snapshot`, `wazuh_agent_config` | the audit chain | EV-01, EV-05 |
| `key_snapshot`, `key_record`, `certificate_record` | private keys and certificates on disk | EV-02, EV-06 to EV-08 |
| `config_file` for `sshd -T` ([op.exp.2](op.exp.2.md)) | algorithms sshd accepts | EV-03 |
| sshd logins (rule 5715) | key type of each public key login | EV-04 |

The stores of P-02 reach the agent as `key_stores` and auditd as audit
watches; when the machine has key stores, `/usr/bin/ssh-keygen` and
`/usr/bin/openssl` are watched for execution.

### `key_record`, `certificate_record`, `key_snapshot`

The agent reads files of at most 64 KiB under `/etc`, `/root`, `/home`,
`/srv`, `/opt`, `/usr/local/etc`, `/var/lib` and the stores of P-02, the
public CA stores and package databases left out, at most 2000 PEM files a
pass. `key_record`: `path`, `key_kind`, `fingerprint` (SHA256 of the public
part, from the `.pub` of an OpenSSH key), `mode`, `owner`.
`certificate_record`: `path`, `subject`, `not_after`, `key_algorithm`,
`key_bits`, `signature_algorithm`. Emitted only when they change.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 key inventory `clave \| finalidad \| soporte \| ubicacion \| responsable \| estado \| huella` | `estado` activa or retirada | EV-06 |
| P-02 key stores `ruta \| modo_maximo \| propietario` | platform; built-in per system type | EV-01, EV-02, EV-08 |
| P-03 authorised algorithms `uso \| algoritmo \| longitud_min` | `algoritmo` as sshd names it, or part of it | EV-03, EV-04, EV-07 |
| P-04 cryptographic services | documentary | |
| P-05 generation and operation `medio \| funcion \| aislamiento` | `funcion` generacion or explotacion | EV-05 |
| P-06 archive of retired keys | documentary | |
| P-07 key life cycle procedure | documentary | |
| P-08 accounts allowed to the keys `cuenta \| claves \| operacion` | | EV-01 |
| P-09 CCN-STIC ciphers | documentary | |
| P-10 days of notice before a certificate expires | | EV-07 |
| P-ATT documentary attestations | r2.1 | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opexp10`.

- EV-01 audited accesses. Every successful access of the window under a
  store of P-02 by an account outside P-08: NON_COMPLIANT. Silence needs the
  audit chain (op.acc.4): auditd running and every store watched.
- EV-02 keys outside the stores. A private key whose directory is not
  under a store of P-02: NON_COMPLIANT.
- EV-03 algorithms configured. Every cipher, MAC, key exchange and host
  key algorithm sshd accepts must contain an `algoritmo` of P-03.
- EV-04 algorithms used. The key type of every public key login of the
  window must be named in an `algoritmo` of P-03.
- EV-05 generation. On a machine P-05 calls `explotacion`, an execution
  of ssh-keygen or openssl in the window: NON_COMPLIANT.
- EV-06 retired keys. A key of P-01 `retirada` found on the machine by
  fingerprint or by location: NON_COMPLIANT.
- EV-07 certificates. An expired certificate, an RSA key under 2048 bits,
  or a signature with MD5 or SHA-1: NON_COMPLIANT. Those expiring within
  P-10 days are named.
- EV-08 key files. A private key more open than `modo_maximo` of its
  store, or with another owner: NON_COMPLIANT. A key outside every store
  must be readable by its owner only.

## Not measured

- Windows key stores.
