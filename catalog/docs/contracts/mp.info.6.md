# mp.info.6 fact contract

mp.info.6 (backups) judges the copies each machine declares in P-04: the
date and size of the newest copy, how long the oldest one has been kept,
who can read them and their encryption keys, whether one lives on another
machine, and the restore tests the organisation records.

## 1. Requirements and evidences

| Requirement | Levels | Evidences |
|---|---|---|
| 6.1 backups made | B/M/A | EV-01, EV-02 |
| 6.2.a frequency | B/M/A | EV-02 |
| 6.2.b storage on site | B/M/A | EV-03 |
| 6.2.c storage elsewhere | B/M/A | attestation (P-ATT) |
| 6.2.d authorised access | B/M/A | EV-04 |
| r1.1 restore tests | M/A | EV-05 |
| r2.1 a copy kept apart | A | EV-06 |

A machine without rows in P-04 makes and keeps no copies: every requirement
is NOT_APPLICABLE there.

## 2. Sources

| Source | Content | Used by |
|---|---|---|
| `backup_snapshot` fact | the copies of each source of P-04 and the keys of P-08 | EV-01 to EV-04, EV-06 |
| P-06 restore register | | EV-05 |

The `ruta` of P-04 reach the agent as `backup_sources`, next to the
sources of op.exp.3 P-07; the keys of P-08 as `backup_keys`.

### `backup_snapshot`

One per pass, emitted only when it changes. `sources`, one per source:

- `source`: `git:<directory>` (the entries of its HEAD reflog, as etckeeper
  keeps `/etc`), a directory or a file pattern (every regular file under
  what it matches, at most 100000 a source, `truncated` beyond).
- `status`: `read`, `absent` (no copy) or `error`.
- `newest`, `oldest`: times of the newest and oldest copy.
- `files`, `bytes`, `newest_bytes`: how many copies, their size and the
  size of the newest one.
- `mode`, `owner` (`user:group`): of the directory the source starts from.
- `group_readable`, `other_readable`: copies the group or anyone can read.
- `filesystem`, `device`: the mount holding the source, from
  `/proc/self/mountinfo`.

`key_files`, one per key of P-08: `path`, `status`, `mode`, `owner`.

## 3. Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 hours between copies | when the copy sets none | EV-02 |
| P-02 margin in hours | | EV-02 |
| P-03 retention days | when the copy sets none | EV-03 |
| P-04 copies `copia \| ruta \| frecuencia_horas \| retencion_dias` | system | EV-01 to EV-04, EV-06 |
| P-05 days without a restore test | | EV-05 |
| P-06 restore register `fecha \| maquina \| copia \| resultado \| verificacion` | `resultado` correcta or fallida | EV-05 |
| P-07 accounts allowed to read the copies | system | EV-04 |
| P-08 encryption key files | system | EV-04 |
| P-09 alternative location, P-10 backup tool | documentary | |
| P-ATT documentary attestations | 6.2.c | |

## 4. Evidence judgement

Judges are in `engine/internal/controls/ens/mpinfo6`. A source of P-04 the
agent has not read yet, or could not read, leaves EV-01 to EV-04 and EV-06
NOT_EVALUABLE.

- **EV-01 last copy.** Every copy must have a newest copy, and outside git
  it must not be empty.
- **EV-02 interval.** The newest copy of every copy must be younger than its
  `frecuencia_horas`, or P-01, plus P-02.
- **EV-03 retention.** The oldest copy kept must be at least `retencion_dias`
  old, or P-03. A truncated source is NOT_EVALUABLE.
- **EV-04 access.** No copy readable by anyone; the owner of each source, and
  its group when copies are group readable, in P-07. Every key of P-08 must
  exist, be readable by its owner only and belong to an account of P-07.
- **EV-05 restore tests.** The newest `correcta` row of P-06 for the machine
  must be within P-05 days.
- **EV-06 copy apart.** At least one copy must live on a filesystem of
  another machine: NFS, SMB, SSHFS, S3 and other network or FUSE remote
  filesystems, or a device named `host:path` or `//host/share`.

## 5. Parity with v1 and deliberate differences

Kept: the requirements and EV-01 to EV-06.

Changed on purpose:

- v1 read Proxmox Backup Server and Zimbra through their own collectors.
  The copies are now read from disk whatever tool makes them: a tool's own
  result of a run is not read.
- EV-05 is the restore register P-06; v1 restored a witness file on the
  backup server itself.
- EV-07 (collector heartbeat) is out: a missing fact already leaves every
  evidence NOT_EVALUABLE.
- 6.2.c is an attestation: it asks for the procedure, not for a copy apart,
  which r2.1 measures at ALTO.
