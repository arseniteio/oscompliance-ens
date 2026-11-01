# mp.eq.2 fact contract

mp.eq.2 (locking the workstation) judges, on every workstation, the lock
after the idle time of P-01, the cancellation of idle sessions after the
longer time of P-02, and tools that keep the session from going idle.

## 1. Requirements and evidences

| Requirement | Levels | Evidences |
|---|---|---|
| 2.1 idle lock with new authentication | M/A | EV-01, EV-05 |
| r1.1 open sessions cancelled later | A | EV-02 |

A machine that is not a workstation (P-03, or by default one without a
graphical session) or that P-04 excepts: every evidence and requirement
NOT_APPLICABLE.

## 2. Sources

| Source | Content | Used by |
|---|---|---|
| `device_security` fact | screen lock, idle timeouts, graphical session | EV-01, EV-02, decisions |
| `wazuh-states-inventory-processes-*` (manager through the API) | processes named in P-05 | EV-05 |

### `device_security`

One per pass, emitted only when it changes:

- `chassis_type` (SMBIOS, `/sys/class/dmi/id/chassis_type`) and `portable`
  (types 8 to 11, 14, 30 to 32).
- `graphical`: a display manager is installed (`display-manager.service`,
  gdm, lightdm or sddm).
- `lock_idle_delay_seconds`, `lock_enabled`, `lock_delay_seconds`: GNOME's
  `org/gnome/desktop/session/idle-delay` and
  `org/gnome/desktop/screensaver/lock-enabled`, `lock-delay` in the system
  dconf keyfiles (`/etc/dconf/db/*.d/*`), the last file winning.
- `shell_timeout_seconds`, `shell_timeout_readonly`: the shortest `TMOUT` of
  `/etc/profile`, `/etc/bash.bashrc` and `/etc/profile.d/*.sh`, and whether
  it is declared read-only.
- `logind_idle_seconds`: `StopIdleSessionSec` of logind.conf and its
  drop-ins.
- `root_device`, `root_encrypted`: the device mounted on `/` and whether it
  or a device under it is dm-crypt (mp.eq.3).

## 3. Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 minutes idle before the lock | | EV-01, EV-02 |
| P-02 minutes idle before cancelling | | EV-02 |
| P-03 the machine is a workstation | system; manager: no | decisions |
| P-04 exceptions `equipo \| justificacion \| medidas \| aprobador` | | decisions |
| P-05 idle inhibitors | process names | EV-05 |
| P-ATT documentary attestations | | |

## 4. Evidence judgement

Judges are in `engine/internal/controls/ens/mpeq2`.

- **EV-01 lock.** With a graphical session: lock enabled, idle delay set and
  not 0, idle plus lock delay within P-01 minutes. Without one: a read-only
  `TMOUT` within P-01 minutes.
- **EV-02 cancellation.** `StopIdleSessionSec`, or the `TMOUT` without a
  graphical session, longer than P-01 and within P-02 minutes.
- **EV-05 inhibitors.** No process named in P-05 (by default caffeine,
  caffeine-ng, caffeinate, jiggler, mousejiggler, keepawake, nosleep,
  insomnia, stay-awake).

## 5. Parity with v1 and deliberate differences

Kept: the requirements and EV-01, EV-02, EV-05.

Changed on purpose:

- EV-03 and EV-04 (lock events and long sessions without a lock) are out:
  the lock of a Linux session leaves no event Wazuh decodes.
- EV-06 (coverage and exceptions) is the scope itself: a workstation is
  judged unless P-04 excepts it.
- The lock is read from the system dconf databases; a user's own dconf
  settings are not read.
