# mp.eq.2 Bloqueo de puesto de trabajo

mp.eq.2 (locking the workstation) judges, on every workstation, the lock
after the idle time of P-01, the cancellation of idle sessions after the
longer time of P-02, and tools that keep the session from going idle.

Levels: MEDIO, ALTO. Annex II section 5.3.2. Definition: [`catalog/controls/ens/mp.eq.2.json`](../../../catalog/controls/ens/mp.eq.2.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 2.1 idle lock with new authentication | M/A | EV-01, EV-05 |
| r1.1 open sessions cancelled later | A | EV-02 |

A machine that is not a workstation (P-03, or by default one without a
graphical session) or that P-04 excepts: every evidence and requirement
NOT_APPLICABLE.

## Sources

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
- `dns_resolvers`: the `nameserver` lines of `/etc/resolv.conf`; for the
  stub of systemd-resolved, those of `/run/systemd/resolve/resolv.conf`
  (mp.s.3).
- `cpu_count`, `load_percent`, `memory_used_percent`, `syn_cookies`: the
  15-minute load average against the CPUs and the memory in use, both
  rounded down to tens so the fact changes only when a step is crossed,
  and `net.ipv4.tcp_syncookies` (mp.s.4).

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 minutes idle before the lock | | EV-01, EV-02 |
| P-02 minutes idle before cancelling | | EV-02 |
| P-03 the machine is a workstation | system; manager: no | decisions |
| P-04 exceptions `equipo \| justificacion \| medidas \| aprobador` | | decisions |
| P-05 idle inhibitors | process names | EV-05 |
| P-ATT documentary attestations | | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/mpeq2`.

- EV-01 lock. With a graphical session: lock enabled, idle delay set and
  not 0, idle plus lock delay within P-01 minutes. Without one: a read-only
  `TMOUT` within P-01 minutes.
- EV-02 cancellation. `StopIdleSessionSec`, or the `TMOUT` without a
  graphical session, longer than P-01 and within P-02 minutes.
- EV-05 inhibitors. No process named in P-05 (by default caffeine,
  caffeine-ng, caffeinate, jiggler, mousejiggler, keepawake, nosleep,
  insomnia, stay-awake).

## Not measured

- Lock events and long sessions without a lock. The lock of a Linux session leaves no event Wazuh decodes.
