# op.exp.4 Mantenimiento y actualizaciones de seguridad

op.exp.4 (security maintenance and updates) judges that every machine is
scanned for vulnerabilities, that each one is fixed within the deadline of
its severity, that the machine follows its vendor's updates and support,
that only authorised accounts patch and only inside the maintenance
windows, that patches go through pre-production first and that a reversion
point exists before each change.

Levels: BAJO, MEDIO, ALTO. Annex II section 4.3.4. Definition: [`catalog/controls/ens/op.exp.4.json`](../../catalog/controls/ens/op.exp.4.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 4.1 follow the vendor's announcements | B/M/A | EV-01, EV-03, EV-05, EV-06 |
| 4.2 deadlines by risk | B/M/A | EV-01, EV-02, EV-07 |
| 4.3 maintenance by authorised staff | B/M/A | EV-04 |
| r1.1 tested in pre-production | M/A | EV-08 |
| r2.1 reversion mechanism | A | EV-09 |
| r3.1 firmware integrity | none | |
| r4.1 continuous monitoring | none | EV-01 |

## Sources

| Source | Content | Used by |
|---|---|---|
| `wazuh-states-vulnerabilities-*` | open CVEs per package and machine: severity, CVSS, detection date | EV-01, EV-02 |
| inventory and freshness of op.exp.1 | packages, OS, syscollector settings, keepalive | EV-01, EV-05, EV-06 |
| `wazuh-states-inventory-packages-*` (`package.vendor`) | vendors of the installed software | EV-06 |
| `update_status` fact | pending upgrades and the age of the package lists | EV-03 |
| `package_transaction` records and their snapshot | apt transactions: when, who, what | EV-04, EV-07, EV-09 |
| dpkg alerts, rule 2902 (`data.package`, `data.version`) | versions installed on the pre-production machines | EV-08 |
| `snapshot_list` fact | LVM, ZFS and Btrfs snapshots and their dates | EV-09 |

Wazuh does not scan the manager for vulnerabilities in the state indices:
EV-01 and EV-02 of the manager are NOT_EVALUABLE by COLLECTION.

### `update_status`

One per pass: `manager` (`apt`, `none`), `status` (`read`, `error`),
`lists_updated` (newest file of `/var/lib/apt/lists`), `pending` and
`security` (upgrades `apt-get -s dist-upgrade` would install, and those
from a `-security` pocket). Emitted only when it changes.

### `package_transaction` and `transaction_snapshot`

The transactions of `/var/log/apt/history.log`, one record each:
`start`, `end`, `actor` (`Requested-By`, or `unattended-upgrades` when its
command line is unattended-upgrade, else `root`), `command`, and
`installed`, `upgraded`, `removed` (`name version`). The snapshot carries
`status` and `records_emitted`. Emitted only when the log changes.

### `snapshot_list`

One per pass: `status` and `snapshots` with `tool` (`lvm`, `zfs`,
`btrfs`), `name` and `created`. Tools absent are left out.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 deadlines `criticidad \| dias` | Crítica, Alta, Media, Baja; empty days: no deadline | EV-02 |
| P-02 accounts authorised to patch `cuenta \| ambito \| tipo` | | EV-04 |
| P-03 vendor announcement sources `fabricante \| fuente \| canal` | `fabricante` is matched inside the package vendor | EV-06 |
| P-04 maintenance windows `sistema \| ventana` | `*` for every machine; `sab 22:00-02:00; * 06:00-07:30` | EV-07 |
| P-05 end of support `producto \| version \| eol` | system; built-in per system type | EV-05 |
| P-06 pre-production `sistema_prod \| sistema_preprod \| consistencia` | agent names | EV-08 |
| P-07 reversion `sistema \| mecanismo \| evidencia \| ventana_horas` | | EV-09 |
| P-08 severity by CVSS `criticidad \| cvss_minimo` | documentary: Wazuh assigns the severity | |
| P-10 days the package lists may be old | | EV-03 |
| P-ATT documentary attestations | | |

P-10 is new.

## How each evidence is judged

Judges are in `engine/internal/controls/ens/opexp4`. A source missing is
NOT_EVALUABLE by COLLECTION; a parameter missing or unusable is
NOT_EVALUABLE by CONFIGURATION.

- **EV-01 vulnerability inventory.** The package inventory is current (op.exp.1
  EV-02): COMPLIANT with the open CVEs by severity. Otherwise the
  freshness judgement of op.exp.1.
- **EV-02 remediation within deadline.** An open CVE whose age since
  `detected_at` exceeds the days of its severity: NON_COMPLIANT with the
  count per severity and some CVEs. Wazuh gives the severity from the CVSS
  score; a CVE without one takes the row `Sin puntuación`. A severity
  without days has no deadline. None overdue: COMPLIANT.
- **EV-03 patch level.** Package lists older than P-10 days: NON_COMPLIANT,
  the machine does not learn of new updates. Otherwise COMPLIANT with the
  pending and security upgrades.
- **EV-04 who patches.** Every transaction of the window must have an actor
  in P-02: otherwise NON_COMPLIANT.
- **EV-05 end of support.** The machine's OS matched in P-05 (product and
  version prefix) with an end date past: NON_COMPLIANT. No row for its OS:
  NOT_EVALUABLE by CONFIGURATION.
- **EV-06 announcement sources.** Every package vendor of the machine must
  contain a `fabricante` of P-03: otherwise NON_COMPLIANT with the vendors.
- **EV-07 maintenance windows.** Every transaction of the window must start
  inside a window of P-04 for the machine (its row, else `*`): otherwise
  NON_COMPLIANT. Times are the machine's.
- **EV-08 pre-production.** On a production machine of P-06, every version
  installed in the window must have been installed on its pre-production
  machine before, or be there now: otherwise NON_COMPLIANT. A machine not
  in P-06 as production: NOT_EVALUABLE by CONFIGURATION.
- **EV-09 reversion point.** Every transaction of the window needs a
  snapshot created at most `ventana_horas` before it: otherwise
  NON_COMPLIANT.

## Not measured

- EV-10 (evolution of the debt): Wazuh keeps no history of resolved vulnerabilities.
- EV-11 (firmware): nothing reads firmware. R3 is not required at any category.
- dnf transactions and updates: EV-03, EV-04, EV-07 and EV-09 of an rpm machine are NOT_EVALUABLE by COLLECTION.
