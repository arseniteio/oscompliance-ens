# mp.com.3 Protección de la integridad y de la autenticidad

mp.com.3 (integrity and authenticity) judges whether machines authenticate
the other end before exchanging, use the algorithms the CCN authorises,
detect active attacks and open an incident when they do, run their
channels outside the domain through encrypted tunnels, change channel
configurations only under change control, and use certified products.

Levels: BAJO, MEDIO, ALTO. Annex II section 5.4.3. Definition: [`catalog/controls/ens/mp.com.3.json`](../../catalog/controls/ens/mp.com.3.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 3.1 the other end authenticated first | B/M/A | EV-01, EV-02, EV-10 |
| 3.2 active attacks handled as incidents | B/M/A | EV-04 to EV-07 |
| 3.3 legal identification mechanisms accepted | B/M/A | attestation (P-ATT) |
| r1.1 encrypted VPN outside the domain | M/A | EV-08 |
| r2.1 algorithms authorised by the CCN | M/A | EV-02, EV-03, EV-10 |
| r3.1 hardware VPN devices | A | attestation (P-ATT) |
| r4.1 products certified under op.pl.5 | A | EV-11 |
| r5.1 CCN-STIC ciphers | none | |

## Sources

| Source | Content | Used by |
|---|---|---|
| `config_file` of `/etc/ssh/ssh_config` and its drop-ins | `Host`, `StrictHostKeyChecking`, `UserKnownHostsFile` | EV-01 |
| `config_file` for `sshd -T`, sshd logins ([op.exp.10](op.exp.10.md)) | algorithms accepted and key types used | EV-02, EV-03 |
| Wazuh API rules ([op.mon.1](op.mon.1.md)) | rules of the indicators of P-02 | EV-04 to EV-07 |
| alerts of those rules, by machine and hour | | EV-07 |
| op.exp.7 P-13 incident register | | EV-07 |
| network inventory ([mp.com.1](mp.com.1.md)) | tunnel interfaces and processes | EV-08 |
| FIM alerts ([op.exp.5](op.exp.5.md)), op.exp.5 P-10 | changes under P-06 and their requests | EV-10 |

The paths of P-06 outside Wazuh's default FIM directories reach the agent
in the group configuration as FIM directories.

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 channels outside the domain | documentary | |
| P-02 active attack indicators `ataque \| indicador \| fuente \| reglas` | `ataque` alteración, inyección or secuestro | EV-04 to EV-07 |
| P-03 incident procedure, P-04 identification mechanisms, P-08 hardware VPN | documentary | |
| P-05 tunnels `canal \| sistema \| tunel \| protocolo \| cifrado` | `tunel` an interface or process | EV-08 |
| P-06 channel configurations | system; built-in per system type | EV-10 |
| P-07 certified products `producto \| certificacion \| referencia \| vigencia` | | EV-11 |
| op.exp.10 P-03 authorised algorithms | | EV-02, EV-03 |
| P-ATT documentary attestations | 3.3, r3.1 | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/mpcom3`.

- **EV-01 the other end.** No `StrictHostKeyChecking no` (or `off`) and no
  `UserKnownHostsFile /dev/null` in the SSH client configuration.
- **EV-02, EV-03 algorithms.** As op.exp.10 EV-03 and EV-04.
- **EV-04 to EV-06 active attacks.** Alteration, injection and hijacking each
  have rows in P-02, and every row a loaded rule of level 1 or more.
- **EV-07 incidents.** Every hour of the window with an alert of those rules
  on the machine has an incident of op.exp.7 involving it opened from an
  hour before to a day after.
- **EV-08 tunnels.** Every row of P-05 for the machine has its `tunel` up as
  an interface or running as a process.
- **EV-10 configuration changes.** Every FIM change of the window under P-06
  covered by a request of op.exp.5 P-10.
- **EV-11 products.** Every product of P-07 with a `referencia` and a
  `vigencia` not past.

## Not measured

- **Mechanisms not refused.** No log tells a refused legal mechanism; 3.3 is an attestation.
