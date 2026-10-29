# op.exp.2 fact contract

op.exp.2 (security configuration) judges that every machine is hardened: it
is assessed against a secure baseline and scores above the threshold,
standard accounts are gone, nothing listens that is not justified, the
defaults are the secure ones, and virtual machines are managed like physical
ones.

## 1. Requirements and evidences

| Requirement | Levels | Evidences |
|---|---|---|
| 2.1 standard accounts and passwords removed | B/M/A | EV-01, EV-02 |
| 2.2 minimum functionality | B/M/A | EV-01, EV-03, EV-06 |
| 2.3 security by default | B/M/A | EV-01, EV-04, EV-06 |
| 2.4 virtual machines with the same rigour | B/M/A | EV-05 |

Levels and evidence lists are in `controls/ens/op.exp.2.json`.

## 2. Sources

| Source | Content | Used by |
|---|---|---|
| SCA summary alerts (rules 19001 to 19005, `data.sca.type: summary`) | policy, score, passed and failed checks of each assessment | EV-01, EV-06 |
| `wazuh_agent_config` fact | the agent's SCA settings | EV-01, EV-06 |
| `wazuh-monitoring-*` | last keepalive of each agent | EV-01, EV-06 |
| `identity_snapshot`, `identity_record` (op.acc.1 contract) | accounts, password state, UID, keys | EV-02, EV-04 |
| sshd logins, rule 5715 and children | successful logins | EV-02 |
| `listening_snapshot`, `listening_socket` (op.acc.6 contract) | listening sockets and their process | EV-03 |
| `config_snapshot`, `config_file` (`sshd -T`) | effective sshd settings | EV-04 |
| `acl_snapshot`, `acl_record` (op.acc.2 contract) | mode and owner of the files of P-08 | EV-04 |
| `virtualization` fact | whether the machine is a virtual machine | EV-05 |

Wazuh raises an SCA summary only when the result changes, so the newest
summary of each policy is the current one however old it is. The engine
reads it back 366 days. Freshness is proven as in op.exp.1: SCA enabled,
its interval within P-09 and the last keepalive within P-09.

The paths of P-08 reach the agent with the ACL paths of the group
configuration (`acl_paths`).

### `wazuh_agent_config`, SCA fields

| Field | Meaning |
|---|---|
| `sca_disabled` | `<enabled>no</enabled>` in `<sca>`, or no `<sca>` block |
| `sca_interval` | seconds between assessments; Wazuh's default is 12 hours |

### `config_file` for `sshd -T`

Adds `permitrootlogin`, `permitemptypasswords`, `x11forwarding`,
`hostbasedauthentication`, `ignorerhosts`, `ciphers`, `macs` and
`kexalgorithms` to the keys op.acc.6 already sends.

### `virtualization`

One per pass: `status` (`read`, `unreadable`), `virtual`, `platform` (as
`systemd-detect-virt --vm` names it, `unknown` when only DMI or the CPU say
so), `vendor`, `product` and `source` (`systemd-detect-virt`, `dmi`,
`cpuinfo`). Containers are not virtual machines.

## 3. Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 SCA policies of the machine (policy ids) | system; built-in per system type | EV-01, EV-06 |
| P-02 justified services `servicio \| puertos` | system; process name, ports comma-separated, empty for any | EV-03 |
| P-03 standard accounts `cuenta \| producto` | | EV-02 |
| P-04 authorised exceptions `activo \| comprobacion \| motivo \| aprobo \| vigencia` | | EV-04 |
| P-05 minimum SCA score (%) | | EV-06 |
| P-06 virtual machines `hipervisor \| maquina \| gestion` | `maquina` and `gestion` are agent names or a reference | EV-05 |
| P-07 check before production | documentary | |
| P-08 sensitive files `ruta \| modo \| propietario` | system; built-in per system type | EV-04 |
| P-09 hours an assessment may go without refresh | | EV-01, EV-06 |
| P-ATT documentary attestations | | |

P-08 and P-09 are new: v1 kept the file list in the collector and had no
freshness parameter.

## 4. Evidence judgement

Judges are in `engine/internal/controls/ens/opexp2`. A source missing is
NOT_EVALUABLE by COLLECTION; a parameter missing or unusable is
NOT_EVALUABLE by CONFIGURATION.

- **EV-01 baseline assessment.** SCA off, interval above P-09 or no contact
  within P-09: NON_COMPLIANT. No summary of any P-01 policy: NON_COMPLIANT.
  Otherwise COMPLIANT with each policy and its score.
- **EV-02 standard accounts.** A P-03 account that exists and is active (the
  op.acc.1 definition: a usable password or SSH keys with a login shell), or
  that logged in during the window: NON_COMPLIANT. One that exists disabled
  is reported, not failed.
- **EV-03 justified services.** Each listening socket must match a P-02 row
  by process and, when the row has ports, by port: otherwise
  NON_COMPLIANT with process and port.
- **EV-04 secure defaults.** Deviations: sshd `permitrootlogin` other than
  `no`, `permitemptypasswords`, `x11forwarding` or `hostbasedauthentication`
  `yes`, `ignorerhosts` `no`, weak ciphers, MACs or key exchanges; a P-08
  file more open than its mode or not owned by its owner; an account with an
  empty password; a UID 0 other than root. Each is named
  `<check>[:<subject>]` (`ssh_permitrootlogin`, `permisos:/etc/shadow`,
  `uid0:toor`). A deviation with a P-04 row for this machine and a `vigencia`
  not past is authorised. Any other: NON_COMPLIANT.
- **EV-05 virtual machines.** A machine that is not virtual: COMPLIANT. A
  virtual machine must be a `maquina` of P-06, and when its `gestion` names
  an agent that agent must be reporting: otherwise NON_COMPLIANT.
- **EV-06 baseline score.** The newest score of every P-01 policy assessed
  must be at least P-05: otherwise NON_COMPLIANT with the scores below it.

## 5. Parity with v1 and deliberate differences

Kept: the requirements, EV-01 to EV-06 and the meaning of the parameters.

Changed on purpose:

- EV-07 (conformity before production) is out: no fact shows the order
  between hardening and going live. P-07 stays as documentation.
- The SCA results come from Wazuh's own summaries; v1 re-emitted them from a
  collector. Their freshness is the SCA settings plus the keepalive.
- P-01, P-02 and P-08 are per machine, with built-in values per system type;
  v1 keyed them by a profile name.
- An exception needs a `vigencia` not past; v1 did not read it.
- Standard accounts follow op.acc.1's definition of an active account; v1
  failed any existing one.
