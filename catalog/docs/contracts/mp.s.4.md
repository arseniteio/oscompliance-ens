# mp.s.4 fact contract

mp.s.4 (protection against denial of service) judges the machines of the
exposed services: their CPU and memory headroom, SYN cookies and a default
drop firewall, UDP services that could amplify attacks, the rules and the
active response of Wazuh against denial of service, and the register of
episodes with their reaction.

## 1. Requirements and evidences

| Requirement | Levels | Evidences |
|---|---|---|
| 4.1 capacity with headroom | M/A | EV-01, EV-10 |
| 4.2 prevention of known attacks | M/A | EV-02, EV-10 |
| r1.1 detection and treatment | A | EV-03, EV-07, EV-10 |
| r1.2 reaction with the communications provider | A | EV-06 |
| r2.1 attacks from the own premises | none | EV-09 |

A machine that is not a `maquina` of P-01: every evidence and requirement
NOT_APPLICABLE. When no machine of P-01 reports to Wazuh, the manager carries
the control: EV-01, EV-02 and EV-09 are NON_COMPLIANT there.

## 2. Sources

| Source | Content | Used by |
|---|---|---|
| `device_security` fact (mp.eq.2 contract) | `load_percent`, `memory_used_percent`, `syn_cookies` | EV-01, EV-02 |
| `firewall_snapshot` fact (op.acc.4 contract) | input chains and their policy | EV-02 |
| Wazuh API rules and active response (op.mon.1 contract) | | EV-03, EV-07 |
| `listening_snapshot`, `listening_socket` (op.acc.6 contract) | UDP sockets | EV-09 |
| P-07 episodes | | EV-06, EV-10 |

## 3. Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 exposed services `servicio \| maquina \| criticidad \| disponibilidad` | | scope |
| P-02 maximum CPU and memory in use, per cent | | EV-01 |
| P-03 denial of service indicators `ataque \| indicador \| fuente \| reglas` | | EV-03, EV-07 |
| P-04 prevention technologies, P-05 reaction procedure, P-06 provider contact, P-09 planned load | documentary | |
| P-07 episodes `inicio \| fin \| servicio \| vector \| impacto \| respuesta \| proveedor` | | EV-06, EV-10 |
| P-08 authorised amplifying services | names or ports | EV-09 |
| P-ATT documentary attestations | | |

## 4. Evidence judgement

Judges are in `engine/internal/controls/ens/mps4`.

- **EV-01 headroom.** `load_percent` and `memory_used_percent` at most P-02.
- **EV-02 prevention.** SYN cookies on and a chain hooked on input whose
  policy is drop.
- **EV-03 detection.** As mp.com.3 EV-04 for the indicators of P-03.
- **EV-07 containment.** An active response not disabled whose rules
  include a loaded rule of P-03.
- **EV-06 provider.** Every episode of `impacto` alto with `proveedor`.
- **EV-10 episodes.** Every episode with `vector`, `impacto` and
  `respuesta`.
- **EV-09 amplifiers.** No UDP socket on 19, 53, 123, 161, 389, 1900, 5353
  or 11211 bound beyond loopback, unless P-08 names the service or port.

## 5. Parity with v1 and deliberate differences

Kept: the requirements and EV-01 to EV-03, EV-06, EV-07, EV-09, EV-10.

Changed on purpose:

- EV-01 reads the load of the machine; v1 compared request rates of the
  services with P-02, which no common log gives.
- EV-04 and EV-05 (impact and characterisation of each episode) are the
  columns of P-07 that EV-10 asks for.
- EV-08 (outbound attacks) is out: no common source tells it; EV-09 keeps
  the amplifiers.
