# mp.com.1 fact contract

mp.com.1 (secure perimeter) judges the perimeter devices through their logs
in Wazuh, the flows they let through and the review of their rules; and, on
every machine, the ways around the perimeter: interfaces, gateways, tunnels
and administration reached from the internet.

## 1. Requirements and evidences

| Requirement | Levels | Evidences |
|---|---|---|
| 1.1 perimeter all traffic crosses | B/M/A | EV-01, EV-03, EV-04, EV-05, EV-07, EV-08 |
| 1.2 flows authorised beforehand | B/M/A | EV-01, EV-02, EV-06, EV-07, EV-08 |

## 2. Sources

| Source | Content | Used by |
|---|---|---|
| alerts of each device of P-01 | hours with alerts, a week back; a device is matched by `agent.name`, `predecoder.hostname` or `location` | EV-01, EV-08 |
| alerts of those devices with `data.action` accept, allow, pass or permit | `data.srcip`, `data.dstip`, `data.protocol`, `data.dstport` | EV-02 |
| `wazuh-states-inventory-interfaces-*`, `-networks-*`, `-protocols-*` | interfaces, addresses and gateways | EV-03, EV-04, EV-05 |
| `wazuh-states-inventory-processes-*` | processes of tunnelling tools | EV-05 |
| authentication alerts (`sshd`, `authentication_*`) with `data.srcip` | sources of each machine's logins | EV-07 |

The manager's inventory is read through the Wazuh API
(`/syscollector/000/netiface`, `netaddr`, `netproto`, `processes`).

Tunnelling tools: openvpn, openconnect, vpnc, charon, tailscaled,
zerotier-one, ngrok, cloudflared, frpc, chisel, autossh, sshuttle, stunnel,
iodine, ptunnel, dns2tcp, gost, tmate, teamviewerd, anydesk, rustdesk.

## 3. Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 perimeter devices `elemento \| tipo \| ubicacion \| fuente` | | EV-01, EV-02, EV-08 |
| P-02 authorised flows `origen \| destino \| protocolo \| puerto \| autorizado_por \| fecha` | CIDR, address or `*`; port, range or `*` | EV-02, EV-06 |
| P-03 exits `salida \| elemento \| pasarela` | | EV-04 |
| P-04 days between rule reviews | | EV-06 |
| P-05 forbidden rules, P-06 interconnection ITS | documentary | |
| P-07 expected interfaces | system; globs; built-in per system type | EV-03 |
| P-08 authorised tunnels | system; interface or process names | EV-05 |
| P-09 authorised internet sources of administration | CIDR or address | EV-07 |
| P-10 hours without perimeter logs | | EV-01, EV-08 |
| P-11 rule reviews `fecha \| elemento \| responsable \| hallazgos` | | EV-06 |
| P-ATT documentary attestations | | |

## 4. Evidence judgement

Judges are in `engine/internal/controls/ens/mpcom1`.

- **EV-01 perimeter logs.** Every device of P-01 with an alert within P-10
  hours.
- **EV-02 flows.** Every accepted flow of the window matches a row of P-02
  with `autorizado_por`.
- **EV-03 interfaces.** Every interface `up` matches a pattern of P-07.
- **EV-04 exits.** Every gateway of the machine is a `pasarela` of P-03.
- **EV-05 tunnels.** No tunnel interface up (type tunnel, ppp, tun, tap,
  wireguard; names tun, tap, wg, ppp, ipsec, vti, gre, tailscale, zt) and no
  tunnelling tool running, outside P-08.
- **EV-06 rules.** No row of P-02 open to any origin on every port or an
  administration port (22, 23, 139, 161, 445, 1433, 1521, 2375, 3306, 3389,
  5432, 5900, 5985, 5986, 6379, 9200, 27017), and the newest review of P-11
  within P-04 days.
- **EV-07 administration from the internet.** No authentication of the
  window from a public address outside P-09.
- **EV-08 continuity.** No device of P-01 more than P-10 hours without
  alerts in the last week.

## 5. Parity with v1 and deliberate differences

Kept: the requirements and the eight evidences.

Changed on purpose:

- Interfaces, gateways and tunnelling tools come from Wazuh's inventory; v1
  ran its own collector.
- EV-06 judges the authorised flows and the review register; v1 looked for
  rules without traffic, which are reported nowhere a verdict can rest on.
- EV-07 reads authentications from public addresses; v1 read perimeter
  logs of inbound traffic to administration ports.
