# mp.eq.4 Otros dispositivos conectados a la red

mp.eq.4 (other devices connected to the network) judges the devices that
take no agent: every device a machine sees next to it inventoried or part
of the fleet, their flows within what their type may do, their own logs
reaching Wazuh, and a wipe for those that keep information.

Levels: BAJO, MEDIO, ALTO. Annex II section 5.3.4. Definition: [`catalog/controls/ens/mp.eq.4.json`](../../../catalog/controls/ens/mp.eq.4.json).

## Requirements

| Requirement | Levels | Evidences |
|---|---|---|
| 4.1 secure configuration and controlled flows | B/M/A | EV-01 to EV-04 |
| 4.2 wipe of the devices' storage | B/M/A | EV-04, EV-08 |
| r1.1 products under op.pl.5 | M/A | attestation (P-ATT) |
| r2.1 control of connected devices | none | EV-01 |

## Sources

| Source | Content | Used by |
|---|---|---|
| `neighbour_snapshot` fact ([op.exp.1](op.exp.1.md)) | the machine's neighbour table | EV-01, EV-02 |
| network inventory ([mp.com.1](mp.com.1.md)) | addresses of every machine of the fleet | EV-02 |
| alerts of the sources of P-03 with accepted flows ([mp.com.1](mp.com.1.md)) | | EV-03 |
| alerts of each device of P-04 | hours with alerts, a week back | EV-04 |

## Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 devices `dispositivo \| tipo \| direccion \| mac \| responsable \| almacenamiento` | | EV-02, EV-03, EV-08 |
| P-02 flows by type `tipo \| destino \| protocolo \| puerto` | | EV-03 |
| P-03 flow sources `fuente \| tipo \| nombre_wazuh` | | EV-03 |
| P-04 devices with logs `dispositivo \| configuracion \| fuente` | | EV-04 |
| P-05 wipes `dispositivo \| almacenamiento \| metodo \| cuando` | | EV-08 |
| P-06 hours without a device's logs | | EV-04 |
| P-07 certified products, P-08 guests and personal devices, P-09 connection control | documentary | |
| P-ATT documentary attestations | r1.1 | |

## How each evidence is judged

Judges are in `engine/internal/controls/ens/mpeq4`.

- EV-01 discovery. The machine's neighbour table read.
- EV-02 inventory. Every neighbour matches a device of P-01 by MAC or
  address, or is an address of a machine of the fleet.
- EV-03 flows. Every accepted flow of the sources of P-03 with a device
  of P-01 at either end is allowed for its `tipo` towards the other end.
  No source: NOT_EVALUABLE.
- EV-04 device logs. As mp.com.1 EV-01 over the devices of P-04 and
  P-06; no device in P-04: NON_COMPLIANT.
- EV-08 wipe. Every device of P-01 with `almacenamiento` sí has a
  `metodo` in P-05.

## Not measured

- EV-05 (administration panels), EV-06 (connections and disconnections) and EV-07 (guest devices): their sources are device specific and reach Wazuh in no common form.
- The wipe itself: EV-08 judges that a wipe is defined, because a wipe leaves no common record.
