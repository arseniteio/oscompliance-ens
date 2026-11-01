# mp.com.4 fact contract

mp.com.4 (segregation of networks) judges the segments of the network:
every machine in a declared segment and in only one unless it is an
interconnection point, flows between segments limited to the matrix,
wireless kept in its own segment, the chosen way of segmenting in place,
the interconnection points monitored, and incidents contained in their
segment.

## 1. Requirements and evidences

| Requirement | Levels | Evidences |
|---|---|---|
| 4.1 traffic segregated | M/A | EV-01, EV-02, EV-03, EV-09, EV-10 |
| 4.2 wireless in a separate segment | M/A | EV-04 |
| r1.1 segments by VLAN | M | EV-07 |
| r1.2 users, services and administration | M | EV-08 |
| r2.1 segments by VPN | M/A | EV-07 |
| r3.1 segments by separate physical media | M/A | attestation (P-ATT) |
| r4.1 entry control to each segment | A | EV-05 |
| r4.2 interconnection point monitored | A | EV-05 |

P-03 picks one way of segmenting: the reinforcements of the other two are
NOT_APPLICABLE.

## 2. Sources

| Source | Content | Used by |
|---|---|---|
| network inventory (mp.com.1 contract) | addresses by interface, interface types | EV-01, EV-03, EV-04, EV-07, EV-09 |
| alerts of each point of P-05 | hours with alerts and accepted flows (mp.com.1 contract) | EV-02, EV-05 |
| op.exp.7 P-13 incident register | incidents of the last 90 days and their systems | EV-09 |
| `wazuh-monitoring-*` | agent names, to find the machines of an incident | EV-09 |

## 3. Parameters

| ID | Content | Used by |
|---|---|---|
| P-01 segments `segmento \| proposito \| rango \| vlan` | `proposito` usuarios, servicios, administración, inalámbrico, otro | EV-01 to EV-04, EV-07 to EV-09 |
| P-02 flow matrix `origen \| destino \| protocolo \| puerto` | segment names or `*` | EV-02 |
| P-03 way of segmenting | VLAN, VPN, medios físicos separados | EV-07, decisions |
| P-04 wireless networks, P-06 entry control | documentary | |
| P-05 interconnection points `punto \| segmentos \| equipo \| fuente` | | EV-02, EV-03, EV-05 |
| P-07 days between matrix reviews | | EV-10 |
| P-08 matrix reviews `fecha \| responsable \| cambios` | | EV-10 |
| P-09 hours without logs of a point | | EV-05 |
| P-ATT documentary attestations | r3.1 | |

## 4. Evidence judgement

Judges are in `engine/internal/controls/ens/mpcom4`. An address belongs to
the narrowest range of P-01 holding it; loopback and link-local addresses
belong to none.

- **EV-01 declared segment.** Every address of the machine in a segment.
- **EV-02 flows.** Every accepted flow of the points of P-05 between two
  segments matches a row of P-02. No point: NOT_EVALUABLE.
- **EV-03 bridges.** The machine in one segment, or named as `equipo` of a
  point of P-05.
- **EV-04 wireless.** Every wireless interface up (type wireless or a name
  starting `wl`) with its addresses in an `inalámbrico` segment.
- **EV-05 interconnection logs.** As mp.com.1 EV-01 over the points of P-05
  and P-09.
- **EV-07 way of segmenting.** VLAN: every segment with its `vlan`; VPN: a
  tunnel interface up on the machine.
- **EV-08 minimum segments.** Segments for users, services and
  administration.
- **EV-09 incidents contained.** No incident of the last 90 days whose
  machines are in more than one segment.
- **EV-10 matrix reviewed.** The newest review of P-08 within P-07 days.

## 5. Parity with v1 and deliberate differences

Kept: the requirements and EV-01 to EV-05, EV-07 to EV-10.

Changed on purpose:

- EV-06 (users matched to their segment) is out: no network access control
  log reaches Wazuh in a form the engine can read; P-06 stays documentary.
- r3.1 is an attestation: separate physical media leave no record.
- EV-10 judges the review of the matrix; v1 listed unused and unexpected
  flows without a verdict.
