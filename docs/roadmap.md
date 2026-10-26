# Roadmap

Work agreed but not started. Each item says what done means.

## Controls

- op.acc.1 to op.acc.6 are migrated: contracts in `catalog/docs/contracts`,
  facts, engine, tests, and a lab check of every evidence. What is left of
  them is below (manager side, plugin parameters, auditd).

## Installation

- **One install for the agent side.** Installing on a machine sets up the
  oscompliance agent with every control, and the Wazuh agent integration it
  needs, so facts start flowing to the chosen manager with no manual step.
  Review how the Wazuh agent itself can deploy it (package, group shared
  files, or a Wazuh wodle) instead of a separate install.
- **The manager is audited like any machine.** It belongs to no group, so the
  installer adds the facts `<localfile>` to the manager's own `ossec.conf`.
- Manager side (decoder, rules) installed once, by package or Wazuh API.
- **Configuration from parameters.** Some controls watch what a parameter
  names. The manager side writes it to the group configuration, which Wazuh
  sends to its agents; the lab does it by hand in `scripts/manager-setup.sh`:
  - labelled `<localfile>` blocks per machine for op.acc.5 P-02 (one
    `<agent_config name="...">` per machine with a service);
  - `<syscheck><directories>` for op.acc.2 P-02 paths outside the default
    FIM directories;
  - a `<localfile>` with `log_format audit` for `/var/log/audit/audit.log`;
  - the shared `oscompliance.json`: `acl_paths` (op.acc.2 P-08),
    `audit_watches` (op.acc.2 P-06, op.acc.4 P-07, the op.acc.3 security
    paths) and `exec_watches` (op.acc.3 P-03 binaries).
- **auditd on the machines.** op.acc.2 EV-06, op.acc.3 and op.acc.4 EV-04
  and EV-07 need it running; the agent loads the watches and rules itself.

## Scale

- The engine judges agent by agent, with a few queries per control and
  agent. Before a fleet of hundreds of thousands: batch those queries per
  pass, run controls in parallel, and size the pass interval to the fleet
  (the lab runs every 5 minutes; hourly facts need no more than hourly
  passes).
- Group configuration written by the engine (see Installation) must stay
  per group and system type: a block per machine does not scale and every
  change restarts the agents of the group.

## Plugin

- Read verdicts from `oscompliance-verdicts` instead of evaluating.
- Read evidence levels, requirements, parameter classes and templates from
  `catalog/` instead of its TypeScript copies.
- Evaluate the manager row with every control, not only organisation ones.
- Show identity changes (EV-02) from the verdict reason or from
  `oscompliance-identity-history`.

- New parameters the engine already reads:
  - op.acc.6 P-12, register of compromised and departed accounts,
    `usuario | fecha | motivo` (organisation);
  - op.acc.4 P-08, register of access rights reviews, `fecha | alcance |
    responsable` (organisation);
  - op.acc.3 P-04 gains the command of each task as its third column.

## Parameters

- Suggest parameter values from the facts already received (P-07 from the
  active accounts, P-03 from system accounts) so the administrator confirms
  instead of typing.
