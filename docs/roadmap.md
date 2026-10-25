# Roadmap

Work agreed but not started. Each item says what done means.

## Controls

- Migrate every op.acc control (op.acc.2 to op.acc.6) to agent facts and
  engine judgement, with the method and quality of op.acc.1: contract, facts,
  engine, tests, lab. In progress.

## Installation

- **One install for the agent side.** Installing on a machine sets up the
  oscompliance agent with every control, and the Wazuh agent integration it
  needs, so facts start flowing to the chosen manager with no manual step.
  Review how the Wazuh agent itself can deploy it (package, group shared
  files, or a Wazuh wodle) instead of a separate install.
- **The manager is audited like any machine.** It belongs to no group, so the
  installer adds the facts `<localfile>` to the manager's own `ossec.conf`.
- Manager side (decoder, rules) installed once, by package or Wazuh API.

## Plugin

- Read verdicts from `oscompliance-verdicts` instead of evaluating.
- Read evidence levels, requirements, parameter classes and templates from
  `catalog/` instead of its TypeScript copies.
- Evaluate the manager row with every control, not only organisation ones.
- Show identity changes (EV-02) from the verdict reason or from
  `oscompliance-identity-history`.

## Parameters

- Suggest parameter values from the facts already received (P-07 from the
  active accounts, P-03 from system accounts) so the administrator confirms
  instead of typing.
