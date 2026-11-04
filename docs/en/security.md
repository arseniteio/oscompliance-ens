# Security

A compliance tool runs as root on every machine and holds credentials next to
the SIEM. This page states what each part can do, what it cannot, and what
an attacker gains by compromising it.

## Agent

The agent runs as root from cron, one pass at a time, with a lock file that prevents overlap. It reads local system files and the output of local commands, listed per collector in [Facts](facts.md).

It writes `/var/log/oscompliance/facts.ndjson` (0640), `/var/lib/oscompliance/` (0700) and one syslog line per pass. Its only change to the system is adding auditd watches at runtime, tagged `oscompliance_*`, for the paths in the group configuration. It never removes a rule and never writes to `/etc/audit`.

It opens no socket and listens on nothing. Facts travel through the Wazuh agent's existing channel. It never sends password hashes, private keys, file contents or configuration values the controls do not judge.

It runs as root because the facts that matter are root-only: `/etc/shadow`,
`sshd -T`, sudoers, auditd. It reads them; it does not change them.

Configuration files can hold secrets, so the `config` collector sends only the
keys the controls judge (for example `PasswordAuthentication` of sshd, never
a whole file). The `keys` collector finds private keys by their PEM header
and sends the path, kind, public fingerprint, mode and owner, never the key.
The `backups` collector sends dates, sizes and permissions of copies, never
their content.

## Rules

The rules accept a fact only from `/var/log/oscompliance/facts.ndjson`, which
only root can write. A local user who writes a fact-shaped line to syslog or
the journal does not produce a fact. Service events (op.acc.5) are refused
from syslog, the journal and the system authentication logs for the same
reason. No rule raises an alert above level 3: OSCompliance adds no noise to
the SOC.

## Engine

The engine runs as a systemd service on the manager host, with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome` and `PrivateTmp`. It writes nothing locally.

In the indexer it has its own user and role. It reads Wazuh's alerts, monitoring, inventory and vulnerability indices and the Power ENS configuration, and writes only `oscompliance-*`.

In the Wazuh API it has its own user and policy. It reads agents, groups, inventory, manager configuration and rules, and writes only the group configuration. The policy grants `group:read`, `group:create`, `group:update_config`, `agent:read`, `syscollector:read`, `manager:read` and `rules:read`.

Its credentials are in `/etc/oscompliance/engine.env`, mode 0600, read through the environment. They never appear on the command line or in logs. Certificates are verified against the CA given with `-ca` and `-wazuh-api-ca`, and there is no option to skip verification.

The only change the engine makes to the Wazuh deployment is the marked region
of each ENS group's `agent.conf`. It is opt-in (`-sync-apply`), limited to the
groups in the ENS scope, and every change is recorded with the region before
and after in `oscompliance-config-history`. The engine cannot run commands on
agents, change rules or decoders, or touch any other group.

Roles: [`catalog/wazuh/engine-role.json`](../../catalog/wazuh/engine-role.json),
[`catalog/wazuh/engine-api-role.json`](../../catalog/wazuh/engine-api-role.json).

## Plugin

The Power ENS plugin runs inside the Wazuh dashboard with the dashboard's
authentication and the indexer's access control. It writes the ENS
configuration and reads verdicts. It judges nothing, so a modified plugin can
misdisplay verdicts but cannot change the ones stored.

## Threat model

An unprivileged account on an audited machine gains nothing specific to OSCompliance. It cannot write facts, forge service events or read the facts file.

Root on an audited machine can stop the agent. The machine's evidences turn NOT_EVALUABLE by COLLECTION and it shows as non-compliant, so the stop cannot be hidden. It can also write false facts about that machine, but not about any other. It cannot forge what Wazuh itself collects (logins, sudo, FIM, SCA, inventory, vulnerabilities), which many evidences read instead of the agent.

The engine host is the Wazuh manager host. Whoever controls it can change verdicts, but Wazuh is already compromised at that point.

The engine's indexer credentials allow writing false verdicts. They do not allow reading beyond Wazuh's indices or changing Wazuh's data.

The engine's API credentials allow changing the group configuration of any group. They do not allow running commands, restarting agents or changing rules.

This is why the audited machine reports facts, never verdicts, and why silence is never compliance. Where Wazuh already observes something, the engine reads Wazuh, not the agent.

## Supply chain

- The agent and the engine use only the Go standard library and this
  repository's own catalog. There is no third-party code in either binary.
- `make dist` builds with `CGO_ENABLED=0` and `-trimpath` and writes
  `SHA256SUMS`. `make check` runs gofmt, `go vet` and every test.
- The binaries are static: no shared library on the host is loaded.

## Reporting a vulnerability

Report it privately through a GitHub security advisory on this repository.
Do not open a public issue.
