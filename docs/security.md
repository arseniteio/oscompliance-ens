# Security

A compliance tool runs as root on every machine and holds credentials next to
the SIEM. This page states what each part can do, what it cannot, and what
an attacker gains by compromising it.

## Agent

| | |
|---|---|
| Runs as | root, from cron, one pass at a time (a lock file prevents overlap) |
| Reads | local system files and the output of local commands, listed per collector in [facts](facts.md) |
| Writes | `/var/log/oscompliance/facts.ndjson` (0640), `/var/lib/oscompliance/` (0700), one syslog line per pass |
| Changes | adds auditd watches at runtime, tagged `oscompliance_*`, for the paths the group configuration lists; never removes a rule, never writes to `/etc/audit` |
| Network | none; it opens no socket and listens on nothing; facts travel through the Wazuh agent's existing channel |
| Never sends | password hashes, private keys, file contents, configuration values the controls do not judge |

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

| | |
|---|---|
| Runs as | a systemd service on the manager host, with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome` and `PrivateTmp` |
| Indexer | its own user and role: read Wazuh's alerts, monitoring, inventory, vulnerability and Power ENS indices; write only `oscompliance-*` |
| Wazuh API | its own user and policy: read agents, groups, inventory, manager configuration and rules; write only group configuration |
| Credentials | `/etc/oscompliance/engine.env`, 0600, read through the environment; never on the command line or in logs |
| TLS | certificates verified against the CA given with `-ca` and `-wazuh-api-ca`; there is no option to skip verification |
| Local writes | none |

The only change the engine makes to the Wazuh deployment is the marked region
of each ENS group's `agent.conf`. It is opt-in (`-sync-apply`), limited to the
groups in the ENS scope, and every change is recorded with the region before
and after in `oscompliance-config-history`. The engine cannot run commands on
agents, change rules or decoders, or touch any other group.

Roles: [`catalog/wazuh/engine-role.yml`](../catalog/wazuh/engine-role.yml),
[`catalog/wazuh/engine-api-role.json`](../catalog/wazuh/engine-api-role.json).

## Plugin

The Power ENS plugin runs inside the Wazuh dashboard with the dashboard's
authentication and the indexer's access control. It writes the ENS
configuration and reads verdicts. It judges nothing, so a modified plugin can
misdisplay verdicts but cannot change the ones stored.

## Threat model

| If an attacker controls | They can | They cannot |
|---|---|---|
| an unprivileged account on an audited machine | nothing specific to OSCompliance | write facts, forge service events, read the facts file |
| root on an audited machine | stop the agent: its evidences turn NOT_EVALUABLE by COLLECTION and the machine shows as non-compliant | hide that it stopped; forge what Wazuh itself collects (logins, sudo, FIM, SCA, inventory, vulnerabilities), which many evidences read instead of the agent |
| root on an audited machine | write false facts about that machine | affect any other machine |
| the engine host | change verdicts | it is the Wazuh manager host: Wazuh is already compromised |
| the engine's indexer credentials | write false verdicts | read beyond Wazuh's indices, change Wazuh's data |
| the engine's API credentials | change the group configuration of any group | run commands, restart agents, change rules |

The design choice behind the second row is deliberate: the audited machine
reports facts, never verdicts, and silence is never compliance. Where Wazuh
already observes something, the engine reads Wazuh, not the agent.

## Supply chain

- The agent and the engine use only the Go standard library and this
  repository's own catalog. There is no third-party code in either binary.
- `make dist` builds with `CGO_ENABLED=0` and `-trimpath` and writes
  `SHA256SUMS`. `make check` runs gofmt, `go vet` and every test.
- The binaries are static: no shared library on the host is loaded.

## Reporting a vulnerability

Report it privately through a GitHub security advisory on this repository.
Do not open a public issue.
