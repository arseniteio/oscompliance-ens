# OSCompliance ENS

OSCompliance ENS measures the Esquema Nacional de Seguridad (Real Decreto 311/2022) on your Wazuh deployment. It turns what your machines actually do into a verdict per control, per requirement and per machine, with the reason behind every result, every 15 minutes.

It adds one agent binary to each Linux machine and one engine next to the Wazuh indexer. Wazuh keeps doing the collection. Nothing is judged on the machine being audited, and nothing that cannot be proven counts as compliant.

## Get started

1. Build the packages and unpack the one for your architecture:

```bash
make dist VERSION=0.10.0
tar xzf dist/oscompliance-ens-0.10.0-linux-amd64.tar.gz
cd oscompliance-ens-0.10.0-linux-amd64
```

2. On the Wazuh manager: install the rules and the engine, create its least-privilege users and its service unit ([guide](docs/install.md#1-manager)), and start it.

```bash
install -o wazuh -g wazuh -m 660 wazuh/oscompliance_facts_rules.xml /var/ossec/etc/rules/
install -m 755 bin/oscompliance-engine /usr/local/bin/
systemctl enable --now oscompliance-engine
```

3. On every machine to audit: install the agent and its cron entries ([guide](docs/install.md#3-audited-machines)).

```bash
install -m 755 bin/oscompliance-agent /usr/local/bin/
printf '%s\n' '17 * * * * root /usr/local/bin/oscompliance-agent' \
  '23 3 * * * root /usr/local/bin/oscompliance-agent -collect sweep' > /etc/cron.d/oscompliance
```

4. Set your ENS category and parameters in Power ENS, in the Wazuh dashboard.

The [installation guide](docs/install.md) covers every step, including users, roles, the service unit and verification.

## How it works

The agent writes facts to a local file. The Wazuh agent ships that file with the logs, FIM, SCA and inventory to the manager. The manager indexes the facts through rules 119000-119004. Every 15 minutes the engine reads the indexer and writes verdicts, and Power ENS shows them in the dashboard.

- The agent reports facts, never verdicts. Accounts, PAM, sshd, sudoers, listeners, packages, backups, keys: what is there, not whether it is right.
- The engine judges. It reads the facts, Wazuh's own alerts and inventory, the manager through the Wazuh API, and the parameters your organisation declares, and writes one verdict per evidence, requirement and control.
- Missing proof fails. A log that does not reach Wazuh, a parameter nobody set or an agent that stopped reporting shows as not evaluable, with the cause, and the requirement does not comply.
- It scales. 10,000 agents judged in about two minutes per pass on a single indexer node.

More in [architecture](docs/architecture.md) and [verdicts](docs/verdicts.md).

## Controls

34 controls of Annex II, each with the requirements of its categories (BAJO, MEDIO, ALTO):

| Area | Controls |
|---|---|
| Access control | op.acc.1, op.acc.2, op.acc.3, op.acc.4, op.acc.5, op.acc.6 |
| Operation | op.exp.1 to op.exp.10 |
| Continuity | op.cont.2, op.cont.3 |
| Monitoring | op.mon.1, op.mon.2, op.mon.3 |
| Cloud services | op.nub.1 |
| Communications | mp.com.1, mp.com.3, mp.com.4 |
| Equipment | mp.eq.2, mp.eq.3, mp.eq.4 |
| Information | mp.info.6 |
| Services | mp.s.1, mp.s.2, mp.s.3, mp.s.4 |
| Software | mp.sw.2 |

Each control has a page with what the ENS requires, how every evidence is measured, its parameters and what is left to documentary attestation: [controls](docs/controls/README.md).

## Documentation

| | |
|---|---|
| [Installation](docs/install.md) | install, verify, upgrade, uninstall |
| [Configuration](docs/configuration.md) | engine flags, agent settings, ENS parameters |
| [Architecture](docs/architecture.md) | components, data flow, scale |
| [Verdicts](docs/verdicts.md) | statuses, causes, scoring |
| [Controls](docs/controls/README.md) | one page per control |
| [Facts](docs/facts.md) | every fact the agent emits |
| [Security](docs/security.md) | privileges, data handling, threat model |
| [Operations](docs/operations.md) | logs, troubleshooting, capacity |

## Build

```bash
make check                 # gofmt, go vet and tests
make dist VERSION=0.10.0   # packages in dist/
```

## Security

Report vulnerabilities privately through a GitHub security advisory. See [security](docs/security.md).
