# OSCompliance ENS

[Versión en español](README.es.md)

OSCompliance ENS measures the Esquema Nacional de Seguridad (Real Decreto 311/2022) on a Wazuh deployment. It turns what your machines do into a verdict per control, per requirement and per machine, with the reason behind every result, every 15 minutes.

It adds one agent binary to each Linux machine and one engine next to the Wazuh indexer. Wazuh keeps doing the collection. Nothing is judged on the machine being audited, and nothing that cannot be proven counts as compliant. The results are shown in the Wazuh dashboard by the [Power ENS](https://github.com/arseniteio/power-ens) plugin.

It runs on Wazuh 4.14.7, 4.14.8 and 4.14.9, with audited machines on Linux.

## Get started

The quick install below covers one server with Wazuh 4.14.8 or 4.14.9 installed from packages, and Linux amd64 machines. For Wazuh 4.14.7 use the `osd-2.19.5` zip. For Docker, other architectures or the details of each step, follow the full guides:

- [Installation with packages](docs/en/install.md)
- [Installation with Docker](docs/en/install-docker.md)

### Quick install

On the server, as root, with `gh` signed in to GitHub. `engine-users.sh` asks for the password of `wazuh-wui` and for two new passwords.

```bash
gh release download v1.0.0 -R arseniteio/oscompliance-ens -D osc -p '*-linux-amd64.tar.gz' -p SHA256SUMS
gh release download v1.0.0 -R arseniteio/power-ens -D plugin
(cd osc && sha256sum -c --ignore-missing SHA256SUMS) && (cd plugin && sha256sum -c --ignore-missing SHA256SUMS)
tar xzf osc/oscompliance-ens-1.0.0-linux-amd64.tar.gz && cd oscompliance-ens-1.0.0-linux-amd64
install -o wazuh -g wazuh -m 660 wazuh/oscompliance_facts_rules.xml /var/ossec/etc/rules/
systemctl restart wazuh-manager && sleep 60
/var/ossec/bin/agent_groups -a -g ens -q
bash wazuh/engine-users.sh create
bash ../plugin/deploy-plugin.sh ../plugin/power-ens-1.0.0-osd-2.19.6.zip
```

In the dashboard, open Power ENS, Configuración, Organización, fill in Cliente and press Guardar configuración global. Then start the engine and add each machine to the `ens` group, with the agent ID from `agent_control -l`.

```bash
install -m 755 bin/oscompliance-engine /usr/local/bin/
install -m 644 wazuh/oscompliance-engine.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now oscompliance-engine
/var/ossec/bin/agent_groups -a -i <id> -g ens -q
```

On each machine, copy the same package and unpack it. When `grep -c facts.ndjson /var/ossec/etc/shared/agent.conf` prints a number above 0, install the agent.

```bash
cd oscompliance-ens-1.0.0-linux-amd64
install -m 755 bin/oscompliance-agent /usr/local/bin/
install -m 644 agent/oscompliance.cron /etc/cron.d/oscompliance
install -d -m 750 /var/log/oscompliance && install -d -m 700 /var/lib/oscompliance
touch /var/log/oscompliance/facts.ndjson && systemctl restart wazuh-agent
sleep 30 && oscompliance-agent -full
```

The first verdicts appear in Power ENS after the next engine pass, within 15 minutes.

## How it works

The agent writes facts to a local file. The Wazuh agent ships that file with the logs, FIM, SCA and inventory to the manager, which indexes the facts through rules 119000 to 119004. Every 15 minutes the engine reads the indexer and writes verdicts, and Power ENS shows them.

The agent reports facts, never verdicts: accounts, PAM, sshd, sudoers, listeners, packages, backups and keys, as they are.

The engine judges. It reads the facts, Wazuh's own alerts and inventory, the manager through the Wazuh API, and the parameters your organisation declares, and writes one verdict per evidence, requirement and control.

Missing proof fails. A log that does not reach Wazuh, a parameter nobody set or an agent that stopped reporting shows as not evaluable, with the cause, and the requirement does not comply.

A pass over 10,000 simulated agents takes about two minutes on a single indexer node.

## Controls

It covers 34 controls of Annex II, each with the requirements of its categories (BAJO, MEDIO, ALTO): access control (op.acc), operation (op.exp), continuity (op.cont), monitoring (op.mon), cloud services (op.nub), communications (mp.com), equipment (mp.eq), information (mp.info), services (mp.s) and software (mp.sw).

Each control has a page with what the ENS requires, how every evidence is measured, its parameters and what is left to documentary attestation. See [Controls](docs/en/controls/README.md).

## Documentation

- [Installation with packages](docs/en/install.md) and [with Docker](docs/en/install-docker.md): install, verify, upgrade and uninstall.
- [Configuration](docs/en/configuration.md): engine flags, agent settings and ENS parameters.
- [Architecture](docs/en/architecture.md): components, data flow and scale.
- [Verdicts](docs/en/verdicts.md): statuses, causes and scoring.
- [Controls](docs/en/controls/README.md): one page per control.
- [Facts](docs/en/facts.md): every fact the agent emits.
- [Security](docs/en/security.md): privileges, data handling and threat model.
- [Operations](docs/en/operations.md): logs, troubleshooting and capacity.

## Build and test

Check formatting, run go vet, golangci-lint and the tests. golangci-lint 2.15.0 or later must be installed.

```bash
make check
```

Build the packages in `dist/`.

```bash
make dist VERSION=1.0.0
```

## Security

Report vulnerabilities privately through a GitHub security advisory. See [Security](docs/en/security.md).

## License

Copyright (c) 2026 Arsenite.

OSCompliance ENS is licensed under the GNU Affero General Public License version 3 (AGPL-3.0-only). See [LICENSE](LICENSE).

Arsenite also offers OSCompliance ENS under a commercial license, for organisations that cannot meet the obligations of the AGPL, such as keeping changes private in a product or a network service. Contact devqs@quersystem.com for terms.
