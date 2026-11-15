# OSCompliance ENS

[Versión en español](README.es.md)

OSCompliance ENS measures the Esquema Nacional de Seguridad (Real Decreto 311/2022) on a Wazuh deployment. It turns what your machines do into a verdict per control, per requirement and per machine, with the reason behind every result, every 15 minutes.

It adds one agent binary to each Linux machine and one engine next to the Wazuh indexer. Wazuh keeps doing the collection. Nothing is judged on the machine being audited, and nothing that cannot be proven counts as compliant. The results are shown in the Wazuh dashboard by the [Power ENS](https://github.com/arseniteio/power-ens) plugin.

It runs on Wazuh 4.14.7, 4.14.8 and 4.14.9, with audited machines on Linux.

## Get started

On a Wazuh server with the manager, indexer and dashboard installed from packages, run as a user with sudo:

```bash
curl -fsSL https://github.com/arseniteio/oscompliance-ens/releases/latest/download/install.sh | sudo bash -s -- server
```

The script installs the rules, the engine and its users, the Power ENS plugin for your dashboard, and audits the manager. It asks for the password of `wazuh-wui` and for two new passwords.

In the dashboard, open Power ENS, Configuración, Organización, fill in Cliente and press Guardar configuración global. Then add each machine to audit to the `ens` group, with its ID from `/var/ossec/bin/agent_control -l`.

```bash
sudo /var/ossec/bin/agent_groups -a -i <id> -g ens -q
```

On each of those machines:

```bash
curl -fsSL https://github.com/arseniteio/oscompliance-ens/releases/latest/download/install.sh | sudo bash -s -- agent
```

The first verdicts appear in Power ENS within 15 minutes. Run the same commands with a newer release to upgrade, and with `uninstall` to remove everything.

To check the files before running anything, download the package and verify it. `install.sh` inside the package uses the files next to it.

```bash
v=1.1.0
url=https://github.com/arseniteio/oscompliance-ens/releases/download/v$v
curl -fLO "$url/oscompliance-ens-$v-linux-amd64.tar.gz" -O "$url/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
tar xzf "oscompliance-ens-$v-linux-amd64.tar.gz"
sudo "./oscompliance-ens-$v-linux-amd64/install.sh" agent
```

On the server, the script downloads the plugin from the power-ens release and checks it. To install without access to GitHub, copy the plugin zip and `deploy-plugin.sh` into the package folder first.

For Wazuh on Docker, a distributed deployment or the detail of each step, follow the full guides:

- [Installation with packages](docs/en/install.md)
- [Installation with Docker](docs/en/install-docker.md)

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

Build the packages in `dist/`, with `install.sh` and `SHA256SUMS`. Go 1.27.2 or later is required.

```bash
make dist VERSION=1.1.0
```

## Security

Report vulnerabilities privately through a GitHub security advisory. See [Security](docs/en/security.md).

## License

Copyright (c) 2026 Arsenite.

OSCompliance ENS is licensed under the GNU Affero General Public License version 3 (AGPL-3.0-only). See [LICENSE](LICENSE).

Arsenite also offers OSCompliance ENS under a commercial license, for organisations that cannot meet the obligations of the AGPL, such as keeping changes private in a product or a network service. Contact devqs@quersystem.com for terms.
