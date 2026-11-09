# Installation with packages

This guide installs OSCompliance ENS and Power ENS on a Wazuh deployment installed from packages, with the manager, indexer and dashboard on one server. For Wazuh on Docker, see [Installation with Docker](install-docker.md).

Plan for about one hour on the server and a few minutes per audited machine. All commands run as root.

## Requirements

- Wazuh 4.14.7, 4.14.8 or 4.14.9.
- Audited machines on Linux, amd64 or arm64, with a Wazuh agent enrolled in the manager.
- `jq` and `unzip` on the server, `cron` and `auditd` on the audited machines.
- Go and Docker on the machine that builds the packages. It can be any machine.

auditd feeds op.acc.2 EV-06, op.acc.3 and op.acc.4 EV-04 and EV-07. Without it those evidences are not evaluable.

## 1. Build the packages

Build the agent and the engine in this repository. Use the package of your architecture, and copy it to the server and to every audited machine.

```bash
make dist VERSION=0.10.1
```

The result is in `dist/`, with a `SHA256SUMS` file. Each package holds the binaries in `bin/`, the Wazuh files in `wazuh/`, and the agent's cron file and example configuration in `agent/`.

Find the OpenSearch Dashboards version of your dashboard on the server. It is 2.19.5 on Wazuh 4.14.7 and 2.19.6 on 4.14.8 and 4.14.9.

```bash
grep -m1 '"version"' /usr/share/wazuh-dashboard/package.json
```

Build the plugin for that version in the power-ens repository. The first build takes about 20 minutes. Copy the zip and `config/deploy-plugin.sh` to the server.

```bash
ci/build-zip.sh 2.19.6
```

On the server and on every audited machine, unpack the package. The commands below run from this folder.

```bash
tar xzf oscompliance-ens-0.10.1-linux-amd64.tar.gz
cd oscompliance-ens-0.10.1-linux-amd64
```

## 2. Install the rules and create the group

The rules use IDs 119000 to 119004. They index facts, the authentication probe, service events and audited accesses, and raise nothing above level 3. `wazuh-analysisd -t` must print no errors.

```bash
install -o wazuh -g wazuh -m 660 wazuh/oscompliance_facts_rules.xml /var/ossec/etc/rules/
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
```

Wait one minute for the manager to start. Then create the `ens` group and add each machine to audit, replacing `<id>` with the agent ID from the list. A machine keeps its other groups.

```bash
/var/ossec/bin/agent_groups -a -g ens -q
/var/ossec/bin/agent_control -l
/var/ossec/bin/agent_groups -a -i <id> -g ens -q
```

## 3. Create the engine users

The engine has its own user in the indexer and in the Wazuh API, with the permissions listed in [Security](security.md#engine). This script creates them and writes the credentials to `/etc/oscompliance/engine.env`.

It asks for the password of `wazuh-wui`, found in `wazuh-passwords.txt` inside `wazuh-install-files.tar`, and for two new passwords. Each new password needs 8 to 64 characters with upper and lower case, a digit and a symbol, and cannot hold `$`, `&`, quotes, backslashes or spaces.

```bash
bash wazuh/engine-users.sh create
```

## 4. Install the plugin

The script validates the zip, keeps a copy of any previous version in `/var/backups/power-ens`, installs the plugin and restarts the dashboard. It must end with the dashboard active.

```bash
bash deploy-plugin.sh powerEns-2.19.6.zip
```

Log in to the dashboard and open Power ENS. If it says `No se puede leer el inventario de agentes`, the dashboard has not yet written its agent inventory, which it does every 15 minutes: wait and press Reintentar. A user with `all_access` can change the configuration. To allow another user, see [Power ENS installation](https://github.com/arseniteio/power-ens/blob/main/docs/en/install.md).

## 5. Set the ENS configuration

The screens are in Spanish. In Power ENS, open Configuración.

1. In Organización, fill in Cliente and press Guardar configuración global. This creates the configuration, at level MEDIO, with the `ens` group in scope. Change Nivel ENS if your system has another level.
2. In Plantillas, open each control, press Completar configuración, fill in what is missing and save.
3. In Agentes, open each machine and fill in the parameters that belong to the machine.

Each page in [Controls](controls/README.md) lists the parameters of its control. A control can be filled in later: until then it shows as not evaluable by configuration.

## 6. Start the engine

```bash
install -m 755 bin/oscompliance-engine /usr/local/bin/
install -m 644 wazuh/oscompliance-engine.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now oscompliance-engine
```

Wait 20 seconds. The log must show a `group configuration` line with `applied` true and a `pass` line with no `error`.

```bash
journalctl -u oscompliance-engine -n 10 --no-pager
```

The group configuration must now hold a block between `oscompliance begin` and `oscompliance end`, with the `facts.ndjson` localfile.

```bash
cat /var/ossec/etc/shared/ens/agent.conf
```

The engine writes only that block. It leaves the rest of the file untouched.

## 7. Install the agent on the audited machines

On each machine in the `ens` group, install the agent and its cron file. It reads `/etc/shadow`, `sshd -T` and the sudoers files, so it runs as root. It needs no configuration on a standard system.

```bash
install -m 755 bin/oscompliance-agent /usr/local/bin/
install -m 644 agent/oscompliance.cron /etc/cron.d/oscompliance
install -d -m 750 /var/log/oscompliance
install -d -m 700 /var/lib/oscompliance
```

Wait until the machine has received the group configuration: this command must print a number above 0.

```bash
grep -c facts.ndjson /var/ossec/etc/shared/agent.conf
```

Then create the facts file and restart the Wazuh agent before the first pass. Otherwise Wazuh opens the file later and skips what is already in it.

```bash
touch /var/log/oscompliance/facts.ndjson
systemctl restart wazuh-agent
sleep 30
oscompliance-agent -full
```

The last line of the file must be JSON with `"oscompliance":"1"`.

```bash
tail -n 1 /var/log/oscompliance/facts.ndjson
```

The agent adds its audit watches at runtime with `auditctl`, tagged `oscompliance_*`. It never removes a rule and never writes to `/etc/audit`. With SELinux enforcing, also run `restorecon -R /usr/local/bin/oscompliance-agent /etc/cron.d/oscompliance /var/log/oscompliance`.

On RHEL and Rocky, `cron` is the `cronie` package.

```bash
dnf install -y cronie && systemctl enable --now crond
```

## 8. Audit the manager

The manager is judged like any other machine. Until the agent runs on it, its row shows as not compliant. It belongs to no group, so it needs two settings of its own.

```bash
install -m 755 bin/oscompliance-agent /usr/local/bin/
install -m 644 agent/oscompliance.cron /etc/cron.d/oscompliance
install -d -m 750 /var/log/oscompliance
install -d -m 700 /var/lib/oscompliance
echo '{"paths": {"wazuh_shared_conf": "/var/ossec/etc/shared/ens/agent.conf", "wazuh_client_keys": ""}}' > /etc/oscompliance/agent.json
touch /var/log/oscompliance/facts.ndjson
```

Add the facts file and the audit log to `/var/ossec/etc/ossec.conf`, inside `<ossec_config>`.

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/oscompliance/facts.ndjson</location>
</localfile>
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

Restart the manager and run the first pass.

```bash
systemctl restart wazuh-manager
sleep 60
oscompliance-agent -full
```

## 9. Verify

Log in to an audited machine over SSH, so that a real login reaches Wazuh, and wait one minute. Then run an engine pass. The last `pass` line must show `verdicts` above 0 and no `error`.

```bash
systemctl restart oscompliance-engine
sleep 20
journalctl -u oscompliance-engine -n 5 --no-pager
```

In the dashboard, open Discover on `wazuh-alerts-*`. `rule.id:119001` must show the facts of each machine, and `rule.id:119002` one authentication probe per machine and pass.

In Power ENS, open Detalle del control and choose a machine. Each evidence shows its status and the reason. The usual result on a new machine is partial: an evidence stays not evaluable until its parameters are declared, and a requirement that depends on a document stays open until its attestation is declared in P-ATT.

The first complete picture needs one agent pass and one engine pass after it. Without `-full` that takes up to 75 minutes.

If a step gives another result, see [Operations](operations.md#troubleshooting).

## Upgrade

Upgrade the engine first: it reads facts from older agents. Save the current binary, so you can return to it by putting it back and restarting the service.

```bash
cp /usr/local/bin/oscompliance-engine /usr/local/bin/oscompliance-engine.prev
install -m 755 bin/oscompliance-engine /usr/local/bin/
systemctl restart oscompliance-engine
```

If the rules changed, install them as in section 2. If the role changed, run `wazuh/engine-users.sh create` again, which also sets the passwords again. On each audited machine, install the new agent binary: the next cron run uses it. Install the plugin zip built from the matching commit as in section 4.

## Uninstall

On each audited machine:

```bash
rm -f /etc/cron.d/oscompliance /usr/local/bin/oscompliance-agent
rm -rf /etc/oscompliance /var/log/oscompliance /var/lib/oscompliance
augenrules --load
```

On the server, remove the engine, the plugin, the rules and the block in the group configuration, and restart the manager.

```bash
systemctl disable --now oscompliance-engine
rm -f /etc/systemd/system/oscompliance-engine.service /usr/local/bin/oscompliance-engine
systemctl daemon-reload
sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin remove powerEns
systemctl restart wazuh-dashboard
rm -f /var/ossec/etc/rules/oscompliance_facts_rules.xml
sed -i '/<!-- oscompliance begin/,/<!-- oscompliance end -->/d' /var/ossec/etc/shared/ens/agent.conf
systemctl restart wazuh-manager
```

Remove the engine users. The script asks for the password of `wazuh-wui`.

```bash
bash wazuh/engine-users.sh remove
```

The indices `oscompliance-verdicts`, `oscompliance-identity-history`, `oscompliance-config-history` and `wazuh-ens-configuration` stay in the indexer, so the history is not lost. Delete them from Dev Tools when you no longer need them. If you audited the manager, also run the commands for audited machines on the server, and remove its two localfile blocks from `ossec.conf`.
