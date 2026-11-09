# Installation with Docker

This guide installs OSCompliance ENS and Power ENS on a Wazuh deployment based on the official wazuh-docker single-node compose file. For Wazuh installed from packages, see [Installation with packages](install.md).

Plan for about one hour on the Docker host and a few minutes per audited machine. All commands run as root on the Docker host, except in section 7.

## Requirements

- Wazuh 4.14.7, 4.14.8 or 4.14.9, with ports 9200 and 55000 published on the host.
- Audited machines on Linux, amd64 or arm64, with a Wazuh agent enrolled in the manager.
- `jq` on the host, `cron` and `auditd` on the audited machines.
- Go on the machine that builds the packages. It can be any machine.

auditd feeds op.acc.2 EV-06, op.acc.3 and op.acc.4 EV-04 and EV-07. Without it those evidences are not evaluable.

## 1. Set the variables

Set these in a shell and keep it open until section 6. `WAZUH_DIR` is the folder of your `docker-compose.yml`. `PROJECT` is the compose project name, shown by `docker compose ls`.

```bash
export WAZUH_DIR=/srv/wazuh-docker/single-node
export PROJECT=single-node
export WAZUH_VERSION=4.14.8
export MGR=$PROJECT-wazuh.manager-1
```

Keep a copy of your compose file. Section 5 changes it, and the uninstall section restores it.

```bash
cp "$WAZUH_DIR/docker-compose.yml" "$WAZUH_DIR/docker-compose.yml.bak"
```

Check the dashboard version. It must be 2.19.5 on Wazuh 4.14.7 and 2.19.6 on 4.14.8 and 4.14.9. Build the plugin for that version in section 2.

```bash
docker exec "$PROJECT-wazuh.dashboard-1" grep -m1 '"version"' /usr/share/wazuh-dashboard/package.json
```

## 2. Build the packages

Build the agent and the engine in this repository. Use the package of your architecture, and copy it to the host and to every audited machine.

```bash
make dist VERSION=0.10.1
```

Build the plugin in the power-ens repository: 2.19.5 for Wazuh 4.14.7, 2.19.6 for 4.14.8 and 4.14.9. The first build takes about 20 minutes. Copy the zip and `ci/dashboard.Dockerfile` to the host.

```bash
ci/build-zip.sh 2.19.6
```

On the host and on every audited machine, unpack the package. The commands below run from this folder.

```bash
tar xzf oscompliance-ens-0.10.1-linux-amd64.tar.gz
cd oscompliance-ens-0.10.1-linux-amd64
```

## 3. Install the rules and create the group

`wazuh-analysisd -t` must print no errors.

```bash
docker cp wazuh/oscompliance_facts_rules.xml "$MGR:/var/ossec/etc/rules/"
docker exec "$MGR" chown wazuh:wazuh /var/ossec/etc/rules/oscompliance_facts_rules.xml
docker exec "$MGR" chmod 660 /var/ossec/etc/rules/oscompliance_facts_rules.xml
docker exec "$MGR" /var/ossec/bin/wazuh-analysisd -t
docker exec "$MGR" /var/ossec/bin/wazuh-control restart
```

Wait one minute for the manager to start. Then create the `ens` group and add each machine to audit, replacing `<id>` with the agent ID from the list. A machine keeps its other groups.

```bash
docker exec "$MGR" /var/ossec/bin/agent_groups -a -g ens -q
docker exec "$MGR" /var/ossec/bin/agent_control -l
docker exec "$MGR" /var/ossec/bin/agent_groups -a -i <id> -g ens -q
```

## 4. Create the engine users

The engine has its own user in the indexer and in the Wazuh API, with the permissions listed in [Security](security.md#engine). This script creates them and writes the credentials to `/etc/oscompliance/engine.env` on the host. The two variables make it reach the indexer under the name in its certificate.

It asks for the password of `wazuh-wui`, which is `API_PASSWORD` in your compose file, and for two new passwords. Each new password needs 8 to 64 characters with upper and lower case, a digit and a symbol, and cannot hold `$`, `&`, quotes, backslashes or spaces.

```bash
export CERTS=$WAZUH_DIR/config/wazuh_indexer_ssl_certs
export INDEXER_URL=https://wazuh.indexer:9200
export INDEXER_RESOLVE=wazuh.indexer:9200:127.0.0.1
bash wazuh/engine-users.sh create
```

## 5. Install the plugin

The plugin goes into its own image, because anything installed in a running container is lost when the container is recreated. From the folder holding the zip and the Dockerfile:

```bash
docker build -f dashboard.Dockerfile --build-arg WAZUH_VERSION="$WAZUH_VERSION" --build-arg PLUGIN_ZIP=powerEns-2.19.6.zip -t power-ens/wazuh-dashboard:1.8.0 .
```

In `docker-compose.yml`, change the image of the `wazuh.dashboard` service.

```yaml
    image: power-ens/wazuh-dashboard:1.8.0
```

Recreate the service.

```bash
docker compose --project-directory "$WAZUH_DIR" -p "$PROJECT" up -d wazuh.dashboard
```

Log in to the dashboard and open Power ENS. If it says `No se puede leer el inventario de agentes`, the dashboard has not yet written its agent inventory, which it does every 15 minutes: wait and press Reintentar. A user with `all_access` can change the configuration. To allow other users, create the `power_ens_admin` role with the variables of section 4. The list replaces the previous one, so name every user who needs the role. Both responses must be `CREATED` or `OK`.

```bash
os() {
  curl -sS --resolve "$INDEXER_RESOLVE" --cacert "$CERTS/root-ca.pem" \
    --cert "$CERTS/admin.pem" --key "$CERTS/admin-key.pem" \
    -H 'Content-Type: application/json' "$@"
}
SEC=$INDEXER_URL/_plugins/_security/api
os -X PUT "$SEC/roles/power_ens_admin" -d '{"cluster_permissions":[]}'; echo
os -X PUT "$SEC/rolesmapping/power_ens_admin" -d '{"users":["<user>"]}'; echo
```

Now set the ENS configuration, as in [section 5 of the package guide](install.md#5-set-the-ens-configuration).

## 6. Start the engine

The engine runs as one more service of the compose project, defined in its own file. Keep that file with your compose file, and add it with `-f` whenever you run compose for this service.

```bash
install -m 755 bin/oscompliance-engine /usr/local/bin/
cp wazuh/engine.compose.yml "$WAZUH_DIR/"
cd "$WAZUH_DIR"
docker compose -p "$PROJECT" -f docker-compose.yml -f engine.compose.yml up -d oscompliance.engine
```

Wait 20 seconds. The log must show a `group configuration` line with `applied` true and a `pass` line with no `error`.

```bash
docker logs --tail 10 "$PROJECT-oscompliance.engine-1"
```

The group configuration must now hold a block between `oscompliance begin` and `oscompliance end`, with the `facts.ndjson` localfile.

```bash
docker exec "$MGR" cat /var/ossec/etc/shared/ens/agent.conf
```

## 7. Install the agent on the audited machines

Follow [section 7 of the package guide](install.md#7-install-the-agent-on-the-audited-machines) on each machine in the `ens` group.

This guide does not audit the manager container, so its row shows as not compliant. To see each result, choose the machine in the Máquina selector.

## 8. Verify

Log in to an audited machine over SSH, so that a real login reaches Wazuh, and wait one minute. Then run an engine pass. The last `pass` line must show `verdicts` above 0 and no `error`.

```bash
docker restart "$PROJECT-oscompliance.engine-1"
sleep 20
docker logs --tail 5 "$PROJECT-oscompliance.engine-1"
```

Then check the dashboard as in [section 9 of the package guide](install.md#9-verify).

## Upgrade Wazuh

The dashboard image is built on one Wazuh version, so it does not change when you upgrade the other services. Follow the official Wazuh procedure. Before you recreate the services, build the plugin for the new version, build the image with a new tag and set that tag in the `wazuh.dashboard` service, as in section 5. The plugin must match the dashboard: 2.19.5 for Wazuh 4.14.7, 2.19.6 for 4.14.8 and 4.14.9.

## Uninstall

On each audited machine, follow the first step of [the package guide](install.md#uninstall).

On the host, restore the compose file and recreate the services. If you edited the compose file for other reasons after the copy, remove the image change by hand instead. Then remove the rules and the block in the group configuration, and restart the manager.

```bash
cd "$WAZUH_DIR"
cp docker-compose.yml.bak docker-compose.yml
docker compose -p "$PROJECT" -f docker-compose.yml up -d --remove-orphans
docker image rm power-ens/wazuh-dashboard:1.8.0
rm -f engine.compose.yml /usr/local/bin/oscompliance-engine
docker exec "$MGR" rm -f /var/ossec/etc/rules/oscompliance_facts_rules.xml
docker exec "$MGR" sed -i '/<!-- oscompliance begin/,/<!-- oscompliance end -->/d' /var/ossec/etc/shared/ens/agent.conf
docker exec "$MGR" /var/ossec/bin/wazuh-control restart
```

Remove the engine users, with the same variables as in section 4. The script asks for the password of `wazuh-wui`.

```bash
bash wazuh/engine-users.sh remove
```

The indices `oscompliance-verdicts`, `oscompliance-identity-history`, `oscompliance-config-history` and `wazuh-ens-configuration` stay in the indexer, so the history is not lost. Delete them from Dev Tools when you no longer need them.
