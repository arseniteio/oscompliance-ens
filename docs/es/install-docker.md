# Instalación con Docker

Esta guía instala OSCompliance ENS y Power ENS en un despliegue de Wazuh basado en el fichero de compose single-node oficial de wazuh-docker. Para Wazuh instalado por paquetes, consulta [Instalación por paquetes](install.md).

Calcula alrededor de una hora en el host de Docker y unos minutos por máquina auditada. Todos los comandos se ejecutan como root en el host de Docker, salvo en el apartado 7.

## Requisitos

- Wazuh 4.14.7, 4.14.8 o 4.14.9, con los puertos 9200 y 55000 publicados en el host.
- Máquinas auditadas en Linux, amd64 o arm64, con un agente de Wazuh registrado en el manager.
- `jq` en el host, `cron` y `auditd` en las máquinas auditadas.
- Go en la máquina donde se compilan los paquetes. Puede ser cualquier máquina.

auditd alimenta EV-06 de op.acc.2, op.acc.3 y EV-04 y EV-07 de op.acc.4. Sin él, esas evidencias no son evaluables.

## 1. Definir las variables

Defínelas en un shell y mantenlo abierto hasta el apartado 6. `WAZUH_DIR` es la carpeta de tu `docker-compose.yml`. `PROJECT` es el nombre del proyecto de compose, que muestra `docker compose ls`.

```bash
export WAZUH_DIR=/srv/wazuh-docker/single-node
export PROJECT=single-node
export WAZUH_VERSION=4.14.8
export MGR=$PROJECT-wazuh.manager-1
```

Guarda una copia de tu fichero de compose. El apartado 5 lo cambia, y la desinstalación lo restaura.

```bash
cp "$WAZUH_DIR/docker-compose.yml" "$WAZUH_DIR/docker-compose.yml.bak"
```

## 2. Compilar los paquetes

Compila el agente y el motor en este repositorio. Usa el paquete de tu arquitectura y cópialo al host y a cada máquina auditada.

```bash
make dist VERSION=0.10.1
```

Compila el plugin en el repositorio power-ens: 2.19.5 para Wazuh 4.14.7, 2.19.6 para 4.14.8 y 4.14.9. La primera compilación tarda unos 20 minutos. Copia el zip y `ci/dashboard.Dockerfile` al host.

```bash
ci/build-zip.sh 2.19.6
```

En el host y en cada máquina auditada, descomprime el paquete. Los comandos siguientes se ejecutan desde esta carpeta.

```bash
tar xzf oscompliance-ens-0.10.1-linux-amd64.tar.gz
cd oscompliance-ens-0.10.1-linux-amd64
```

## 3. Instalar las reglas y crear el grupo

`wazuh-analysisd -t` no debe mostrar errores.

```bash
docker cp wazuh/oscompliance_facts_rules.xml "$MGR:/var/ossec/etc/rules/"
docker exec "$MGR" chown wazuh:wazuh /var/ossec/etc/rules/oscompliance_facts_rules.xml
docker exec "$MGR" chmod 660 /var/ossec/etc/rules/oscompliance_facts_rules.xml
docker exec "$MGR" /var/ossec/bin/wazuh-analysisd -t
docker exec "$MGR" /var/ossec/bin/wazuh-control restart
```

Espera un minuto a que arranque el manager. Después crea el grupo `ens` y añade cada máquina que quieras auditar, sustituyendo `<id>` por el identificador del agente que aparece en la lista. Cada máquina conserva sus otros grupos.

```bash
docker exec "$MGR" /var/ossec/bin/agent_groups -a -g ens -q
docker exec "$MGR" /var/ossec/bin/agent_control -l
docker exec "$MGR" /var/ossec/bin/agent_groups -a -i <id> -g ens -q
```

## 4. Crear los usuarios del motor

El motor tiene su propio usuario en el indexer y en la API de Wazuh, con los permisos que indica [Seguridad](security.md#motor). Este script los crea y escribe las credenciales en `/etc/oscompliance/engine.env` en el host. Las dos variables hacen que llegue al indexer con el nombre de su certificado.

Pide la contraseña de `wazuh-wui`, que es `API_PASSWORD` en tu fichero de compose, y dos contraseñas nuevas. Cada contraseña nueva necesita entre 8 y 64 caracteres con mayúscula, minúscula, número y símbolo, y no puede contener `$`, `&`, comillas, barras invertidas ni espacios.

```bash
export CERTS=$WAZUH_DIR/config/wazuh_indexer_ssl_certs
export INDEXER_URL=https://wazuh.indexer:9200
export INDEXER_RESOLVE=wazuh.indexer:9200:127.0.0.1
bash wazuh/engine-users.sh create
```

## 5. Instalar el plugin

El plugin va en una imagen propia, porque lo que se instala en un contenedor en marcha se pierde al recrearlo. Desde la carpeta que contiene el zip y el Dockerfile:

```bash
docker build -f dashboard.Dockerfile --build-arg WAZUH_VERSION="$WAZUH_VERSION" --build-arg PLUGIN_ZIP=powerEns-2.19.6.zip -t power-ens/wazuh-dashboard:1.8.0 .
```

En `docker-compose.yml`, cambia la imagen del servicio `wazuh.dashboard`.

```yaml
    image: power-ens/wazuh-dashboard:1.8.0
```

Recrea el servicio.

```bash
docker compose --project-directory "$WAZUH_DIR" -p "$PROJECT" up -d wazuh.dashboard
```

Entra en el dashboard y abre Power ENS. Si indica `No se puede leer el inventario de agentes`, el dashboard aún no ha escrito su inventario de agentes, lo que hace cada 15 minutos: espera y pulsa Reintentar. Un usuario con `all_access` puede cambiar la configuración. Para dar permiso a otro usuario, consulta la [instalación de Power ENS](https://github.com/arseniteio/power-ens/blob/main/docs/es/install.md).

Ahora define la configuración ENS, como en el [apartado 5 de la guía por paquetes](install.md#5-definir-la-configuración-ens).

## 6. Arrancar el motor

El motor se ejecuta como un servicio más del proyecto de compose, definido en su propio fichero. Guarda ese fichero junto a tu fichero de compose y añádelo con `-f` siempre que ejecutes compose para este servicio.

```bash
install -m 755 bin/oscompliance-engine /usr/local/bin/
cp wazuh/engine.compose.yml "$WAZUH_DIR/"
cd "$WAZUH_DIR"
docker compose -p "$PROJECT" -f docker-compose.yml -f engine.compose.yml up -d oscompliance.engine
```

Espera 20 segundos. El registro debe mostrar una línea `group configuration` con `applied` true y una línea `pass` sin `error`.

```bash
docker logs --tail 10 "$PROJECT-oscompliance.engine-1"
```

La configuración de grupo debe contener ahora un bloque entre `oscompliance begin` y `oscompliance end`, con el localfile de `facts.ndjson`.

```bash
docker exec "$MGR" cat /var/ossec/etc/shared/ens/agent.conf
```

## 7. Instalar el agente en las máquinas auditadas

Sigue el [apartado 7 de la guía por paquetes](install.md#7-instalar-el-agente-en-las-máquinas-auditadas) en cada máquina del grupo `ens`.

Esta guía no audita el contenedor del manager, así que su fila aparece como no conforme. Para ver cada resultado, elige la máquina en el selector Máquina.

## 8. Comprobar el resultado

Inicia sesión por SSH en una máquina auditada, para que un inicio de sesión real llegue a Wazuh, y espera un minuto. Después ejecuta una pasada del motor. La última línea `pass` debe mostrar `verdicts` mayor que 0 y ningún `error`.

```bash
docker restart "$PROJECT-oscompliance.engine-1"
sleep 20
docker logs --tail 5 "$PROJECT-oscompliance.engine-1"
```

Después comprueba el dashboard como en el [apartado 9 de la guía por paquetes](install.md#9-comprobar-el-resultado).

## Actualizar Wazuh

La imagen del dashboard se construye sobre una versión de Wazuh, así que no cambia al actualizar los demás servicios. Sigue el procedimiento oficial de Wazuh. Antes de recrear los servicios, compila el plugin para la nueva versión, construye la imagen con una etiqueta nueva y pon esa etiqueta en el servicio `wazuh.dashboard`, como en el apartado 5. El plugin debe coincidir con el dashboard: 2.19.5 para Wazuh 4.14.7, 2.19.6 para 4.14.8 y 4.14.9.

## Desinstalar

En cada máquina auditada, sigue el primer paso de [la guía por paquetes](install.md#desinstalar).

En el host, restaura el fichero de compose y recrea los servicios. Si editaste el fichero de compose por otros motivos después de la copia, deshaz a mano el cambio de imagen. Después retira las reglas y el bloque de la configuración de grupo, y reinicia el manager.

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

Retira los usuarios del motor, con las mismas variables del apartado 4. El script pide la contraseña de `wazuh-wui`.

```bash
bash wazuh/engine-users.sh remove
```

Los índices `oscompliance-verdicts`, `oscompliance-identity-history`, `oscompliance-config-history` y `wazuh-ens-configuration` se quedan en el indexer, así que no se pierde el historial. Bórralos desde Dev Tools cuando ya no los necesites.
