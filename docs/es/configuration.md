# Configuración

Se configuran tres cosas, en tres lugares. El operador define la conexión y los tiempos del motor una vez, con flags y `/etc/oscompliance/engine.env` en el manager. El operador define las rutas del agente en `/etc/oscompliance/agent.json`, solo en máquinas no estándar. El responsable de seguridad define la política ENS (nivel, alcance y cada parámetro de control) en Power ENS en cualquier momento. Se guarda en `wazuh-ens-configuration`.

La política nunca reside en las máquinas. Los agentes solo guardan rutas; cada valor que decide el cumplimiento es un parámetro de Power ENS, y el motor lo recarga en cada pasada.

## Motor

`oscompliance-engine` no lee ningún fichero de configuración, solo flags y dos variables de entorno. Sin `-interval` ejecuta una pasada y termina.

| Flag | Por defecto | Función |
|---|---|---|
| `-indexer` | `https://wazuh.indexer:9200` | URL del indexer |
| `-user` | `admin` | usuario del indexer; contraseña en `OSC_INDEXER_PASSWORD` |
| `-ca` | raíces del sistema | certificado de CA del indexer (PEM) |
| `-wazuh-api` | vacío | URL de la API de Wazuh; vacío desactiva todo lo que se lee o se escribe en la API |
| `-wazuh-api-user` | `oscompliance` | usuario de la API; contraseña en `OSC_WAZUH_API_PASSWORD` |
| `-wazuh-api-ca` | raíces del sistema | certificado con el que se confía en la API (PEM) |
| `-wazuh-api-server-name` | host de la URL | nombre comprobado en el certificado de la API |
| `-interval` | `0` | tiempo entre pasadas; `0` ejecuta una vez |
| `-window` | `26h` | cuentan los eventos más recientes que esto |
| `-lookback` | `168h` | se juzgan los agentes con hechos así de recientes |
| `-sync-interval` | `15m` | tiempo mínimo entre dos sincronizaciones de la configuración de grupo |
| `-sync-apply` | desactivado | escribe la configuración de grupo; sin él los cambios solo se registran |
| `-controls` | vacío | controles que juzgar, separados por comas; vacío los juzga todos |
| `-alerts-index` | `wazuh-alerts-*` | patrón del índice de alertas |
| `-monitoring-index` | `wazuh-monitoring-*` | patrón del índice de keepalive de los agentes |
| `-states-prefix` | `wazuh-states-` | prefijo de los índices de inventario y vulnerabilidades de Wazuh |
| `-config-index` | `wazuh-ens-configuration` | índice de configuración de Power ENS |
| `-verdicts-index` | `oscompliance-verdicts` | veredictos |
| `-history-index` | `oscompliance-identity-history` | historial por cuenta |
| `-config-history-index` | `oscompliance-config-history` | cambios en la configuración de grupo |

| Variable de entorno | Función |
|---|---|
| `OSC_INDEXER_PASSWORD` | contraseña del indexer |
| `OSC_WAZUH_API_PASSWORD` | contraseña de la API de Wazuh |

La ventana es de 26 horas para que un agente horario y un barrido diario siempre tengan una pasada dentro, con margen para una ejecución tardía de cron.

## Configuración de grupo

Con `-wazuh-api` y `-sync-apply`, el motor mantiene una región marcada en el `agent.conf` de cada grupo de Wazuh nombrado en el alcance ENS:

```xml
<!-- oscompliance begin: written by oscompliance-engine from the ENS configuration, do not edit -->
<agent_config>
  <!-- oscompliance {"acl_paths":["/srv/data"],"audit_watches":["/srv/data"],"exec_watches":["/usr/bin/git"]} -->
  <localfile><log_format>json</log_format><location>/var/log/oscompliance/facts.ndjson</location></localfile>
  <localfile><log_format>audit</log_format><location>/var/log/audit/audit.log</location></localfile>
</agent_config>
<agent_config name="sede-01">
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/sede/auth.json</location>
    <label key="oscompliance_service">sede</label>
  </localfile>
</agent_config>
<!-- oscompliance end -->
```

| Contenido | Procede de |
|---|---|
| `acl_paths` | P-08 de op.acc.2, P-08 de op.exp.2 |
| `audit_watches` | P-06 de op.acc.2, rutas de P-03 de op.acc.3 y las rutas de seguridad, P-07 de op.acc.4 |
| `exec_watches` | binarios de P-03 de op.acc.3 |
| `backup_sources`, `backup_keys` | P-07 de op.exp.3, P-04 y P-08 de mp.info.6 |
| `key_stores` | P-02 de op.exp.10 |
| `<directories>` de FIM | rutas de P-02 de op.acc.2 fuera de los valores por defecto de Wazuh |
| localfiles de servicio | P-02 de op.acc.5 |

Lo que comparten la mayoría de las máquinas del grupo va a todos los agentes; una máquina que necesita otras rutas o tiene servicios propios recibe un bloque con su nombre. Todo lo que queda fuera de las marcas no se toca. Cada cambio se registra en `oscompliance-config-history` con la región anterior y posterior; sin `-sync-apply` el cambio se registra pero no se escribe.

## Grupos por control

Con la opción activada en Power ENS (`scope.controlGroups`), el motor crea un grupo de Wazuh por control, `ens-excluir-<control>`, en su siguiente sincronización de grupos. Necesita `-wazuh-api`, `-sync-apply` y `group:create` en su rol de API. Para sacar una máquina de un control, añádela a ese grupo. Al desactivar la opción, los grupos se ignoran y no se borra ninguno. Consulta [Veredictos](verdicts.md).

## Agente

`/etc/oscompliance/agent.json` es opcional. Sin él, el agente usa los valores por defecto; con él, solo cambian las claves presentes. Una clave desconocida detiene el agente con un error. El fichero se lee en cada ejecución.

| Clave | Por defecto | Función |
|---|---|---|
| `output` | `/var/log/oscompliance/facts.ndjson` | fichero al que se añaden los hechos |
| `host` | nombre de host del sistema | nombre de host escrito en cada hecho |
| `state` | `/var/lib/oscompliance/state.json` | lo último que envió cada colector, para enviar solo los cambios |
| `collectors` | todos menos `sweep` | colectores de la pasada horaria |
| `sweep_timeout` | `15m` | límite de tiempo del barrido diario del sistema de ficheros |
| `paths.passwd` | `/etc/passwd` | base de datos de cuentas |
| `paths.shadow` | `/etc/shadow` | caducidad y bloqueo de contraseñas |
| `paths.group` | `/etc/group` | base de datos de grupos |
| `paths.sshd` | `/usr/sbin/sshd` | binario de sshd, al que se pide su configuración efectiva |
| `paths.sudoers` | `/etc/sudoers` | fichero sudoers principal; se siguen los includes |
| `paths.pam_dir` | `/etc/pam.d` | configuración de PAM |
| `paths.wazuh_shared_conf` | `/var/ossec/etc/shared/agent.conf` | configuración de grupo que escribe el motor |
| `paths.wazuh_client_keys` | `/var/ossec/etc/client.keys` | la clave del agente, que da nombre a la máquina en esa configuración; vacío en el manager |

`agent/agent.example.json` contiene cada clave con su valor por defecto.

| Flag | Función |
|---|---|
| `-config ruta` | lee otro fichero; debe existir |
| `-collect a,b` | ejecuta estos colectores en lugar de los configurados |
| `-full` | envía todo, incluso lo que no ha cambiado |

Colectores: `identity`, `groups`, `umask`, `sudoers`, `config`, `pam`, `authprobe`, `listening`, `services`, `wazuh`, `acl`, `audit`, `firewall`, `neighbours`, `virtualization`, `packages`, `units`, `backups`, `updates`, `transactions`, `snapshots`, `malware`, `timesync`, `keys`, `device` y `sweep`. Lo que lee cada uno está en [Hechos](facts.md).

Quitar un colector de la lista deja las evidencias que lo necesitan en NOT_EVALUABLE por COLLECTION. Nunca hace que pasen.

## Política ENS

Se define en Power ENS, en Configuración, y se guarda en el documento `ACTIVE_CONFIGURATION` de `wazuh-ens-configuration`.

| Ajuste | Efecto |
|---|---|
| Categoría ENS | BAJO, MEDIO o ALTO; los requisitos fuera de ella son NOT_APPLICABLE |
| Alcance | los grupos de Wazuh auditados |
| Tipo de sistema de cada máquina | elige su plantilla de parámetros integrada |
| Control activado | un control desactivado es NOT_APPLICABLE en todas partes |
| Parámetros del control | listados en cada [página de control](controls/README.md) |

Cada parámetro tiene una clase que decide de dónde sale su valor:

| Clase | Valor |
|---|---|
| `organisation` | el valor común del control; se ignoran los valores por máquina |
| `system` | el valor propio de la máquina o, si no, su plantilla o, si no, el valor común |
| `platform` | como `system`; las plantillas integradas por tipo de sistema traen valores para él |

Plantillas: la asignada a la máquina, integrada (`catalog/templates/`) o propia; `none` la desactiva; sin ninguna asignada, la plantilla integrada del tipo de sistema de la máquina. El tipo de sistema es el definido a mano o, si no, el que implica la plataforma del inventario de Wazuh (`catalog/system-types.json`).

Las listas comparan sin distinguir mayúsculas. Un parámetro marcado como expresión regular usa RE2, compara el valor completo, distingue mayúsculas y tiene 512 caracteres como máximo. Las tablas son filas de celdas separadas por `|`.

Un parámetro sin definir da NOT_EVALUABLE por CONFIGURATION en las evidencias que lo necesitan. El motor nunca aplica un valor que nadie haya elegido, salvo los dos valores por defecto del producto que documenta op.acc.1 (el UID más bajo de una persona y los grupos privilegiados), y el veredicto indica cuándo lo hace.
