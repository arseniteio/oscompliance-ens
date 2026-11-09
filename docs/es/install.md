# Instalación por paquetes

Esta guía instala OSCompliance ENS y Power ENS en un despliegue de Wazuh instalado por paquetes, con el manager, el indexer y el dashboard en un mismo servidor. Para Wazuh en Docker, consulta [Instalación con Docker](install-docker.md).

Calcula alrededor de una hora en el servidor y unos minutos por máquina auditada. Todos los comandos se ejecutan como root.

## Requisitos

- Wazuh 4.14.7, 4.14.8 o 4.14.9.
- Máquinas auditadas en Linux, amd64 o arm64, con un agente de Wazuh registrado en el manager.
- `jq` y `unzip` en el servidor, `cron` y `auditd` en las máquinas auditadas.
- Go y Docker en la máquina donde se compilan los paquetes. Puede ser cualquier máquina.

auditd alimenta EV-06 de op.acc.2, op.acc.3 y EV-04 y EV-07 de op.acc.4. Sin él, esas evidencias no son evaluables.

## 1. Compilar los paquetes

Compila el agente y el motor en este repositorio. Usa el paquete de tu arquitectura y cópialo al servidor y a cada máquina auditada.

```bash
make dist VERSION=0.10.1
```

El resultado está en `dist/`, con un fichero `SHA256SUMS`. Cada paquete contiene los binarios en `bin/`, los ficheros de Wazuh en `wazuh/`, y el fichero de cron y la configuración de ejemplo del agente en `agent/`.

Consulta en el servidor la versión de OpenSearch Dashboards de tu dashboard. Es 2.19.5 en Wazuh 4.14.7 y 2.19.6 en 4.14.8 y 4.14.9.

```bash
grep -m1 '"version"' /usr/share/wazuh-dashboard/package.json
```

Compila el plugin para esa versión en el repositorio power-ens. La primera compilación tarda unos 20 minutos. Copia el zip y `config/deploy-plugin.sh` al servidor.

```bash
ci/build-zip.sh 2.19.6
```

En el servidor y en cada máquina auditada, descomprime el paquete. Los comandos siguientes se ejecutan desde esta carpeta.

```bash
tar xzf oscompliance-ens-0.10.1-linux-amd64.tar.gz
cd oscompliance-ens-0.10.1-linux-amd64
```

## 2. Instalar las reglas y crear el grupo

Las reglas usan los identificadores 119000 a 119004. Indexan hechos, la sonda de autenticación, eventos de servicio y accesos auditados, y no generan nada por encima del nivel 3. `wazuh-analysisd -t` no debe mostrar errores.

```bash
install -o wazuh -g wazuh -m 660 wazuh/oscompliance_facts_rules.xml /var/ossec/etc/rules/
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
```

Espera un minuto a que arranque el manager. Después crea el grupo `ens` y añade cada máquina que quieras auditar, sustituyendo `<id>` por el identificador del agente que aparece en la lista. Cada máquina conserva sus otros grupos.

```bash
/var/ossec/bin/agent_groups -a -g ens -q
/var/ossec/bin/agent_control -l
/var/ossec/bin/agent_groups -a -i <id> -g ens -q
```

## 3. Crear los usuarios del motor

El motor tiene su propio usuario en el indexer y en la API de Wazuh, con los permisos que indica [Seguridad](security.md#motor). Este script los crea y escribe las credenciales en `/etc/oscompliance/engine.env`.

Pide la contraseña de `wazuh-wui`, que está en `wazuh-passwords.txt` dentro de `wazuh-install-files.tar`, y dos contraseñas nuevas. Cada contraseña nueva necesita entre 8 y 64 caracteres con mayúscula, minúscula, número y símbolo, y no puede contener `$`, `&`, comillas, barras invertidas ni espacios.

```bash
bash wazuh/engine-users.sh create
```

## 4. Instalar el plugin

El script valida el zip, guarda una copia de la versión anterior en `/var/backups/power-ens`, instala el plugin y reinicia el dashboard. Debe terminar con el dashboard activo.

```bash
bash deploy-plugin.sh powerEns-2.19.6.zip
```

Entra en el dashboard y abre Power ENS. Si indica `No se puede leer el inventario de agentes`, el dashboard aún no ha escrito su inventario de agentes, lo que hace cada 15 minutos: espera y pulsa Reintentar. Un usuario con `all_access` puede cambiar la configuración. Para dar permiso a otro usuario, consulta la [instalación de Power ENS](https://github.com/arseniteio/power-ens/blob/main/docs/es/install.md).

## 5. Definir la configuración ENS

En Power ENS, abre Configuración.

1. En Organización, rellena Cliente y pulsa Guardar configuración global. Esto crea la configuración, con nivel MEDIO y el grupo `ens` en alcance. Cambia Nivel ENS si tu sistema tiene otro nivel.
2. En Plantillas, abre cada control, pulsa Completar configuración, rellena lo que falta y guarda.
3. En Agentes, abre cada máquina y rellena los parámetros que corresponden a la máquina.

Cada página de [Controles](controls/README.md) lista los parámetros de su control. Un control se puede rellenar más tarde: hasta entonces aparece como no evaluable por configuración.

## 6. Arrancar el motor

```bash
install -m 755 bin/oscompliance-engine /usr/local/bin/
install -m 644 wazuh/oscompliance-engine.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now oscompliance-engine
```

Espera 20 segundos. El registro debe mostrar una línea `group configuration` con `applied` true y una línea `pass` sin `error`.

```bash
journalctl -u oscompliance-engine -n 10 --no-pager
```

La configuración de grupo debe contener ahora un bloque entre `oscompliance begin` y `oscompliance end`, con el localfile de `facts.ndjson`.

```bash
cat /var/ossec/etc/shared/ens/agent.conf
```

El motor solo escribe ese bloque. Deja intacto el resto del fichero.

## 7. Instalar el agente en las máquinas auditadas

En cada máquina del grupo `ens`, instala el agente y su fichero de cron. Lee `/etc/shadow`, `sshd -T` y los ficheros sudoers, así que se ejecuta como root. No necesita configuración en un sistema estándar.

```bash
install -m 755 bin/oscompliance-agent /usr/local/bin/
install -m 644 agent/oscompliance.cron /etc/cron.d/oscompliance
install -d -m 750 /var/log/oscompliance
install -d -m 700 /var/lib/oscompliance
```

Espera a que la máquina reciba la configuración de grupo: este comando debe devolver un número mayor que 0.

```bash
grep -c facts.ndjson /var/ossec/etc/shared/agent.conf
```

Después crea el fichero de hechos y reinicia el agente de Wazuh antes de la primera pasada. Si no, Wazuh abre el fichero más tarde y omite lo que ya contiene.

```bash
touch /var/log/oscompliance/facts.ndjson
systemctl restart wazuh-agent
sleep 30
oscompliance-agent -full
```

La última línea del fichero debe ser JSON con `"oscompliance":"1"`.

```bash
tail -n 1 /var/log/oscompliance/facts.ndjson
```

El agente añade sus vigilancias de auditoría en tiempo de ejecución con `auditctl`, etiquetadas `oscompliance_*`. Nunca retira una regla y nunca escribe en `/etc/audit`. Con SELinux en enforcing, ejecuta también `restorecon -R /usr/local/bin/oscompliance-agent /etc/cron.d/oscompliance /var/log/oscompliance`.

En RHEL y Rocky, `cron` es el paquete `cronie`.

```bash
dnf install -y cronie && systemctl enable --now crond
```

## 8. Auditar el manager

El manager se juzga como cualquier otra máquina. Hasta que el agente se ejecute en él, su fila aparece como no conforme. No pertenece a ningún grupo, así que necesita dos ajustes propios.

```bash
install -m 755 bin/oscompliance-agent /usr/local/bin/
install -m 644 agent/oscompliance.cron /etc/cron.d/oscompliance
install -d -m 750 /var/log/oscompliance
install -d -m 700 /var/lib/oscompliance
echo '{"paths": {"wazuh_shared_conf": "/var/ossec/etc/shared/ens/agent.conf", "wazuh_client_keys": ""}}' > /etc/oscompliance/agent.json
touch /var/log/oscompliance/facts.ndjson
```

Añade el fichero de hechos y el registro de auditoría a `/var/ossec/etc/ossec.conf`, dentro de `<ossec_config>`.

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

Reinicia el manager y ejecuta la primera pasada.

```bash
systemctl restart wazuh-manager
sleep 60
oscompliance-agent -full
```

## 9. Comprobar el resultado

Inicia sesión por SSH en una máquina auditada, para que un inicio de sesión real llegue a Wazuh, y espera un minuto. Después ejecuta una pasada del motor. La última línea `pass` debe mostrar `verdicts` mayor que 0 y ningún `error`.

```bash
systemctl restart oscompliance-engine
sleep 20
journalctl -u oscompliance-engine -n 5 --no-pager
```

En el dashboard, abre Discover sobre `wazuh-alerts-*`. `rule.id:119001` debe mostrar los hechos de cada máquina, y `rule.id:119002` una sonda de autenticación por máquina y pasada.

En Power ENS, abre Detalle del control y elige una máquina. Cada evidencia muestra su estado y el motivo. El resultado habitual en una máquina nueva es parcial: una evidencia queda no evaluable hasta que se declaran sus parámetros, y un requisito que depende de un documento queda abierto hasta que se declara su atestación en P-ATT.

El primer resultado completo necesita una pasada del agente y una pasada del motor después. Sin `-full` tarda hasta 75 minutos.

Si un paso da otro resultado, consulta [Operación](operations.md#resolución-de-problemas).

## Actualizar

Actualiza primero el motor: lee hechos de agentes más antiguos. Guarda el binario actual, para poder volver a él poniéndolo de nuevo y reiniciando el servicio.

```bash
cp /usr/local/bin/oscompliance-engine /usr/local/bin/oscompliance-engine.prev
install -m 755 bin/oscompliance-engine /usr/local/bin/
systemctl restart oscompliance-engine
```

Si han cambiado las reglas, instálalas como en el apartado 2. Si ha cambiado el rol, ejecuta de nuevo `wazuh/engine-users.sh create`, que también vuelve a definir las contraseñas. En cada máquina auditada, instala el nuevo binario del agente: lo usa la siguiente ejecución de cron. Instala el zip del plugin compilado desde el commit correspondiente como en el apartado 4.

## Desinstalar

En cada máquina auditada:

```bash
rm -f /etc/cron.d/oscompliance /usr/local/bin/oscompliance-agent
rm -rf /etc/oscompliance /var/log/oscompliance /var/lib/oscompliance
augenrules --load
```

En el servidor, retira el motor, el plugin, las reglas y el bloque de la configuración de grupo, y reinicia el manager.

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

Retira los usuarios del motor. El script pide la contraseña de `wazuh-wui`.

```bash
bash wazuh/engine-users.sh remove
```

Los índices `oscompliance-verdicts`, `oscompliance-identity-history`, `oscompliance-config-history` y `wazuh-ens-configuration` se quedan en el indexer, así que no se pierde el historial. Bórralos desde Dev Tools cuando ya no los necesites. Si auditaste el manager, ejecuta también en el servidor los comandos para máquinas auditadas y retira sus dos bloques localfile de `ossec.conf`.
