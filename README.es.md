# OSCompliance ENS

[English version](README.md)

OSCompliance ENS mide el Esquema Nacional de Seguridad (Real Decreto 311/2022) sobre un despliegue de Wazuh. Convierte lo que hacen tus máquinas en un veredicto por control, por requisito y por máquina, con el motivo de cada resultado, cada 15 minutos.

Añade un binario de agente en cada máquina Linux y un motor junto al indexer de Wazuh. Wazuh sigue haciendo la recogida. No se juzga nada en la máquina auditada, y lo que no se puede demostrar no cuenta como cumplido. El plugin [Power ENS](https://github.com/arseniteio/power-ens) muestra los resultados en el dashboard de Wazuh.

Funciona en Wazuh 4.14.7, 4.14.8 y 4.14.9, con las máquinas auditadas en Linux.

## Primeros pasos

La instalación rápida de abajo cubre un servidor con Wazuh 4.14.8 o 4.14.9 instalado por paquetes y máquinas Linux amd64. Con Wazuh 4.14.7, usa el zip `osd-2.19.5`. Para Docker, otras arquitecturas o el detalle de cada paso, sigue las guías completas:

- [Instalación por paquetes](docs/es/install.md)
- [Instalación con Docker](docs/es/install-docker.md)

### Instalación rápida

En el servidor, como root y con `gh` autenticado en GitHub. `engine-users.sh` pide la contraseña de `wazuh-wui` y dos contraseñas nuevas.

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

En el dashboard, abre Power ENS, Configuración, Organización, rellena Cliente y pulsa Guardar configuración global. Después arranca el motor y añade cada máquina al grupo `ens`, con el ID de agente de `agent_control -l`.

```bash
install -m 755 bin/oscompliance-engine /usr/local/bin/
install -m 644 wazuh/oscompliance-engine.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now oscompliance-engine
/var/ossec/bin/agent_groups -a -i <id> -g ens -q
```

En cada máquina, copia el mismo paquete y descomprímelo. Cuando `grep -c facts.ndjson /var/ossec/etc/shared/agent.conf` muestre un número mayor que 0, instala el agente.

```bash
cd oscompliance-ens-1.0.0-linux-amd64
install -m 755 bin/oscompliance-agent /usr/local/bin/
install -m 644 agent/oscompliance.cron /etc/cron.d/oscompliance
install -d -m 750 /var/log/oscompliance && install -d -m 700 /var/lib/oscompliance
touch /var/log/oscompliance/facts.ndjson && systemctl restart wazuh-agent
sleep 30 && oscompliance-agent -full
```

Los primeros veredictos aparecen en Power ENS tras la siguiente pasada del motor, en menos de 15 minutos.

## Cómo funciona

El agente escribe hechos en un fichero local. El agente de Wazuh envía ese fichero al manager junto con los registros, FIM, SCA e inventario, y el manager indexa los hechos mediante las reglas 119000 a 119004. Cada 15 minutos, el motor lee el indexer y escribe veredictos, y Power ENS los muestra.

El agente informa de hechos, nunca de veredictos: cuentas, PAM, sshd, sudoers, puertos en escucha, paquetes, copias y claves, tal como están.

El motor juzga. Lee los hechos, las alertas y el inventario de Wazuh, el manager mediante la API de Wazuh y los parámetros que declara tu organización, y escribe un veredicto por evidencia, requisito y control.

La falta de prueba es un fallo. Un registro que no llega a Wazuh, un parámetro sin definir o un agente que ha dejado de informar aparece como no evaluable, con la causa, y el requisito no se cumple.

Una pasada sobre 10.000 agentes simulados tarda unos dos minutos en un indexer de un solo nodo.

## Controles

Cubre 34 controles del Anexo II, cada uno con los requisitos de sus categorías (BAJO, MEDIO, ALTO): control de acceso (op.acc), explotación (op.exp), continuidad (op.cont), monitorización (op.mon), servicios en la nube (op.nub), comunicaciones (mp.com), equipos (mp.eq), información (mp.info), servicios (mp.s) y software (mp.sw).

Cada control tiene una página con lo que exige el ENS, cómo se mide cada evidencia, sus parámetros y lo que queda para la atestación documental. Consulta [Controles](docs/es/controls/README.md).

## Documentación

- [Instalación por paquetes](docs/es/install.md) y [con Docker](docs/es/install-docker.md): instalar, comprobar, actualizar y desinstalar.
- [Configuración](docs/es/configuration.md): flags del motor, ajustes del agente y parámetros ENS.
- [Arquitectura](docs/es/architecture.md): componentes, flujo de datos y escala.
- [Veredictos](docs/es/verdicts.md): estados, causas y puntuación.
- [Controles](docs/es/controls/README.md): una página por control.
- [Hechos](docs/es/facts.md): cada hecho que emite el agente.
- [Seguridad](docs/es/security.md): privilegios, tratamiento de datos y modelo de amenazas.
- [Operación](docs/es/operations.md): registros, resolución de problemas y capacidad.

## Compilar y probar

Comprueba el formato y ejecuta go vet, golangci-lint y las pruebas. Necesita golangci-lint 2.15.0 o posterior.

```bash
make check
```

Compila los paquetes en `dist/`.

```bash
make dist VERSION=1.0.0
```

## Seguridad

Notifica las vulnerabilidades en privado mediante un aviso de seguridad de GitHub. Consulta [Seguridad](docs/es/security.md).

## Licencia

Copyright (c) 2026 Arsenite.

OSCompliance ENS se distribuye bajo la GNU Affero General Public License versión 3 (AGPL-3.0-only). Consulta [LICENSE](LICENSE).

Arsenite ofrece también OSCompliance ENS con una licencia comercial, para organizaciones que no pueden cumplir las obligaciones de la AGPL, como mantener privados los cambios en un producto o en un servicio en red. Escribe a devqs@quersystem.com para conocer las condiciones.
