# OSCompliance ENS

[English version](README.md)

OSCompliance ENS mide el Esquema Nacional de Seguridad (Real Decreto 311/2022) sobre un despliegue de Wazuh. Convierte lo que hacen tus máquinas en un veredicto por control, por requisito y por máquina, con el motivo de cada resultado, cada 15 minutos.

Añade un binario de agente en cada máquina Linux y un motor junto al indexer de Wazuh. Wazuh sigue haciendo la recogida. No se juzga nada en la máquina auditada, y lo que no se puede demostrar no cuenta como cumplido. El plugin [Power ENS](https://github.com/arseniteio/power-ens) muestra los resultados en el dashboard de Wazuh.

Funciona en Wazuh 4.14.7, 4.14.8 y 4.14.9, con las máquinas auditadas en Linux.

## Primeros pasos

En un servidor de Wazuh con el manager, el indexer y el dashboard instalados por paquetes, ejecuta como un usuario con sudo:

```bash
curl -fsSL https://github.com/arseniteio/oscompliance-ens/releases/latest/download/install.sh | sudo bash -s -- server
```

El script instala las reglas, el motor y sus usuarios, el plugin Power ENS para tu dashboard, y audita el manager. Pide la contraseña de `wazuh-wui` y dos contraseñas nuevas.

En el dashboard, abre Power ENS, Configuración, Organización, rellena Cliente y pulsa Guardar configuración global. Después añade cada máquina que se audita al grupo `ens`, con su ID de `/var/ossec/bin/agent_control -l`.

```bash
sudo /var/ossec/bin/agent_groups -a -i <id> -g ens -q
```

En cada una de esas máquinas:

```bash
curl -fsSL https://github.com/arseniteio/oscompliance-ens/releases/latest/download/install.sh | sudo bash -s -- agent
```

Los primeros veredictos aparecen en Power ENS en menos de 15 minutos. Ejecuta los mismos comandos con una versión más nueva para actualizar, y con `uninstall` para quitarlo todo.

Para revisar los ficheros antes de ejecutar nada, descarga el paquete y compruébalo. El `install.sh` del paquete usa los ficheros que tiene al lado.

```bash
v=1.1.0
url=https://github.com/arseniteio/oscompliance-ens/releases/download/v$v
curl -fLO "$url/oscompliance-ens-$v-linux-amd64.tar.gz" -O "$url/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
tar xzf "oscompliance-ens-$v-linux-amd64.tar.gz"
sudo "./oscompliance-ens-$v-linux-amd64/install.sh" agent
```

En el servidor, el script descarga el plugin de la versión de power-ens y lo comprueba. Para instalar sin acceso a GitHub, copia antes el zip del plugin y `deploy-plugin.sh` en la carpeta del paquete.

Para Wazuh en Docker, un despliegue distribuido o el detalle de cada paso, sigue las guías completas:

- [Instalación por paquetes](docs/es/install.md)
- [Instalación con Docker](docs/es/install-docker.md)

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

Compila los paquetes en `dist/`, con `install.sh` y `SHA256SUMS`. Hace falta Go 1.27.2 o posterior.

```bash
make dist VERSION=1.1.0
```

## Seguridad

Notifica las vulnerabilidades en privado mediante un aviso de seguridad de GitHub. Consulta [Seguridad](docs/es/security.md).

## Licencia

Copyright (c) 2026 Arsenite.

OSCompliance ENS se distribuye bajo la GNU Affero General Public License versión 3 (AGPL-3.0-only). Consulta [LICENSE](LICENSE).

Arsenite ofrece también OSCompliance ENS con una licencia comercial, para organizaciones que no pueden cumplir las obligaciones de la AGPL, como mantener privados los cambios en un producto o en un servicio en red. Escribe a devqs@quersystem.com para conocer las condiciones.
