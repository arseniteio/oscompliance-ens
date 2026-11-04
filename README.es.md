# OSCompliance ENS

[English version](README.md)

OSCompliance ENS mide el Esquema Nacional de Seguridad (Real Decreto 311/2022) sobre un despliegue de Wazuh. Convierte lo que hacen de verdad tus máquinas en un veredicto por control, por requisito y por máquina, con el motivo de cada resultado, cada 15 minutos.

Añade un binario de agente en cada máquina Linux y un motor junto al indexer de Wazuh. Wazuh sigue haciendo la recogida. No se juzga nada en la máquina auditada, y lo que no se puede demostrar no cuenta como cumplido. El plugin [Power ENS](https://github.com/arseniteio/power-ens) muestra los resultados en el dashboard de Wazuh.

Funciona en Wazuh 4.14.7, 4.14.8 y 4.14.9, con las máquinas auditadas en Linux.

## Primeros pasos

Sigue la guía de tu despliegue. Cada una lleva alrededor de una hora en el servidor y unos minutos por máquina auditada.

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

Comprueba el formato y ejecuta las pruebas.

```bash
make check
```

Compila los paquetes en `dist/`.

```bash
make dist VERSION=0.10.1
```

## Seguridad

Notifica las vulnerabilidades en privado mediante un aviso de seguridad de GitHub. Consulta [Seguridad](docs/es/security.md).
