# Controles

Cada control tiene una página con las mismas secciones:

- Requisitos: lo que exige el Anexo II del ENS, en qué niveles, y las evidencias que prueban cada requisito.
- Fuentes: lo que se lee para juzgarlo: hechos del agente, alertas de Wazuh, inventario, la API de Wazuh.
- Parámetros: lo que declara la organización en Power ENS.
- Cómo se juzga cada evidencia: cuándo una evidencia es COMPLIANT, NON_COMPLIANT, NOT_EVALUABLE o NOT_APPLICABLE.
- No se mide: lo que el control deja deliberadamente a la atestación, y por qué.

Cómo se suman las evidencias en requisitos y controles está en [Veredictos](../verdicts.md).

## Control de acceso

| Control | Título | Niveles |
|---|---|---|
| [op.acc.1](op.acc.1.md) | Identificación | B/M/A |
| [op.acc.2](op.acc.2.md) | Requisitos de acceso | B/M/A |
| [op.acc.3](op.acc.3.md) | Segregación de funciones y tareas | M/A |
| [op.acc.4](op.acc.4.md) | Proceso de gestión de derechos de acceso | B/M/A |
| [op.acc.5](op.acc.5.md) | Mecanismo de autenticación (usuarios externos) | B/M/A |
| [op.acc.6](op.acc.6.md) | Mecanismo de autenticación (usuarios de la organización) | B/M/A |

## Continuidad del servicio

| Control | Título | Niveles |
|---|---|---|
| [op.cont.2](op.cont.2.md) | Plan de continuidad | A |
| [op.cont.3](op.cont.3.md) | Pruebas periódicas | A |

## Explotación

| Control | Título | Niveles |
|---|---|---|
| [op.exp.1](op.exp.1.md) | Inventario de activos | B/M/A |
| [op.exp.2](op.exp.2.md) | Configuración de seguridad | B/M/A |
| [op.exp.3](op.exp.3.md) | Gestión de la configuración de seguridad | B/M/A |
| [op.exp.4](op.exp.4.md) | Mantenimiento y actualizaciones de seguridad | B/M/A |
| [op.exp.5](op.exp.5.md) | Gestión de cambios | M/A |
| [op.exp.6](op.exp.6.md) | Protección frente a código dañino | B/M/A |
| [op.exp.7](op.exp.7.md) | Gestión de incidentes | B/M/A |
| [op.exp.8](op.exp.8.md) | Registro de la actividad | B/M/A |
| [op.exp.9](op.exp.9.md) | Registro de la gestión de incidentes | B/M/A |
| [op.exp.10](op.exp.10.md) | Protección de claves criptográficas | B/M/A |

## Monitorización del sistema

| Control | Título | Niveles |
|---|---|---|
| [op.mon.1](op.mon.1.md) | Detección de intrusión | B/M/A |
| [op.mon.2](op.mon.2.md) | Sistema de métricas | B/M/A |
| [op.mon.3](op.mon.3.md) | Vigilancia | B/M/A |

## Servicios en la nube

| Control | Título | Niveles |
|---|---|---|
| [op.nub.1](op.nub.1.md) | Protección de servicios en la nube | B/M/A |

## Protección de las comunicaciones

| Control | Título | Niveles |
|---|---|---|
| [mp.com.1](mp.com.1.md) | Perímetro seguro | B/M/A |
| [mp.com.3](mp.com.3.md) | Protección de la integridad y de la autenticidad | B/M/A |
| [mp.com.4](mp.com.4.md) | Separación de flujos de información en la red | M/A |

## Protección de los equipos

| Control | Título | Niveles |
|---|---|---|
| [mp.eq.2](mp.eq.2.md) | Bloqueo de puesto de trabajo | M/A |
| [mp.eq.3](mp.eq.3.md) | Protección de dispositivos portátiles | B/M/A |
| [mp.eq.4](mp.eq.4.md) | Otros dispositivos conectados a la red | B/M/A |

## Protección de la información

| Control | Título | Niveles |
|---|---|---|
| [mp.info.6](mp.info.6.md) | Copias de seguridad | B/M/A |

## Protección de los servicios

| Control | Título | Niveles |
|---|---|---|
| [mp.s.1](mp.s.1.md) | Protección del correo electrónico | B/M/A |
| [mp.s.2](mp.s.2.md) | Protección de servicios y aplicaciones web | B/M/A |
| [mp.s.3](mp.s.3.md) | Protección de la navegación web | B/M/A |
| [mp.s.4](mp.s.4.md) | Protección frente a la denegación de servicio | M/A |

## Protección de las aplicaciones informáticas

| Control | Título | Niveles |
|---|---|---|
| [mp.sw.2](mp.sw.2.md) | Aceptación y puesta en servicio | B/M/A |
