# Contribuir

Esta guía explica cómo proponer un cambio en OSCompliance ENS.

## Antes de empezar

Abre una issue antes de un cambio grande, para acordar el enfoque antes del trabajo. Las correcciones pequeñas pueden ir directamente a una pull request.

Comunica las vulnerabilidades de seguridad en privado a devqs@quersystem.com, no en una issue.

## Entorno de desarrollo

Instala Go 1.27.2 o posterior y golangci-lint. El repositorio tiene tres módulos Go: `catalog/`, `agent/` y `engine/`.

## Comprobaciones

```bash
make check
```

Ejecuta gofmt, go vet, golangci-lint y los tests de cada módulo, y los tests de `install.sh`.

## Código

- El código, los identificadores, los comentarios, los mensajes de commit y las pull requests van en inglés.
- Sigue las convenciones que ya tiene el repositorio. Los nombres claros, las funciones pequeñas y el manejo explícito de errores van antes que los comentarios.
- Escribe un comentario solo para lo que el código no puede decir: un invariante, una restricción externa o un apaño con su referencia.
- Los tests van en sus propios ficheros.
- Cada control vive en `engine/internal/controls/ens/<control>` con `evaluator.go`, `judge.go` y un único `<control>_test.go`. Añade otros ficheros solo para helpers que compartan varios jueces.
- El catálogo de `catalog/` es la fuente de verdad. Después de cambiarlo, ejecuta `npx tsx config/sync-catalog.ts` en power-ens-wazuh y haz commit del resultado también allí.
- Prueba contra el laboratorio de [wazuh-lab-docker](https://github.com/arseniteio/wazuh-lab-docker), de un nodo o distribuido, no contra servidores de producción.

## Commits

Usa [Conventional Commits](https://www.conventionalcommits.org/) con ámbito, en una línea de 72 caracteres como máximo, en imperativo y en minúscula:

```text
fix(install): wait for the rules of the release on workers
```

Tipos: feat, fix, refactor, perf, test, docs, build, ci, chore, style y revert.

## Pull requests

- Un cambio lógico por pull request, en una rama `feat/<tema>` o `fix/<tema>`.
- Las comprobaciones de arriba pasan.
- El comportamiento nuevo trae tests, y una corrección trae un test que falla sin ella.
- Los cambios de documentación van a `docs/en` y `docs/es`, y a los dos README, con el mismo contenido.
- Una línea bajo `[Unreleased]` en `CHANGELOG.md`, en inglés. Las etiquetas en español de la interfaz van entre comillas dobles con una glosa breve en inglés, como el botón "Excluir de este control" (exclude from this control).

## Licencia

El proyecto se distribuye bajo AGPL-3.0-only, y Quer System Informática lo ofrece también con una licencia comercial. Para que las dos sean posibles, Quer System Informática necesita los derechos de cada contribución. Antes de que se fusione tu primera pull request, firma el acuerdo de licencia de contribuidor de Quer System Informática. Pídelo en devqs@quersystem.com.
