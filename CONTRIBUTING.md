# Contributing

This guide explains how to propose a change to OSCompliance ENS.

## Before you start

Open an issue before a large change, so that the approach is agreed before the work. Small fixes can go straight to a pull request.

Report security vulnerabilities privately to devqs@quersystem.com, not in an issue.

## Development setup

Install Go 1.27.2 or later and golangci-lint. The repository holds three Go modules: `catalog/`, `agent/` and `engine/`.

## Checks

```bash
make check
```

It runs gofmt, go vet, golangci-lint and the tests of every module, and the tests of `install.sh`.

## Code

- Code, identifiers, comments, commit messages and pull requests are in English.
- Follow the conventions already in the repository. Clear names, small functions and explicit error handling come before comments.
- Write a comment only for what the code cannot say: an invariant, an external constraint or a workaround with its reference.
- Tests live in their own files.
- Each control lives in `engine/internal/controls/ens/<control>` with `evaluator.go`, `judge.go` and one `<control>_test.go`. Add other files only for helpers that several judges share.
- The catalog in `catalog/` is the source of truth. After changing it, run `npx tsx config/sync-catalog.ts` in power-ens-wazuh and commit the result there too.
- Test against the lab in [wazuh-lab-docker](https://github.com/arseniteio/wazuh-lab-docker), single node or distributed, not against production servers.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) with a scope, in one line of at most 72 characters, imperative and lowercase:

```text
fix(install): wait for the rules of the release on workers
```

Types: feat, fix, refactor, perf, test, docs, build, ci, chore, style and revert.

## Pull requests

- One logical change per pull request, on a branch named `feat/<topic>` or `fix/<topic>`.
- The checks above pass.
- New behaviour comes with tests, and a bug fix with a test that fails without it.
- Documentation changes go to `docs/en` and `docs/es`, and to both READMEs, with the same meaning.
- A line under `[Unreleased]` in `CHANGELOG.md`. Spanish labels of the user interface go in double quotes with a short English gloss, such as the "Excluir de este control" (exclude from this control) button.

## License

The project is licensed under AGPL-3.0-only, and Quer System Informática also offers it under a commercial license. To keep both possible, Quer System Informática needs the rights to every contribution. Before your first pull request is merged, sign the Quer System Informática contributor license agreement. Ask for it at devqs@quersystem.com.
