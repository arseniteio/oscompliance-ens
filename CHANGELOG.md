# Changelog

All notable changes to OSCompliance ENS are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Maturity (Anexo II, apdo. 6). Each control verdict carries the CMM level its evidence accredits on that machine, L0 to L2 over 30 days. Each pass writes `organization` verdicts with the lowest level of each control, the level, target and author declared in the configuration, declared measures without engine, and the distribution and global level for the whole ENS.
- The agent unloads the `oscompliance_*` audit watches the group configuration no longer asks for, only when it holds the engine's block, and the read watches loaded with `-w` before the auid filter. `audit_watch_snapshot` lists them in `unloaded`.
- `oscompliance-agent -guard-audit`, run by cron every 2 minutes, unloads for one hour a read watch that records more than `audit_read_limit` successful reads per minute (60 by default) over 5 minutes. The next passes report it in `failed` and the controls that judge those reads are NOT_EVALUABLE by COLLECTION until the suspension ends. Rule 119006 alerts at level 10 on every suspension.
- The engine deduces each machine's distro, role (manager, server or workstation) and services from the Wazuh inventory on every pass, and writes them to `oscompliance-host-profile` with the signal behind each one. The rules are in `catalog/host-signals.json`. Verdicts do not change.
- `-host-profile-index` names that index.
- Profiles give parameter values to every machine whose host profile meets their conditions, in four layers (distro, role, service, site): lists add up across layers and other values come from the most specific one. Each profile is a `PROFILE` document in `wazuh-ens-configuration`. The catalog ships `ubuntu` and `manager-wazuh` with the values of the built-in templates, so verdicts do not change.
- `-profile-groups` keeps one Wazuh group per profile, `ens-perfil-<id>`, with the machines that get it and the label `ens.perfil.<id>`. The engine API role already allows it (`agent:modify_group`).
- `oscompliance-policy`, installed with the engine, checks, plans, applies, exports and deletes profiles written in YAML, and explains which profiles and values a machine gets.

### Changed

- Rule 119005 drops on the manager the 119004 reads (`oscompliance_read`) of files every process reads: the NSS files, the loader cache, the CA store, the time zone, `/usr` and `/lib`. Agents of 1.2.0 and earlier loaded such watches and filled disks within minutes. `install.sh` checks IDs 119000 to 119005.
- The agent does not load a read rule on a path from `catalog.HotReadPaths`, under one, or on a directory that holds one, and reports it in `failed` of `audit_watch_snapshot`. The path stays out of `loaded`, so the controls that judge reads show it as a collection gap. Writes, executions and attribute changes are still audited.
- The group configuration splits the auditd watches in two. `audit_watches` (op.exp.3 P-04) records only writes and attribute changes. The new `read_watches` (op.acc.2 P-06, op.acc.3 P-03 paths and the security paths, op.acc.4 P-07, op.exp.10 P-02) adds reads, recorded only for sessions with a login UID (`auid!=-1`). Read watches on world-readable files such as /etc/group made every NSS lookup an alert 119004. `audit_watch_snapshot` gains `read_wanted`. Machines upgraded from 1.2.0 keep their old watches until `auditctl -D -k oscompliance_read` and `auditctl -D -k oscompliance_exec` run once.
- The repository is now `arseniteio/oscompliance-ens-wazuh`, to leave room for other SIEMs. The Go module paths and schema `$id` URLs follow it, and the packages are named `oscompliance-ens-wazuh-<version>-linux-<arch>.tar.gz`. `install.sh` downloads from the new repositories and expects the new plugin zip name.
- The installation guide lists the hardware the agent, the engine and the verdicts need, measured in the lab.
- The configuration guide presents Power ENS > Configuración > Perfiles as the place to manage profiles, and `oscompliance-policy` as the option for automation.
- `CONTRIBUTING.md` and `CONTRIBUTING.es.md` explain how to propose a change and the contributor license agreement.

## [1.2.0] - 2026-11-16

### Added

- `install.sh server` detects the node and installs only its part: rules, manager audit and engine on the master manager or single node, a restart once the rules of the release arrive on a worker, and the Power ENS plugin on a dashboard node.
- `install.sh server --only <components>` replaces the detection with a comma-separated list of `rules`, `audit`, `engine`, `plugin` and `worker`.
- `install.sh agent --group <name>` asks the engine to add the machine to a Wazuh group and reads the facts file through a localfile in the agent's own `ossec.conf` until the group configuration arrives.
- The agent sends `wazuh_group` from `agent.json` as `requested_group` in every `agent_pass` fact.
- The engine creates the groups of the ENS scope that do not exist and adds to them the agents that ask for them, never to a group outside the scope.
- The engine logs a warning for agents that ask for a group outside the ENS scope.
- `-indexer` accepts several comma-separated URLs and fails over to the next one when one does not answer.
- `catalog/default-configuration.json` holds the default ENS configuration: level MEDIO and the `ens` group in scope.

### Changed

- Until a configuration is saved in Power ENS, the engine judges with the catalog default, so the "Guardar configuración global" (save global configuration) step is no longer required for the first verdicts.
- The engine unit reads the indexer URLs and CA certificate from `/etc/oscompliance/engine.conf`, which `install.sh server` writes from the Filebeat output of the manager.
- `engine-users.sh` uses the indexer admin certificate when it is on the host and otherwise asks for the password of the indexer `admin` user, so no certificate is copied between hosts.
- `install.sh server` keeps the passwords of existing engine users on a rerun and updates their permissions.
- The Wazuh API role of the engine adds `group:modify_assignments` and `agent:modify_group`.
- `install.sh uninstall` removes from each node only what is installed there, and the rules only on the master.
- The installation guide covers distributed deployments, with the steps of each node type.
- `install.sh server` installs `jq` and `unzip` with the system package manager when they are missing.

### Fixed

- The engine logs in to the Wazuh API again when its token is revoked by a change of roles, as happens right after `engine-users.sh` creates them, instead of skipping the group configuration until the next sync.

## [1.1.0] - 2026-11-15

### Added

- `install.sh`, published with each release and included in each package. `install.sh server` installs the rules, the engine and its users and the Power ENS plugin on an all-in-one Wazuh server installed from packages, and audits the manager. `install.sh agent` installs the agent and runs its first pass once the group configuration arrives. `install.sh uninstall` removes both. It verifies every download against `SHA256SUMS`.

### Changed

- The installation guides download the release with `curl` and `sha256sum`, and building from source moves to its own section.

## [1.0.0] - 2026-11-13

First release.

### Added

- Agent `oscompliance-agent` for Linux amd64 and arm64. It writes facts about accounts, groups, PAM, sshd, sudoers, listening sockets, packages, backups and keys to `/var/log/oscompliance/facts.ndjson`, and judges nothing.
- Engine `oscompliance-engine`. Every 15 minutes it reads the facts, the Wazuh alerts and inventory, the Wazuh API and the parameters declared in Power ENS, and writes one verdict per evidence, requirement and control to the `oscompliance-verdicts` index.
- Catalog of 34 controls of Annex II of Real Decreto 311/2022, with one documentation page per control.
- Wazuh rules 119000 to 119004 for facts, the authentication probe, service events and audited accesses.
- `engine-users.sh`, which creates the engine users in the indexer and the Wazuh API with the permissions the engine needs.
- systemd unit for the engine and cron file for the agent.
- Packages for Linux amd64 and arm64 with a `SHA256SUMS` file.
- Support for Wazuh 4.14.7, 4.14.8 and 4.14.9, installed from packages or on Docker.

[Unreleased]: https://github.com/arseniteio/oscompliance-ens-wazuh/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/arseniteio/oscompliance-ens-wazuh/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/arseniteio/oscompliance-ens-wazuh/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/arseniteio/oscompliance-ens-wazuh/releases/tag/v1.0.0
