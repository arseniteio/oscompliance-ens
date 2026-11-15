# Changelog

All notable changes to OSCompliance ENS are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/arseniteio/oscompliance-ens/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/arseniteio/oscompliance-ens/releases/tag/v1.0.0
