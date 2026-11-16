# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project intends to use [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- OSV-Scanner installation now prefers checksummed official Linux binaries on
  x86_64 and arm64, avoiding an unnecessary Go toolchain dependency.
- The Go-based fallback validates the installed toolchain and blocks execution
  when the prerequisite is missing or incompatible.
- Codex installation now uses OpenAI's standalone user installer without a
  Node.js/npm prerequisite, preserves IDE-managed copies, and gives fAIry a
  stable executable independent of the launching environment.
- Claude Code installation now uses Anthropic's recommended native user
  installer instead of npm, preserving IDE-managed copies and providing the
  same stable executable resolution used for Codex.

## [0.1.2] - 2026-11-16

### Added

- Public factory configuration with ignored local overrides.
- Read-only stack inventory across configurable project roots and exclusions.
- Configurable advisory sources including ACN, GitHub Advisory Database, OSV,
  CISA KEV, OpenSSF Malicious Packages, and CVE List V5.
- Shared Codex and Claude security-advisory skill.
- Daily reports, current summary, active follow-up, and monthly closed-issue
  archives under ignored local output.
- Interactive CLI and native PySide6 desktop application.
- Guided configuration forms, backup/import, factory restore, AI account status,
  usage statistics, issue assistant, and Linux application-menu integration.
- Synthetic public screenshots and comprehensive desktop user guide.

### Security

- Local configuration and environment-derived output are excluded from Git.
- Backup import validates paths, declared members, sizes, hashes, and YAML.
- Scanned projects remain read-only throughout analysis.

[Unreleased]: https://github.com/mecio/fairy-security-advisory/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/mecio/fairy-security-advisory/releases/tag/v0.1.2
