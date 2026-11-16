# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project intends to use [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- The desktop sidebar now groups operational pages, administration pages, and
  help pages in task-oriented order with non-selectable visual separators.
- Run check now explains that the selected coordinator affects only Inventory
  projects without an explicit Codex or Claude preference.
- Complete desktop analyses now show the active Codex or Claude provider,
  current phase, elapsed time, and verified project-group progress in both the
  Run check page and a cross-page footer indicator.
- The Linux application icon now uses a true transparent background instead of
  embedding the dark rounded-square tile.
- Technology inventory projects can now be included or excluded from advisory
  analysis individually and routed to Codex or Claude; `-` inherits the launch
  coordinator, local choices survive inventory refreshes, provider evidence is
  isolated, one coordinator consolidates canonical reports, and each run writes
  a private line-oriented audit summary and chronological event log in a
  year/month archive. The desktop Logs page can read and delete individual runs.
- OSV-Scanner installation now prefers checksummed official Linux binaries on
  x86_64 and arm64, avoiding an unnecessary Go toolchain dependency.
- The Go-based fallback validates the installed toolchain and blocks execution
  when the prerequisite is missing or incompatible.
- Codex installation now uses OpenAI's standalone user installer without a
  Node.js/npm prerequisite, preserves IDE-managed copies, and gives fAIry a
  stable executable independent of the launching environment.
- Non-interactive Codex checks now use an explicit no-prompt sandbox policy
  that works without an IDE approval reviewer, and retain CLI diagnostics in
  the private run log. Agent stdin is explicitly closed so Codex and Claude do
  not wait indefinitely for additional piped instructions.
- Child Codex processes now discard transient parent IDE/session sandbox
  variables while preserving authentication and user configuration. Complete
  runs also verify canonical report changes and return exit code 2 instead of a
  false success when the coordinator could not publish its result.
- The Codex coordinator explicitly enables network access inside its
  `workspace-write` sandbox, avoiding Bubblewrap loopback failures without
  granting `danger-full-access`.
- Claude Code installation now uses Anthropic's recommended native user
  installer instead of npm, preserving IDE-managed copies and providing the
  same stable executable resolution used for Codex.
- The AI issue assistant now gives the affected project a dedicated prominent
  heading and separates it visually from activity and advisory metadata.

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
