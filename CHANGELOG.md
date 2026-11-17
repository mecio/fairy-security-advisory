# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project intends to use [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Run check now builds version-aware technology baselines, preselects missing
  combinations for historical initialization, and maintains conservative
  per-source incremental checkpoints with a configurable overlap.
- Routed runs now require machine-validated baseline markers and a structured
  evidence receipt before updating baseline or source checkpoint state.
- Technology inventory now shows red, orange, and green version-evidence
  quality independently from security severity.
- Lockfile inventory preserves concurrent versions and reads Composer, npm,
  Yarn, pnpm, Pipenv, Poetry, uv, Cargo, Bundler, and Go resolution data.
- Release metadata now uses a versioned shared cache, a private local overlay,
  optional deps.dev batch lookups, and review-only shared-cache candidate exports.

### Changed

- Release metadata now reads the actual deps.dev batch response, retains
  package ecosystem identity, prioritizes verified cache entries, and bounds
  batch and response sizes.

- Inventory refresh is always explicit, creates a safety backup, replaces
  technology/version edits, and preserves project inclusion and AI routing.
- Initialization and incremental analyses share the daily report format and
  filter applicability against current inventoried versions.
- Large GUI technology selections now use a private consumed request file
  instead of expanding every key onto the process command line, with symlink
  rejection on both creation and consumption.
- Hybrid checks now keep per-technology release-date baselines separate from
  per-source incremental windows; manual versions remain unverified/orange.
- Run summaries distinguish completed, completed-with-limitations, and failed
  baseline coverage; unsafe or corrupt advisory state now blocks analysis.

## [0.2.0] - 2026-11-17

### Added

- Run check now presents an animated fAIry workflow linked to actual check and
  AI phase events, with the detailed process log in a separate panel.
- The desktop application now presents a versioned first-run EULA notice with
  an explicit acceptance checkbox; the acceptance version and UTC timestamp
  remain in ignored local configuration.
- Linux AI startup now includes a read-only Bubblewrap/AppArmor preflight and a
  guided, reviewable setup action for Codex and Claude Code.
- Reports now offers a confirmed reset that archives current daily reports,
  summary, follow-up, and closed-issue history locally before a fresh check.
- Inventory now accepts user-declared technologies per project, marks them
  separately from scanner findings, and preserves them across refreshes.
- Complete checks now require an explicit coverage line for each selected
  project in the newest daily report section before reporting success.

### Changed

- Follow-up activities now show a descriptive, searchable issue title in Reports
  and AI issue assistant, alongside identifiers and source links.
- Run check now separates the animated Activity view and full-height Detailed
  log into tabs; switching tabs does not interrupt an active analysis.
- Clear reports now leaves a manual reset snapshot that subsequent AI checks
  ignore; new reports and follow-up are rebuilt from current evidence only.
- The Run check fairy now faces incoming sources and projects, turns toward
  matching, and casts an animated wand trail during consolidation.
- Successful terminal handoffs close the desktop window automatically; active
  analysis and chat processes block the handoff until they finish.
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
  `workspace-write` sandbox without granting `danger-full-access`.
- Claude processes launched by fAIry now require the OS sandbox, disable
  unsandboxed command retries, and fail closed when isolation is unavailable.
- Claude Code installation now uses Anthropic's recommended native user
  installer instead of npm, preserving IDE-managed copies and providing the
  same stable executable resolution used for Codex.
- The AI issue assistant now gives the affected project a dedicated prominent
  heading and separates it visually from activity and advisory metadata.

### Security

- Ubuntu 24.04 AppArmor remediation now uses the distribution's
  `bwrap-userns-restrict` profile and loads only that profile. Unknown Linux
  restriction failures do not offer an executable system change.

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

[Unreleased]: https://github.com/mecio/fairy-security-advisory/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mecio/fairy-security-advisory/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/mecio/fairy-security-advisory/releases/tag/v0.1.2
