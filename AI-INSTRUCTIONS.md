# Shared AI instructions for security advisory analysis

This is the canonical instruction file for every supported AI assistant. Tool-
specific entrypoints such as `AGENTS.md` and `CLAUDE.md` must reference this
file and contain only genuinely tool-specific additions. Keep project output in
English and use UTC for all generated timestamps and reports.

## Purpose

This project stores repeatable checks for security advisories that may affect
applications developed in local repositories. Always distinguish between:

- the presence of a technology or dependency in source code;
- the version declared in manifests;
- the version actually installed in the verified environment;
- production status, confirmed only through system-administrator evidence or an
  authorized check on the relevant server.

## Sources

The mandatory starting source is the ACN “Alerts and Bulletins” page:

<https://www.acn.gov.it/portale/ricerca?category=40487>

Do not limit ACN filters to primary programming languages. Select topics that
cover the entire application stack: frontend, backend, runtimes, databases, web
servers, operating systems, containers, virtualization, CI/CD, libraries,
package managers, appliances, and network services. Open every relevant alert
and record at least its CVEs, affected versions, fixed versions, exploitation
prerequisites, and mitigations.

Confirm the information with primary sources in this order:

1. vendor advisories or release notes;
2. official project mailing lists or repositories;
3. official CVE records;
4. secondary sources only for additional context.

Never base a conclusion solely on a bulletin title or on a technology name
appearing in a repository.

## Projects to check

Load enabled project roots exclusively from the ignored local file
`config/local/projects.yaml`. At the beginning of every check, discover Git
repositories and unversioned projects under those roots. Include newly
discovered projects. Exclude runtime copies, caches, dependencies, duplicate
worktrees, and worklog-only directories when they are not deployable products.

Before analyzing a project, read its `AGENTS.md` and referenced directives.
Preserve local changes and untracked files.

## Technology scope for filters

The following list is the initial ACN topic scope. It is not exhaustive: compare
it with current manifests, lockfiles, container images, and configuration during
every check, and add newly detected technologies.

### Languages, runtimes, and executable formats

- PHP, including PHP-FPM, Apache `mod_php`, PHP extensions, and embedded runtimes;
- Python and CPython;
- JavaScript, Node.js, and TypeScript;
- Java;
- Perl and CGI;
- POSIX shell and Bash, plus Zsh and Fish support scripts or fixtures;
- Ruby;
- SQL;
- HTML, XHTML, CSS, SCSS, Sass, and Less;
- XML, XSL/XSLT, WSDL, and XSD;
- Twig, Smarty, Dwoo, EJS, and Handlebars templates.

### Web frameworks, libraries, and toolchains

- Zend Framework 1, `zf1-future`, Laravel, Laravel Sanctum, and Laminas;
- Composer and Packagist;
- PyPI, `pip`, virtualenv, and `uv`;
- npm, Node.js, Vite, webpack, esbuild, Grunt, Babel, and Cypress;
- React, Redux, RxJS, Express, Socket.IO, and jQuery;
- Bootstrap, Tailwind CSS, and CKEditor;
- PHPUnit, pytest, and Vitest when an advisory also affects CI or development;
- direct and transitive lockfile dependencies, even when not listed above.

### Backend, data, and infrastructure

- Apache HTTP Server, PHP-FPM, and CGI/FastCGI configuration;
- Linux, especially Debian and Ubuntu, including security backports;
- Docker, Docker Compose, and Dockerfile base images;
- Vagrant, VirtualBox, and other virtualization components;
- systemd and other service managers;
- PostgreSQL, MySQL/MariaDB, SQLite, MongoDB, and Redis;
- OpenSSL, cURL, and TLS/HTTP libraries;
- Git, GitHub, and CI/CD pipeline components;
- Phing, build scripts, installers, updaters, and deployment mechanisms;
- FreeRADIUS/RADIUS, UniFi, and other network components;
- cloud services and SDKs actually present, including AWS and Google Cloud;
- deployed or locally loaded AI/ML components, including ONNX Runtime,
  Sherpa-ONNX, Vosk, Whisper.cpp, and externally downloaded models.

Supply-chain alerts, malicious packages, credential theft, compromised
container images, and development tools are in scope even when they do not
directly affect web-server code.

## Local inventory

Per-project `manual_technologies` in local inventory are user-declared scope
hints, not scanner findings or verified installed and production versions. Use
them to look for relevant advisories, then verify applicability independently.
Per-project `production_technologies` are environment-specific records kept
separate from detected or manual inventory versions. Each production record
must retain its evidence type, evidence note, and UTC verification timestamp.
Treat administrator-confirmed and explicitly authorized checks as production
evidence; label reported-only values as unverified. Include every distinct
inventory and production version in advisory scope, preserve production records
during inventory refreshes, and never infer production from local evidence.
An explicit ecosystem-scoped manual exclusion records a human decision that a
detected dependency is not used in that project; do not restore it to the active
scope without new evidence or a user-requested inventory refresh.
The inventory UI may mark version evidence as red (missing), orange (uncertain,
constrained, manually supplied, or production-reported only), or green (exact
and resolved from a lockfile, verified locally, administrator-confirmed in
production, or verified through an authorized production check). These colors describe inventory
quality only, never vulnerability or production status. Whenever a version value
is present, use that value as the advisory applicability boundary regardless of
its displayed confidence. The user may override the displayed inventory-version
status; that assessment remains GUI-only, is excluded from advisory plans, and
never changes the saved version.

The detected project inventory is environment-derived data and belongs only in
the ignored `config/local/projects.yaml`. Never copy local project names,
paths, versions, production state, or findings into versioned instruction or
configuration files. Vendored or generated files may contain other languages;
count them only when they are actually distributed or executed. Worklog, issue,
runtime, and documentation directories are evidence or context, not standalone
applications.

## Daily procedure

1. Record the date, time, UTC timezone, and covered interval.
2. Read new ACN alerts and select those compatible with inventoried technologies,
   runtimes, frameworks, libraries, and infrastructure.
3. For every possible match, inspect manifests, lockfiles, container images,
   runtime, web-server, database, OS, and CI/CD configuration, plus actual use of
   vulnerable APIs. Exclude `vendor`, virtual environments, caches, and vendored
   third-party sources when they would create false positives, unless that
   component is itself distributed.
4. When a local environment is available, verify its installed version without
   modifying it. For web services, distinguish the web SAPI from the CLI.
5. Never infer production state from development. Clearly identify administrator
   confirmations and checks that were not performed.
6. Classify each item as `immediate action`, `follow-up`, `monitor`, or
   `not applicable`, and explain the decision.
7. Save the report as `output/daily-advisory-check/YYYY-MM-DD.md`. If it already exists,
   extend it without losing earlier evidence.
8. Update `output/followup.md` with status, owner, next action, and closure
   evidence. Update `output/check-summary.md` with a very short summary of
   completed checks.

When the launcher supplies technology baseline state, use the current
technology/version combinations as the applicability boundary. A missing
baseline triggers historical initialization for the selected combinations; a
known baseline uses each source's last successful checkpoint minus the
configured overlap. A hybrid run keeps these windows separate: resolve the
official release date for every selected version and cover its baseline from
that date through the run. Package dependencies use the exact resolved version;
platform technologies use the beginning of their applicable release line.
Check already initialized technologies
from the incremental source windows. Do not advance a source checkpoint when its content
coverage is unavailable, partial, or failed. A technology without a version
receives a generic, explicitly partial baseline and human-review limitation.
Go `go.mod` requirements are minimum version hints, and `replace` directives
in `go.mod` or `go.work` may change the code used. Workspace modules outside
the selected project remain unresolved for human review. Until the effective
build-list version is confirmed
and saved by the user, scan these entries generically and keep their baselines
partial. Do not treat `go.sum` checksums as installed versions.
Reports are informational and must never change inventory versions.
Perform deterministic package/version and affected-range matching first. Use AI
judgment only for ambiguous identity, prerequisites, reachability, or incomplete
evidence; unresolved cases belong in the report for human review.
In routed mode, account for every selected baseline and active source in the
machine-readable evidence receipt requested by the launcher. Reachability alone
never makes source coverage complete. A completed baseline receipt records its
official release date and the actual searched interval; if those facts cannot
be established, mark the baseline partial for human review.
Prefer verified metadata from the versioned shared release cache, then the
private local cache, then approved public registry services. Never send private
package names or local project identifiers to a public metadata service.

## Minimum report content

- sources and consultation date;
- examined advisories and CVEs;
- advisory-to-project mapping;
- local evidence with paths and versions;
- decisions and ownership;
- checks not performed and residual risk;
- changes made, normally none during analysis-only work.

## Operating rules

For desktop screens that combine an inventory table with creation or editing,
use separate tabs for the table and the form. Open the form with the selected
row's current values, apply changes to the table preview, and let the user
review that preview before saving.

- Analysis is read-only unless implementation is explicitly requested.
- Do not update dependencies, runtimes, servers, or configuration during a check.
- Do not deploy, push, or perform other remote writes.
- Do not disclose secrets, credentials, tokens, private addresses, or sensitive
  configuration contents.
- Write all environment-derived reports, findings, paths, versions, project
  identifiers, and follow-up state only below the Git-ignored `output/`
  directory or in `config/local/`.
- Do not declare a vulnerability resolved merely because a mitigation exists;
  distinguish patching, mitigation, and risk acceptance.
- Tie every conclusion to collected evidence and state confidence.
