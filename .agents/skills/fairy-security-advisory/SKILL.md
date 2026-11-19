---
name: fairy-security-advisory
description: Run AI-assisted periodic security advisory checks by correlating public sources, local inventory, manifests, lockfiles, and follow-up records without modifying scanned projects. Use for complete checks or for updating this repository's security reports and activities.
---

# fAIry Security Advisory

Run a repeatable, evidence-based, read-only check against inventoried projects. Write only to local configuration and outputs in this repository.

## Mandatory directives

Before an advisory check, read [directives/README.md](references/directives/README.md)
and every directive it routes to for the current phase. These directives define
non-negotiable applicability, source-coverage, consolidation, and receipt
rules. They take precedence over an analyst's confidence judgment: confidence
may qualify a conclusion but must never remove a populated inventory version
or an in-scope source candidate from analysis.

## Start

1. Locate the repository root from the skill directory, read the mandatory
   directives above, then read `AGENTS.md`,
   the effective configuration, preferring files under `config/local/` and
   falling back to the versioned factory files in `config/`,
   `output/followup.md`, archived follow-ups under
   `output/followup-archive/YYYY/MM.md` when present, and the latest daily report under
   `output/daily-advisory-check/` in full. Treat `output/report-resets/` as a
   manual backup archive: do not read it during an advisory check. After
   **Clear reports and follow-up**, use only current files and new evidence.
   If the local project configuration is missing, explain how to copy
   `config/projects.example.yaml` as documented
   in the README; never invent local paths.
2. Before analyzing a project, read its `AGENTS.md` and referenced directives relevant to version, dependency, and infrastructure scanning.
3. Validate configuration with `python3 scripts/validate_project.py --config-dir config`.
   If `inventory.projects` in `config/local/projects.yaml` is empty or older
   than `refresh_after_hours`, report that condition. Never refresh it as a
   side effect of an advisory check: inventory discovery and technology/version
   replacement run only after an explicit user action and confirmation.
4. Build the analysis scope from inventory projects whose
   `advisory_checks.enabled` value is not `false`. Keep disabled projects in the
   inventory, but do not inspect their manifests or lockfiles, run OSV-Scanner
   or Trivy against them, create findings for them, or add follow-up activities
   for them. Mention the local selection as the reason when scope exclusions
   need to be reported.

## Check

1. Record date, time, UTC timezone, and covered interval. Discover new projects under every enabled root.
2. Consult every active source in priority order. Handle HTML, RSS/Atom, JSON,
   API, and repository sources according to their type and filter. ACN is the
   mandatory starting source; do not limit filters to primary programming
   languages. Follow the execution mode supplied by the launcher, or
   `default_execution_mode` from the effective AI configuration (local override
   first, factory fallback) when none is supplied:
   `economical` processes sources sequentially without sub-agents; other modes
   may use parallel source work and no more than their configured
   `max_subagents`. If sub-agents are unavailable, continue within the source
   concurrency limit. The primary agent must merge and deduplicate findings and
   verify primary-source evidence itself.
3. Correlate advisories with the selected inventory scope: packages, runtimes,
   frontend/backend, databases, web servers, operating systems, containers,
   virtualization, CI/CD, IaC, appliances, and supply chain. When the launcher
   supplies an `output/analysis-runs/*/plan.json`, treat it as the authoritative
   boundary and routing plan. `preferred_ai: codex` or `claude` routes the
   project to that CLI; `null` routes it to the coordinator selected at launch.
   Other-provider phases are read-only and return a dossier. Only the
   coordinator may merge dossiers, deduplicate findings, and update canonical
   reports. Stop without updating reports if a required evidence phase fails.
   When the plan contains `technology_scope`, `baseline_scan`,
   `baseline_windows`, `run_kind`, and `source_windows`, treat them as
   authoritative. Historical initialization is limited to selected baseline
   combinations and starts at each exact version's official release date;
   package dependencies use their exact version, while runtimes, databases,
   operating systems, and similar platforms start at the applicable release
   line recorded in `baseline_version`;
   `source_windows` independently bound the incremental portion of a hybrid
   run. Ordinary applicability analysis
   is limited to current inventoried versions. Ignore advisories whose affected
   ranges cannot include the current version. Unknown versions require a
   generic low-confidence scan and an explicit human-review limitation.
4. Open every candidate advisory and collect its identifier/CVE, affected and fixed versions, prerequisites, vector, mitigations, and date. Confirm through primary sources in this order: vendor, official project, CVE record. Treat aggregators as signals, not sole evidence. When the launcher supplies `candidate-intake.json`, treat it as immutable: preserve every candidate ID and exact advisory/source/CVE identifier in the ledger and staged reports. Do not invent correspondence scores; the launcher calculates them deterministically and presentation thresholds never remove candidates.
5. Check manifests and lockfiles and, when possible without mutation, installed versions. Always distinguish presence, declared version, verified installed version, and production. Never infer production from local development.
   Treat `manual_technologies` in the local inventory as user-declared scope
   hints; verify their actual use and version before claiming applicability.
   Treat `production_technologies` as separate, environment-specific scope.
   Preserve their evidence type, evidence note, and UTC verification time;
   distinguish administrator confirmation and authorized checks from unverified
   reports. Analyze every distinct inventory and production version without
   inferring that either represents the other. Treat every populated version as
   the applicability value regardless of its informational confidence/status;
   a user status override is GUI-only, is excluded from the routed plan, and
   does not change the version used for matching.
6. If `osv-scanner` or `trivy` is available, use it read-only on relevant targets and record the command, version, and summary. If missing, run the validator and show the suggested Linux commands, making clear that execution requires review and explicit authorization; read [references/linux-tool-installation.md](references/linux-tool-installation.md) when explaining alternatives. Do not install tools or update databases/caches without an explicit request, and do not treat an automated finding as proven applicability.
7. Evaluate actual API use, reachability, configuration, and mitigations. Classify each item as `immediate-action`, `follow-up`, `monitor`, or `not-applicable`, with risk and confidence.
8. Review open activities in the current local follow-up and current closed-issue
   archive. Do not reopen an activity recorded as externally resolved without
   new evidence. After a report reset, do not recover old activities, IDs, or
   closure decisions from reset snapshots; rebuild current records only from
   new evidence. Keep vulnerability closure, mitigations, runtime migrations,
   and other remediation work as separate activities when their evidence or
   completion criteria differ.

## Output

Read [references/report-format.md](references/report-format.md) before writing. Use English and UTC. If the daily file exists, extend it without losing evidence. Update in this order:

1. `output/daily-advisory-check/YYYY-MM-DD.md`;
2. `output/check-summary.md` with current status and a short history entry;
3. `output/followup.md`, preserving stable IDs, dates, closure evidence, and a
   primary `Source URL` when one is known.
4. Run `./fairy-security-advisory --action archive-followups` so completed,
   externally closed, resolved, and non-applicable rows move into the configured
   year/month archive only after the active follow-up has been updated.

Repeat all unfinished activities in the daily report. Do not mark a vulnerability resolved merely because a mitigation exists. Always list unperformed checks, residual risk, confidence, and changes made.
Label initialization sections `Initialization baseline`; keep them in the same
daily report format used by incremental checks. Report fixed versions as
recommendations only and never write them back to inventory.
For every selected baseline key, include the exact machine-readable marker
required by the routed plan. Write the routed run's `evidence-state.json`
receipt with one status for every selected baseline and every active source.
Never mark a source complete from reachability alone; partial or failed source
coverage must not advance its checkpoint.
For every completed baseline receipt, record `baseline_version`, `release_date`,
`release_source_url`, `searched_since`, and `searched_until`. Use `partial` when the official release date or complete
historical interval cannot be verified.

## Constraints

- Do not modify, format, update, or install anything in scanned projects; do not run tests that write data or start services.
- Do not deploy, push, commit, create issues, or perform other remote writes.
- Do not disclose secrets, credentials, tokens, private addresses, or sensitive configuration contents.
- Keep every environment-derived report, finding, path, version, project
  identifier, and follow-up record below the Git-ignored `output/` directory or
  in `config/local/projects.yaml`; never copy it into versioned files.
- In routed mode, do not broaden the plan scope. Evidence agents must not write
  files or invoke scanners; the coordinator may run scanners only on selected
  paths and is the sole writer of canonical output.
- Request authorization before checking servers or production.
- If a source is unavailable, record the limitation; never invent missing data.
