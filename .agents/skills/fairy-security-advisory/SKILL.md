---
name: fairy-security-advisory
description: Run AI-assisted periodic security advisory checks by correlating public sources, local inventory, manifests, lockfiles, and follow-up records without modifying scanned projects. Use for complete checks or for updating this repository's security reports and activities.
---

# fAIry Security Advisory

Run a repeatable, evidence-based, read-only check against inventoried projects. Write only to local configuration and outputs in this repository.

## Start

1. Locate the repository root from the skill directory and read `AGENTS.md`,
   the effective configuration, preferring files under `config/local/` and
   falling back to the versioned factory files in `config/`,
   `output/followup.md`, archived follow-ups under
   `output/followup-archive/YYYY/MM.md` when present, and the latest daily report under
   `output/daily-advisory-check/` in full. If `output/report-resets/` contains
   snapshots, consult their follow-up and closed-issue archives, newest first,
   for historical status evidence. Their files are not current findings.
   If the local project configuration is missing, explain how to copy
   `config/projects.example.yaml` as documented
   in the README; never invent local paths.
2. Before analyzing a project, read its `AGENTS.md` and referenced directives relevant to version, dependency, and infrastructure scanning.
3. Validate configuration with `python3 scripts/validate_project.py --config-dir config`. If `inventory.projects` in `config/local/projects.yaml` is empty or older than `refresh_after_hours`, run `python3 scripts/inventory.py --config-dir config`.
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
4. Open every candidate advisory and collect its identifier/CVE, affected and fixed versions, prerequisites, vector, mitigations, and date. Confirm through primary sources in this order: vendor, official project, CVE record. Treat aggregators as signals, not sole evidence.
5. Check manifests and lockfiles and, when possible without mutation, installed versions. Always distinguish presence, declared version, verified installed version, and production. Never infer production from local development.
   Treat `manual_technologies` in the local inventory as user-declared scope
   hints; verify their actual use and version before claiming applicability.
6. If `osv-scanner` or `trivy` is available, use it read-only on relevant targets and record the command, version, and summary. If missing, run the validator and show the suggested Linux commands, making clear that execution requires review and explicit authorization; read [references/linux-tool-installation.md](references/linux-tool-installation.md) when explaining alternatives. Do not install tools or update databases/caches without an explicit request, and do not treat an automated finding as proven applicability.
7. Evaluate actual API use, reachability, configuration, and mitigations. Classify each item as `immediate-action`, `follow-up`, `monitor`, or `not-applicable`, with risk and confidence.
8. Review open activities in the local follow-up. Do not reopen an activity
   recorded as externally resolved without new evidence. After a report reset,
   carry still-open work into the new follow-up with stable IDs and dates only
   when it remains applicable to selected projects; retain historical closure
   decisions as context rather than new open findings. Keep vulnerability
   closure, mitigations, runtime migrations, and other remediation work as
   separate activities when their evidence or completion criteria differ.

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
