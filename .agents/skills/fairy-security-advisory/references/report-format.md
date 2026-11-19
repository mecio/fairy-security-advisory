# Output format

All maintained output is written below the Git-ignored `output/` directory, in
English, and all timestamps use UTC. Do not copy environment-derived content
into versioned files.

## Daily report

Use these sections, adapting them without removing historical evidence:

1. `Check metadata`: date/time, UTC timezone, interval, mode, and author.
2. `Sources checked`: URL, type, outcome, and time; distinguish checked, unavailable, and incomplete.
3. `Projects and technologies involved`: only relevant items, with non-sensitive paths or identifiers.
4. `Relevant advisories`: risk, CVE/advisory, affected/fixed versions, prerequisites, evidence, applicability, decision, and confidence.
5. `Excluded advisories`: identifier and verifiable rationale.
6. `Open follow-up activities`: ID, issue title, project, priority, status, and next action for every unfinished activity.
7. `Recommended actions`: owner and urgency, without applying changes.
8. `Limitations and residual risk`: unverified production, missing sources/tools, and declared-versus-installed version gaps.
9. `Changes made`: normally reports, summary, follow-up, and local inventory only.

For an initialization or hybrid run, title the historical subsection
`Initialization baseline` and list every selected canonical technology/version combination,
including partial generic scans for missing versions. For incremental runs,
record the per-source covered interval and configured overlap. Never present an
inventory quality color as a security risk rating.
Each selected initialization entry must include the exact line
``- Technology key: `<key>` — ...`` so deterministic validation can reject an
incomplete baseline report.
The corresponding machine receipt marks a baseline `completed` only when it
includes `baseline_version`, the official `release_date`, an HTTPS
`release_source_url`, and an actual `searched_since` through `searched_until`
interval covering that release through the run date.

Cite sources close to supported claims. Do not copy long passages.
Give each finding and follow-up activity a concise, searchable `Issue title`
that names the affected component and the security problem. Include a
well-established public advisory name, such as PHP2Shell, only when a source
uses it; otherwise use a descriptive title without presenting it as an official
name. Keep CVE/advisory IDs and primary-source links in separate fields so
users can verify the issue by title or identifier. The title never replaces
the IDs or evidence.
For routed checks, include one line ``- Project: `<id>` — ...`` under the newest
`Projects and technologies involved` heading for **every** selected project,
including other-provider dossier projects and projects with no confirmed
finding. State its evidence, disposition, and limits. The launcher checks these
lines before declaring the run complete.

## Summary

`output/check-summary.md` contains `Current status` with a few bullets and `History`
with one subsection per date and a report link. Do not duplicate the full report.

## Follow-up

The `output/followup.md` table contains at least: stable ID, Issue title,
Advisory / CVE, Project,
Description, Priority, Owner, Status, Opened, Last updated, Next action, Due date,
and Completion evidence. Add the optional `Source URL` column when a primary
advisory URL is known. Use either a raw HTTPS URL or a Markdown link such as
`[Vendor advisory](https://example.invalid/advisory)`. The desktop interface
uses that source and otherwise links recognized CVE identifiers to their
official CVE records.

Use one row for one consolidated issue or remediation activity. When it affects
multiple projects, put every distinct project ID in that row's `Project` cell,
separated by semicolons (for example, `api; worker`); do not duplicate the row
only to name another affected project. Keep separate rows only when the work,
evidence, owner, status, or completion criteria are genuinely different.

An administrator confirmation may produce `Externally closed`, but it must state
that this project did not independently verify production. A mitigation normally
produces `Monitor` or `Completed in code`, not production vulnerability closure.
