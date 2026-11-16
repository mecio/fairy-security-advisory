# fAIry Security Advisory — Desktop user guide

This guide describes the local desktop application and the purpose of every
main screen. fAIry Security Advisory helps correlate public security notices
with the technologies and dependency evidence found in locally configured
projects. It is an analysis and follow-up tool: it does not patch applications,
upgrade dependencies, deploy software, or assert that a production system is
safe without supporting evidence.

The desktop interface is a native local application. It does not start a web
server, reserve a TCP port, or require Docker. Configuration derived from the
computer, technology inventories, security reports, conversations, and backups
remain in Git-ignored local directories.

## Contents

- [Starting the application](#starting-the-application)
- [Dashboard](#dashboard)
- [Configuration](#configuration)
- [Technology inventory](#technology-inventory)
- [Reports and follow-up](#reports-and-follow-up)
- [Analysis logs](#analysis-logs)
- [AI issue assistant](#ai-issue-assistant)
- [Running security checks](#running-security-checks)
- [System status and AI authentication](#system-status-and-ai-authentication)
- [Configuration backups](#configuration-backups)
- [About, version, and license](#about-version-and-license)
- [Privacy and local data](#privacy-and-local-data)
- [Troubleshooting](#troubleshooting)

## Starting the application

From the project root, run:

```bash
./fairy-security-advisory --gui
```

The launcher checks whether the project virtual environment and desktop
dependencies are available. On first use it can offer to create the isolated
`.venv` and install the required PySide6 packages after confirmation. This
environment belongs only to fAIry and does not modify Python environments in
the projects being scanned. The same desktop action is also available from the
interactive command-line menu.

On Linux, install a per-user application-menu shortcut and the square fAIry
icon with menu option 17 or:

```bash
./fairy-security-advisory --action desktop-install
```

No administrator privileges are required. The launcher is written below the
user's XDG application-data directory and starts this checkout with `--gui`.
Menu option 18, or `--action desktop-remove`, removes only that shortcut and its
installed icon; it does not remove the project or local configuration.

On a new installation, the recommended workflow is:

1. Open **Configuration** and initialize the local configuration.
2. Review the local project roots and exclusion rules.
3. Refresh the technology inventory.
4. Check **System status** and authenticate at least one supported AI CLI.
5. Optionally install OSV-Scanner and Trivy after reviewing the displayed
   commands.
6. Open **Run check**, verify prerequisites and advisory sources, then start a
   complete analysis.
7. Review the generated report and follow-up activities before taking action.

Closing the window does not modify scanned projects. If an analysis process is
still running, the application asks for confirmation before closing so that it
is not stopped accidentally.

## Dashboard

The Dashboard is the operational overview. It derives its values from the
ignored local reports and follow-up records; it does not contact advisory
sources or an AI provider merely to display the page.

The headline counters have the following meaning:

- **Open activities** counts follow-up work that is not completed, externally
  closed, or otherwise archived.
- **Found today** counts activities associated with the current UTC date.
- **Found this month** gives a broader view of recent findings, including work
  that may already have been completed.
- **Projects involved** counts distinct project names represented by the
  available activity history.

The charts group the same local evidence by priority, current status, project,
and technologies mentioned in the latest daily report. Different colors make
categories easier to compare; bar length is relative to the largest value in
that chart. Archived follow-up entries remain useful for historical statistics
even though they no longer clutter the active follow-up table.

Use **Refresh dashboard** after changing reports outside the GUI or completing
an operation in another terminal. **Open Run check** moves directly to the page
where deterministic checks and AI-assisted analysis can be started. A zero
counter means no matching local records were found; it does not by itself prove
that the scanned environment has no vulnerabilities.

## Configuration

Configuration is divided into public factory defaults and private local
overrides. Files directly under `config/` are safe templates distributed with
the project. Personal paths, preferences, and discovered inventory are written
under `config/local/`, which is ignored by Git. At runtime the local file takes
precedence over the corresponding factory file.

The page offers two editing modes:

- **Simple** presents guided fields, tables, selectors, and validation suitable
  for normal use.
- **Advanced YAML** exposes every field, including extension fields that are not
  represented in the guided form.

Switching from Simple mode to Advanced YAML merges the guided values into the
document while preserving unknown fields. A structured save may normalize YAML
formatting or remove comments, so use Advanced YAML when comments or exact
layout are important. Every GUI save is validated and written atomically: a
temporary file is completed first and then replaces the destination.

The action buttons below the page change according to the active tab. This
keeps destructive or unrelated actions away from sections where they do not
apply. Green buttons save or create recoverable data, red buttons restore or
remove data, yellow buttons initialize or install something, and neutral
buttons validate, reload, or navigate.

### Developer tools

Enable **Developer tools** only when maintaining or preparing fAIry itself for
publication. This preference is saved in the ignored local application
configuration, so enabling it does not alter the defaults seen by other users.
When the option is disabled, maintainer-specific commands such as
**Pre-publication check** remain hidden from the Run check page.

Developer tools do not grant additional operating-system permissions and do
not change the read-only rule applied to scanned projects. They only reveal
maintenance actions that would otherwise distract normal users.

### Local projects

This section defines where inventory discovery is allowed to look.

- **Add directory** creates another enabled scan root.
- **Browse** opens the native directory chooser and avoids manual path entry.
- **Remove** deletes the selected root from fAIry configuration; it never
  deletes that directory from disk.
- **Enabled** temporarily includes or excludes a root without losing its
  settings.
- Double-click **Exclusions** to edit one glob rule per line.

Exclusion rules are applied both while discovering projects and while
inspecting project files. Typical exclusions include `.git`, dependency trees,
virtual environments, caches, generated build output, vendor directories, and
other material that would create duplicate or misleading evidence. Excluding a
directory means fAIry will not use it as evidence, so review custom exclusions
carefully.

**Refresh inventory after (hours)** determines when an inventory is considered
stale. **Maximum files per project** bounds discovery work in unusually large
trees. Saving scan-root settings preserves the already detected inventory; use
the Inventory page when an immediate rescan is desired.

### Advisory sources

This section defines the public bulletins, feeds, APIs, and repositories that
can contribute candidate advisories.

Use **Add advisory source** to create a source and **Edit** to change the
selected entry. Each source records a human-readable name, stable identifier,
URL, transport type, optional category or filter, relevant technologies,
priority, and active state. The stable identifier should not change after
reports begin referring to it.

The supported types are HTML, RSS, Atom, JSON, API, and repository. A source's
technology list is a routing hint, not proof that an advisory applies to a
project. fAIry must still inspect the individual notice, affected versions,
fixed versions, prerequisites, and local dependency evidence. **Open** launches
the public URL in the system browser so the source can be reviewed manually.
Disabling a source keeps its configuration but omits it from subsequent source
checks.

### Reports

Report settings control where ignored local output is written and how it is
classified. The default timezone is UTC so reports remain comparable across
machines. The language setting controls generated narrative where supported;
it does not translate advisory source content automatically.

Output paths should remain below `output/`. The section also defines evidence
retention, accepted risk levels, and applicability decisions. Keeping unfinished
activities in subsequent reports ensures that an open remediation does not
disappear simply because the original advisory was found on a previous day.
Evidence retention prevents later checks from silently discarding useful
technical observations.

### Backups

Backup settings define the local archive directory, filename prefix, checksum
behavior, and configuration files included in an archive. The destination
should remain below ignored `output/` storage because a backup can contain real
local paths and other environment-derived information.

**Back up configurations** creates a timestamped archive. **Import backup** is
intentionally styled as a potentially destructive action because it can replace
current local settings; the import workflow validates the archive and creates a
safety backup before doing so. More detail is available in the Configuration
backups section of this guide.

### AI agents

AI agent settings separate model capability from execution concurrency.

Model profiles select the aliases used for Codex and Claude. The economical
profile is the default for routine checks, while balanced and thorough profiles
can be chosen when the evidence is ambiguous or additional reasoning is worth
the higher consumption. Changing a model alias affects future launches only.

Execution modes control source concurrency and whether bounded source-analysis
sub-agents may be used. Economical mode processes work sequentially and avoids
sub-agents. Faster modes may reduce elapsed time but can increase token use and
the number of simultaneous network requests. The maximum sub-agent setting is
an upper bound, not a guarantee that every run will create that many agents.

### AI Codex and AI Claude

The provider-specific tabs show whether the corresponding command-line agent is
installed and authenticated. They deliberately delegate credential handling to
the official CLI:

- **Install** appears when the executable is missing and opens a reviewed
  installation command only after confirmation.
- **Log in** appears when the CLI exists but has no usable authenticated
  session. Authentication continues in a visible terminal or browser flow.
- **Refresh status and usage** repeats the non-secret status checks after an
  installation or login has completed.

fAIry stores neither passwords nor access tokens. The provider CLI owns its
credential files and authentication lifecycle.

For Codex on Linux, **Install** uses OpenAI's standalone installer and creates a
stable user command at `~/.local/bin/codex`; Node.js and npm are not required.
The installer runs with prompts disabled, which means it never accepts an offer
to uninstall a Codex copy managed by an IDE or another package manager. fAIry
explicitly prefers the standalone user command when it exists. PhpStorm, VS
Code, and other IDE integrations can therefore continue using their own bundled
executables without being overwritten. If only an IDE-bundled command is
visible, fAIry can use it in that inherited session, but a desktop-menu launch
may still require the standalone user installation.

For Claude Code on Linux, **Install** uses Anthropic's recommended native
installer. It creates `~/.local/bin/claude` as a launcher for versioned binaries
under `~/.local/share/claude/versions/`, requires neither Node.js nor npm, and
does not remove IDE-managed executables. fAIry applies the same resolution rule:
the stable user launcher is preferred when present, while a bundled IDE command
remains usable within sessions that expose it through `PATH`.

These tabs also show aggregate measurements for complete, non-interactive
analyses launched through fAIry. The ignored
`output/ai-usage/events.jsonl` history records provider, selected model and
profile, duration, exit status, aggregate token totals, and any cost reported
by the CLI. It does not include arbitrary Codex or Claude sessions started from
another project, and it currently does not count conversations in the AI issue
assistant.

When supported by the installed Codex version, fAIry asks the authenticated
local Codex app-server for the remaining allowance and reset time. If that
interface is unavailable, the GUI reports the value as unavailable rather than
guessing. Claude Code exposes plan information through its interactive
`/usage` command, so open Claude Code and run `/usage` for the provider-wide
subscription remainder.

### Configuration actions

- **Initialize local configuration** copies all factory documents into the
  ignored local configuration directory without publishing personal values.
- **Reload** discards unsaved editor changes and rereads the effective file.
- **Validate settings** checks the active guided form; **Validate YAML** parses
  and checks the advanced document.
- **Save settings** or **Save current file** asks for confirmation before
  replacing the selected local override.
- **Restore factory defaults…** creates a complete safety backup and then
  replaces only the active local section with its versioned public factory
  file. Restoring Local projects also clears its detected inventory, which must
  be refreshed before the next analysis.
- **Run full validation** checks relationships across configuration files and
  reports missing optional scanners.
- **Back up configurations** creates a private local ZIP with integrity data.
- **Import backup** validates and restores a selected archive after creating a
  safety backup.

## Technology inventory

The Technology inventory page shows the structured inventory stored in local
configuration. Each row identifies a detected project, its probable roles, and
technologies supported by file, manifest, lockfile, or configuration evidence.
Roles such as frontend, backend, infrastructure, or mixed are classification
aids rather than access permissions. Technical discovery fields are read-only;
only the local advisory selection and AI preference can be changed here.

Use the checkbox in **Check** to decide whether a project belongs to the active
advisory-analysis scope. A cleared checkbox excludes that project from advisory
correlation, manifest and lockfile inspection, OSV-Scanner and Trivy targets,
new findings, and new follow-up activities. It remains visible and refreshable
in the inventory so that it can be selected again later.

**Preferred AI** accepts **-**, **Codex**, or **Claude**. The default **-** uses
the coordinator selected in Run check. An explicit Codex or Claude choice
routes that project to the matching CLI and to that provider's model in the
selected profile. Click **Save project choices** to write these choices to
ignored local configuration.

The inventory can include languages and versions, frameworks, runtimes,
package manifests, lockfiles, databases, web servers, reverse proxies,
containers, operating systems, CI/CD definitions, Infrastructure as Code, and
virtualization components when recognizable evidence exists. Absence from the
table means the detector did not find sufficient evidence; it does not prove a
technology is absent from production.

Use **Refresh inventory from configured paths** after adding a project,
changing exclusions, or making significant dependency changes. The refresh:

1. reads enabled project roots and their exclusion rules;
2. discovers Git repositories and eligible non-versioned projects;
3. inspects relevant files without modifying them;
4. writes the resulting structured inventory only to ignored local
   configuration.

Refreshing preserves saved project checkboxes and preferred-AI choices for
projects that are detected at the same path. Newly discovered projects are
selected by default and use **-** as their AI preference.

The scanner does not update dependencies, run project installers, or rewrite
manifests. Paths shown here are local operational data and must not be copied
into public example configuration or committed to Git.

## Reports and follow-up

This page combines rendered Markdown output with actionable follow-up work. The
left-hand list places **Follow-up** first because unresolved activities require
attention more often than historical reports. Other entries include the current
summary, the daily report for each available date, and year/month archives of
closed work.

Daily reports document the time of the check, consulted sources, involved
projects and technologies, relevant and excluded advisories, risk assessment,
evidence, recommended actions, open work, and incomplete controls. The current
summary provides a shorter operational view and check history. Both are
rendered read-only in the desktop interface; deterministic processes update the
underlying ignored Markdown files.

### Active follow-up

The active table shows one stable activity per row. Important columns include
the issue identifier, advisory or CVE, affected project, description, priority,
owner, state, dates, next action, deadline, and completion evidence. Hover over
shortened cells to read their full value.

The activity/advisory cell includes the configured primary-source link below
the identifier. When no source URL is recorded, recognized CVE identifiers link
to their official CVE records. Opening a link launches the system browser and
does not change the activity.

Available actions are deliberately tied to the stable issue ID:

- **Set as solved** asks for completion evidence, confirms the exact ID and
  project, marks the activity Completed, and moves it to the appropriate
  year/month archive. A mitigation or accepted risk should not be recorded as a
  completed patch unless the evidence supports that conclusion.
- **AI chat** opens the selected activity in the assistant and prepares a
  remediation-oriented question. The assistant can propose changes but cannot
  apply them without confirmation.

Activities that still require work or verification remain in active follow-up
and are repeated in later daily reports. Closed rows are catalogued under
`Archive · YYYY / MM`, keeping the current table manageable without losing
historical evidence.

## Analysis logs

The **Logs** page presents completed and failed analysis runs as an archive tree
organized by year, month, and run. New runs are stored physically below
`output/analysis-runs/YYYY/MM/<run-id>/`; legacy flat run directories remain
readable. Selecting a run opens `run-summary.txt` first. Use the file selector
to inspect its chronological `run.log`, routing `plan.json`, coordinator output,
and provider evidence dossiers.

**Delete selected run…** permanently removes only the selected run directory
after confirmation. This includes its summary, log, plan, coordinator output,
and evidence dossiers. It does not remove daily reports, follow-up activities,
configuration, or scanned projects. Empty year and month directories are
cleaned up automatically. Log archives remain local and Git-ignored.

## AI issue assistant

The AI issue assistant provides a focused conversation about one existing open
follow-up activity. It is intended for questions such as how to validate
applicability, what evidence is still missing, which remediation order is
safest, who has taken ownership, or why an advisory is not relevant to a
specific project.

Before sending a message:

1. select the open activity;
2. select an authenticated Codex or Claude provider;
3. choose the appropriate model profile;
4. review the issue context shown by the interface.

The affected project is displayed first in a dedicated, high-contrast heading.
The activity ID, advisory/CVE, priority, status, owner, and next action remain in
a separate context block, reducing the risk of discussing or updating the wrong
project when several open activities have similar identifiers.

The prompt contains the selected stable ID, project, advisory/CVE, priority,
owner, status, next action, and recent local conversation history. It does not
automatically provide every file from the affected project. The agent may use
the supplied evidence and read-only project context when available, but its
answer remains advice until supported and confirmed.

Guided prompts help record ownership, discuss resolution evidence, or explain
non-applicability. The AI runs with read-only or planning permissions. If it
detects a clear management update, it may propose one of the restricted actions
`take_ownership`, `resolve`, `not_applicable`, or `update`.

**Review proposed issue update** displays the exact fields before anything is
written. A separate confirmation is required, and the deterministic updater
changes only the selected stable ID. Resolution requires completion evidence;
non-applicability requires a technical rationale or evidence. Production is not
considered fixed merely because an AI recommends a patch or a mitigation.

Conversation history stays under `output/ai-conversations/` and is excluded
from Git. Issue context and user messages are sent to the selected external AI
provider, so never enter passwords, API keys, tokens, customer data, or other
secrets in the chat.

## Running security checks

The Run security checks page contains deterministic preparation commands and
the complete AI-assisted workflow. Choose an AI provider, model profile, and
execution mode before starting the full analysis.

### Check prerequisites

**Check prerequisites** verifies that required commands, agent authentication,
configured project roots, and local inventory are usable. OSV-Scanner and Trivy
are optional: when absent, fAIry reports the limitation and displays reviewed
Linux installation commands but never installs them automatically during a
security check.

A failed prerequisite prevents the complete analysis from starting. Correct
the reported item, refresh inventory or authentication when appropriate, and
run the check again.

### Check sources

**Check sources** performs lightweight reachability checks against active
advisory sources. It uses the configured request method, including POST where
an API requires it, and respects the selected concurrency mode. Success means a
source answered the configured request; it does not certify the completeness or
accuracy of that source.

This action accesses the network but does not invoke the AI agent and does not
modify scanned projects.

### Run complete AI analysis

**Run complete AI analysis** starts the shared security-advisory skill through
the selected authenticated CLI. Before launch, fAIry validates configuration,
refreshes stale inventory when confirmed, checks prerequisites, and tests source
reachability. The agent is started from the fAIry project root so it receives
the project instructions, skill, effective local configuration, inventory,
reports, and follow-up context.

The selected agent is the **coordinator**. Projects with **-** use that agent;
projects explicitly assigned to Codex or Claude use the corresponding CLI and
the matching model in the selected profile. The confirmation dialog shows the
project count for each provider, excluded projects, and models before anything
starts. Every required CLI must be installed and authenticated.

An additional provider runs first in read-only evidence mode and stores its
private dossier under `output/analysis-runs/`. It cannot update canonical
reports or run scanners. The coordinator analyzes its own group, consumes and
verifies those dossiers, deduplicates findings, and performs the only canonical
report update. A failed evidence phase stops the run before consolidation.

Every started run has a private audit directory below `output/analysis-runs/`.
Open `run-summary.txt` for a simple one-field-per-line overview of who ran the
analysis, which AI providers and models were used, project counts, timestamps,
phase outcomes, and exit code. `run.log` contains chronological phase events;
`coordinator-output.md` retains the coordinator's final visible response.
Credentials and provider account e-mail addresses are not logged.

The complete workflow asks the agent to:

1. review configured advisory sources;
2. correlate candidates with the detected stack;
3. prefer primary vendor, project, and CVE evidence;
4. inspect relevant manifests and lockfiles;
5. use OSV-Scanner and Trivy when already installed;
6. assess actual applicability rather than matching names alone;
7. carry unresolved follow-up work forward;
8. update the daily report, current summary, and follow-up records.

The selected profile determines the model. The selected execution mode controls
parallel source work and sub-agent limits. Economical is the default for both
because it reduces consumption and makes routine checks easier to repeat.

The output pane streams progress and the final exit code. A successful process
exit indicates that the command completed, not that every advisory was resolved;
review the report's limitations and incomplete controls. **Clear log** removes
only the visible process text from the widget.

**Stop** first requests graceful process termination. If the process does not
exit promptly, the desktop application may force it to stop. A stopped run can
leave a partial report, so validate output before relying on it.

### Pre-publication check

**Pre-publication check** is a maintainer function and appears only when
Developer tools is enabled. It validates the fAIry repository itself before
public distribution, including documentation, public configuration, local-data
separation, and other project invariants. It is not part of normal advisory
analysis and does not assess the configured application projects.

## System status and AI authentication

System status summarizes dependencies and local readiness in one table. The
possible states are:

- **Ready**: the component or local data is available for use.
- **Missing**: a required executable was not found.
- **Optional**: an optional scanner is absent; analysis can continue with a
  documented limitation.
- **Login required**: an AI CLI exists but is not authenticated.
- **Not created**: local configuration or inventory still needs initialization.

The Details column shows non-secret diagnostic information such as executable
location, inventory age, or local configuration path. The Action column offers
only operations relevant to the current state.

On Linux, the **Linux desktop launcher** row reports whether fAIry is registered
in the current user's application menu. **Install** creates the same launcher
and square icon as CLI action `desktop-install`; once installed, the action
changes to the red **Remove** button. Removing it affects only the per-user menu
entry and copied icon, not the project, configuration, reports, or backups.

**Install** displays the reviewed command and asks before opening it in a
terminal. The terminal remains visible so package-manager messages, password
prompts, and failures are not hidden. **Log in** similarly opens `codex login`
or `claude auth login`; browser or device authorization remains entirely under
provider control. After the external operation, return to fAIry and refresh the
status.

fAIry checks only whether authentication is usable. It does not copy provider
credential files into its configuration, backups, reports, or usage history.

## Configuration backups

Configuration backups protect private local settings before substantial edits
or restoration. By default, archives are timestamped ZIP files under
`output/config-backups/`. Each archive contains a manifest describing declared
members and their hashes; an optional SHA-256 sidecar protects the archive as a
whole.

Creating a backup includes only the configured local files. It does not back up
the scanned projects, complete report history, provider credentials, virtual
environment, or Git repository.

The Configuration page also uses this backup service before every
**Restore factory defaults…** operation. Factory restore is intentionally
section-specific: it does not reset unrelated local configuration files, and
the generated safety archive can be imported if the previous values are needed.

Import performs several checks before replacing anything:

- archive members must remain inside the expected configuration hierarchy;
- undeclared or oversized files are rejected;
- manifest hashes must match;
- the optional archive checksum must match;
- restored configuration must be valid YAML;
- a safety backup of the current configuration is created first.

Choose the archive carefully and review the confirmation message. Restoring a
backup may reintroduce project paths that do not exist on the current machine.
Run full validation and refresh inventory after importing a backup from another
installation.

Backups are private but not encrypted. Anyone who can read the ZIP may be able
to see local paths, source preferences, and detected environment information.
Store or transfer them accordingly.

## About, version, and license

The About page presents the project banner and metadata loaded from
`VERSION.yaml`, including name, version, author, last-modified year, and license.
The footer repeats the current version and the `AGPL-3.0-or-later` identifier so
the running build can be identified from every page.

The displayed license applies to the project source code and distribution. The
software is provided without warranty; users remain responsible for validating
findings, protecting local data, and deciding whether and how to apply security
changes.

## Privacy and local data

The following directories are intentionally excluded from Git:

- `config/local/` contains effective private overrides and discovered
  inventory;
- `output/` contains reports, follow-up, conversations, usage measurements,
  archives, migration material, and configuration backups.

These files can reveal local paths, software versions, infrastructure details,
security findings, assigned responsibilities, remediation evidence, and user
conversations. Git exclusion prevents accidental publication through this
repository, but it is not encryption or an operating-system access control.
Protect filesystem permissions and backups separately.

The desktop application starts no listening server and uploads no backup.
Network access occurs when checking configured advisory sources, opening public
links, authenticating provider CLIs, or deliberately running an external AI
analysis or issue-assistant conversation. Scanned projects are read-only unless
the user separately performs a remediation outside this workflow.

Before sharing a screenshot, report, log, or backup, inspect it for local paths,
project names, versions, security findings, email addresses, and other private
context.

## Troubleshooting

### The GUI does not start

Run the root launcher again and accept installation of the isolated desktop
dependencies. Check the terminal for a missing Python, virtual-environment, or
PySide6 error. The launcher should be used from the project root so relative
assets and configuration are resolved consistently.

### Configuration cannot be saved

Use **Validate settings** in Simple mode or **Validate YAML** in Advanced mode.
Then run **Run full validation** to detect cross-file problems. If a guided form
contains unsaved changes, save or reload it before switching sections. Create a
configuration backup before correcting a large document manually.

### Inventory is empty or incomplete

Confirm that at least one project root is enabled, exists, and is readable.
Review exclusion rules for patterns that are too broad, then refresh inventory.
Remember that generated dependencies and cache directories may be intentionally
excluded and that production-only components require external evidence.

### An advisory source fails

Use **Open** in Advisory sources to check the URL manually. Confirm the source
type and required request method, then retry **Check sources**. Authentication-
protected or anti-automation pages may require a different public feed or API.
Record persistent limitations in the daily report rather than silently treating
the source as checked.

### Codex or Claude cannot run

Open **System status** or the provider's Configuration tab. Install the missing
CLI or complete its official login flow, then refresh status and usage. If the
CLI works in a terminal but not in fAIry, verify that the GUI process inherits a
`PATH` containing the executable.

Provider allowance and authentication are different checks. An authenticated
CLI can still be unavailable because its usage limit has been reached. Codex
allowance may appear directly in the GUI; for Claude Code, run `/usage` in an
interactive Claude session.

### A scanner is missing

OSV-Scanner and Trivy are optional. Review and copy the Linux installation
command shown by fAIry, or continue without the scanner and retain the reported
analysis limitation. fAIry never installs these tools automatically during a
security check. On Linux x86_64 and arm64, the OSV-Scanner action downloads the
official precompiled release, verifies its published SHA-256 checksum, and
installs it under `~/.local/bin` without `sudo` or a Go toolchain. On other
architectures, fAIry validates the Go prerequisite and blocks execution when
the toolchain is missing or incompatible.

### A report looks incomplete

Inspect the process exit code and the report's limitations section. A stopped
agent, unreachable source, missing scanner, stale inventory, or exhausted AI
allowance can all reduce coverage. Correct the condition and rerun the check;
when updating an existing daily report, preserve earlier evidence instead of
replacing it with an unsupported conclusion.

### A restored backup behaves unexpectedly

Run full validation, confirm the restored paths exist on this computer, and
refresh inventory. If necessary, use the safety backup created immediately
before import to recover the previous local configuration.
