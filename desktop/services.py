# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Framework-independent services used by the desktop interface."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

from scripts.tool_installation import installation_plan, resolve_agent_executable
from scripts.configuration import (
    CONFIG_SPECS, effective_config_path, factory_for_local, initialize_local_overrides,
    restore_local_override,
)
from scripts.followup_archive import archive_closed_followups, is_closed_status
from scripts.config_backup import (
    BackupError, create_configuration_backup, create_factory_restore_backup,
    import_configuration_backup,
    inspect_configuration_backup, latest_configuration_backup,
)
from scripts.ai_usage import codex_rate_limits, summarize_usage
from scripts.desktop_integration import (
    desktop_entry_installed, install_linux_desktop_entry, integration_paths,
    remove_linux_desktop_entry,
)


ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
VERSION_FILE = ROOT / "VERSION.yaml"
LOCAL_CONFIG_DIR = CONFIG_DIR / "local"
LOCAL_CONFIG = LOCAL_CONFIG_DIR / "projects.yaml"
LOCAL_APPLICATION_CONFIG = LOCAL_CONFIG_DIR / "application.yaml"
EXAMPLE_CONFIG = CONFIG_DIR / "projects.example.yaml"
CONFIG_FILES: tuple[tuple[str, Path], ...] = tuple(
    (title, LOCAL_CONFIG_DIR / local_name)
    for title, _factory_name, local_name in CONFIG_SPECS
)


class ConfigurationError(ValueError):
    """Raised when a configuration editor contains invalid YAML or schema."""


def project_metadata() -> dict[str, Any]:
    data = load_yaml(VERSION_FILE)
    return {
        "name": str(data.get("name", "fAIry Security Advisory")),
        "version": str(data.get("version", "unknown")),
        "author": str(data.get("author", "unknown")),
        "last_modified_year": str(data.get("last_modified_year", "unknown")),
        "license": str(data.get("license", "unknown")),
    }


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def validate_config_text(text: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as error:
        raise ConfigurationError(str(error)) from error
    if not isinstance(data, dict):
        raise ConfigurationError("The YAML document must contain a mapping at its root.")
    if data.get("schema_version") != 1:
        raise ConfigurationError("schema_version must be 1.")
    return data


def dump_config_data(data: dict[str, Any]) -> str:
    """Serialize structured form data as stable, human-readable YAML."""
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


def write_config_text(path: Path, text: str, *, private: bool = False) -> None:
    """Validate and atomically replace a project configuration file."""
    validate_config_text(text)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700 if private else 0o755)
    if private:
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text if text.endswith("\n") else f"{text}\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600 if private else 0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def developer_tools_enabled() -> bool:
    data = load_yaml(effective_config_path(CONFIG_DIR, "application.yaml"))
    return bool((data.get("application", {}) or {}).get("developer_tools", False))


def set_developer_tools_enabled(enabled: bool) -> None:
    source = effective_config_path(CONFIG_DIR, "application.yaml")
    data = load_yaml(source)
    data.setdefault("schema_version", 1)
    application = data.setdefault("application", {})
    if not isinstance(application, dict):
        raise ConfigurationError("application must be a YAML mapping.")
    application["developer_tools"] = bool(enabled)
    write_config_text(
        LOCAL_APPLICATION_CONFIG, dump_config_data(data), private=True,
    )


def initialize_local_configuration() -> list[Path]:
    return initialize_local_overrides(CONFIG_DIR)


def restore_factory_configuration(local_path: Path) -> tuple[Path, Path]:
    """Restore one GUI-visible local override from its public factory file."""
    if local_path.parent.resolve() != LOCAL_CONFIG_DIR.resolve():
        raise ConfigurationError("Factory restore is restricted to config/local/ overrides.")
    factory = factory_for_local(CONFIG_DIR, local_path)
    validate_config_text(factory.read_text(encoding="utf-8"))
    return restore_local_override(CONFIG_DIR, local_path.name)


def effective_path_for_local(local_path: Path) -> Path:
    factory = factory_for_local(CONFIG_DIR, local_path)
    return effective_config_path(CONFIG_DIR, factory.name)


def inventory() -> dict[str, Any]:
    return load_yaml(effective_config_path(CONFIG_DIR, "projects.example.yaml")).get("inventory", {})


def inventory_projects() -> list[dict[str, Any]]:
    projects = inventory().get("projects", [])
    return [project for project in projects if isinstance(project, dict)]


def inventory_age() -> str:
    generated_at = inventory().get("generated_at")
    if not generated_at:
        return "not generated"
    try:
        generated = dt.datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
        age = dt.datetime.now(dt.timezone.utc) - generated.astimezone(dt.timezone.utc)
    except (TypeError, ValueError):
        return "invalid timestamp"
    return f"{age.total_seconds() / 3600:.1f} hours old"


def technology_names(project: dict[str, Any]) -> list[str]:
    technologies: set[str] = set()
    for language in project.get("languages", []):
        if isinstance(language, dict) and language.get("name"):
            technologies.add(str(language["name"]))
    for key in (
        "frameworks_and_tooling", "containers", "databases",
        "web_servers_and_proxies", "operating_systems", "ci_cd",
        "infrastructure_as_code", "virtualization_and_services",
    ):
        for value in project.get(key, []):
            if isinstance(value, str):
                technologies.add(value)
            elif isinstance(value, dict):
                name = value.get("name") or value.get("technology")
                if name:
                    technologies.add(str(name))
    return sorted(technologies, key=str.casefold)


def reports_config() -> dict[str, Any]:
    return load_yaml(effective_config_path(CONFIG_DIR, "reports.yaml")).get("reports", {})


def report_entries() -> list[tuple[str, Path]]:
    config = reports_config()
    entries: list[tuple[str, Path]] = []
    summary = ROOT / str(config.get("summary_file", "output/check-summary.md"))
    followup = ROOT / str(config.get("followup_file", "output/followup.md"))
    if followup.is_file():
        entries.append(("Follow-up", followup))
    if summary.is_file():
        entries.append(("Current summary", summary))
    archive_directory = ROOT / str(
        config.get("followup_archive_directory", "output/followup-archive")
    )
    if archive_directory.is_dir():
        for path in sorted(archive_directory.glob("[0-9][0-9][0-9][0-9]/[0-9][0-9].md"), reverse=True):
            entries.append((f"Archive · {path.parent.name} / {path.stem}", path))
    daily = ROOT / str(config.get("daily_directory", "output/daily-advisory-check"))
    if daily.is_dir():
        entries.extend(
            (f"Daily · {path.stem}", path)
            for path in sorted(daily.glob("*.md"), reverse=True)
        )
    return entries


def followup_activities(path: Path | None = None) -> list[dict[str, str]]:
    """Read the Markdown follow-up table without depending on a Markdown parser."""
    followup_path = path or ROOT / str(
        reports_config().get("followup_file", "output/followup.md")
    )
    if not followup_path.is_file():
        return []
    headers: list[str] = []
    activities: list[dict[str, str]] = []
    for line in followup_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        if not headers:
            headers = cells
            continue
        if all(cell and set(cell) <= {"-", ":"} for cell in cells):
            continue
        if len(cells) == len(headers):
            activities.append(dict(zip(headers, cells)))
    return activities


def followup_source_links(activity: dict[str, str]) -> list[tuple[str, str]]:
    """Return safe primary-source links, falling back to official CVE records."""
    configured = activity.get("Source URL", "") or activity.get("Source", "")
    links: list[tuple[str, str]] = []
    if configured:
        markdown_links = re.findall(
            r"\[([^\]]+)\]\((https?://[^\s)]+)\)", configured, flags=re.IGNORECASE,
        )
        if markdown_links:
            links.extend((label.strip(), url) for label, url in markdown_links)
        else:
            urls = re.findall(r"https?://[^\s;,]+", configured, flags=re.IGNORECASE)
            links.extend(("Primary source" if len(urls) == 1 else f"Source {index}", url)
                         for index, url in enumerate(urls, start=1))
    if links:
        return links

    identifiers = dict.fromkeys(re.findall(
        r"\bCVE-\d{4}-\d{4,}\b", activity.get("Advisory / CVE", ""),
        flags=re.IGNORECASE,
    ))
    return [
        (identifier.upper(), f"https://www.cve.org/CVERecord?id={identifier.upper()}")
        for identifier in identifiers
    ]


def open_followup_activities(path: Path | None = None) -> list[dict[str, str]]:
    """Return activities that still require attention or verification."""
    return [
        activity for activity in followup_activities(path)
        if not is_closed_status(activity.get("Status", ""))
    ]


def archived_followup_activities(directory: Path) -> list[dict[str, str]]:
    activities: list[dict[str, str]] = []
    if directory.is_dir():
        for path in sorted(directory.glob("[0-9][0-9][0-9][0-9]/[0-9][0-9].md")):
            activities.extend(followup_activities(path))
    return activities


def _safe_markdown_cell(value: Any) -> str:
    return " ".join(str(value).replace("|", "\\|").split())[:2000]


def update_followup_activity(
    issue_id: str, changes: dict[str, str], *, path: Path | None = None,
    today: dt.date | None = None,
) -> dict[str, str]:
    """Atomically update one exact follow-up row selected by stable issue ID."""
    allowed = {"Owner", "Status", "Next action", "Completion evidence"}
    unknown = set(changes) - allowed
    if unknown:
        raise ConfigurationError(f"Unsupported follow-up fields: {sorted(unknown)}")
    followup_path = path or ROOT / str(
        reports_config().get("followup_file", "output/followup.md")
    )
    if not followup_path.is_file():
        raise ConfigurationError("The local follow-up report does not exist.")
    lines = followup_path.read_text(encoding="utf-8").splitlines()
    headers: list[str] = []
    target_index = -1
    updated: dict[str, str] = {}
    for index, line in enumerate(lines):
        if not line.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        if not headers:
            headers = cells
            continue
        if len(cells) != len(headers) or cells[0] != issue_id:
            continue
        updated = dict(zip(headers, cells))
        for field, value in changes.items():
            updated[field] = _safe_markdown_cell(value)
        updated["Last updated"] = (today or dt.datetime.now(dt.timezone.utc).date()).isoformat()
        lines[index] = "| " + " | ".join(_safe_markdown_cell(updated.get(header, "")) for header in headers) + " |"
        target_index = index
        break
    if target_index < 0:
        raise ConfigurationError(f"Follow-up activity not found: {issue_id}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{followup_path.name}.", suffix=".tmp", dir=followup_path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, followup_path)
    finally:
        temporary.unlink(missing_ok=True)
    return updated


def assistant_history_path(issue_id: str) -> Path:
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", issue_id).strip("-") or "general"
    return ROOT / "output/ai-conversations" / f"{safe_id}.jsonl"


def assistant_history(issue_id: str) -> list[dict[str, str]]:
    path = assistant_history_path(issue_id)
    if not path.is_file():
        return []
    entries: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict) and entry.get("role") in {"user", "assistant"}:
            entries.append({key: str(value) for key, value in entry.items()})
    return entries


def append_assistant_history(issue_id: str, role: str, content: str) -> None:
    if role not in {"user", "assistant"}:
        raise ValueError("Unsupported conversation role.")
    path = assistant_history_path(issue_id)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    entry = json.dumps({
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "role": role,
        "content": content[:50000],
    }, ensure_ascii=False)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(existing)
            handle.write(entry + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def ai_model(provider: str, profile: str) -> str:
    config = load_yaml(effective_config_path(CONFIG_DIR, "ai-agents.yaml"))
    try:
        return str(config["profiles"][profile]["agents"][provider]["model"])
    except (KeyError, TypeError) as error:
        raise ConfigurationError(f"No {provider} model configured for profile {profile}.") from error


def agent_authentication(provider: str, executable: str | None = None) -> bool:
    """Check CLI authentication without exposing account metadata or credentials."""
    command = executable or resolve_agent_executable(provider)
    if not command:
        return False
    arguments = (
        [command, "login", "status"] if provider == "codex"
        else [command, "auth", "status"] if provider == "claude"
        else []
    )
    if not arguments:
        return False
    try:
        result = subprocess.run(
            arguments, cwd=ROOT, check=False, capture_output=True,
            text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    if provider == "claude":
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return True
        return bool(data.get("loggedIn")) if isinstance(data, dict) else False
    return True


def agent_component_status(provider: str) -> tuple[str, str, str]:
    """Return installation and account-authentication status for one AI CLI."""
    executable = resolve_agent_executable(provider)
    authenticated = agent_authentication(provider, executable) if executable else False
    state = "Ready" if authenticated else ("Login required" if executable else "Missing")
    detail = (
        f"{executable}; authenticated" if authenticated else
        f"{executable}; account authentication required" if executable else
        "not installed"
    )
    return provider, state, detail


def _compact_tokens(value: int) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return str(value)


def agent_usage_status(provider: str) -> tuple[str, str]:
    """Return fAIry-local accounting and provider allowance when safely available."""
    summary = summarize_usage(provider)
    local = (
        f"Tracked full checks: {summary['runs']} ({summary['successful_runs']} completed) · "
        f"input {_compact_tokens(summary['input_tokens'])} · "
        f"output {_compact_tokens(summary['output_tokens'])}"
    )
    if summary["cost_usd"]:
        local += f" · reported cost ${summary['cost_usd']:.4f}"
    if provider == "codex":
        executable = resolve_agent_executable("codex")
        snapshot = codex_rate_limits(executable) if executable and agent_authentication("codex", executable) else None
        rate_limits = snapshot.get("rateLimits", {}) if isinstance(snapshot, dict) else {}
        primary = rate_limits.get("primary", {}) if isinstance(rate_limits, dict) else {}
        used = primary.get("usedPercent") if isinstance(primary, dict) else None
        if isinstance(used, int):
            remaining = max(0, 100 - used)
            reset = primary.get("resetsAt")
            reset_text = ""
            if isinstance(reset, int):
                reset_at = dt.datetime.fromtimestamp(reset, dt.timezone.utc)
                reset_text = f" · resets {reset_at.strftime('%Y-%m-%d %H:%M UTC')}"
            return local, f"Codex allowance: {remaining}% remaining{reset_text}"
        return local, "Codex allowance: unavailable from the installed CLI"
    return local, "Claude allowance: open Claude Code and run /usage"


def assistant_prompt(
    issue: dict[str, str], message: str, history: list[dict[str, str]],
) -> str:
    recent = history[-8:]
    return f"""You are the issue assistant for fAIry Security Advisory.
Reply in the user's language. Give concise, evidence-based security guidance.
Never claim that production is fixed without explicit evidence. Distinguish remediation,
mitigation, non-applicability, and risk acceptance. Do not modify any file.

Selected follow-up activity:
{json.dumps(issue, ensure_ascii=False, indent=2)}

Recent local conversation:
{json.dumps(recent, ensure_ascii=False, indent=2)}

User message:
{message}

If the user is only asking for advice, answer normally and do not emit an update tag.
If the user clearly reports an issue-management change, end with exactly one proposal:
<issue-update>{{"action":"take_ownership|resolve|not_applicable|update","owner":"...","status":"...","next_action":"...","evidence":"..."}}</issue-update>
Use resolve only with completion evidence. Use not_applicable only with a technical rationale
or evidence. A proposal is never applied without separate user confirmation in the GUI.
"""


def assistant_command(provider: str, profile: str, prompt: str) -> list[str]:
    executable = resolve_agent_executable(provider)
    if not executable:
        raise ConfigurationError(f"{provider} CLI is not installed.")
    if not agent_authentication(provider, executable):
        raise ConfigurationError(
            f"{provider} CLI is not authenticated. Use System status → Log in first."
        )
    model = ai_model(provider, profile)
    if provider == "codex":
        return [
            executable, "--search", "exec", "--model", model,
            "--sandbox", "read-only", "--ask-for-approval", "never", prompt,
        ]
    if provider == "claude":
        return [
            executable, "--print", "--model", model,
            "--permission-mode", "plan", "--permission-prompts", "none", prompt,
        ]
    raise ConfigurationError(f"Unsupported AI provider: {provider}")


def extract_issue_update(response: str) -> tuple[str, dict[str, str] | None]:
    """Remove and validate the optional machine-readable proposal from AI text."""
    matches = list(re.finditer(r"<issue-update>\s*(\{.*?\})\s*</issue-update>", response, re.DOTALL))
    if not matches:
        return response.strip(), None
    match = matches[-1]
    visible = (response[:match.start()] + response[match.end():]).strip()
    try:
        raw = json.loads(match.group(1))
    except json.JSONDecodeError:
        return visible, None
    if not isinstance(raw, dict) or raw.get("action") not in {
        "take_ownership", "resolve", "not_applicable", "update",
    }:
        return visible, None
    proposal = {
        key: _safe_markdown_cell(raw.get(key, ""))
        for key in ("action", "owner", "status", "next_action", "evidence")
    }
    return visible, proposal


def proposal_changes(proposal: dict[str, str]) -> dict[str, str]:
    """Map a reviewed AI proposal to the restricted follow-up columns."""
    action = proposal.get("action")
    if action == "take_ownership":
        if not proposal.get("owner"):
            raise ConfigurationError("A responsible owner is required for taking ownership.")
        return {
            "Owner": proposal["owner"],
            "Status": "In progress",
            "Next action": proposal.get("next_action") or "Continue investigation and remediation",
        }
    if action == "resolve":
        if not proposal.get("evidence"):
            raise ConfigurationError("Completion evidence is required before resolution.")
        return {
            "Status": "Completed",
            "Next action": proposal.get("next_action") or "No further action",
            "Completion evidence": proposal["evidence"],
        }
    if action == "not_applicable":
        if not proposal.get("evidence"):
            raise ConfigurationError("Technical rationale or evidence is required for non-applicability.")
        return {
            "Status": "Not applicable",
            "Next action": proposal.get("next_action") or "Reassess only if new evidence emerges",
            "Completion evidence": proposal["evidence"],
        }
    if action == "update" and proposal.get("next_action"):
        return {"Next action": proposal["next_action"]}
    raise ConfigurationError("The proposal does not contain an applicable issue update.")


def technologies_in_latest_report(daily_directory: Path) -> dict[str, int]:
    """Count language mentions in the latest report's involved-stack section."""
    reports = sorted(daily_directory.glob("*.md"), reverse=True) if daily_directory.is_dir() else []
    if not reports:
        return {}
    text = reports[0].read_text(encoding="utf-8", errors="replace")
    marker = "## Projects and technologies involved"
    if marker not in text:
        return {}
    section = text.split(marker, 1)[1].split("\n## ", 1)[0]
    aliases = {
        "PHP": ("php",),
        "Python": ("python", "cpython"),
        "JavaScript": ("javascript", "node.js"),
        "TypeScript": ("typescript",),
        "Java": ("java",),
        "Ruby": ("ruby",),
        "Perl": ("perl",),
        "Shell": ("shell", "bash"),
        "SQL": ("sql",),
    }
    counts = {name: 0 for name in aliases}
    bullets = [line.casefold() for line in section.splitlines() if line.startswith("- ")]
    for bullet in bullets:
        for name, terms in aliases.items():
            if any(
                re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", bullet)
                for term in terms
            ):
                counts[name] += 1
    return dict(sorted(
        ((name, count) for name, count in counts.items() if count),
        key=lambda item: (-item[1], item[0].casefold()),
    ))


def security_statistics(
    *, followup_path: Path | None = None, daily_directory: Path | None = None,
    archive_directory: Path | None = None, today: dt.date | None = None,
) -> dict[str, Any]:
    """Build dashboard metrics solely from ignored local report output."""
    current_activities = followup_activities(followup_path)
    if archive_directory is None and followup_path is None:
        archive_directory = ROOT / str(
            reports_config().get("followup_archive_directory", "output/followup-archive")
        )
    historical = archived_followup_activities(archive_directory) if archive_directory else []
    activities = current_activities + historical
    current_date = today or dt.datetime.now(dt.timezone.utc).date()
    open_activities = [
        activity for activity in activities
        if not is_closed_status(activity.get("Status", ""))
    ]

    def count(
        field: str, rows: list[dict[str, str]], *, normalize_project: bool = False,
    ) -> dict[str, int]:
        values: dict[str, int] = {}
        for activity in rows:
            value = activity.get(field, "Unknown").strip().strip("`") or "Unknown"
            if normalize_project:
                value = re.sub(
                    r"\s+(production|staging|development)$", "", value,
                    flags=re.IGNORECASE,
                )
            values[value] = values.get(value, 0) + 1
        return dict(sorted(values.items(), key=lambda item: (-item[1], item[0].casefold())))

    daily = daily_directory or ROOT / str(
        reports_config().get("daily_directory", "output/daily-advisory-check")
    )
    opened_today = sum(
        activity.get("Opened") == current_date.isoformat() for activity in activities
    )
    opened_month = sum(
        activity.get("Opened", "").startswith(current_date.strftime("%Y-%m"))
        for activity in activities
    )
    priorities = count("Priority", activities)
    risk_order = ("Critical", "High", "Medium", "Low", "Informational")
    priorities = {
        name: priorities[name] for name in risk_order if name in priorities
    } | {
        name: value for name, value in priorities.items() if name not in risk_order
    }
    return {
        "total": len(activities),
        "open": len(open_activities),
        "today": opened_today,
        "month": opened_month,
        "projects": count("Project", activities, normalize_project=True),
        "priorities": priorities,
        "statuses": count("Status", activities),
        "languages": technologies_in_latest_report(daily),
    }


def ai_options() -> tuple[str, list[str], str, list[str]]:
    config = load_yaml(effective_config_path(CONFIG_DIR, "ai-agents.yaml"))
    profiles = config.get("profiles", {})
    modes = config.get("execution_modes", {})
    return (
        str(config.get("default_profile", "economical")),
        list(profiles) if isinstance(profiles, dict) else [],
        str(config.get("default_execution_mode", "economical")),
        list(modes) if isinstance(modes, dict) else [],
    )


def component_status() -> list[tuple[str, str, str]]:
    projects = inventory_projects()
    projects_config = effective_config_path(CONFIG_DIR, "projects.example.yaml")
    local_ready = projects_config != EXAMPLE_CONFIG
    rows = [
        ("Local configuration", "Ready" if local_ready else "Missing", str(projects_config)),
        ("Inventory", "Ready" if projects else "Missing", f"{len(projects)} projects; {inventory_age()}"),
    ]
    git = shutil.which("git")
    rows.append(("git", "Ready" if git else "Missing", git or "not installed"))
    for name in ("codex", "claude"):
        rows.append(agent_component_status(name))
    for name in ("osv-scanner", "trivy"):
        executable = shutil.which(name)
        rows.append((name, "Ready" if executable else "Optional", executable or "not installed"))
    if sys.platform.startswith("linux"):
        desktop_path, _icon_path = integration_paths()
        installed = desktop_entry_installed()
        rows.append((
            "Linux desktop launcher", "Ready" if installed else "Not created",
            str(desktop_path) if installed else "not installed for the current user",
        ))
    try:
        latest = latest_configuration_backup(ROOT)
        rows.append((
            "Configuration backup", "Ready" if latest else "Not created",
            str(latest.relative_to(ROOT)) if latest else "no local backup",
        ))
    except BackupError as error:
        rows.append(("Configuration backup", "Missing", str(error)))
    return rows


def install_desktop_launcher() -> tuple[Path, Path]:
    return install_linux_desktop_entry()


def remove_desktop_launcher() -> tuple[Path, Path]:
    return remove_linux_desktop_entry()


def action_command(
    action: str, *, provider: str | None = None, profile: str | None = None,
    mode: str | None = None, assume_yes: bool = False,
    non_interactive: bool = False,
) -> list[str]:
    command = [str(ROOT / "fairy-security-advisory"), "--action", action]
    if provider:
        command.extend(("--provider", provider))
    if profile:
        command.extend(("--profile", profile))
    if mode:
        command.extend(("--mode", mode))
    if assume_yes:
        command.append("--yes")
    if non_interactive:
        command.append("--non-interactive")
    return command
