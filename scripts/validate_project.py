#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Validate configuration, Markdown outputs, and scanner availability."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import yaml

try:
    from tool_installation import installation_plan, linux_distribution
except ImportError:
    from scripts.tool_installation import installation_plan, linux_distribution
try:
    from config_backup import BackupError, backup_directory, configured_files, load_backup_settings
except ImportError:
    from scripts.config_backup import BackupError, backup_directory, configured_files, load_backup_settings
try:
    from configuration import effective_config_path
except ImportError:
    from scripts.configuration import effective_config_path
try:
    from release_cache import load_cache, ReleaseCacheError, SHARED_CACHE
except ImportError:
    from scripts.release_cache import load_cache, ReleaseCacheError, SHARED_CACHE
try:
    from inventory import normalize_manual_technologies
except ImportError:
    from scripts.inventory import normalize_manual_technologies
try:
    from technology_state import ambiguous_manual_dependencies
except ImportError:
    from scripts.technology_state import ambiguous_manual_dependencies


SOURCE_TYPES = {"html", "rss", "atom", "json", "api", "repository"}
FOLLOWUP_COLUMNS = {
    "ID", "Advisory / CVE", "Project", "Description", "Priority",
    "Owner", "Status", "Opened", "Last updated", "Next action",
    "Due date", "Completion evidence",
}


def print_install_commands(missing: list[str]) -> None:
    """Display official Linux installation commands without executing them."""
    if not missing:
        return
    distro_id, _distro_like = linux_distribution()
    print(f"\nMissing tools: {', '.join(missing)}")
    print(f"Suggested installation commands for Linux ({distro_id}):")
    print("NOTE: these commands are displayed only and are not executed automatically.\n")

    if "osv-scanner" in missing:
        print("# OSV-Scanner")
        plan = installation_plan("osv-scanner")
        print(plan["command"] if plan else "See the official installation documentation.")
        print("# Official container alternative")
        print("docker pull ghcr.io/google/osv-scanner:latest\n")

    if "trivy" in missing:
        print("# Trivy")
        plan = installation_plan("trivy")
        print(plan["command"] if plan else "See the official installation documentation.")
        print("# Official container alternative")
        print("docker pull aquasec/trivy:latest")

    print("\nOfficial documentation:")
    print("- https://google.github.io/osv-scanner/installation/")
    print("- https://trivy.dev/docs/latest/getting-started/installation/")


def fail(message: str, errors: list[str]) -> None:
    errors.append(message)


def load_config_file(path: Path, errors: list[str]) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        fail(f"unable to read {path}: {exc}", errors)
        return {}
    if not isinstance(data, dict):
        fail(f"invalid configuration: {path}", errors)
        return {}
    if data.get("schema_version") != 1:
        fail(f"{path}: schema_version must be 1", errors)
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", default="config")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    config_dir = (root / args.config_dir).resolve() if not Path(args.config_dir).is_absolute() else Path(args.config_dir)
    errors: list[str] = []
    try:
        load_cache(Path(__file__).resolve().parent.parent / SHARED_CACHE, missing_ok=False)
    except ReleaseCacheError as error:
        fail(str(error), errors)
    projects_config = load_config_file(
        effective_config_path(config_dir, "projects.example.yaml"), errors,
    )
    sources_config = load_config_file(
        effective_config_path(config_dir, "advisory-sources.yaml"), errors,
    )
    reports_config = load_config_file(
        effective_config_path(config_dir, "reports.yaml"), errors,
    )
    overlap_days = (reports_config.get("reports", {}) or {}).get(
        "incremental_overlap_days", 10,
    )
    if not isinstance(overlap_days, int) or isinstance(overlap_days, bool) or not 1 <= overlap_days <= 90:
        fail("reports.incremental_overlap_days must be an integer from 1 to 90", errors)
    release_metadata = (reports_config.get("reports", {}) or {}).get("release_metadata", {})
    if not isinstance(release_metadata, dict):
        fail("reports.release_metadata must be a mapping", errors)
    else:
        online_enabled = release_metadata.get("online_enabled", True)
        negative_ttl = release_metadata.get("negative_ttl_days", 30)
        if not isinstance(online_enabled, bool):
            fail("reports.release_metadata.online_enabled must be a boolean", errors)
        if not isinstance(negative_ttl, int) or isinstance(negative_ttl, bool) or not 1 <= negative_ttl <= 365:
            fail("reports.release_metadata.negative_ttl_days must be an integer from 1 to 365", errors)
    agents_config = load_config_file(
        effective_config_path(config_dir, "ai-agents.yaml"), errors,
    )
    load_config_file(effective_config_path(config_dir, "backups.yaml"), errors)
    application_config = load_config_file(
        effective_config_path(config_dir, "application.yaml"), errors,
    )
    factory_application_config = load_config_file(config_dir / "application.yaml", errors)
    developer_tools = (application_config.get("application", {}) or {}).get(
        "developer_tools", False,
    )
    if not isinstance(developer_tools, bool):
        fail("application.developer_tools must be a boolean", errors)
    eula = (factory_application_config.get("application", {}) or {}).get("eula", {})
    if not isinstance(eula, dict):
        fail("application.eula must be a mapping", errors)
    else:
        if eula.get("required_version") in {None, ""}:
            fail("application.eula.required_version is required", errors)
        if eula.get("accepted_version") is not None and not isinstance(
            eula.get("accepted_version"), (str, int),
        ):
            fail("application.eula.accepted_version must be null, a string, or an integer", errors)
        if eula.get("accepted_at_utc") is not None and not isinstance(
            eula.get("accepted_at_utc"), str,
        ):
            fail("application.eula.accepted_at_utc must be null or a string", errors)
    if not projects_config.get("project_roots"):
        fail("project_roots is empty", errors)
    for index, project_root in enumerate(projects_config.get("project_roots", []), start=1):
        if not isinstance(project_root, dict):
            fail(f"project root {index}: must be a mapping", errors)
            continue
        exclude = project_root.get("exclude", [])
        if not isinstance(exclude, list) or any(not isinstance(pattern, str) for pattern in exclude):
            fail(f"project root {index}: exclude must be a list of glob strings", errors)
    inventory_projects = projects_config.get("inventory", {}).get("projects", [])
    if not isinstance(inventory_projects, list):
        fail("inventory.projects must be a list", errors)
        inventory_projects = []
    for index, project in enumerate(inventory_projects, start=1):
        if not isinstance(project, dict):
            fail(f"inventory project {index}: must be a mapping", errors)
            continue
        try:
            manual = normalize_manual_technologies(project.get("manual_technologies", []))
            ambiguous = ambiguous_manual_dependencies(project, manual)
            if ambiguous:
                fail(f"inventory project {index}: manual dependencies need an ecosystem: "
                     + ", ".join(ambiguous), errors)
        except ValueError as error:
            fail(f"inventory project {index}: {error}", errors)
        advisory_checks = project.get("advisory_checks", {})
        if not isinstance(advisory_checks, dict):
            fail(f"inventory project {index}: advisory_checks must be a mapping", errors)
            continue
        if "enabled" in advisory_checks and not isinstance(advisory_checks["enabled"], bool):
            fail(f"inventory project {index}: advisory_checks.enabled must be a boolean", errors)
        if advisory_checks.get("preferred_ai") not in {None, "codex", "claude"}:
            fail(
                f"inventory project {index}: advisory_checks.preferred_ai must be "
                "null, codex, or claude",
                errors,
            )
    required_source_keys = {"id", "name", "url", "type", "technologies", "priority", "active"}
    for index, source in enumerate(sources_config.get("advisory_sources", []), start=1):
        missing = required_source_keys - set(source)
        if missing:
            fail(f"source {index}: missing keys {sorted(missing)}", errors)
        if source.get("type") not in SOURCE_TYPES:
            fail(f"source {index}: invalid type {source.get('type')!r}", errors)
    if not sources_config.get("advisory_sources"):
        fail("advisory_sources is empty", errors)
    profiles = agents_config.get("profiles", {})
    default_profile = agents_config.get("default_profile")
    if not isinstance(profiles, dict) or not profiles:
        fail("ai agents: profiles is empty", errors)
    elif default_profile not in profiles:
        fail("ai agents: default_profile must reference a configured profile", errors)
    profile_items = profiles.items() if isinstance(profiles, dict) else []
    for profile_name, profile in profile_items:
        agents = profile.get("agents", {}) if isinstance(profile, dict) else {}
        for provider in ("codex", "claude"):
            model = agents.get(provider, {}).get("model") if isinstance(agents.get(provider), dict) else None
            if not isinstance(model, str) or not model.strip():
                fail(f"ai agents: profile {profile_name!r} is missing {provider}.model", errors)
    execution_modes = agents_config.get("execution_modes", {})
    default_execution_mode = agents_config.get("default_execution_mode")
    if not isinstance(execution_modes, dict) or not execution_modes:
        fail("ai agents: execution_modes is empty", errors)
    elif default_execution_mode not in execution_modes:
        fail("ai agents: default_execution_mode must reference a configured mode", errors)
    mode_items = execution_modes.items() if isinstance(execution_modes, dict) else []
    for mode_name, mode in mode_items:
        if not isinstance(mode, dict):
            fail(f"ai agents: execution mode {mode_name!r} must be a mapping", errors)
            continue
        concurrency = mode.get("max_parallel_sources")
        subagents = mode.get("max_subagents")
        if not isinstance(concurrency, int) or concurrency < 1:
            fail(f"ai agents: mode {mode_name!r} needs max_parallel_sources >= 1", errors)
        if not isinstance(mode.get("use_subagents"), bool):
            fail(f"ai agents: mode {mode_name!r} needs a boolean use_subagents", errors)
        if not isinstance(subagents, int) or subagents < 0:
            fail(f"ai agents: mode {mode_name!r} needs max_subagents >= 0", errors)
        if mode.get("use_subagents") is False and subagents != 0:
            fail(f"ai agents: mode {mode_name!r} disables subagents but max_subagents is not 0", errors)
    reports = reports_config.get("reports", {})
    for key in (
        "daily_directory", "summary_file", "followup_file",
        "followup_archive_directory", "timezone",
    ):
        if not reports.get(key):
            fail(f"reports.{key} is missing", errors)
    try:
        backup_settings = load_backup_settings(root)
        backup_directory(root, backup_settings)
        configured_files(root, backup_settings)
    except BackupError as error:
        fail(f"backups: {error}", errors)
    followup_path = root / reports.get("followup_file", "output/followup.md")
    if followup_path.exists():
        text = followup_path.read_text(encoding="utf-8")
        for column in FOLLOWUP_COLUMNS:
            if column not in text:
                fail(f"follow-up: missing column {column}", errors)
    else:
        print(f"follow-up: not created yet ({followup_path})")
    archive_directory = root / reports.get(
        "followup_archive_directory", "output/followup-archive",
    )
    if archive_directory.is_dir():
        for archive in archive_directory.glob("[0-9][0-9][0-9][0-9]/[0-9][0-9].md"):
            text = archive.read_text(encoding="utf-8")
            for column in FOLLOWUP_COLUMNS:
                if column not in text:
                    fail(f"follow-up archive {archive}: missing column {column}", errors)

    missing_tools: list[str] = []
    for tool in ("osv-scanner", "trivy"):
        installed = shutil.which(tool)
        state = installed or "not available"
        print(f"{tool}: {state}")
        if not installed:
            missing_tools.append(tool)
    print_install_commands(missing_tools)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    count = len(inventory_projects)
    selected = sum(
        project.get("advisory_checks", {}).get("enabled", True)
        for project in inventory_projects
        if isinstance(project, dict) and isinstance(project.get("advisory_checks", {}), dict)
    )
    print(f"Configuration valid; inventoried projects: {count} ({selected} selected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
