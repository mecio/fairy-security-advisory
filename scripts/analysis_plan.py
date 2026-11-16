#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Build a deterministic per-provider scope for complete advisory analyses."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


PROVIDERS = ("codex", "claude")


class AnalysisPlanError(ValueError):
    """Raised when local inventory cannot produce a safe analysis plan."""


def build_analysis_plan(config: dict[str, Any], default_provider: str) -> dict[str, Any]:
    if default_provider not in PROVIDERS:
        raise AnalysisPlanError(f"Unsupported default AI provider: {default_provider}")
    inventory = config.get("inventory", {})
    projects = inventory.get("projects", []) if isinstance(inventory, dict) else []
    if not isinstance(projects, list):
        raise AnalysisPlanError("inventory.projects must be a list")
    groups: dict[str, list[dict[str, str]]] = {provider: [] for provider in PROVIDERS}
    excluded: list[dict[str, str]] = []
    for index, project in enumerate(projects, start=1):
        if not isinstance(project, dict):
            raise AnalysisPlanError(f"Inventory project {index} must be a mapping")
        path = str(project.get("path", "")).strip()
        if not path:
            raise AnalysisPlanError(f"Inventory project {index} has no path")
        project_id = str(project.get("id") or Path(path).name or f"project-{index}")
        settings = project.get("advisory_checks", {})
        if not isinstance(settings, dict):
            raise AnalysisPlanError(f"Inventory project {project_id} has invalid advisory_checks")
        entry = {"id": project_id, "path": path}
        if settings.get("enabled", True) is False:
            excluded.append(entry)
            continue
        preferred = settings.get("preferred_ai")
        if preferred not in {None, "", *PROVIDERS}:
            raise AnalysisPlanError(f"Inventory project {project_id} has invalid preferred_ai")
        groups[str(preferred or default_provider)].append(entry)
    for provider in PROVIDERS:
        groups[provider].sort(key=lambda item: (item["id"].casefold(), item["path"]))
    excluded.sort(key=lambda item: (item["id"].casefold(), item["path"]))
    return {
        "schema_version": 1,
        "default_provider": default_provider,
        "groups": groups,
        "excluded": excluded,
        "selected_count": sum(len(group) for group in groups.values()),
        "excluded_count": len(excluded),
    }


def required_providers(plan: dict[str, Any]) -> list[str]:
    default = str(plan["default_provider"])
    required = [default]
    required.extend(
        provider for provider in PROVIDERS
        if provider != default and plan.get("groups", {}).get(provider)
    )
    return required


def plan_summary(plan: dict[str, Any]) -> str:
    groups = plan.get("groups", {})
    return (
        f"Codex: {len(groups.get('codex', []))} project(s); "
        f"Claude: {len(groups.get('claude', []))} project(s); "
        f"excluded: {int(plan.get('excluded_count', 0))}"
    )


def write_private_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def write_private_text(path: Path, text: str) -> None:
    """Atomically write a local audit artifact with private permissions."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(text.rstrip() + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def append_private_line(path: Path, line: str) -> None:
    """Append one timestamped audit line without making the file public."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, (line.rstrip() + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)
    path.chmod(0o600)
