"""Validate AI-produced advisory candidates before publishing local reports."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


DECISIONS = {"immediate-action", "follow-up", "monitor", "not-applicable"}
RELATIONS = {"overlaps", "disjoint", "unresolved"}


def validate_candidate_ledger(
    path: Path, technology_scope: list[dict[str, Any]], daily_report: Path, followup: Path,
) -> None:
    """Reject incomplete candidate accounting or unpublished retained candidates."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"candidate ledger is unreadable: {error}") from error
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("candidate ledger needs schema_version 1")
    candidates = document.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("candidate ledger needs a candidates list")
    scope = {str(item.get("key")): item for item in technology_scope}
    seen: set[tuple[str, str, str]] = set()
    daily = daily_report.read_text(encoding="utf-8", errors="replace")
    followup_text = followup.read_text(encoding="utf-8", errors="replace")
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("candidate ledger entries must be mappings")
        advisory = str(candidate.get("advisory_id", "")).strip()
        key = str(candidate.get("technology_key", "")).strip()
        project_id = str(candidate.get("project_id", "")).strip()
        source_id = str(candidate.get("source_id", "")).strip()
        relation = str(candidate.get("range_relation", "")).strip()
        decision = str(candidate.get("decision", "")).strip()
        declared = str(candidate.get("declared_value", "")).strip()
        if (
            not advisory or key not in scope or not project_id or not source_id
            or relation not in RELATIONS or decision not in DECISIONS
            or not str(candidate.get("affected_range", "")).strip()
            or not str(candidate.get("prerequisite_status", "")).strip()
        ):
            raise ValueError("candidate ledger has an invalid advisory, technology key, relation, or decision")
        if project_id not in scope[key].get("projects", []):
            raise ValueError("candidate ledger project is outside the authoritative technology scope")
        if declared != str(scope[key].get("version", "")).strip():
            raise ValueError("candidate ledger declared value disagrees with the authoritative plan")
        identity = (advisory, key, decision)
        if identity in seen:
            raise ValueError("candidate ledger contains a duplicate advisory decision")
        seen.add(identity)
        if relation == "overlaps" and decision == "not-applicable":
            raise ValueError("an overlapping candidate cannot be marked not-applicable")
        if relation == "unresolved" and decision == "not-applicable":
            raise ValueError("an unresolved candidate cannot be marked not-applicable")
        if decision != "not-applicable" and not re.search(re.escape(advisory), daily, re.IGNORECASE):
            raise ValueError("a retained candidate is missing from the staged daily report")
        if decision in {"immediate-action", "follow-up"} and not re.search(
            re.escape(advisory), followup_text, re.IGNORECASE,
        ):
            raise ValueError("an actionable candidate is missing from the staged follow-up")
        if decision == "not-applicable" and not str(candidate.get("decision_reason", "")).strip():
            raise ValueError("an excluded candidate needs a decision reason")
