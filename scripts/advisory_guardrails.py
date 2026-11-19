"""Validate AI-produced advisory candidates before publishing local reports."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

try:
    from candidate_intake import (
        PREREQUISITE_ABSENT, PREREQUISITE_STATUSES, SCORE_MODEL_VERSION,
        load_candidate_intake, score_candidate, validate_presentation_settings,
    )
except ImportError:
    from scripts.candidate_intake import (
        PREREQUISITE_ABSENT, PREREQUISITE_STATUSES, SCORE_MODEL_VERSION,
        load_candidate_intake, score_candidate, validate_presentation_settings,
    )
try:
    from followup_archive import markdown_cells
except ImportError:
    from scripts.followup_archive import markdown_cells
try:
    from version_ranges import ranges_relation
except ImportError:
    from scripts.version_ranges import ranges_relation


DECISIONS = {"immediate-action", "follow-up", "monitor", "not-applicable"}
RELATIONS = {"overlaps", "disjoint", "unresolved"}


def _followup_rows(text: str) -> list[dict[str, str]]:
    headers: list[str] = []
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = markdown_cells(line)
        if not headers:
            headers = cells
        elif all(cell and set(cell) <= {"-", ":"} for cell in cells):
            continue
        elif len(cells) == len(headers):
            rows.append(dict(zip(headers, cells)))
    return rows


def _row_projects(row: dict[str, str]) -> set[str]:
    return {
        value.strip().strip("`").casefold()
        for value in re.split(r"\s*(?:;|,)\s*", row.get("Project", ""))
        if value.strip().strip("`")
    }


def validate_candidate_ledger(
    path: Path, technology_scope: list[dict[str, Any]], daily_report: Path, followup: Path,
    *, candidate_intake_path: Path | None = None,
    finding_presentation: dict[str, Any] | None = None,
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
    intake_by_id: dict[str, dict[str, Any]] = {}
    has_intake = candidate_intake_path is not None
    expected: set[tuple[str, str, str]] = set()
    configured_presentation = validate_presentation_settings(finding_presentation)
    if candidate_intake_path is not None:
        intake = load_candidate_intake(candidate_intake_path)
        ledger_sources = document.get("sources")
        if not isinstance(ledger_sources, list):
            raise ValueError("candidate ledger needs a sources list")
        if ledger_sources != intake["sources"]:
            raise ValueError("candidate ledger sources must be an immutable copy of candidate intake")
        for item in intake["candidates"]:
            candidate_id = str(item.get("candidate_id", "")).strip()
            intake_by_id[candidate_id] = item
            for key_value in item.get("technology_keys", []):
                key = str(key_value)
                allowed_projects = set(scope.get(key, {}).get("projects", []))
                requested_projects = {
                    str(value) for value in item.get("project_ids", []) if str(value)
                }
                projects = requested_projects or allowed_projects
                if not projects <= allowed_projects:
                    raise ValueError("candidate intake project is outside the authoritative scope")
                expected.update((candidate_id, key, project) for project in projects)
    seen: set[tuple[str, str, str]] = set()
    daily = daily_report.read_text(encoding="utf-8", errors="replace")
    followup_text = followup.read_text(encoding="utf-8", errors="replace")
    followup_rows = _followup_rows(followup_text)
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("candidate ledger entries must be mappings")
        advisory = str(candidate.get("advisory_id", "")).strip()
        candidate_id = str(candidate.get("candidate_id", "")).strip()
        key = str(candidate.get("technology_key", "")).strip()
        project_id = str(candidate.get("project_id", "")).strip()
        source_id = str(candidate.get("source_id", "")).strip()
        relation = str(candidate.get("range_relation", "")).strip()
        decision = str(candidate.get("decision", "")).strip()
        declared = str(candidate.get("declared_value", "")).strip()
        prerequisite_status = str(candidate.get("prerequisite_status", "")).casefold()
        if (
            not advisory or key not in scope or not project_id or not source_id
            or relation not in RELATIONS or decision not in DECISIONS
            or not str(candidate.get("affected_range", "")).strip()
            or prerequisite_status not in PREREQUISITE_STATUSES
        ):
            raise ValueError("candidate ledger has an invalid advisory, technology key, relation, or decision")
        if project_id not in scope[key].get("projects", []):
            raise ValueError("candidate ledger project is outside the authoritative technology scope")
        if declared != str(scope[key].get("version", "")).strip():
            raise ValueError("candidate ledger declared value disagrees with the authoritative plan")
        if has_intake:
            intake_candidate = intake_by_id.get(candidate_id)
            if intake_candidate is None:
                raise ValueError(f"candidate ledger contains an advisory absent from intake: {candidate_id}")
            if source_id != str(intake_candidate.get("source_id", "")):
                raise ValueError("candidate ledger source disagrees with candidate intake")
            if advisory != str(intake_candidate.get("advisory_id", "")):
                raise ValueError("candidate ledger advisory ID disagrees with candidate intake")
            if key not in {str(value) for value in intake_candidate.get("technology_keys", [])}:
                raise ValueError("candidate ledger technology key disagrees with candidate intake")
            expected_constraints = list(intake_candidate.get("affected_constraints", []))
            expected_relation = ranges_relation(declared, expected_constraints)
            if (
                str(candidate.get("affected_range", ""))
                != str(intake_candidate.get("affected_range", ""))
                or candidate.get("affected_constraints") != expected_constraints
                or relation != expected_relation
            ):
                raise ValueError(
                    "candidate ledger affected range or deterministic relation disagrees with intake"
                )
            expected_score, expected_band, expected_breakdown = score_candidate(
                candidate, intake_candidate, finding_presentation,
            )
            if (
                candidate.get("match_score") != expected_score
                or candidate.get("confidence") != expected_band
                or candidate.get("score_model_version") != SCORE_MODEL_VERSION
                or candidate.get("score_breakdown") != expected_breakdown
                or candidate.get("notification_eligible") != bool(
                    configured_presentation["notify_below_threshold"]
                    or expected_score >= configured_presentation["review_threshold"]
                )
            ):
                raise ValueError("candidate ledger correspondence score is missing or inconsistent")
        identity = (candidate_id or advisory, key, project_id)
        if identity in seen:
            raise ValueError("candidate ledger contains a duplicate advisory decision")
        seen.add(identity)
        if (
            relation == "overlaps" and decision == "not-applicable"
            and prerequisite_status not in PREREQUISITE_ABSENT
        ):
            raise ValueError("an overlapping candidate cannot be marked not-applicable")
        if (
            relation == "unresolved" and decision == "not-applicable"
            and prerequisite_status not in PREREQUISITE_ABSENT
        ):
            raise ValueError("an unresolved candidate cannot be marked not-applicable")
        if not re.search(re.escape(advisory), daily, re.IGNORECASE):
            raise ValueError("a candidate is missing from the staged daily report")
        required_markers = [advisory]
        if has_intake:
            required_markers.extend(
                str(value).strip() for value in intake_candidate.get("identifiers", [])
                if str(value).strip()
            )
            source_record = str(intake_candidate.get("source_record_id", "")).strip()
            if source_record:
                required_markers.append(source_record)
        missing_daily_markers = [
            marker for marker in dict.fromkeys(required_markers)
            if not re.search(re.escape(marker), daily, re.IGNORECASE)
        ]
        if missing_daily_markers:
            raise ValueError(
                "candidate identifiers missing from the staged daily report: "
                + ", ".join(missing_daily_markers)
            )
        if decision in {"immediate-action", "follow-up"}:
            matching_rows = []
            for row in followup_rows:
                advisory_cell = row.get("Advisory / CVE", "")
                if all(
                    re.search(re.escape(marker), advisory_cell, re.IGNORECASE)
                    for marker in dict.fromkeys(required_markers)
                ) and project_id.casefold() in _row_projects(row):
                    matching_rows.append(row)
            if not matching_rows:
                raise ValueError(
                    "actionable candidate identifiers and project must share one staged "
                    f"follow-up row: {candidate_id or advisory}/{project_id}"
                )
        if decision == "not-applicable" and not str(candidate.get("decision_reason", "")).strip():
            raise ValueError("an excluded candidate needs a decision reason")
    missing = expected - seen
    if missing:
        rendered = ", ".join(
            f"{candidate_id}/{key}/{project}" for candidate_id, key, project in sorted(missing)
        )
        raise ValueError("candidate intake decisions missing from ledger: " + rendered)
