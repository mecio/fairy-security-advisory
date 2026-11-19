"""Authoritative advisory intake and deterministic correspondence scoring."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

try:
    from version_ranges import ranges_relation
except ImportError:
    from scripts.version_ranges import ranges_relation


CVE_PATTERN = re.compile(r"(?i)\bCVE-\d{4}-\d{4,}\b")
GHSA_PATTERN = re.compile(r"(?i)\bGHSA-[a-z0-9]{4}(?:-[a-z0-9]{4}){2}\b")
ACN_PATTERN = re.compile(r"(?i)\b[A-Z]{2}\d{2}/\d{6}/[A-Z0-9-]+\b")
IDENTITY_STATUSES = {"confirmed", "supported", "unverified", "conflicting"}
SOURCE_QUALITIES = {"primary", "official-aggregator", "secondary", "unknown"}
EXTRACTION_STATUSES = {"complete", "partial", "failed"}
SOURCE_STATUSES = {"complete", "partial", "failed"}
SCORE_MODEL_VERSION = 2
PREREQUISITE_PRESENT = {"confirmed", "confirmed-present", "present", "not-required"}
PREREQUISITE_ABSENT = {"confirmed-absent", "absent"}
PREREQUISITE_STATUSES = PREREQUISITE_PRESENT | PREREQUISITE_ABSENT | {
    "unknown", "unverified", "not-checked",
}
DEFAULT_PRESENTATION = {
    "actionable_threshold": 80,
    "review_threshold": 50,
    "collapse_below_threshold": 50,
    "notify_below_threshold": False,
    "show_weak_signals": False,
}


def advisory_identifiers(text: str) -> set[str]:
    """Extract stable advisory identifiers without rejecting long CVE serials."""
    identifiers: set[str] = set()
    for pattern in (CVE_PATTERN, GHSA_PATTERN, ACN_PATTERN):
        identifiers.update(match.group(0).upper() for match in pattern.finditer(text))
    return identifiers


def presentation_settings(settings: dict[str, Any] | None) -> dict[str, Any]:
    result = dict(DEFAULT_PRESENTATION)
    if isinstance(settings, dict):
        result.update({key: settings[key] for key in result if key in settings})
    return result


def validate_presentation_settings(settings: dict[str, Any] | None) -> dict[str, Any]:
    result = presentation_settings(settings)
    for key in ("actionable_threshold", "review_threshold", "collapse_below_threshold"):
        value = result[key]
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100:
            raise ValueError(f"finding_presentation.{key} must be an integer from 0 to 100")
    if result["review_threshold"] > result["actionable_threshold"]:
        raise ValueError("finding_presentation.review_threshold cannot exceed actionable_threshold")
    for key in ("notify_below_threshold", "show_weak_signals"):
        if not isinstance(result[key], bool):
            raise ValueError(f"finding_presentation.{key} must be a boolean")
    return result


def load_candidate_intake(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"candidate intake is unreadable: {error}") from error
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("candidate intake needs schema_version 1")
    if not isinstance(document.get("candidates"), list):
        raise ValueError("candidate intake needs a candidates list")
    if not isinstance(document.get("sources"), list):
        raise ValueError("candidate intake needs a sources list")
    return document


def _dossier_identifiers(paths: Iterable[Path]) -> set[str]:
    identifiers: set[str] = set()
    for path in paths:
        if path.is_file():
            identifiers.update(advisory_identifiers(
                path.read_text(encoding="utf-8", errors="replace")
            ))
    return identifiers


def validate_candidate_intake(
    path: Path,
    technology_scope: list[dict[str, Any]],
    active_sources: Iterable[str | dict[str, Any]],
    dossier_paths: Iterable[Path] = (),
) -> dict[str, Any]:
    """Validate discovery output before the coordinator can consume it."""
    document = load_candidate_intake(path)
    scope_keys = {str(item.get("key")) for item in technology_scope}
    source_kinds: dict[str, str] = {}
    for source in active_sources:
        if isinstance(source, dict):
            source_id = str(source.get("id", "")).strip()
            source_kinds[source_id] = str(source.get("type", "")).strip().casefold()
        else:
            source_id = str(source).strip()
            source_kinds[source_id] = ""
    expected_sources = set(source_kinds)
    source_results: dict[str, str] = {}
    source_candidate_ids: dict[str, set[str]] = {}
    for item in document["sources"]:
        if not isinstance(item, dict):
            raise ValueError("candidate intake source entries must be mappings")
        source_id = str(item.get("id", "")).strip()
        status = str(item.get("status", "")).strip()
        candidate_ids = item.get("candidate_ids")
        records_checked = item.get("records_checked")
        coverage_basis = str(item.get("coverage_basis", "")).strip()
        if (
            source_id in source_results or source_id not in expected_sources
            or status not in SOURCE_STATUSES
            or not isinstance(candidate_ids, list)
            or any(not isinstance(value, str) or not value.strip() for value in candidate_ids)
            or len(set(candidate_ids)) != len(candidate_ids)
            or not isinstance(records_checked, int) or isinstance(records_checked, bool)
            or records_checked < 0 or not coverage_basis
        ):
            raise ValueError("candidate intake has an invalid or duplicate source result")
        if status == "complete" and records_checked == 0:
            raise ValueError("a complete source needs a non-zero deterministic record count")
        if status == "complete" and source_kinds.get(source_id) == "html":
            raise ValueError("an HTML discovery source cannot claim exhaustive completion")
        source_results[source_id] = status
        source_candidate_ids[source_id] = {str(value) for value in candidate_ids}
    missing_sources = expected_sources - set(source_results)
    extra_sources = set(source_results) - expected_sources
    if missing_sources or extra_sources:
        raise ValueError(
            "candidate intake source accounting mismatch: "
            f"missing={sorted(missing_sources)}, extra={sorted(extra_sources)}"
        )

    seen: set[str] = set()
    accounted_identifiers: set[str] = set()
    actual_source_candidates: dict[str, set[str]] = {
        source_id: set() for source_id in expected_sources
    }
    for candidate in document["candidates"]:
        if not isinstance(candidate, dict):
            raise ValueError("candidate intake entries must be mappings")
        candidate_id = str(candidate.get("candidate_id", "")).strip()
        advisory_id = str(candidate.get("advisory_id", "")).strip()
        source_id = str(candidate.get("source_id", "")).strip()
        title = str(candidate.get("title", "")).strip()
        url = str(candidate.get("url", "")).strip()
        affected_range = str(candidate.get("affected_range", "")).strip()
        affected_constraints = candidate.get("affected_constraints")
        identity_status = str(candidate.get("identity_status", "")).strip()
        source_quality = str(candidate.get("source_quality", "")).strip()
        extraction_status = str(candidate.get("extraction_status", "")).strip()
        identifiers = candidate.get("identifiers")
        technology_keys = candidate.get("technology_keys")
        project_ids = candidate.get("project_ids", [])
        if (
            not candidate_id or candidate_id in seen or not advisory_id
            or source_id not in expected_sources
            or not title or not url.startswith("https://") or not affected_range
            or not isinstance(affected_constraints, list) or not affected_constraints
            or any(
                not isinstance(value, str) or not value.strip()
                for value in affected_constraints
            )
            or identity_status not in IDENTITY_STATUSES
            or source_quality not in SOURCE_QUALITIES
            or extraction_status not in EXTRACTION_STATUSES
            or not isinstance(identifiers, list) or not identifiers
            or not isinstance(technology_keys, list) or not technology_keys
            or any(str(key) not in scope_keys for key in technology_keys)
            or not isinstance(project_ids, list)
        ):
            raise ValueError("candidate intake has an invalid candidate entry")
        clean_identifiers = [str(value).strip().upper() for value in identifiers if str(value).strip()]
        if len(clean_identifiers) != len(identifiers):
            raise ValueError("candidate intake identifiers must be non-empty strings")
        for identifier in clean_identifiers:
            if identifier.startswith("CVE-") and CVE_PATTERN.fullmatch(identifier) is None:
                raise ValueError(f"candidate intake has an invalid CVE identifier: {identifier}")
        seen.add(candidate_id)
        actual_source_candidates[source_id].add(candidate_id)
        accounted_identifiers.update(clean_identifiers)
        accounted_identifiers.update(advisory_identifiers(advisory_id))
        accounted_identifiers.update(advisory_identifiers(candidate_id))
        accounted_identifiers.update(advisory_identifiers(str(candidate.get("source_record_id", ""))))

    if source_candidate_ids != actual_source_candidates:
        raise ValueError("candidate intake source candidate accounting is incomplete or inconsistent")

    missing_dossier = _dossier_identifiers(dossier_paths) - accounted_identifiers
    if missing_dossier:
        raise ValueError(
            "candidate intake omitted dossier identifiers: " + ", ".join(sorted(missing_dossier))
        )
    return document


def score_candidate(
    ledger_candidate: dict[str, Any], intake_candidate: dict[str, Any],
    settings: dict[str, Any] | None = None,
) -> tuple[int, str, dict[str, int]]:
    """Calculate a transparent correspondence score; never suppress a candidate."""
    configured = validate_presentation_settings(settings)
    identity = {
        "confirmed": 20, "supported": 15, "unverified": 7, "conflicting": 2,
    }[str(intake_candidate["identity_status"])]
    source = {
        "primary": 15, "official-aggregator": 12, "secondary": 7, "unknown": 2,
    }[str(intake_candidate["source_quality"])]
    relation = {"overlaps": 40, "unresolved": 20, "disjoint": 0}.get(
        str(ledger_candidate.get("range_relation")), 0,
    )
    prerequisite_value = str(ledger_candidate.get("prerequisite_status", "")).casefold()
    prerequisite = (
        15 if prerequisite_value in PREREQUISITE_PRESENT
        else 0 if prerequisite_value in PREREQUISITE_ABSENT
        else 8
    )
    extraction = {
        "complete": 10, "partial": 5, "failed": 0,
    }[str(intake_candidate["extraction_status"])]
    breakdown = {
        "advisory_identity": identity,
        "source_quality": source,
        "version_relation": relation,
        "prerequisites": prerequisite,
        "source_extraction": extraction,
    }
    score = sum(breakdown.values())
    band = (
        "confirmed" if score >= configured["actionable_threshold"]
        else "review" if score >= configured["review_threshold"]
        else "weak"
    )
    return score, band, breakdown


def score_candidate_ledger(
    ledger_path: Path, intake_path: Path, settings: dict[str, Any] | None = None,
    *, technology_scope: list[dict[str, Any]] | None = None,
) -> None:
    """Enrich the AI ledger with deterministic, versioned scoring metadata."""
    configured = validate_presentation_settings(settings)
    intake = load_candidate_intake(intake_path)
    intake_by_id = {
        str(candidate.get("candidate_id")): candidate for candidate in intake["candidates"]
    }
    versions_by_key = {
        str(item.get("key", "")): str(item.get("version", "")).strip()
        for item in technology_scope or []
    }
    try:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"candidate ledger is unreadable: {error}") from error
    candidates = ledger.get("candidates") if isinstance(ledger, dict) else None
    if not isinstance(candidates, list):
        raise ValueError("candidate ledger needs a candidates list")
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        intake_candidate = intake_by_id.get(str(candidate.get("candidate_id", "")))
        if intake_candidate is None:
            continue
        candidate["advisory_id"] = str(intake_candidate.get("advisory_id", ""))
        candidate["source_id"] = str(intake_candidate.get("source_id", ""))
        candidate["affected_range"] = str(intake_candidate.get("affected_range", ""))
        candidate["affected_constraints"] = list(
            intake_candidate.get("affected_constraints", [])
        )
        technology_key = str(candidate.get("technology_key", ""))
        if technology_key in versions_by_key:
            candidate["declared_value"] = versions_by_key[technology_key]
        candidate["range_relation"] = ranges_relation(
            str(candidate.get("declared_value", "")), candidate["affected_constraints"],
        )
        score, band, breakdown = score_candidate(candidate, intake_candidate, configured)
        candidate["match_score"] = score
        candidate["confidence"] = band
        candidate["score_model_version"] = SCORE_MODEL_VERSION
        candidate["score_breakdown"] = breakdown
        candidate["notification_eligible"] = bool(
            configured["notify_below_threshold"]
            or score >= configured["review_threshold"]
        )
        candidate["identifiers"] = list(intake_candidate.get("identifiers", []))
        candidate["title"] = str(intake_candidate.get("title", ""))
        candidate["source_url"] = str(intake_candidate.get("url", ""))
        candidate["source_record_id"] = str(
            intake_candidate.get("source_record_id", "")
        )
    ledger_path.write_text(
        json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    ledger_path.chmod(0o600)
