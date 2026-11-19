#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Normalize inventory technologies and maintain private advisory baselines."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable


STATE_SCHEMA_VERSION = 1
UNKNOWN_VERSION = "unknown"
UNRESOLVED_GO_SOURCES = {
    "go-minimum", "go-replaced", "go-replacement-candidate", "go-workspace-unresolved",
}
STATE_PATH = Path("output/advisory-state.json")

TECHNOLOGY_LIST_FIELDS = (
    "frameworks_and_tooling", "databases", "web_servers_and_proxies", "containers",
    "operating_systems", "ci_cd", "infrastructure_as_code",
    "virtualization_and_services",
)
PRODUCT_ALIASES = {
    "mongo": "mongodb", "mongodb": "mongodb", "nginx": "nginx",
    "node": "node", "node.js": "node", "php": "php",
    "postgres": "postgresql", "postgresql": "postgresql", "redis": "redis",
    "mysql": "mysql", "mariadb": "mariadb",
}


class StateError(ValueError):
    """Raised when persisted advisory state exists but cannot be trusted."""


def _clean(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip())


def normalize_version(value: Any) -> str:
    value = _clean(value)
    return value.casefold() if value else UNKNOWN_VERSION


def version_quality(
    version: Any, source: str = "detected", version_status: str = "",
) -> str:
    """Classify version evidence without confusing declarations with verification."""
    value = _clean(version)
    if not value or value.casefold() in {"unknown", "unconstrained", "latest", "stable"}:
        return "red"
    if version_status == "confirmed":
        return "green"
    if version_status in {"unverified", "hypothetical"}:
        return "orange"
    exact = re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?", value)
    digest = re.fullmatch(r"sha256:[0-9a-fA-F]{64}", value)
    authoritative = source in {
        "resolved-lockfile", "verified-local",
        "production-administrator-confirmed", "production-authorized-check",
    }
    return "green" if (exact or digest) and authoritative else "orange"


def split_container_image(value: str) -> tuple[str, str]:
    image = value.split("@", 1)
    if len(image) == 2:
        return image[0], image[1]
    last = value.rsplit("/", 1)[-1]
    if ":" in last:
        name, version = value.rsplit(":", 1)
        return name, version
    return value, ""


def technology_key(category: str, name: str, version: Any, ecosystem: str = "") -> str:
    category, name, ecosystem = canonical_scope_identity(category, name, ecosystem)
    identity = json.dumps(
        [category.casefold(), ecosystem.casefold(), _clean(name).casefold(), normalize_version(version)],
        ensure_ascii=False, separators=(",", ":"),
    )
    slug = re.sub(r"[^a-z0-9]+", "-", _clean(name).casefold()).strip("-")[:44] or "technology"
    return f"{slug}-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:16]}"


def canonical_identity(category: str, name: str) -> tuple[str, str]:
    """Collapse well-known product aliases across runtime/container categories."""
    cleaned = _clean(name).casefold()
    leaf = cleaned.rsplit("/", 1)[-1]
    product = PRODUCT_ALIASES.get(leaf) if category != "dependencies" else None
    return ("product", product) if product else (category, cleaned)


def canonical_scope_identity(
    category: str, name: str, ecosystem: str = "",
) -> tuple[str, str, str]:
    """Normalize identities used by advisory baselines, including Composer PHP."""
    cleaned_ecosystem = _clean(ecosystem).casefold()
    cleaned_name = _clean(name).casefold()
    if (
        category == "dependencies" and cleaned_name == "php"
        and cleaned_ecosystem in {"", "composer"}
    ):
        return "product", "php", ""
    canonical_category, canonical_name = canonical_identity(category, name)
    return canonical_category, canonical_name, cleaned_ecosystem


def ambiguous_manual_dependencies(
    project: dict[str, Any], manual_items: Iterable[dict[str, Any]],
) -> list[str]:
    """Find unscoped manual names shared by multiple detected ecosystems."""
    ecosystems: dict[str, set[str]] = {}
    for record in project.get("technology_inventory", []) or []:
        if isinstance(record, dict) and record.get("category") == "dependencies":
            name = _clean(record.get("name")).casefold()
            ecosystem = _clean(record.get("ecosystem")).casefold()
            if name and ecosystem:
                ecosystems.setdefault(name, set()).add(ecosystem)
    return sorted({
        _clean(item.get("name")) for item in manual_items
        if isinstance(item, dict) and item.get("category") == "dependencies"
        and not _clean(item.get("ecosystem"))
        and len(ecosystems.get(_clean(item.get("name")).casefold(), set())) > 1
    }, key=str.casefold)


def _add_record(
    records: dict[tuple[str, str, str, str], dict[str, str]], category: str, name: Any,
    version: Any = "", source: str = "detected", ecosystem: str = "",
    public_registry: bool = False, version_status: str = "",
) -> None:
    name_text = _clean(name)
    if not name_text:
        return
    version_text = _clean(version)
    key = (category, ecosystem.casefold(), name_text.casefold(), normalize_version(version_text))
    existing = records.get(key)
    candidate = {
        "category": category, "name": name_text, "version": version_text,
        "quality": version_quality(version_text, source, version_status), "source": source,
    }
    if ecosystem:
        candidate["ecosystem"] = ecosystem
    if public_registry:
        candidate["public_registry"] = True
    if version_status:
        candidate["version_status"] = version_status
    if existing is None or (
        existing["quality"] != "green" and candidate["quality"] == "green"
    ):
        records[key] = candidate


def project_technology_records(project: dict[str, Any]) -> list[dict[str, str]]:
    """Return effective technologies, applying current manual values as overrides."""
    records: dict[tuple[str, str, str, str], dict[str, str]] = {}
    stored = project.get("technology_inventory", [])
    if isinstance(stored, list):
        for item in stored:
            if isinstance(item, dict):
                _add_record(
                    records, _clean(item.get("category")) or "other", item.get("name"),
                    item.get("version"), _clean(item.get("source")) or "detected",
                    _clean(item.get("ecosystem")),
                    item.get("public_registry") is True,
                )
    if not records:
        for language in project.get("languages", []):
            if isinstance(language, dict):
                _add_record(records, "languages", language.get("name"))
        runtime_sources = project.get("runtime_version_sources", {})
        runtimes = project.get("declared_or_local_runtime_versions", {})
        if isinstance(runtimes, dict):
            for name, version in runtimes.items():
                source = runtime_sources.get(name, "declared") if isinstance(runtime_sources, dict) else "declared"
                _add_record(records, "runtimes", name, version, source)
        dependency_sources = project.get("dependency_version_sources", {})
        dependency_records = project.get("dependency_version_records", [])
        resolved_names: set[str] = set()
        if isinstance(dependency_records, list):
            for item in dependency_records:
                if not isinstance(item, dict):
                    continue
                name = _clean(item.get("name"))
                if not name:
                    continue
                resolved_names.add(name.casefold())
                _add_record(
                    records, "dependencies", name, item.get("version"),
                    _clean(item.get("source")) or "resolved-lockfile",
                    _clean(item.get("ecosystem")),
                    item.get("public_registry") is True,
                )
        dependencies = project.get("dependencies", {})
        if isinstance(dependencies, dict):
            for name, version in dependencies.items():
                if str(name).casefold() in resolved_names:
                    continue
                source = dependency_sources.get(name, "declared") if isinstance(dependency_sources, dict) else "declared"
                _add_record(records, "dependencies", name, version, source)
        framework_aliases = project.get("framework_package_aliases", {})
        for field in TECHNOLOGY_LIST_FIELDS:
            for value in project.get(field, []) or []:
                if (
                    field == "frameworks_and_tooling" and isinstance(framework_aliases, dict)
                    and value in framework_aliases
                ):
                    continue
                if field == "containers" and isinstance(value, str):
                    name, version = split_container_image(value)
                    _add_record(records, field, name, version)
                elif isinstance(value, str):
                    _add_record(records, field, value)
                elif isinstance(value, dict):
                    _add_record(records, field, value.get("name"), value.get("version"))
    manual_items = [
        item for item in project.get("manual_technologies", []) or []
        if isinstance(item, dict) and _clean(item.get("name"))
    ]
    ambiguous = {name.casefold() for name in ambiguous_manual_dependencies(project, manual_items)}
    manual_items = [item for item in manual_items if _clean(item.get("name")).casefold() not in ambiguous
                    or item.get("category") != "dependencies" or _clean(item.get("ecosystem"))]
    manual_identities = {
        (canonical_identity(_clean(item.get("category")) or "other", _clean(item.get("name"))),
         _clean(item.get("ecosystem")).casefold()) for item in manual_items
        if "replaces_version" not in item
    }
    targeted_replacements = {
        (_clean(item.get("category")) or "other", _clean(item.get("ecosystem")).casefold(),
         _clean(item.get("name")).casefold(), normalize_version(item.get("replaces_version")))
        for item in manual_items if "replaces_version" in item
    }
    detected_ecosystems: dict[tuple[str, str], set[str]] = {}
    for record in records.values():
        if record["category"] == "dependencies" and record.get("ecosystem"):
            identity = canonical_identity(record["category"], record["name"])
            detected_ecosystems.setdefault(identity, set()).add(record["ecosystem"])
    for key in list(records):
        record = records[key]
        identity = canonical_identity(record["category"], record["name"])
        ecosystem = _clean(record.get("ecosystem")).casefold()
        if (key in targeted_replacements or
            (identity, ecosystem) in manual_identities or
            (record["category"] == "dependencies" and (identity, "") in manual_identities)):
            records.pop(key, None)
    for item in manual_items:
        if item.get("exclude") is True:
            continue
        category = _clean(item.get("category")) or "other"
        name = _clean(item.get("name"))
        ecosystem = _clean(item.get("ecosystem"))
        if category == "dependencies" and not ecosystem:
            known = detected_ecosystems.get(canonical_identity(category, name), set())
            if len(known) == 1:
                ecosystem = next(iter(known))
        _add_record(
            records, category, name, item.get("version"), "manual", ecosystem,
            version_status=_clean(item.get("version_status")),
        )
    return sorted(records.values(), key=lambda item: (item["name"].casefold(), item["version"]))


def production_technology_records(project: dict[str, Any]) -> list[dict[str, str]]:
    """Return production versions without conflating them with local inventory."""
    records: list[dict[str, str]] = []
    for item in project.get("production_technologies", []) or []:
        if not isinstance(item, dict):
            continue
        name = _clean(item.get("name"))
        category = _clean(item.get("category")) or "other"
        version = _clean(item.get("version"))
        environment = _clean(item.get("environment"))
        evidence_type = _clean(item.get("evidence_type")) or "reported-unverified"
        if not name or not version or not environment:
            continue
        source = f"production-{evidence_type}"
        record = {
            "category": category,
            "name": name,
            "version": version,
            "quality": version_quality(version, source),
            "source": source,
            "environment": environment,
            "evidence_type": evidence_type,
            "evidence": _clean(item.get("evidence")),
            "verified_at": _clean(item.get("verified_at")),
        }
        ecosystem = _clean(item.get("ecosystem"))
        if ecosystem:
            record["ecosystem"] = ecosystem
        records.append(record)
    return sorted(
        records,
        key=lambda item: (
            item["name"].casefold(), item.get("ecosystem", ""),
            item["environment"].casefold(), item["version"],
        ),
    )


def collect_technology_scope(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Deduplicate selected project technologies and retain their project mapping."""
    combined: dict[str, dict[str, Any]] = {}
    projects = config.get("inventory", {}).get("projects", [])
    if not isinstance(projects, list):
        return []
    for project in projects:
        if not isinstance(project, dict):
            continue
        settings = project.get("advisory_checks", {})
        if isinstance(settings, dict) and settings.get("enabled", True) is False:
            continue
        project_id = _clean(project.get("id")) or "unnamed"
        inventory_records = project_technology_records(project)
        production_records = production_technology_records(project)
        versioned_products = {
            canonical_scope_identity(
                record["category"], record["name"], record.get("ecosystem", ""),
            )
            for record in inventory_records if record.get("version")
        }
        for record in [*inventory_records, *production_records]:
            identity = canonical_scope_identity(
                record["category"], record["name"], record.get("ecosystem", ""),
            )
            is_production = "environment" in record
            if not is_production and not record.get("version") and identity in versioned_products:
                continue
            key = technology_key(record["category"], record["name"], record["version"],
                                 record.get("ecosystem", ""))
            display_only_fields = {"version_status"}
            if is_production:
                # Environment-specific evidence belongs only to the deployment
                # list. Keeping a second singular copy on the aggregate entry
                # can combine fields from different environments.
                display_only_fields.update({
                    "environment", "evidence_type", "evidence", "verified_at",
                })
            scope_record = {
                field: value for field, value in record.items()
                if field not in display_only_fields
            }
            if identity[:2] == ("product", "php"):
                scope_record["name"] = "PHP"
                if record["category"] == "dependencies":
                    scope_record["category"] = "runtimes"
                    scope_record.pop("ecosystem", None)
            if not is_production:
                # A user-selected version status is display metadata. Advisory
                # scope uses the saved version and technical source unchanged.
                scope_record["quality"] = version_quality(
                    record.get("version"), str(record.get("source") or "detected"),
                )
            entry = combined.setdefault(
                key, {**scope_record, "key": key, "projects": []},
            )
            if entry.get("quality") != "green" and scope_record.get("quality") == "green":
                entry["quality"] = "green"
                entry["source"] = scope_record["source"]
            if project_id not in entry["projects"]:
                entry["projects"].append(project_id)
            if is_production:
                deployment = {
                    "project": project_id,
                    "environment": record["environment"],
                    "evidence_type": record["evidence_type"],
                    "evidence": record["evidence"],
                    "verified_at": record["verified_at"],
                }
                deployments = entry.setdefault("production_deployments", [])
                if deployment not in deployments:
                    deployments.append(deployment)
            else:
                inventory_projects = entry.setdefault("inventory_projects", [])
                if project_id not in inventory_projects:
                    inventory_projects.append(project_id)
    for entry in combined.values():
        entry["projects"].sort(key=str.casefold)
        if "inventory_projects" in entry:
            entry["inventory_projects"].sort(key=str.casefold)
        if "production_deployments" in entry:
            entry["production_deployments"].sort(
                key=lambda item: (item["project"].casefold(), item["environment"].casefold()),
            )
    return sorted(
        combined.values(), key=lambda item: (item["name"].casefold(), item["version"], item["key"]),
    )


def load_state(root: Path) -> dict[str, Any]:
    path = root / STATE_PATH
    if path.parent.is_symlink() or path.is_symlink():
        raise StateError("advisory state path must not be a symlink")
    if not path.is_file():
        return {"schema_version": STATE_SCHEMA_VERSION, "baselines": {}, "sources": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise StateError(f"advisory state is unreadable or invalid: {error}") from error
    if not isinstance(value, dict) or value.get("schema_version") != STATE_SCHEMA_VERSION:
        raise StateError(f"advisory state must use schema_version {STATE_SCHEMA_VERSION}")
    if not isinstance(value.get("baselines"), dict):
        raise StateError("advisory state baselines must be a mapping")
    if not isinstance(value.get("sources"), dict):
        raise StateError("advisory state sources must be a mapping")
    return value


def load_state_for_run(root: Path, daily_directory: Path) -> dict[str, Any]:
    """Discard checkpoints when their canonical daily reports are absent."""
    state = load_state(root)
    if not daily_directory.is_dir() or not any(daily_directory.glob("*.md")):
        state["baselines"] = {}
        state["sources"] = {}
    return state


def save_state(root: Path, state: dict[str, Any]) -> Path:
    path = root / STATE_PATH
    if path.parent.is_symlink() or path.is_symlink():
        raise OSError("advisory state path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def scan_rows(config: dict[str, Any], state: dict[str, Any]) -> list[dict[str, Any]]:
    baselines = state.get("baselines", {})
    rows = []
    for item in collect_technology_scope(config):
        baseline = baselines.get(item["key"], {}) if isinstance(baselines, dict) else {}
        baseline_status = baseline.get("status") if isinstance(baseline, dict) else None
        status = baseline_status or "missing"
        rows.append({**item, "baseline_status": status, "selected": status == "missing"})
    return rows


def prune_inactive_baselines(state: dict[str, Any], active_keys: Iterable[str]) -> None:
    active = set(active_keys)
    baselines = state.setdefault("baselines", {})
    if isinstance(baselines, dict):
        for key in list(baselines):
            if key not in active:
                del baselines[key]


def record_completed_baselines(
    state: dict[str, Any], scope: Iterable[dict[str, Any]], results: dict[str, str],
    completed_at: dt.datetime,
) -> None:
    timestamp = completed_at.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    baselines = state.setdefault("baselines", {})
    for item in scope:
        reported_status = results.get(item["key"])
        if reported_status not in {"completed", "partial"}:
            continue
        status = (
            "partial" if item.get("quality") == "red"
            or item.get("source") in UNRESOLVED_GO_SOURCES else reported_status
        )
        baselines[item["key"]] = {
            "status": status, "completed_at": timestamp,
            "name": item["name"], "version": item.get("version") or UNKNOWN_VERSION,
            "category": item["category"],
        }


def incremental_since(
    state: dict[str, Any], source_id: str, overlap_days: int, now: dt.datetime,
) -> str | None:
    source = state.get("sources", {}).get(source_id, {})
    raw = source.get("last_success_at") if isinstance(source, dict) else None
    if not isinstance(raw, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (parsed - dt.timedelta(days=overlap_days)).astimezone(dt.timezone.utc).isoformat().replace(
        "+00:00", "Z",
    )


def baseline_windows(
    scope: Iterable[dict[str, Any]], baseline_keys: Iterable[str], now: dt.datetime,
    release_metadata: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Describe historical windows separately from incremental source checkpoints."""
    scope_by_key = {item["key"]: item for item in scope}
    through = now.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    metadata = release_metadata or {}
    windows = {
        key: {
            "technology": scope_by_key[key]["name"],
            "version": scope_by_key[key].get("version") or UNKNOWN_VERSION,
            "baseline_version": (
                metadata.get(key, {}).get("baseline_version")
                or (scope_by_key[key].get("version") if scope_by_key[key].get("ecosystem")
                    and scope_by_key[key].get("source") not in UNRESOLVED_GO_SOURCES else None)
            ),
            "anchor_policy": (
                "go-declaration-to-verify" if scope_by_key[key].get("source") in UNRESOLVED_GO_SOURCES
                else "package-exact" if scope_by_key[key].get("ecosystem")
                else "platform-release-line-to-resolve"
            ),
            "since": metadata.get(key, {}).get("release_date"),
            "since_basis": (
                metadata.get(key, {}).get("source_kind")
                or "official-version-release-date-to-resolve"
            ),
            "release_source_url": metadata.get(key, {}).get("source_url"),
            "until": through,
        }
        for key in baseline_keys
    }
    return windows


def record_source_successes(
    state: dict[str, Any], source_ids: Iterable[str], completed_at: dt.datetime,
) -> None:
    timestamp = completed_at.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    sources = state.setdefault("sources", {})
    for source_id in source_ids:
        sources[source_id] = {"last_success_at": timestamp}


def validate_evidence_state(
    path: Path, expected_baseline_keys: Iterable[str], expected_source_ids: Iterable[str],
    expected_baseline_windows: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, str], list[str]]:
    """Validate the coordinator's machine-readable coverage receipt."""
    expected_baseline_keys = list(expected_baseline_keys)
    expected_source_ids = list(expected_source_ids)
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or unsafe evidence state")
    expected_count = len(set(expected_baseline_keys)) + len(set(expected_source_ids))
    maximum_size = min(64 * 1024 * 1024, max(1_000_000, expected_count * 512 + 65_536))
    if path.stat().st_size > maximum_size:
        raise ValueError("evidence state is too large")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"missing or invalid evidence state: {error}") from error
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("evidence state must use schema_version 1")
    baseline_values = data.get("baselines")
    source_values = data.get("sources")
    if not isinstance(baseline_values, list) or not isinstance(source_values, list):
        raise ValueError("evidence state baselines and sources must be lists")
    baseline_results: dict[str, str] = {}

    def iso_date(value: Any, field: str) -> dt.date:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"completed evidence baseline needs {field}")
        try:
            return dt.datetime.fromisoformat(
                value.strip().replace("Z", "+00:00")
            ).date()
        except ValueError:
            try:
                return dt.date.fromisoformat(value.strip())
            except ValueError as error:
                raise ValueError(f"evidence baseline has invalid {field}") from error

    for item in baseline_values:
        if not isinstance(item, dict):
            raise ValueError("evidence baseline entries must be mappings")
        key, status = _clean(item.get("key")), _clean(item.get("status"))
        if not key or status not in {"completed", "partial", "failed"} or key in baseline_results:
            raise ValueError("evidence baseline entry has an invalid or duplicate key/status")
        if status == "completed" and expected_baseline_windows is not None:
            window = expected_baseline_windows.get(key, {})
            if window.get("anchor_policy") == "go-declaration-to-verify":
                raise ValueError("unresolved Go declaration baseline cannot be completed")
            if str(window.get("version", "")).casefold() in {"", "unknown"}:
                raise ValueError("unknown-version baseline cannot be completed")
            baseline_version = item.get("baseline_version")
            if not isinstance(baseline_version, str) or not baseline_version.strip():
                raise ValueError("completed baseline needs a baseline_version")
            if (
                window.get("anchor_policy") == "package-exact"
                and baseline_version.casefold() != str(window.get("version", "")).casefold()
            ):
                raise ValueError("package baseline_version must match the resolved version")
            release_date = iso_date(item.get("release_date"), "release_date")
            searched_since = iso_date(item.get("searched_since"), "searched_since")
            searched_until = iso_date(item.get("searched_until"), "searched_until")
            expected_until = iso_date(window.get("until"), "baseline until")
            cached_release = window.get("since")
            if cached_release and release_date != iso_date(cached_release, "cached release date"):
                raise ValueError("completed baseline release date disagrees with verified cache")
            source_url = item.get("release_source_url")
            if not isinstance(source_url, str) or not source_url.startswith("https://"):
                raise ValueError("completed baseline needs an HTTPS release source URL")
            if searched_since > release_date:
                raise ValueError("completed baseline starts after the version release date")
            if searched_until < expected_until:
                raise ValueError("completed baseline does not cover through the run date")
        baseline_results[key] = status
    expected_keys = set(expected_baseline_keys)
    if set(baseline_results) != expected_keys:
        raise ValueError("evidence state does not account for every selected baseline key")
    source_results: dict[str, str] = {}
    for item in source_values:
        if not isinstance(item, dict):
            raise ValueError("evidence source entries must be mappings")
        source_id, status = _clean(item.get("id")), _clean(item.get("status"))
        if not source_id or status not in {"complete", "partial", "failed"} or source_id in source_results:
            raise ValueError("evidence source entry has an invalid or duplicate id/status")
        source_results[source_id] = status
    expected_sources = set(expected_source_ids)
    if set(source_results) != expected_sources:
        raise ValueError("evidence state does not account for every active source")
    return baseline_results, sorted(
        source_id for source_id, status in source_results.items() if status == "complete"
    )
