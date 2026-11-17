#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared and private release-date metadata caches."""

from __future__ import annotations

import datetime as dt
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 1
SHARED_CACHE = Path("data/release-cache/entries.json")
LOCAL_CACHE = Path("output/cache/technology-releases.json")
SHARED_CANDIDATES = Path("output/cache/shared-release-cache-candidates.json")
DEPS_DEV_SYSTEMS = {
    "npm": "NPM", "pypi": "PYPI", "go": "GO", "rubygems": "RUBYGEMS",
    "cargo": "CARGO", "maven": "MAVEN", "nuget": "NUGET",
}
MAX_CACHE_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
BATCH_SIZE = 100


class ReleaseCacheError(ValueError):
    """Raised when a release cache exists but is unsafe or malformed."""


def cache_key(ecosystem: str, name: str, version: str) -> str:
    return "|".join((ecosystem.casefold(), name.casefold(), version.casefold()))


def _empty() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "entries": {}}


def load_cache(path: Path, *, missing_ok: bool = True) -> dict[str, Any]:
    if path.parent.is_symlink() or path.is_symlink():
        raise ReleaseCacheError(f"release cache path must not be a symlink: {path}")
    if not path.is_file():
        if missing_ok:
            return _empty()
        raise ReleaseCacheError(f"release cache is missing: {path}")
    if path.stat().st_size > MAX_CACHE_BYTES:
        raise ReleaseCacheError(f"release cache is too large: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseCacheError(f"release cache is invalid: {path}: {error}") from error
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise ReleaseCacheError(f"release cache must use schema_version {SCHEMA_VERSION}: {path}")
    entries = data.get("entries")
    if not isinstance(entries, dict):
        raise ReleaseCacheError(f"release cache entries must be a mapping: {path}")
    for key, entry in entries.items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            raise ReleaseCacheError(f"release cache contains an invalid entry: {path}")
        ecosystem, name, version = (str(entry.get(field, "")) for field in ("ecosystem", "name", "version"))
        if not ecosystem or not name or not version or cache_key(ecosystem, name, version) != key:
            raise ReleaseCacheError(f"release cache key and identity disagree: {key}")
        if entry.get("status") not in {"verified", "not-found"}:
            raise ReleaseCacheError(f"release cache has invalid status: {key}")
        checked = entry.get("checked_at")
        try:
            if checked:
                checked_at = dt.datetime.fromisoformat(str(checked).replace("Z", "+00:00"))
                if checked_at.utcoffset() is None:
                    raise ValueError("checked_at requires a timezone")
            if entry["status"] == "verified":
                release_date = dt.datetime.fromisoformat(str(entry["release_date"]).replace("Z", "+00:00"))
                if release_date.date() > dt.datetime.now(dt.timezone.utc).date():
                    raise ValueError("future release date")
        except (ValueError, KeyError) as error:
            raise ReleaseCacheError(f"release cache has invalid date: {key}") from error
        if entry["status"] == "verified":
            url = urllib.parse.urlparse(str(entry.get("source_url", "")))
            if url.scheme != "https" or not url.hostname or url.username or url.password:
                raise ReleaseCacheError(f"release cache has invalid HTTPS source: {key}")
            if entry.get("source_kind") == "deps.dev-package-authority" and url.hostname != "api.deps.dev":
                raise ReleaseCacheError(f"release cache has unexpected deps.dev source: {key}")
            baseline_version = entry.get("baseline_version")
            if baseline_version is not None and (
                not isinstance(baseline_version, str) or not baseline_version.strip()
                or (ecosystem == "platform" and baseline_version != version
                    and not baseline_version.startswith(version + "."))
            ):
                raise ReleaseCacheError(f"release cache has inconsistent baseline version: {key}")
    return data


def save_local_cache(root: Path, data: dict[str, Any]) -> Path:
    path = root / LOCAL_CACHE
    if path.parent.parent.is_symlink() or path.parent.is_symlink() or path.is_symlink():
        raise ReleaseCacheError("local release cache path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def _cached_entry(
    key: str, shared: dict[str, Any], local: dict[str, Any], now: dt.datetime,
    negative_ttl_days: int,
) -> dict[str, Any] | None:
    local_entry = local["entries"].get(key)
    shared_entry = shared["entries"].get(key)
    entry = next((value for value in (local_entry, shared_entry)
                  if isinstance(value, dict) and value.get("status") == "verified"), None)
    if entry is None:
        entry = local_entry or shared_entry
    if not isinstance(entry, dict):
        return None
    if entry.get("status") != "not-found":
        return entry
    checked = entry.get("checked_at")
    try:
        checked_at = dt.datetime.fromisoformat(str(checked).replace("Z", "+00:00"))
    except ValueError:
        return None
    if checked_at.utcoffset() is None:
        return None
    age = now - checked_at
    return entry if dt.timedelta() <= age <= dt.timedelta(days=negative_ttl_days) else None


def resolve_release_metadata(
    root: Path, technologies: Iterable[dict[str, Any]], *, online_enabled: bool = True,
    negative_ttl_days: int = 30, now: dt.datetime | None = None,
) -> dict[str, dict[str, Any]]:
    """Resolve public package publication dates, preferring shared/local caches."""
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    shared = load_cache(root / SHARED_CACHE)
    local = load_cache(root / LOCAL_CACHE)
    resolved: dict[str, dict[str, Any]] = {}
    pending: list[tuple[dict[str, Any], str, str]] = []
    for technology in technologies:
        ecosystem = str(technology.get("ecosystem", "")).casefold()
        version = str(technology.get("version", "")).strip()
        name = str(technology.get("name", "")).strip()
        if not name or not version:
            continue
        lookup_ecosystem = ecosystem or "platform"
        lookup_name = name
        if not ecosystem:
            try:
                from scripts.technology_state import canonical_identity
            except ImportError:
                from technology_state import canonical_identity
            lookup_name = canonical_identity(str(technology.get("category", "other")), name)[1]
        key = cache_key(lookup_ecosystem, lookup_name, version)
        cached = _cached_entry(key, shared, local, current, negative_ttl_days)
        if cached is None and not ecosystem:
            parts = version.split(".")
            if len(parts) >= 2:
                line_key = cache_key("platform", lookup_name, ".".join(parts[:2]))
                cached = _cached_entry(line_key, shared, local, current, negative_ttl_days)
                if cached is None:
                    major_key = cache_key("platform", lookup_name, parts[0])
                    cached = _cached_entry(major_key, shared, local, current, negative_ttl_days)
        if cached is not None:
            if cached.get("status") == "verified":
                resolved[str(technology["key"])] = cached
            continue
        system = DEPS_DEV_SYSTEMS.get(ecosystem)
        if not system or technology.get("public_registry") is not True:
            continue
        pending.append((technology, key, system))

    if not online_enabled or not pending:
        return resolved
    timestamp = current.isoformat().replace("+00:00", "Z")
    for start in range(0, len(pending), BATCH_SIZE):
        batch = pending[start:start + BATCH_SIZE]
        body = json.dumps({"requests": [{
            "versionKey": {
                "system": system, "name": item["name"], "version": item["version"],
            },
        } for item, _key, system in batch]}).encode("utf-8")
        request = urllib.request.Request(
            "https://api.deps.dev/v3alpha/versionbatch", data=body,
            headers={"Content-Type": "application/json", "User-Agent": "fAIry-security-advisory/1"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    continue
                payload = json.loads(raw)
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            continue
        responses = payload.get("responses", []) if isinstance(payload, dict) else []
        if not isinstance(responses, list) or len(responses) != len(batch):
            continue
        for (technology, key, system), response in zip(batch, responses):
            if not isinstance(response, dict) or response.get("request", {}).get("versionKey") != {
                "system": system, "name": technology["name"], "version": technology["version"],
            }:
                continue
            version_data = response.get("version", {})
            published_at = version_data.get("publishedAt") if isinstance(version_data, dict) else None
            if isinstance(published_at, str) and published_at:
                entry = {
                    "status": "verified", "ecosystem": str(technology["ecosystem"]),
                    "name": str(technology["name"]), "version": str(technology["version"]),
                    "release_date": published_at, "checked_at": timestamp,
                    "source_kind": "deps.dev-package-authority",
                    "source_url": (
                        "https://api.deps.dev/v3alpha/systems/"
                        f"{system.lower()}/packages/"
                        f"{urllib.parse.quote(str(technology['name']), safe='')}/versions/"
                        f"{urllib.parse.quote(str(technology['version']), safe='')}"
                    ),
                }
                local["entries"][key] = entry
                resolved[str(technology["key"])] = entry
            else:
                local["entries"][key] = {
                    "status": "not-found", "ecosystem": str(technology["ecosystem"]),
                    "name": str(technology["name"]), "version": str(technology["version"]),
                    "checked_at": timestamp, "source_kind": "deps.dev",
                }
    save_local_cache(root, local)
    return resolved


def export_shared_candidates(root: Path) -> Path:
    """Export verified public metadata for explicit human review and promotion."""
    local = load_cache(root / LOCAL_CACHE, missing_ok=False)
    candidates = {
        key: value for key, value in local["entries"].items()
        if isinstance(value, dict) and value.get("status") == "verified"
    }
    if not candidates:
        raise ReleaseCacheError("the local release cache has no verified public candidates")
    path = root / SHARED_CANDIDATES
    if path.parent.parent.is_symlink() or path.parent.is_symlink() or path.is_symlink():
        raise ReleaseCacheError("shared cache candidate path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(
                {"schema_version": SCHEMA_VERSION, "entries": candidates},
                indent=2, sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return path
