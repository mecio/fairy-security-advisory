#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Create private, local, verifiable archives of project configuration files."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import yaml

try:
    from configuration import effective_config_path
except ImportError:
    from scripts.configuration import effective_config_path


class BackupError(RuntimeError):
    """Raised when a safe configuration backup cannot be created."""


def load_backup_settings(root: Path) -> dict[str, Any]:
    path = effective_config_path(root / "config", "backups.yaml")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as error:
        raise BackupError(f"Unable to read {path}: {error}") from error
    settings = data.get("backups", {}) if isinstance(data, dict) else {}
    if data.get("schema_version") != 1 or not isinstance(settings, dict):
        raise BackupError("The effective backups configuration must use schema_version: 1.")
    return settings


def backup_directory(root: Path, settings: dict[str, Any] | None = None) -> Path:
    selected = settings or load_backup_settings(root)
    relative = Path(str(selected.get("directory", "output/config-backups")))
    if relative.is_absolute():
        raise BackupError("Backup directory must be relative to the project root.")
    destination = (root / relative).resolve()
    output = (root / "output").resolve()
    if destination != output and output not in destination.parents:
        raise BackupError("Backup directory must remain inside the Git-ignored output/ directory.")
    return destination


def configured_targets(root: Path, settings: dict[str, Any]) -> list[Path]:
    include = settings.get("include", [])
    if not isinstance(include, list) or not include:
        raise BackupError("backups.include must be a non-empty list.")
    config_directory = (root / "config").resolve()
    source_relative = Path(str(settings.get("source_directory", "config")))
    if source_relative.is_absolute():
        raise BackupError("backups.source_directory must be relative to the project root.")
    source_directory = (root / source_relative).resolve()
    if source_directory != config_directory and config_directory not in source_directory.parents:
        raise BackupError("backups.source_directory must remain inside config/.")
    targets: list[Path] = []
    for entry in include:
        if not isinstance(entry, str) or Path(entry).name != entry:
            raise BackupError("Backup entries must be plain filenames inside the configured directory.")
        path = source_directory / entry
        if path.is_symlink():
            raise BackupError(f"Refusing to archive symbolic link: {path.relative_to(root)}")
        targets.append(path)
    return targets


def configured_files(root: Path, settings: dict[str, Any]) -> list[Path]:
    files = [path for path in configured_targets(root, settings) if path.is_file()]
    if not files:
        raise BackupError("None of the configured files exists.")
    return files


def _zip_info(name: str, now: dt.datetime) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, now.timetuple()[:6])
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    return info


def create_configuration_backup(
    root: Path, *, now: dt.datetime | None = None,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create an atomic ZIP, verify it, and write a private SHA-256 sidecar."""
    selected = settings or load_backup_settings(root)
    if str(selected.get("checksum", "sha256")).casefold() != "sha256":
        raise BackupError("Only SHA-256 checksums are supported.")
    destination = backup_directory(root, selected)
    files = configured_files(root, selected)
    timestamp = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    prefix = str(selected.get("archive_prefix", "fairy-config")).strip()
    if not prefix or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in prefix):
        raise BackupError("backups.archive_prefix contains unsupported characters.")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.chmod(0o700)
    archive = destination / f"{prefix}-{timestamp.strftime('%Y%m%dT%H%M%S%fZ')}.zip"
    manifest_files = []
    for path in files:
        content = path.read_bytes()
        manifest_files.append({
            "path": path.relative_to(root).as_posix(),
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        })
    manifest = {
        "schema_version": 1,
        "created_at": timestamp.isoformat().replace("+00:00", "Z"),
        "files": manifest_files,
    }

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{prefix}-", suffix=".tmp", dir=destination,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w") as bundle:
            for path in files:
                bundle.writestr(_zip_info(path.relative_to(root).as_posix(), timestamp), path.read_bytes())
            bundle.writestr(
                _zip_info("backup-manifest.json", timestamp),
                json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n",
            )
        with zipfile.ZipFile(temporary, "r") as bundle:
            invalid = bundle.testzip()
            if invalid:
                raise BackupError(f"Backup verification failed for archive member: {invalid}")
        temporary.chmod(0o600)
        os.replace(temporary, archive)
    finally:
        temporary.unlink(missing_ok=True)

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = archive.with_suffix(f"{archive.suffix}.sha256")
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    checksum.chmod(0o600)
    return {
        "archive": archive,
        "checksum_file": checksum,
        "sha256": digest,
        "files": [entry["path"] for entry in manifest_files],
        "created_at": manifest["created_at"],
    }


def create_factory_restore_backup(root: Path) -> dict[str, Any]:
    """Back up all local overrides using trusted factory backup settings."""
    factory = root / "config/backups.yaml"
    try:
        data = yaml.safe_load(factory.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as error:
        raise BackupError(f"Unable to read factory backup settings: {error}") from error
    settings = data.get("backups", {}) if isinstance(data, dict) else {}
    if data.get("schema_version") != 1 or not isinstance(settings, dict):
        raise BackupError("Factory backup settings are invalid.")
    return create_configuration_backup(root, settings=settings)


def latest_configuration_backup(root: Path) -> Path | None:
    settings = load_backup_settings(root)
    destination = backup_directory(root, settings)
    prefix = str(settings.get("archive_prefix", "fairy-config"))
    archives = sorted(destination.glob(f"{prefix}-*.zip"), reverse=True) if destination.is_dir() else []
    return archives[0] if archives else None


def _validated_archive(root: Path, archive: Path) -> dict[str, Any]:
    archive = archive.expanduser().resolve()
    if not archive.is_file() or archive.suffix.casefold() != ".zip":
        raise BackupError("Select an existing ZIP backup archive.")
    if archive.stat().st_size > 50 * 1024 * 1024:
        raise BackupError("Backup archive exceeds the 50 MiB safety limit.")
    settings = load_backup_settings(root)
    allowed = {path.relative_to(root).as_posix() for path in configured_targets(root, settings)}
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    sidecar = archive.with_suffix(f"{archive.suffix}.sha256")
    sidecar_verified = False
    if sidecar.is_file():
        expected = sidecar.read_text(encoding="ascii", errors="replace").split()[0]
        if expected != archive_digest:
            raise BackupError("The archive SHA-256 does not match its sidecar file.")
        sidecar_verified = True

    try:
        with zipfile.ZipFile(archive, "r") as bundle:
            members = bundle.infolist()
            names = [member.filename for member in members]
            if len(names) != len(set(names)):
                raise BackupError("The archive contains duplicate member names.")
            if "backup-manifest.json" not in names:
                raise BackupError("The archive does not contain backup-manifest.json.")
            if sum(member.file_size for member in members) > 20 * 1024 * 1024:
                raise BackupError("Uncompressed backup content exceeds the 20 MiB safety limit.")
            for member in members:
                if member.flag_bits & 0x1:
                    raise BackupError("Encrypted ZIP members are not supported.")
                mode = (member.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise BackupError("Symbolic links are not allowed in backup archives.")
            invalid = bundle.testzip()
            if invalid:
                raise BackupError(f"Archive integrity check failed for: {invalid}")
            try:
                manifest = json.loads(bundle.read("backup-manifest.json"))
            except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as error:
                raise BackupError(f"Invalid backup manifest: {error}") from error
            if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
                raise BackupError("The backup manifest must use schema_version: 1.")
            entries = manifest.get("files")
            if not isinstance(entries, list) or not entries:
                raise BackupError("The backup manifest contains no configuration files.")
            contents: dict[str, bytes] = {}
            for entry in entries:
                if not isinstance(entry, dict):
                    raise BackupError("Invalid file entry in backup manifest.")
                name = str(entry.get("path", ""))
                path = Path(name)
                if name not in allowed or path.name != name.rsplit("/", 1)[-1]:
                    raise BackupError(f"Archive member is not permitted by backup settings: {name}")
                try:
                    content = bundle.read(name)
                except KeyError as error:
                    raise BackupError(f"Manifest member is missing from archive: {name}") from error
                if len(content) != entry.get("size"):
                    raise BackupError(f"Size mismatch for archive member: {name}")
                if hashlib.sha256(content).hexdigest() != entry.get("sha256"):
                    raise BackupError(f"SHA-256 mismatch for archive member: {name}")
                try:
                    data = yaml.safe_load(content.decode("utf-8")) or {}
                except (UnicodeDecodeError, yaml.YAMLError) as error:
                    raise BackupError(f"Invalid YAML in {name}: {error}") from error
                if not isinstance(data, dict) or data.get("schema_version") != 1:
                    raise BackupError(f"{name} must contain schema_version: 1.")
                contents[name] = content
            expected_names = {"backup-manifest.json", *contents}
            if set(names) != expected_names:
                raise BackupError("The archive contains files not declared by its manifest.")
    except (OSError, zipfile.BadZipFile) as error:
        raise BackupError(f"Unable to read backup archive: {error}") from error
    return {
        "archive": archive,
        "created_at": str(manifest.get("created_at", "unknown")),
        "sha256": archive_digest,
        "sidecar_verified": sidecar_verified,
        "files": sorted(contents),
        "contents": contents,
    }


def inspect_configuration_backup(root: Path, archive: Path) -> dict[str, Any]:
    """Validate an import candidate without modifying any configuration."""
    result = _validated_archive(root, archive)
    return {key: value for key, value in result.items() if key != "contents"}


def import_configuration_backup(root: Path, archive: Path) -> dict[str, Any]:
    """Import a validated archive after creating a rollback backup."""
    inspected = _validated_archive(root, archive)
    safety = create_configuration_backup(root)
    config_directory = (root / "config").resolve()
    staged: dict[Path, Path] = {}
    originals: dict[Path, tuple[bytes, int] | None] = {}
    replaced: list[Path] = []
    try:
        for member, content in inspected["contents"].items():
            target = (root / member).resolve()
            if target != config_directory and config_directory not in target.parents:
                raise BackupError(f"Archive target escapes config/: {member}")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if target.is_symlink():
                raise BackupError(f"Refusing to replace symbolic link: {target.name}")
            originals[target] = (
                (target.read_bytes(), target.stat().st_mode & 0o777) if target.exists() else None
            )
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".restore", dir=config_directory,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            temporary = Path(temporary_name)
            temporary.chmod(0o600 if target.name.endswith(".local.yaml") else 0o644)
            staged[target] = temporary
        for target, temporary in staged.items():
            os.replace(temporary, target)
            replaced.append(target)
    except Exception as error:
        for target in reversed(replaced):
            original = originals[target]
            if original is None:
                target.unlink(missing_ok=True)
                continue
            content, mode = original
            descriptor, rollback_name = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".rollback", dir=config_directory,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            rollback = Path(rollback_name)
            rollback.chmod(mode)
            os.replace(rollback, target)
        if isinstance(error, BackupError):
            raise
        raise BackupError(f"Configuration import failed and was rolled back: {error}") from error
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)
    return {
        "archive": inspected["archive"],
        "created_at": inspected["created_at"],
        "sha256": inspected["sha256"],
        "sidecar_verified": inspected["sidecar_verified"],
        "files": inspected["files"],
        "safety_backup": safety["archive"],
    }
