# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Resolve versioned factory configuration and Git-ignored local overrides."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path


LOCAL_DIRECTORY_NAME = "local"
LEGACY_PROJECTS_OVERRIDE = "projects.local.yaml"

CONFIG_SPECS: tuple[tuple[str, str, str], ...] = (
    ("Local projects", "projects.example.yaml", "projects.yaml"),
    ("Advisory sources", "advisory-sources.yaml", "advisory-sources.yaml"),
    ("Reports", "reports.yaml", "reports.yaml"),
    ("Backups", "backups.yaml", "backups.yaml"),
    ("AI agents", "ai-agents.yaml", "ai-agents.yaml"),
)
APPLICATION_CONFIG_SPEC = ("Application", "application.yaml", "application.yaml")
ALL_CONFIG_SPECS = (*CONFIG_SPECS, APPLICATION_CONFIG_SPEC)


def factory_for_local(config_directory: Path, local_path: Path) -> Path:
    """Return the public factory file associated with one local override."""
    local_name = local_path.name
    for _title, factory_name, override_name in ALL_CONFIG_SPECS:
        if override_name == local_name:
            return config_directory / factory_name
    raise KeyError(f"Unknown local configuration file: {local_name}")


def effective_config_path(config_directory: Path, factory_name: str) -> Path:
    """Prefer a local override and otherwise return the public factory file."""
    for _title, configured_factory, override_name in ALL_CONFIG_SPECS:
        if configured_factory == factory_name:
            override = config_directory / LOCAL_DIRECTORY_NAME / override_name
            if override.is_file():
                return override
            if factory_name == "projects.example.yaml":
                legacy = config_directory / LEGACY_PROJECTS_OVERRIDE
                if legacy.is_file():
                    return legacy
            return config_directory / factory_name
    raise KeyError(f"Unknown factory configuration file: {factory_name}")


def initialize_local_overrides(config_directory: Path) -> list[Path]:
    """Create every missing local override as a private copy of its factory file."""
    created: list[Path] = []
    local_directory = config_directory / LOCAL_DIRECTORY_NAME
    local_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        local_directory.chmod(0o700)
    except OSError:
        pass
    for _title, factory_name, override_name in ALL_CONFIG_SPECS:
        factory = config_directory / factory_name
        override = local_directory / override_name
        if override.exists():
            continue
        source = factory
        if factory_name == "projects.example.yaml":
            legacy = config_directory / LEGACY_PROJECTS_OVERRIDE
            if legacy.is_file():
                source = legacy
        if not source.is_file():
            raise FileNotFoundError(source)
        shutil.copyfile(source, override)
        try:
            override.chmod(0o600)
        except OSError:
            pass
        created.append(override)
    return created


def restore_local_override(config_directory: Path, override_name: str) -> tuple[Path, Path]:
    """Atomically replace one private override with its versioned factory file."""
    matching = [
        (factory_name, configured_override)
        for _title, factory_name, configured_override in ALL_CONFIG_SPECS
        if configured_override == override_name
    ]
    if len(matching) != 1:
        raise KeyError(f"Unknown local configuration file: {override_name}")
    factory_name, configured_override = matching[0]
    factory = config_directory / factory_name
    if not factory.is_file() or factory.is_symlink():
        raise FileNotFoundError(factory)
    local_directory = config_directory / LOCAL_DIRECTORY_NAME
    local_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    local_directory.chmod(0o700)
    destination = local_directory / configured_override
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=local_directory,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(factory.read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return factory, destination
