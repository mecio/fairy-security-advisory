#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Install the Linux application-menu launcher for the current user."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "fairy-security-advisory"
SOURCE_ICON = ROOT / "desktop/assets/fairy-security-advisory-icon.png"
DESKTOP_FILENAME = "fairy-security-advisory.desktop"
ICON_FILENAME = "fairy-security-advisory.png"


def user_data_home() -> Path:
    configured = os.environ.get("XDG_DATA_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".local/share"


def integration_paths(data_home: Path | None = None) -> tuple[Path, Path]:
    base = (data_home or user_data_home()).resolve()
    return base / "applications" / DESKTOP_FILENAME, base / "icons" / ICON_FILENAME


def _desktop_quote(value: Path) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def desktop_entry(icon: Path) -> str:
    return (
        "[Desktop Entry]\n"
        "Version=1.0\n"
        "Type=Application\n"
        "Name=fAIry Security Advisory\n"
        "GenericName=Security advisory monitor\n"
        "Comment=Run AI-assisted periodic security advisory checks\n"
        f"Exec={_desktop_quote(LAUNCHER)} --gui\n"
        f"Path={ROOT}\n"
        f"Icon={icon}\n"
        "Terminal=false\n"
        "Categories=System;Security;\n"
        "Keywords=security;advisory;CVE;AI;vulnerability;\n"
        "StartupNotify=true\n"
        "StartupWMClass=fAIry Security Advisory\n"
    )


def _atomic_bytes(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def refresh_desktop_database(applications_directory: Path) -> None:
    command = shutil.which("update-desktop-database")
    if command:
        subprocess.run(
            [command, str(applications_directory)], check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


def install_linux_desktop_entry(data_home: Path | None = None) -> tuple[Path, Path]:
    if not sys.platform.startswith("linux"):
        raise OSError("Linux desktop integration is available only on Linux.")
    if not LAUNCHER.is_file() or not os.access(LAUNCHER, os.X_OK):
        raise OSError(f"Project launcher is not executable: {LAUNCHER}")
    if not SOURCE_ICON.is_file():
        raise OSError(f"Desktop icon is missing: {SOURCE_ICON}")
    desktop_path, icon_path = integration_paths(data_home)
    _atomic_bytes(icon_path, SOURCE_ICON.read_bytes(), 0o644)
    _atomic_bytes(desktop_path, desktop_entry(icon_path).encode("utf-8"), 0o644)
    refresh_desktop_database(desktop_path.parent)
    return desktop_path, icon_path


def remove_linux_desktop_entry(data_home: Path | None = None) -> tuple[Path, Path]:
    desktop_path, icon_path = integration_paths(data_home)
    desktop_path.unlink(missing_ok=True)
    icon_path.unlink(missing_ok=True)
    refresh_desktop_database(desktop_path.parent)
    return desktop_path, icon_path


def desktop_entry_installed(data_home: Path | None = None) -> bool:
    desktop_path, icon_path = integration_paths(data_home)
    return desktop_path.is_file() and icon_path.is_file()
