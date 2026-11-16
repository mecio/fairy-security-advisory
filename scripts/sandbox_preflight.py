#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Read-only Linux sandbox checks and reviewed AppArmor setup guidance."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    from tool_installation import linux_distribution
except ImportError:
    from scripts.tool_installation import linux_distribution


APPARMOR_RESTRICTION = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
APPARMOR_PROFILE = Path("/etc/apparmor.d/bwrap-userns-restrict")
CLAUDE_SANDBOX_DOCUMENTATION = "https://code.claude.com/docs/en/sandboxing"
UBUNTU_APPARMOR_DOCUMENTATION = (
    "https://documentation.ubuntu.com/security/security-features/"
    "privilege-restriction/apparmor/"
)

def claude_sandbox_settings() -> str:
    """Return strict per-process Claude settings without changing user files."""
    return json.dumps({
        "sandbox": {
            "enabled": True,
            "allowUnsandboxedCommands": False,
            "failIfUnavailable": True,
        },
    }, separators=(",", ":"))


def _restriction_value() -> str | None:
    try:
        return APPARMOR_RESTRICTION.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _probe_bwrap(executable: str) -> tuple[bool, str]:
    """Create and immediately discard an isolated namespace without file writes."""
    command = [
        executable,
        "--die-with-parent",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--ro-bind", "/", "/",
        "--proc", "/proc",
        "--dev", "/dev",
        "--", "/bin/true",
    ]
    try:
        result = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, str(error)
    if result.returncode == 0:
        return True, "namespace probe completed"
    diagnostic = (result.stderr or result.stdout).strip().splitlines()
    return False, diagnostic[-1][:500] if diagnostic else f"exit code {result.returncode}"


def sandbox_preflight(providers: Iterable[str] = ("codex", "claude")) -> dict[str, Any]:
    """Inspect the OS sandbox prerequisites used by requested AI providers."""
    requested = {str(provider).casefold() for provider in providers}
    requires_claude = "claude" in requested
    if not sys.platform.startswith("linux"):
        return {
            "state": "Not applicable",
            "ready": True,
            "details": "Linux bwrap/AppArmor preflight is not required on this platform.",
            "guidance": "Use the isolation controls documented for this operating system.",
            "bwrap": None,
            "socat": None,
            "apparmor_restricted": False,
            "probe_ok": None,
            "probe_detail": "not run",
        }

    bwrap = shutil.which("bwrap")
    socat = shutil.which("socat")
    restriction = _restriction_value()
    restricted = restriction == "1"
    probe_ok, probe_detail = _probe_bwrap(bwrap) if bwrap else (False, "bubblewrap is not installed")

    missing: list[str] = []
    if not bwrap:
        missing.append("bubblewrap")
    if requires_claude and not socat:
        missing.append("socat")

    ready = not missing and probe_ok
    if ready:
        state = "Ready"
        details = (
            f"bwrap namespace probe passed via {bwrap}"
            + (f"; Claude relay: {socat}" if requires_claude else "")
        )
        guidance = "No AppArmor change is required for the current launch context."
    elif restricted and bwrap and not probe_ok:
        state = "Action required"
        dependency_detail = f" Missing dependencies: {', '.join(missing)}." if missing else ""
        details = (
            f"Ubuntu AppArmor blocks the bwrap namespace probe: {probe_detail}."
            f"{dependency_detail}"
        )
        guidance = (
            "Review the distribution-specific AppArmor guidance. "
            "Keep the system-wide user-namespace restriction enabled."
        )
    elif missing:
        state = "Missing"
        details = f"Missing Linux sandbox dependencies: {', '.join(missing)}"
        guidance = "Install the missing packages, then repeat the preflight."
    else:
        state = "Failed"
        details = f"bwrap namespace probe failed: {probe_detail}"
        guidance = "Review the diagnostic before starting an AI analysis."

    return {
        "state": state,
        "ready": ready,
        "details": details,
        "guidance": guidance,
        "bwrap": bwrap,
        "socat": socat,
        "apparmor_restricted": restricted,
        "apparmor_profile_present": APPARMOR_PROFILE.is_file(),
        "probe_ok": probe_ok,
        "probe_detail": probe_detail,
    }


def sandbox_setup_plan(*, apparmor_required: bool | None = None) -> dict[str, Any]:
    """Choose package setup, and offer an AppArmor repair only where documented."""
    distro_id, distro_like = linux_distribution()
    family = {distro_id, *distro_like}
    try:
        version = platform.freedesktop_os_release().get("VERSION_ID", "")
    except OSError:
        version = ""
    if family & {"debian", "ubuntu"}:
        package_lines = ("sudo apt-get update", "sudo apt-get install bubblewrap socat")
    elif family & {"rhel", "centos", "fedora", "rocky", "almalinux"}:
        package_lines = ("sudo dnf install bubblewrap socat",)
    elif "arch" in family:
        package_lines = ("sudo pacman -S bubblewrap socat",)
    elif "alpine" in family:
        package_lines = ("sudo apk add bubblewrap socat",)
    else:
        package_lines = ()
    if apparmor_required is None:
        apparmor_required = _restriction_value() == "1"
    lines = ["set -e", *package_lines]
    supported = bool(package_lines)
    note = "Install missing sandbox packages from the distribution repositories."
    if apparmor_required:
        if distro_id == "ubuntu" and version == "24.04":
            lines = [
                "set -e",
                "test ! -e /etc/apparmor.d/bwrap-userns-restrict",
                "test ! -e /etc/apparmor.d/bwrap",
                "sudo apt-get update",
                "sudo apt-get install bubblewrap socat",
                'fairy_profile_tmp="$(mktemp -d)"',
                'test -d "$fairy_profile_tmp"',
                'trap \'rm -r -- "$fairy_profile_tmp"\' EXIT',
                'cd "$fairy_profile_tmp"',
                "apt-get download apparmor-profiles",
                'dpkg-deb -x apparmor-profiles_*.deb "$fairy_profile_tmp/extracted"',
                'test -f "$fairy_profile_tmp/extracted/usr/share/apparmor/extra-profiles/bwrap-userns-restrict"',
                'sudo install -m 0644 "$fairy_profile_tmp/extracted/usr/share/apparmor/extra-profiles/bwrap-userns-restrict" /etc/apparmor.d/bwrap-userns-restrict',
                "sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict",
            ]
            note = (
                "Ubuntu 24.04: install missing sandbox tools, download the official "
                "apparmor-profiles package into a temporary directory, extract only "
                "bwrap-userns-restrict, and load that profile. The package itself "
                "is not installed. Review the apt summary before confirming."
            )
        else:
            supported = False
            note = (
                "This Linux installation restricts user namespaces, but a reviewed "
                "AppArmor repair is not available for this distribution and release. "
                "Install missing packages manually and consult its security documentation."
            )
    if supported:
        lines.append("printf 'Sandbox setup finished. Restart fAIry, then run the preflight again.\\n'")
    return {"command": "\n".join(lines) if supported else "", "supported": supported, "note": note}


def sandbox_setup_command(*, apparmor_required: bool | None = None) -> str:
    """Return a command only for a supported, reviewed Linux setup."""
    return str(sandbox_setup_plan(apparmor_required=apparmor_required)["command"])


def print_sandbox_preflight(providers: Iterable[str] = ("codex", "claude")) -> bool:
    """Print a concise CLI preflight and return whether the sandbox is usable."""
    result = sandbox_preflight(providers)
    marker = "OK  " if result["ready"] else "FAIL"
    print(f"{marker} AI OS sandbox: {result['details']}")
    if not result["ready"]:
        print(f"     {result['guidance']}")
        plan = sandbox_setup_plan(
            apparmor_required=bool(result["apparmor_restricted"] and not result["probe_ok"]),
        )
        print(f"     {plan['note']}")
        if plan["supported"]:
            print("     Reviewed Linux setup command:")
            for line in str(plan["command"]).splitlines():
                print(f"       {line}")
        print(f"     Claude sandbox documentation: {CLAUDE_SANDBOX_DOCUMENTATION}")
        print(f"     Ubuntu AppArmor documentation: {UBUNTU_APPARMOR_DOCUMENTATION}")
    return bool(result["ready"])
