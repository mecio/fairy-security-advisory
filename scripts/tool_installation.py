# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared, explicit Linux installation guidance for optional external tools."""

from __future__ import annotations

from pathlib import Path


def linux_distribution() -> tuple[str, set[str]]:
    """Return ID and ID_LIKE from /etc/os-release without executing commands."""
    values: dict[str, str] = {}
    try:
        for raw_line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in raw_line or raw_line.lstrip().startswith("#"):
                continue
            key, value = raw_line.split("=", 1)
            values[key] = value.strip().strip('"')
    except OSError:
        return "unknown", set()
    distro_id = values.get("ID", "unknown").lower()
    distro_like = {item.lower() for item in values.get("ID_LIKE", "").split()}
    return distro_id, distro_like


def installation_plan(component: str) -> dict[str, str] | None:
    """Return a reviewed command and official documentation for a component."""
    distro_id, distro_like = linux_distribution()
    family = {distro_id, *distro_like}
    fixed = {
        "codex": {
            "command": "npm install -g @openai/codex@latest",
            "documentation": "https://developers.openai.com/codex/cli/",
            "note": "Requires Node.js and npm. Authenticate Codex after installation.",
        },
        "claude": {
            "command": "npm install -g @anthropic-ai/claude-code@latest",
            "documentation": "https://code.claude.com/docs/en/getting-started",
            "note": "Requires Node.js and npm. Authenticate Claude Code after installation.",
        },
    }
    if component in fixed:
        return fixed[component]

    if component == "git":
        if family & {"debian", "ubuntu"}:
            command = "sudo apt-get update && sudo apt-get install -y git"
        elif family & {"rhel", "centos", "fedora", "rocky", "almalinux"}:
            command = "sudo dnf install -y git"
        elif "arch" in family:
            command = "sudo pacman -S git"
        elif "alpine" in family:
            command = "sudo apk add git"
        else:
            return None
        return {
            "command": command,
            "documentation": "https://git-scm.com/downloads/linux",
            "note": f"System package installation for Linux distribution: {distro_id}.",
        }

    if component == "osv-scanner":
        if "arch" in family:
            command = "sudo pacman -S osv-scanner"
        elif "alpine" in family:
            command = "sudo apk add osv-scanner"
        else:
            command = (
                'mkdir -p "$HOME/.local/bin" && '
                'GOBIN="$HOME/.local/bin" go install '
                "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"
            )
        return {
            "command": command,
            "documentation": "https://google.github.io/osv-scanner/installation/",
            "note": "The Go-based installation requires a compatible Go toolchain.",
        }

    if component == "trivy":
        if family & {"debian", "ubuntu"}:
            command = " && \\\n".join((
                "sudo apt-get install -y wget gnupg",
                "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | "
                "gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg >/dev/null",
                'echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] '
                'https://aquasecurity.github.io/trivy-repo/deb generic main" | '
                "sudo tee /etc/apt/sources.list.d/trivy.list",
                "sudo apt-get update",
                "sudo apt-get install -y trivy",
            ))
        elif family & {"rhel", "centos", "fedora", "rocky", "almalinux"}:
            command = "sudo dnf install -y trivy"
        elif "arch" in family:
            command = "sudo pacman -S trivy"
        else:
            return None
        return {
            "command": command,
            "documentation": "https://trivy.dev/docs/latest/getting-started/installation/",
            "note": f"Uses the official package instructions for Linux distribution: {distro_id}.",
        }
    return None
