# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared, explicit Linux installation guidance for optional external tools."""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
import os
from pathlib import Path


OSV_MINIMUM_GO = (1, 26, 2)


def resolve_agent_executable(provider: str) -> str | None:
    """Prefer a stable user CLI without replacing an IDE-managed executable."""
    user_candidate = Path.home() / ".local" / "bin" / provider
    if user_candidate.is_file() and os.access(user_candidate, os.X_OK):
        return str(user_candidate)
    return shutil.which(provider)


def codex_standalone_installation() -> dict[str, str]:
    """Return the official standalone installer in non-destructive mode."""
    installer = "https://github.com/openai/codex/releases/latest/download/install.sh"
    if shutil.which("curl"):
        download = (
            'curl --fail --location --proto "=https" --tlsv1.2 '
            f'-o "$tmp_dir/install.sh" "{installer}"'
        )
    elif shutil.which("wget"):
        download = f'wget --https-only -O "$tmp_dir/install.sh" "{installer}"'
    else:
        return {
            "command": "See the official Codex installation documentation.",
            "documentation": (
                "https://developers.openai.com/cookbook/examples/codex/"
                "using_goals_in_codex#quickstart-using-goals"
            ),
            "note": "The standalone installer requires curl or wget.",
            "blocked": (
                "Neither curl nor wget is available, so the official standalone "
                "installer cannot be downloaded safely."
            ),
        }
    command = " && \\\n".join((
        'tmp_dir="$(mktemp -d)"',
        "trap 'rm -rf \"$tmp_dir\"' EXIT",
        download,
        'CODEX_NON_INTERACTIVE=1 sh "$tmp_dir/install.sh"',
        '"$HOME/.local/bin/codex" --version',
    ))
    return {
        "command": command,
        "documentation": (
            "https://developers.openai.com/cookbook/examples/codex/"
            "using_goals_in_codex#quickstart-using-goals"
        ),
        "note": (
            "Uses OpenAI's official standalone installer. It installs the user copy "
            "under ~/.local/bin and ~/.codex without Node.js or npm. Non-interactive "
            "mode leaves IDE-managed and other existing Codex installations untouched."
        ),
    }


def claude_native_installation() -> dict[str, str]:
    """Return Anthropic's recommended native per-user installer."""
    documentation = "https://code.claude.com/docs/en/setup#install-claude-code"
    if not shutil.which("curl"):
        return {
            "command": "See the official Claude Code installation documentation.",
            "documentation": documentation,
            "note": "The native installer requires curl.",
            "blocked": (
                "curl is not available, so the recommended native Claude Code "
                "installer cannot be downloaded safely."
            ),
        }
    installer = "https://claude.ai/install.sh"
    command = " && \\\n".join((
        'tmp_dir="$(mktemp -d)"',
        "trap 'rm -rf \"$tmp_dir\"' EXIT",
        'curl --fail --silent --show-error --location --proto "=https" --tlsv1.2 '
        f'-o "$tmp_dir/install.sh" "{installer}"',
        'bash "$tmp_dir/install.sh"',
        '"$HOME/.local/bin/claude" --version',
    ))
    return {
        "command": command,
        "documentation": documentation,
        "note": (
            "Uses Anthropic's recommended native installer. It manages a stable "
            "user launcher under ~/.local/bin and versioned binaries under "
            "~/.local/share/claude without Node.js, npm, or administrator privileges. "
            "IDE-managed executables are not removed."
        ),
    }


def go_toolchain_status() -> tuple[bool, str]:
    """Return whether the installed Go toolchain can build current OSV-Scanner."""
    executable = shutil.which("go")
    if not executable:
        return False, "Go is not installed or is not available in PATH."
    try:
        result = subprocess.run(
            [executable, "version"], capture_output=True, text=True, timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"Unable to inspect the Go toolchain: {error}"
    match = re.search(r"\bgo(\d+)\.(\d+)(?:\.(\d+))?\b", result.stdout)
    if result.returncode != 0 or not match:
        return False, "The installed Go version could not be determined."
    version = tuple(int(part or 0) for part in match.groups())
    rendered = ".".join(str(part) for part in version)
    required = ".".join(str(part) for part in OSV_MINIMUM_GO)
    if version < OSV_MINIMUM_GO:
        return False, f"Go {rendered} is installed, but OSV-Scanner requires Go {required} or newer."
    return True, f"Compatible Go toolchain detected: Go {rendered}."


def osv_binary_installation() -> tuple[str, str] | None:
    """Build a checksummed per-user install for an official Linux release binary."""
    architecture = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine().lower())
    if not architecture:
        return None
    missing = [name for name in ("curl", "sha256sum", "install") if not shutil.which(name)]
    if missing:
        return None
    asset = f"osv-scanner_linux_{architecture}"
    base = "https://github.com/google/osv-scanner/releases/latest/download"
    command = " && \\\n".join((
        'tmp_dir="$(mktemp -d)"',
        "trap 'rm -rf \"$tmp_dir\"' EXIT",
        f'curl --fail --location --proto "=https" --tlsv1.2 -o "$tmp_dir/{asset}" "{base}/{asset}"',
        f'curl --fail --location --proto "=https" --tlsv1.2 -o "$tmp_dir/osv-scanner_SHA256SUMS" "{base}/osv-scanner_SHA256SUMS"',
        f'(cd "$tmp_dir" && grep -E "[[:space:]]+{asset}$" osv-scanner_SHA256SUMS | sha256sum --check -)',
        'install -d -m 0755 "$HOME/.local/bin"',
        f'install -m 0755 "$tmp_dir/{asset}" "$HOME/.local/bin/osv-scanner"',
        '"$HOME/.local/bin/osv-scanner" --version',
    ))
    note = (
        f"Uses the official precompiled Linux {architecture} release, verifies its "
        "published SHA-256 checksum, and installs it under ~/.local/bin. "
        "No Go toolchain or administrator privileges are required."
    )
    return command, note


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
    if component == "codex":
        return codex_standalone_installation()
    if component == "claude":
        return claude_native_installation()

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
            note = "Installs OSV-Scanner from the configured Arch Linux package repositories."
        elif "alpine" in family:
            command = "sudo apk add osv-scanner"
            note = "Installs OSV-Scanner from the configured Alpine Linux package repositories."
        else:
            binary = osv_binary_installation()
            if binary:
                command, note = binary
            else:
                compatible, status = go_toolchain_status()
                command = (
                    'mkdir -p "$HOME/.local/bin" && '
                    'GOBIN="$HOME/.local/bin" go install '
                    "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"
                )
                note = status
                if not compatible:
                    return {
                        "command": command,
                        "documentation": "https://google.github.io/osv-scanner/installation/",
                        "note": status,
                        "blocked": (
                            "No safe automatic installation is available for this architecture. "
                            f"{status} Review the official release instructions before continuing."
                        ),
                    }
        return {
            "command": command,
            "documentation": "https://google.github.io/osv-scanner/installation/",
            "note": note,
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
