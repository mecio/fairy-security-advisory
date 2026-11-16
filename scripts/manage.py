#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Interactive launcher for fAIry Security Advisory local operations."""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

try:
    from inventory import build_inventory, safe_load_yaml
except ImportError:  # Support `python -m scripts.manage` and unit-test imports.
    from scripts.inventory import build_inventory, safe_load_yaml

try:
    from config_backup import (
        BackupError, create_configuration_backup, create_factory_restore_backup,
        import_configuration_backup,
        inspect_configuration_backup,
    )
except ImportError:
    from scripts.config_backup import (
        BackupError, create_configuration_backup, create_factory_restore_backup,
        import_configuration_backup,
        inspect_configuration_backup,
    )
try:
    from followup_archive import archive_closed_followups
except ImportError:
    from scripts.followup_archive import archive_closed_followups
try:
    from configuration import (
        CONFIG_SPECS, effective_config_path, initialize_local_overrides,
        restore_local_override,
    )
except ImportError:
    from scripts.configuration import (
        CONFIG_SPECS, effective_config_path, initialize_local_overrides,
        restore_local_override,
    )
try:
    from ai_usage import run_tracked_command
except ImportError:
    from scripts.ai_usage import run_tracked_command
try:
    from analysis_plan import (
        AnalysisPlanError, append_private_line, build_analysis_plan, plan_summary,
        required_providers, write_private_json, write_private_text,
    )
except ImportError:
    from scripts.analysis_plan import (
        AnalysisPlanError, append_private_line, build_analysis_plan, plan_summary,
        required_providers, write_private_json, write_private_text,
    )
try:
    from desktop_integration import install_linux_desktop_entry, remove_linux_desktop_entry
except ImportError:
    from scripts.desktop_integration import install_linux_desktop_entry, remove_linux_desktop_entry
try:
    from tool_installation import installation_plan, resolve_agent_executable
except ImportError:
    from scripts.tool_installation import installation_plan, resolve_agent_executable
try:
    from sandbox_preflight import claude_sandbox_settings, print_sandbox_preflight
except ImportError:
    from scripts.sandbox_preflight import claude_sandbox_settings, print_sandbox_preflight


ROOT = Path(__file__).resolve().parent.parent
# Direct execution (`python scripts/manage.py`) otherwise exposes only the
# scripts directory on sys.path.  Keep project packages such as `desktop`
# importable from both the root launcher and the lower-level entry point.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CONFIG_DIR = ROOT / "config"
LOCAL_CONFIG = CONFIG_DIR / "local/projects.yaml"
EXAMPLE_CONFIG = CONFIG_DIR / "projects.example.yaml"
AI_PROMPTS = {
    "codex": "$fairy-security-advisory run the complete security advisory check",
    "claude": "/fairy-security-advisory run the complete security advisory check",
}
ANALYSIS_PROGRESS_PREFIX = "::fairy-analysis-progress::"


def emit_analysis_progress(
    *, phase: str, status: str, provider: str | None = None,
    completed: int = 0, total: int = 0, active_projects: int = 0,
    message: str = "",
) -> None:
    """Emit one machine-readable GUI progress event on standard output."""
    if os.environ.get("FAIRY_GUI_PROGRESS") != "1":
        return
    event = {
        "phase": phase,
        "status": status,
        "provider": provider,
        "completed": completed,
        "total": total,
        "active_projects": active_projects,
        "message": message,
    }
    print(
        ANALYSIS_PROGRESS_PREFIX + json.dumps(event, separators=(",", ":")),
        flush=True,
    )
AGENT_INSTALLATION = {
    "codex": (
        "Use fAIry's reviewed standalone installation plan.",
        "https://developers.openai.com/cookbook/examples/codex/using_goals_in_codex#quickstart-using-goals",
    ),
    "claude": (
        "Use fAIry's reviewed native installation plan.",
        "https://code.claude.com/docs/en/setup#install-claude-code",
    ),
}

CLI_BANNER = r"""
                 .       *                         .--------.
        *             .-~~~~~-.          . . .---|   +    |
                   .-'   .-.   '-.        *       |  /AI\  |
          .-._   .'     (o o)     '.   _.-.       |  \__/  |
       .-'    '-/        \^/        \-'    '-.    '--------'
      (    .--. |      .-/|\-.      | .--.    )        *
       '._/    \ \   .' / | \ '.   / /    \_.'
          \     '._.'  /  |  \  '._.'     /
       .---'._         /   |   \         _.'---.
    .-'       '--._   /   / \   \   _.--'       '-.
   /    _..--.     '-/___/   \___\-'     .--.._    \
  ( _.-'      '._      /     \      _.'      '-._ )
   '              '--._/       \_.--'              '
                     /  .-~~~-.  \
                    /.-'       '-.\
                   //             \\
                  /_\             /_\
                    \             /
                     '._       _.'
                        '-----'

                 fAIry Security Advisory
             AI-assisted security intelligence
""".strip("\n")

CLI_BANNER_COMPACT = r"""
          *             .--------.
     .-~~~~~-.    . .--|   +    |
 .-./  (o o)  \.-.     |  /AI\  |
(   \   \^/   /   )    '--------'
 '-._'.-/|\-.'_.-'
    '--/ | \--'
      /_/ \_\
       fAIry Security Advisory
""".strip("\n")


def render_cli_banner(*, color: bool | None = None, width: int | None = None) -> str:
    """Return a terminal-safe ASCII splash without affecting redirected output."""
    terminal_width = width or shutil.get_terminal_size(fallback=(80, 24)).columns
    banner = CLI_BANNER_COMPACT if terminal_width < 72 else CLI_BANNER
    use_color = (
        sys.stdout.isatty() and "NO_COLOR" not in os.environ
        if color is None else color
    )
    if not use_color:
        return banner
    cyan = "\033[96m"
    violet = "\033[95m"
    reset = "\033[0m"
    lines = banner.splitlines()
    return "\n".join(
        f"{violet}{line}{reset}" if "fAIry Security Advisory" not in line
        else f"{cyan}{line}{reset}"
        for line in lines
    )


def print_cli_banner() -> None:
    print(render_cli_banner())


def run_command(arguments: list[str]) -> int:
    """Run a project command without invoking a shell."""
    completed = subprocess.run(arguments, cwd=ROOT, check=False)
    return completed.returncode


def confirm(prompt: str) -> bool:
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def project_venv_python() -> Path:
    if sys.platform == "win32":
        return ROOT / ".venv/Scripts/python.exe"
    return ROOT / ".venv/bin/python"


def setup_project_environment(*, assume_yes: bool = False) -> int:
    if not assume_yes and not confirm("Create/update .venv and install requirements.txt?"):
        print("Cancelled.")
        return 0
    python = project_venv_python()
    if not python.exists():
        if run_command([sys.executable, "-m", "venv", str(ROOT / ".venv")]) != 0:
            return 1
    result = run_command([
        str(python), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt"),
    ])
    if result == 0:
        print(f"Project environment ready: {python}")
    return result


def agent_details(provider: str) -> tuple[str | None, bool]:
    executable = resolve_agent_executable(provider)
    if not executable:
        return None, False
    try:
        version_result = subprocess.run(
            [executable, "--version"], cwd=ROOT, check=False, capture_output=True,
            text=True, timeout=15,
        )
        version = (version_result.stdout or version_result.stderr).strip().splitlines()[0]
        auth_command = [executable, "login", "status"] if provider == "codex" else [executable, "auth", "status"]
        auth_result = subprocess.run(
            auth_command, cwd=ROOT, check=False, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15,
        )
        return version or executable, auth_result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return executable, False


def show_agent_installation(provider: str) -> None:
    command, documentation = AGENT_INSTALLATION[provider]
    plan = installation_plan(provider)
    if plan:
        command = plan["command"]
        documentation = plan["documentation"]
    print(f"  Suggested installation: {command}")
    print(f"  Official documentation: {documentation}")
    print(f"  After installation, start `{provider}` once and complete authentication.")


def inventory_is_current(config: dict) -> tuple[bool, str]:
    inventory = config.get("inventory", {})
    projects = inventory.get("projects", [])
    generated_at = inventory.get("generated_at")
    if not projects or not generated_at:
        return False, "missing"
    try:
        generated = dt.datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
        age = dt.datetime.now(dt.timezone.utc) - generated.astimezone(dt.timezone.utc)
        maximum_age = dt.timedelta(hours=float(inventory.get("refresh_after_hours", 168)))
    except (TypeError, ValueError):
        return False, "invalid timestamp"
    return (age <= maximum_age, f"{age.total_seconds() / 3600:.1f} hours old")


def configured_roots_ready(config: dict, *, display: bool = True) -> bool:
    roots = [item for item in config.get("project_roots", []) if isinstance(item, dict) and item.get("enabled", True)]
    if not roots:
        if display:
            print("FAIL no enabled project roots")
        return False
    ready = True
    for item in roots:
        path = Path(str(item.get("path", ""))).expanduser()
        exists = path.is_dir() and os.access(path, os.R_OK | os.X_OK)
        ready = ready and exists
        if display:
            print(f"{'OK  ' if exists else 'FAIL'} project root: {path}")
    return ready


def check_prerequisites(provider: str | None = None) -> int:
    failures = 0
    print(f"OK   Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    print(f"{'OK  ' if shutil.which('git') else 'FAIL'} Git")
    if not shutil.which("git"):
        failures += 1

    projects_config = effective_config_path(CONFIG_DIR, "projects.example.yaml")
    if projects_config == EXAMPLE_CONFIG:
        print("FAIL local configuration is missing; use the initialization menu option")
        failures += 1
    else:
        config = safe_load_yaml(projects_config)
        if not configured_roots_ready(config):
            failures += 1
        current, detail = inventory_is_current(config)
        print(f"{'OK  ' if current else 'FAIL'} local inventory: {detail}")
        if not current:
            failures += 1

    providers = [provider] if provider else list(AI_PROMPTS)
    ready_agents = 0
    for candidate in providers:
        version, authenticated = agent_details(candidate)
        if version:
            if authenticated:
                ready_agents += 1
            print(f"OK   {candidate}: {version}; authenticated: {'yes' if authenticated else 'no'}")
        else:
            print(f"MISS {candidate} CLI")
            show_agent_installation(candidate)
    if ready_agents == 0:
        failures += 1

    for scanner in ("osv-scanner", "trivy"):
        executable = shutil.which(scanner)
        print(f"{'OK  ' if executable else 'OPT '} {scanner}: {executable or 'not installed (optional)'}")

    providers_for_sandbox = (provider,) if provider else tuple(AI_PROMPTS)
    if not print_sandbox_preflight(providers_for_sandbox):
        failures += 1

    if failures > 0:
        print("Prerequisites are incomplete. Follow the guidance above before starting the analysis.")
        return 1
    print("Required prerequisites are ready.")
    return 0


def initialize_local_config(*, assume_yes: bool = False) -> int:
    if not assume_yes and not confirm("Create missing private overrides under config/local/?"):
        print("Cancelled.")
        return 0
    try:
        created = initialize_local_overrides(CONFIG_DIR)
    except OSError as error:
        print(f"Unable to initialize local configuration: {error}", file=sys.stderr)
        return 1
    if not created:
        print("All config/local/ overrides already exist.")
    for path in created:
        print(f"Created: {path.relative_to(ROOT)}")
    print("Local choices remain under the Git-ignored config/local/ directory.")
    return 0


RESTORE_SECTIONS = {
    Path(override_name).stem: (title, factory_name, override_name)
    for title, factory_name, override_name in CONFIG_SPECS
}


def restore_factory_defaults(
    section: str | None = None, *, assume_yes: bool = False,
) -> int:
    if section is None:
        if not sys.stdin.isatty():
            print(
                "Configuration section is required; pass --section followed by one of: "
                + ", ".join(RESTORE_SECTIONS), file=sys.stderr,
            )
            return 1
        names = list(RESTORE_SECTIONS)
        print("Select the configuration section to restore:")
        for index, name in enumerate(names, start=1):
            print(f"  {index}. {RESTORE_SECTIONS[name][0]} ({name})")
        print("  0. Cancel")
        choice = input("Section: ").strip()
        if choice == "0":
            return 0
        section = names[int(choice) - 1] if choice.isdigit() and 1 <= int(choice) <= len(names) else choice
    selected = RESTORE_SECTIONS.get(section)
    if selected is None:
        print(
            "Unknown configuration section. Available values: "
            + ", ".join(RESTORE_SECTIONS), file=sys.stderr,
        )
        return 1
    title, factory_name, override_name = selected
    warning = (
        " This also clears the detected local inventory; refresh it afterwards."
        if override_name == "projects.yaml" else ""
    )
    if not assume_yes and not confirm(
        f"Back up all local configuration, then restore {title} from "
        f"config/{factory_name}?{warning}"
    ):
        print("Cancelled.")
        return 0
    try:
        backup = create_factory_restore_backup(ROOT)
        factory, destination = restore_local_override(CONFIG_DIR, override_name)
    except (OSError, KeyError, BackupError) as error:
        print(f"Factory restore failed: {error}", file=sys.stderr)
        return 1
    print(f"Restored: {destination.relative_to(ROOT)} from {factory.relative_to(ROOT)}")
    print(f"Safety backup: {backup['archive'].relative_to(ROOT)}")
    if override_name == "projects.yaml":
        print("The local inventory was reset; run the inventory refresh before analysis.")
    return 0


def validate_configuration() -> int:
    return run_command([sys.executable, "scripts/validate_project.py", "--config-dir", "config"])


def backup_configuration(*, assume_yes: bool = False) -> int:
    if not assume_yes and not confirm(
        "Create an unencrypted private configuration backup under the ignored output directory?"
    ):
        print("Cancelled.")
        return 0
    try:
        result = create_configuration_backup(ROOT)
    except (OSError, BackupError) as error:
        print(f"Backup failed: {error}", file=sys.stderr)
        return 1
    print(f"Backup created: {result['archive'].relative_to(ROOT)}")
    print(f"Files included: {len(result['files'])}")
    print(f"SHA-256: {result['sha256']}")
    return 0


def import_backup_configuration(
    archive_path: str | None = None, *, assume_yes: bool = False,
) -> int:
    if not archive_path:
        if not sys.stdin.isatty():
            print("Backup archive is required; pass --archive /path/to/file.zip.", file=sys.stderr)
            return 1
        archive_path = input("Backup ZIP path: ").strip()
    archive = Path(archive_path).expanduser()
    try:
        inspected = inspect_configuration_backup(ROOT, archive)
    except (OSError, BackupError) as error:
        print(f"Import validation failed: {error}", file=sys.stderr)
        return 1
    print(f"Archive: {inspected['archive']}")
    print(f"Created: {inspected['created_at']}")
    print(f"Files: {', '.join(inspected['files'])}")
    print(
        "Archive sidecar: verified" if inspected["sidecar_verified"]
        else "Archive sidecar: absent; embedded file checksums verified"
    )
    if not assume_yes and not confirm(
        "Create a safety backup and replace these configuration files?"
    ):
        print("Cancelled.")
        return 0
    try:
        result = import_configuration_backup(ROOT, archive)
    except (OSError, BackupError) as error:
        print(f"Import failed: {error}", file=sys.stderr)
        return 1
    print(f"Imported files: {len(result['files'])}")
    print(f"Safety backup: {result['safety_backup'].relative_to(ROOT)}")
    return 0


def archive_followups() -> int:
    try:
        result = archive_closed_followups(ROOT)
    except (OSError, ValueError) as error:
        print(f"Follow-up archival failed: {error}", file=sys.stderr)
        return 1
    print(f"Archived follow-up activities: {result['archived']}")
    for path in result["archives"]:
        print(path.relative_to(ROOT))
    return 0


def preview_inventory() -> int:
    projects_config = effective_config_path(CONFIG_DIR, "projects.example.yaml")
    if projects_config == EXAMPLE_CONFIG:
        print("Local configuration is missing. Use menu option 3 first.", file=sys.stderr)
        return 1
    config = safe_load_yaml(projects_config)
    projects = build_inventory(config)
    language_names = sorted({
        str(language.get("name"))
        for project in projects
        for language in project.get("languages", [])
        if language.get("name")
    })
    print("Read-only inventory preview")
    print(f"Projects/components detected: {len(projects)}")
    print(f"Languages/formats detected: {', '.join(language_names) if language_names else 'none'}")
    print("No file was written.")
    return 0


def refresh_inventory(*, assume_yes: bool = False) -> int:
    projects_config = effective_config_path(CONFIG_DIR, "projects.example.yaml")
    if projects_config == EXAMPLE_CONFIG:
        print("Local configuration is missing. Use menu option 3 first.", file=sys.stderr)
        return 1
    if not assume_yes and not confirm("Refresh the ignored local inventory now?"):
        print("Cancelled.")
        return 0
    return run_command([sys.executable, "scripts/inventory.py", "--config-dir", "config"])


def source_request(source: dict) -> urllib.request.Request:
    headers = {"User-Agent": "AI-Security-Advisory-Check/1.0"}
    if source.get("id") == "osv" and source.get("type") == "api":
        return urllib.request.Request(
            str(source["url"]),
            data=json.dumps({"queries": []}).encode("utf-8"),
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )
    return urllib.request.Request(str(source["url"]), headers=headers, method="GET")


def check_source(source: dict) -> tuple[bool, str]:
    name = str(source.get("name"))
    try:
        with urllib.request.urlopen(source_request(source), timeout=20) as response:
            response.read(1)
            status = getattr(response, "status", 200)
        return True, f"OK   {status}  {name}"
    except urllib.error.HTTPError as error:
        return False, f"FAIL {error.code}  {name}"
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        reason = error.reason if isinstance(error, urllib.error.URLError) else error
        return False, f"FAIL ----  {name}: {reason}"


def check_sources(execution_mode: str | None = None) -> int:
    source_config = safe_load_yaml(effective_config_path(CONFIG_DIR, "advisory-sources.yaml"))
    active_sources = [source for source in source_config.get("advisory_sources", []) if source.get("active")]
    mode_name, mode = configured_execution(execution_mode)
    concurrency = min(int(mode["max_parallel_sources"]), max(1, len(active_sources)))
    ordered_sources = sorted(active_sources, key=lambda item: str(item.get("priority", "")))
    print(f"Execution mode: {mode_name}; source concurrency: {concurrency}")
    if concurrency == 1:
        results = [check_source(source) for source in ordered_sources]
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            results = list(executor.map(check_source, ordered_sources))
    failures = sum(not success for success, _message in results)
    for _success, message in results:
        print(message)
    print(f"Sources checked: {len(active_sources)}; failures: {failures}")
    return 1 if failures else 0


def run_tests() -> int:
    return run_command([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])


def public_files() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        return []
    return [ROOT / value.decode() for value in completed.stdout.split(b"\0") if value]


def check_local_data_isolation() -> int:
    failures: list[str] = []
    for relative in ("config/local/", "config/projects.local.yaml", "output/followup.md"):
        result = subprocess.run(
            ["git", "check-ignore", "-q", relative], cwd=ROOT, check=False,
        )
        if result.returncode != 0:
            failures.append(f"not ignored: {relative}")

    local_values: set[str] = set()
    projects_config = effective_config_path(CONFIG_DIR, "projects.example.yaml")
    if projects_config != EXAMPLE_CONFIG:
        local_config = safe_load_yaml(projects_config)
        local_values.update(
            str(item.get("path"))
            for item in local_config.get("project_roots", [])
            if isinstance(item, dict) and item.get("path")
        )
        local_values.update(
            str(project.get("path"))
            for project in local_config.get("inventory", {}).get("projects", [])
            if isinstance(project, dict) and project.get("path")
        )
    for path in public_files():
        if not path.is_file() or path.is_symlink():
            continue
        content = path.read_text(encoding="utf-8", errors="ignore")
        if any(value in content for value in local_values):
            failures.append(f"local path found in public file: {path.relative_to(ROOT)}")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print("Local data isolation: valid")
    return 0


def validate_skill_layout() -> int:
    skill = ROOT / ".agents/skills/fairy-security-advisory/SKILL.md"
    claude = ROOT / ".claude/skills/fairy-security-advisory/SKILL.md"
    if not skill.is_file() or not claude.is_file():
        print("FAIL shared Codex/Claude skill is not readable")
        return 1
    text = skill.read_text(encoding="utf-8")
    if not text.startswith("---\n") or "name: fairy-security-advisory" not in text:
        print("FAIL invalid skill frontmatter")
        return 1
    print("Shared Codex/Claude skill layout: valid")
    return 0


def validate_project_license() -> int:
    failures: list[str] = []
    license_path = ROOT / "LICENSE"
    readme_path = ROOT / "README.md"
    eula_path = ROOT / "EULA.md"
    license_text = license_path.read_text(encoding="utf-8") if license_path.is_file() else ""
    readme_text = readme_path.read_text(encoding="utf-8") if readme_path.is_file() else ""
    eula_text = eula_path.read_text(encoding="utf-8") if eula_path.is_file() else ""
    if "GNU AFFERO GENERAL PUBLIC LICENSE" not in license_text:
        failures.append("LICENSE is not the canonical GNU AGPL text")
    if "AGPL-3.0-or-later" not in readme_text:
        failures.append("README does not declare AGPL-3.0-or-later")
    if "[MIT License](LICENSE)" in readme_text:
        failures.append("README still links the project LICENSE as MIT")
    if "AGPL-3.0-or-later" not in eula_text or "provided **as is**" not in eula_text.casefold():
        failures.append("EULA does not declare the AGPL relationship and as-is disclaimer")
    factory_application = safe_load_yaml(ROOT / "config/application.yaml")
    required_eula = str(
        ((factory_application.get("application", {}) or {}).get("eula", {}) or {}).get(
            "required_version", "",
        )
    )
    if not required_eula or f"EULA version: {required_eula}" not in eula_text:
        failures.append("EULA.md version does not match config/application.yaml")
    metadata = safe_load_yaml(ROOT / "VERSION.yaml")
    for key in ("name", "version", "author", "last_modified_year", "license"):
        if metadata.get(key) in (None, ""):
            failures.append(f"VERSION.yaml is missing {key}")
    if metadata.get("license") != "AGPL-3.0-or-later":
        failures.append("VERSION.yaml license does not match the project license")
    for relative in (
        "scripts/fairy-security-advisory",
        "scripts/manage.py",
        "scripts/analysis_plan.py",
        "scripts/inventory.py",
        "scripts/validate_project.py",
        "desktop/__init__.py",
        "desktop/__main__.py",
        "desktop/app.py",
        "desktop/eula_dialog.py",
        "desktop/main_window.py",
        "desktop/services.py",
        "scripts/sandbox_preflight.py",
        "tests/test_desktop_services.py",
        "tests/test_desktop_ui.py",
        "tests/test_analysis_plan.py",
        "tests/test_inventory.py",
        "tests/test_manage.py",
        "tests/test_sandbox_preflight.py",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        if "SPDX-License-Identifier: AGPL-3.0-or-later" not in text:
            failures.append(f"missing AGPL SPDX identifier: {relative}")
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print("Project license: AGPL-3.0-or-later; source headers: valid")
    return 0


def prepublication_check() -> int:
    checks: list[tuple[str, Callable[[], int]]] = [
        ("Runtime prerequisites and AI agents", check_prerequisites),
        ("Configuration and optional tools", validate_configuration),
        ("Automated tests", run_tests),
        ("Shared skill layout", validate_skill_layout),
        ("Project license", validate_project_license),
        ("Local data isolation", check_local_data_isolation),
        ("Advisory source reachability", check_sources),
    ]
    failed: list[str] = []
    for name, check in checks:
        print(f"\n== {name} ==", flush=True)
        if check() != 0:
            failed.append(name)
    if failed:
        print(f"\nPre-publication check failed: {', '.join(failed)}")
        return 1
    print("\nPre-publication check passed.")
    return 0


def show_skill_usage() -> int:
    profile_name, models = configured_models()
    mode_name, mode = configured_execution()
    print("Run the complete AI-assisted advisory analysis from the repository root:")
    print(f"  Default model profile: {profile_name}")
    print(
        f"  Default execution mode: {mode_name} "
        f"(source concurrency={mode['max_parallel_sources']}, sub-agents={mode['max_subagents']})"
    )
    print(f"  Codex ({models['codex']}):       $fairy-security-advisory run the complete security advisory check")
    print(f"  Claude Code ({models['claude']}): /fairy-security-advisory run the complete security advisory check")
    print("Use menu option 10 or --action ai-check for per-project Codex/Claude routing.")
    print("A direct skill invocation uses only the agent in which it was started.")
    return 0


def model_profiles() -> tuple[str, dict]:
    config = safe_load_yaml(effective_config_path(CONFIG_DIR, "ai-agents.yaml"))
    return str(config.get("default_profile", "economical")), config.get("profiles", {})


def execution_modes() -> tuple[str, dict]:
    config = safe_load_yaml(effective_config_path(CONFIG_DIR, "ai-agents.yaml"))
    return str(config.get("default_execution_mode", "economical")), config.get("execution_modes", {})


def configured_execution(mode: str | None = None) -> tuple[str, dict]:
    default_mode, modes = execution_modes()
    selected = mode or default_mode
    if selected not in modes:
        raise ValueError(f"Unknown execution mode: {selected}")
    return selected, modes[selected]


def configured_models(profile: str | None = None) -> tuple[str, dict[str, str]]:
    default_profile, profiles = model_profiles()
    selected = profile or default_profile
    if selected not in profiles:
        raise ValueError(f"Unknown AI model profile: {selected}")
    agents = profiles[selected].get("agents", {})
    return selected, {
        provider: str(agents.get(provider, {}).get("model", "")).strip()
        for provider in AI_PROMPTS
    }


def choose_model_profile() -> str | None:
    default_profile, profiles = model_profiles()
    names = list(profiles)
    print("Select a model profile:")
    for index, name in enumerate(names, start=1):
        profile = profiles[name]
        models = profile.get("agents", {})
        marker = " (default)" if name == default_profile else ""
        print(f"  {index}. {name}{marker}: {profile.get('description', '')}")
        print(
            "     " + ", ".join(
                f"{provider}={models.get(provider, {}).get('model', 'unset')}"
                for provider in AI_PROMPTS
            )
        )
    print("  0. Cancel")
    choice = input(f"Profile [{default_profile}]: ").strip()
    if not choice:
        return default_profile
    if choice == "0":
        return None
    if choice.isdigit() and 1 <= int(choice) <= len(names):
        return names[int(choice) - 1]
    if choice in profiles:
        return choice
    print("Invalid profile.")
    return None


def choose_execution_mode() -> str | None:
    default_mode, modes = execution_modes()
    names = list(modes)
    print("Select speed versus consumption:")
    for index, name in enumerate(names, start=1):
        mode = modes[name]
        marker = " (default)" if name == default_mode else ""
        print(f"  {index}. {name}{marker}: {mode.get('description', '')}")
        print(
            f"     source concurrency={mode.get('max_parallel_sources')}, "
            f"sub-agents={mode.get('max_subagents') if mode.get('use_subagents') else 0}"
        )
    print("  0. Cancel")
    choice = input(f"Execution mode [{default_mode}]: ").strip()
    if not choice:
        return default_mode
    if choice == "0":
        return None
    if choice.isdigit() and 1 <= int(choice) <= len(names):
        return names[int(choice) - 1]
    if choice in modes:
        return choice
    print("Invalid execution mode.")
    return None


def execution_guidance(execution_mode: str | None = None) -> str:
    mode_name, mode = configured_execution(execution_mode)
    if mode.get("use_subagents"):
        execution_instruction = (
            f"Use at most {mode.get('max_subagents')} source-analysis sub-agents when useful, "
            "then merge and deduplicate their evidence in the primary agent."
        )
    else:
        execution_instruction = "Process sources sequentially and do not create sub-agents."
    return (
        f"Execution mode: {mode_name}. Read the effective AI configuration, preferring "
        f"config/local/ai-agents.yaml over config/ai-agents.yaml. {execution_instruction}"
    )


def analysis_prompt(provider: str, execution_mode: str | None = None) -> str:
    return f"{AI_PROMPTS[provider]}\n\n{execution_guidance(execution_mode)}"


def scoped_evidence_prompt(
    provider: str, projects: list[dict[str, str]], execution_mode: str | None = None,
) -> str:
    scope = json.dumps(projects, ensure_ascii=False, indent=2)
    return (
        f"Use the fairy-security-advisory instructions as an evidence analyst. "
        f"This is the read-only {provider} evidence phase, not the final report phase.\n\n"
        f"Authoritative project scope:\n{scope}\n\n"
        "Analyze every and only the projects listed above. Do not inspect any other "
        "inventory project. Do not modify files, do not update canonical reports or "
        "follow-up records, and do not run OSV-Scanner or Trivy directly. Consult the "
        "configured active advisory sources and primary sources as needed. Return one "
        "self-contained Markdown dossier containing checked sources, candidate and "
        "excluded advisories, manifest/lockfile evidence, applicability, risk, confidence, "
        "recommended actions, and limitations. Include the project ID with every finding.\n\n"
        + execution_guidance(execution_mode)
    )


def consolidation_prompt(
    provider: str, plan_path: Path, dossiers: list[Path],
    execution_mode: str | None = None,
) -> str:
    dossier_lines = "\n".join(f"- {path}" for path in dossiers) or "- none"
    return (
        f"{AI_PROMPTS[provider]}\n\n"
        "Run in routed consolidation mode. The JSON plan below is the authoritative "
        "project boundary; never analyze inventory projects absent from its selected "
        "provider groups, and never scan entries in its excluded list. Analyze the "
        f"projects assigned to {provider} directly. Read and critically verify the "
        "read-only dossiers produced by other providers, deduplicate all findings, then "
        "update the canonical daily report, summary, follow-up, and archive exactly once. "
        "In the newest daily report section 'Projects and technologies involved', "
        "include one line '- Project: `<id>` — ...' for every selected project "
        "in every provider group, including projects with no confirmed findings. "
        "Explain each project's evidence, disposition, and limitations; do not "
        "treat a read-only dossier as outside scope merely because another provider "
        "collected it. "
        "If output/report-resets/ has snapshots, consult their follow-up and "
        "closed-issue archives, newest first, for historical status and stable IDs; a reset is "
        "not new evidence that a previously resolved issue is vulnerable again. "
        "OSV-Scanner and Trivy may be used only against paths in the selected groups. "
        "Record provider/model routing and any failed or missing dossier as a limitation.\n\n"
        f"Analysis plan: {plan_path}\nOther-provider dossiers:\n{dossier_lines}\n\n"
        + execution_guidance(execution_mode)
    )


def canonical_report_paths(started_at: dt.datetime) -> dict[str, Path]:
    """Resolve the three canonical local outputs expected from a complete run."""
    config_path = effective_config_path(CONFIG_DIR, "reports.yaml")
    reports = safe_load_yaml(config_path).get("reports", {})
    daily_directory = ROOT / str(
        reports.get("daily_directory", "output/daily-advisory-check")
    )
    daily_filename = started_at.strftime(
        str(reports.get("daily_filename", "%Y-%m-%d.md"))
    )
    return {
        "daily report": daily_directory / daily_filename,
        "summary": ROOT / str(reports.get("summary_file", "output/check-summary.md")),
        "follow-up": ROOT / str(reports.get("followup_file", "output/followup.md")),
    }


def report_signature(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_canonical_report_updates(
    paths: dict[str, Path], before: dict[str, str | None],
    *, expected_project_ids: list[str] | None = None,
    prior_daily_text: str | None = None,
) -> tuple[bool, str]:
    """Reject a nominally successful coordinator that did not publish its result."""
    missing = [
        name for name, path in paths.items()
        if not path.is_file() or not path.stat().st_size
    ]
    changed = {
        name: report_signature(path) != before.get(name)
        for name, path in paths.items()
    }
    unchanged_required = [
        name for name in ("daily report", "summary") if not changed.get(name, False)
    ]
    problems: list[str] = []
    if missing:
        problems.append("missing or empty: " + ", ".join(missing))
    if unchanged_required:
        problems.append("not updated: " + ", ".join(unchanged_required))
    if expected_project_ids and paths["daily report"].is_file():
        daily_text = paths["daily report"].read_text(encoding="utf-8", errors="replace")
        current_text = (
            daily_text[len(prior_daily_text):]
            if prior_daily_text is not None and daily_text.startswith(prior_daily_text)
            else daily_text
        )
        headings = list(re.finditer(
            r"(?im)^(#{2,4})\s+Projects and technologies involved\s*$",
            current_text,
        ))
        if not headings:
            problems.append("missing current projects and technologies section")
        else:
            heading = headings[-1]
            level = len(heading.group(1))
            section = current_text[heading.end():]
            next_heading = re.search(rf"(?m)^#{{1,{level}}}\s+", section)
            if next_heading:
                section = section[:next_heading.start()]
            missing_projects: list[str] = []
            for project_id in sorted(set(expected_project_ids)):
                expected_count = expected_project_ids.count(project_id)
                marker = re.compile(
                    rf"(?m)^\s*-\s*Project:\s*`{re.escape(project_id)}`\s*(?:—|[-:]|$)",
                )
                if len(marker.findall(section)) < expected_count:
                    missing_projects.append(project_id)
            if missing_projects:
                problems.append("missing project coverage: " + ", ".join(missing_projects))
    if problems:
        return False, "; ".join(problems)
    followup_state = "updated" if changed.get("follow-up") else "verified unchanged"
    return True, f"daily report and summary updated; follow-up {followup_state}"


def ai_command(
    provider: str, profile: str | None = None, execution_mode: str | None = None,
    *, non_interactive: bool = False, prompt: str | None = None,
    read_only: bool = False,
) -> list[str] | None:
    executable = resolve_agent_executable(provider)
    if not executable:
        return None
    _profile_name, models = configured_models(profile)
    model = models[provider]
    prompt = prompt or analysis_prompt(provider, execution_mode)
    if provider == "codex":
        if non_interactive:
            command = [executable, "--search", "--ask-for-approval", "never"]
            if not read_only:
                command.extend(("--config", "sandbox_workspace_write.network_access=true"))
            command.extend(("exec", "--model", model))
            if read_only:
                command.extend(("--sandbox", "read-only"))
            else:
                command.extend(("--sandbox", "workspace-write"))
            return [*command, "--json", prompt]
        return [executable, "--search", "--model", model, prompt]
    if non_interactive:
        permission_mode = "plan" if read_only else "auto"
        return [
            executable, "--settings", claude_sandbox_settings(),
            "--print", "--model", model,
            "--permission-mode", permission_mode, "--permission-prompts", "none",
            "--output-format", "stream-json", "--verbose", prompt,
        ]
    return [
        executable, "--settings", claude_sandbox_settings(),
        "--model", model, prompt,
    ]


def prepare_analysis_service(
    provider: str, execution_mode: str | None = None, *, assume_yes: bool = False,
) -> bool:
    projects_config = effective_config_path(CONFIG_DIR, "projects.example.yaml")
    if projects_config == EXAMPLE_CONFIG:
        print("Local configuration is missing. Use menu option 3 first.", file=sys.stderr)
        return False
    config = safe_load_yaml(projects_config)
    if not configured_roots_ready(config):
        print("Fix the configured project roots before starting the analysis.", file=sys.stderr)
        return False
    current, detail = inventory_is_current(config)
    if not current:
        print(f"Local inventory requires refresh: {detail}")
        if not assume_yes and not confirm("Refresh it before starting the analysis?"):
            return False
        if refresh_inventory(assume_yes=True) != 0:
            return False
    if validate_configuration() != 0:
        return False
    if check_prerequisites(provider) != 0:
        return False
    print("Checking advisory source reachability before AI launch...")
    return check_sources(execution_mode) == 0


def run_ai_check(
    provider: str | None = None, profile: str | None = None,
    execution_mode: str | None = None, *, assume_yes: bool = False,
    non_interactive: bool = False,
) -> int:
    interactive_selection = provider is None
    if provider is None:
        print("Select the AI provider:")
        print("  1. Codex")
        print("  2. Claude Code")
        print("  0. Cancel")
        choice = input("Provider: ").strip()
        provider = {"1": "codex", "2": "claude"}.get(choice)
        if choice == "0":
            return 0
        if provider is None:
            print("Invalid provider.")
            return 1
    if interactive_selection and profile is None:
        profile = choose_model_profile()
        if profile is None:
            return 0
    if interactive_selection and execution_mode is None:
        execution_mode = choose_execution_mode()
        if execution_mode is None:
            return 0
    profile_name, models = configured_models(profile)
    mode_name, _mode = configured_execution(execution_mode)
    if not prepare_analysis_service(provider, mode_name, assume_yes=assume_yes):
        print("Analysis was not started because one or more prerequisites failed.")
        return 1
    try:
        plan = build_analysis_plan(
            safe_load_yaml(effective_config_path(CONFIG_DIR, "projects.example.yaml")), provider,
        )
    except AnalysisPlanError as error:
        print(f"Unable to build analysis plan: {error}", file=sys.stderr)
        return 1
    if not plan["selected_count"]:
        print("No inventory projects are selected for advisory analysis.", file=sys.stderr)
        return 1
    required = required_providers(plan)
    for required_provider in required:
        if required_provider == provider:
            continue
        if check_prerequisites(required_provider) != 0:
            print(
                f"Analysis requires {required_provider} for its preferred project group.",
                file=sys.stderr,
            )
            return 1
    summary = plan_summary(plan)
    print(f"Analysis routing: {summary}")
    if not assume_yes and not confirm(
        f"Start routed analysis with {provider} as coordinator and profile {profile_name} "
        f"in {mode_name} mode? {summary}. It may access the network and update ignored "
        "local outputs."
    ):
        print("Cancelled.")
        return 0
    started_at = dt.datetime.now(dt.timezone.utc)
    timestamp = started_at.strftime("%Y%m%dT%H%M%SZ")
    run_directory = (
        ROOT / "output/analysis-runs" / started_at.strftime("%Y/%m")
        / f"{timestamp}-{os.getpid()}"
    )
    plan_path = run_directory / "plan.json"
    summary_path = run_directory / "run-summary.txt"
    log_path = run_directory / "run.log"
    coordinator_output = run_directory / "coordinator-output.md"
    started_monotonic = time.monotonic()
    phase_results: list[str] = []
    plan["profile"] = profile_name
    plan["execution_mode"] = mode_name
    plan["models"] = {name: models[name] for name in required}
    write_private_json(plan_path, plan)
    append_private_line(
        log_path,
        f"{started_at.isoformat().replace('+00:00', 'Z')} START coordinator={provider} "
        f"profile={profile_name} mode={mode_name}",
    )
    completed_projects = 0
    emit_analysis_progress(
        phase="routing", status="running", provider=provider,
        completed=0, total=plan["selected_count"],
        message="Analysis plan ready",
    )

    def finish_run(status: str, exit_code: int) -> int:
        finished_at = dt.datetime.now(dt.timezone.utc)
        duration = round(time.monotonic() - started_monotonic, 2)
        append_private_line(
            log_path,
            f"{finished_at.isoformat().replace('+00:00', 'Z')} FINISH "
            f"status={status} exit_code={exit_code} duration_seconds={duration}",
        )
        groups = plan["groups"]
        lines = [
            f"Run ID: {run_directory.name}",
            f"Status: {status}",
            f"Exit code: {exit_code}",
            f"Started UTC: {started_at.isoformat().replace('+00:00', 'Z')}",
            f"Finished UTC: {finished_at.isoformat().replace('+00:00', 'Z')}",
            f"Duration seconds: {duration}",
            f"Operator: {getpass.getuser()}",
            f"Coordinator: {provider}",
            f"Profile: {profile_name}",
            f"Execution mode: {mode_name}",
            f"Selected projects: {plan['selected_count']}",
            f"Excluded projects: {plan['excluded_count']}",
            f"Codex projects: {len(groups['codex'])}",
            f"Claude projects: {len(groups['claude'])}",
        ]
        lines.extend(
            f"{name.title()} model: {models[name]}" for name in required
        )
        lines.extend(f"Phase: {result}" for result in phase_results)
        lines.extend((
            f"Plan: {plan_path.name}",
            f"Event log: {log_path.name}",
            f"Coordinator output: {coordinator_output.name if coordinator_output.is_file() else 'not produced'}",
        ))
        write_private_text(summary_path, "\n".join(lines))
        return exit_code

    dossiers: list[Path] = []
    for worker in required:
        if worker == provider:
            continue
        projects = plan["groups"][worker]
        dossier = run_directory / f"{worker}-evidence.md"
        command = ai_command(
            worker, profile_name, mode_name, non_interactive=True,
            prompt=scoped_evidence_prompt(worker, projects, mode_name), read_only=True,
        )
        if command is None:
            print(f"{worker} CLI is unavailable after prerequisite checks.", file=sys.stderr)
            phase_results.append(f"{worker} evidence — failed (CLI unavailable)")
            emit_analysis_progress(
                phase="evidence", status="failed", provider=worker,
                completed=completed_projects, total=plan["selected_count"],
                active_projects=len(projects), message="AI CLI unavailable",
            )
            return finish_run("failed", 1)
        print(f"Collecting read-only {worker} evidence for {len(projects)} project(s)...")
        emit_analysis_progress(
            phase="evidence", status="running", provider=worker,
            completed=completed_projects, total=plan["selected_count"],
            active_projects=len(projects), message="Collecting read-only evidence",
        )
        append_private_line(
            log_path,
            f"{dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')} "
            f"PHASE_START provider={worker} type=evidence projects={len(projects)}",
        )
        result = run_tracked_command(
            command, worker, model=models[worker], profile=profile_name,
            execution_mode=mode_name, capture_path=dossier, event_log_path=log_path,
        )
        if (
            result != 0 or not dossier.is_file()
            or not dossier.read_text(encoding="utf-8", errors="replace").strip()
        ):
            print(f"{worker} evidence phase failed; canonical reports were not updated.", file=sys.stderr)
            phase_results.append(f"{worker} evidence — failed (exit {result or 1})")
            append_private_line(
                log_path,
                f"{dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')} "
                f"PHASE_FINISH provider={worker} type=evidence status=failed "
                f"exit_code={result or 1}",
            )
            emit_analysis_progress(
                phase="evidence", status="failed", provider=worker,
                completed=completed_projects, total=plan["selected_count"],
                active_projects=len(projects), message="Evidence collection failed",
            )
            return finish_run("failed", result or 1)
        completed_projects += len(projects)
        phase_results.append(f"{worker} evidence — completed (exit 0)")
        append_private_line(
            log_path,
            f"{dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')} "
            f"PHASE_FINISH provider={worker} type=evidence status=completed exit_code=0",
        )
        emit_analysis_progress(
            phase="evidence", status="completed", provider=worker,
            completed=completed_projects, total=plan["selected_count"],
            message="Evidence group completed",
        )
        dossiers.append(dossier)
    canonical_paths = canonical_report_paths(started_at)
    canonical_before = {
        name: report_signature(path) for name, path in canonical_paths.items()
    }
    daily_path = canonical_paths["daily report"]
    prior_daily_text = (
        daily_path.read_text(encoding="utf-8", errors="replace")
        if daily_path.is_file() else None
    )
    command = ai_command(
        provider, profile_name, mode_name, non_interactive=True,
        prompt=consolidation_prompt(provider, plan_path, dossiers, mode_name),
    )
    if command is None:
        print(f"{provider} CLI is unavailable after prerequisite checks.", file=sys.stderr)
        phase_results.append(f"{provider} consolidation — failed (CLI unavailable)")
        emit_analysis_progress(
            phase="consolidation", status="failed", provider=provider,
            completed=completed_projects, total=plan["selected_count"],
            active_projects=len(plan["groups"][provider]), message="AI CLI unavailable",
        )
        return finish_run("failed", 1)
    print(
        f"Consolidating with {provider} ({models[provider]}) for "
        f"{len(plan['groups'][provider])} directly assigned project(s)..."
    )
    emit_analysis_progress(
        phase="consolidation", status="running", provider=provider,
        completed=completed_projects, total=plan["selected_count"],
        active_projects=len(plan["groups"][provider]),
        message="Consolidating evidence and updating reports",
    )
    append_private_line(
        log_path,
        f"{dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')} "
        f"PHASE_START provider={provider} type=consolidation "
        f"projects={len(plan['groups'][provider])}",
    )
    result = run_tracked_command(
        command, provider, model=models[provider], profile=profile_name,
        execution_mode=mode_name, capture_path=coordinator_output,
        event_log_path=log_path,
    )
    reports_valid = False
    report_validation = "coordinator command failed"
    if result == 0:
        reports_valid, report_validation = validate_canonical_report_updates(
            canonical_paths, canonical_before,
            expected_project_ids=[
                item["id"] for projects in plan["groups"].values() for item in projects
            ],
            prior_daily_text=prior_daily_text,
        )
        if not reports_valid:
            result = 2
            print(
                "Coordinator exited successfully but canonical output validation failed: "
                + report_validation,
                file=sys.stderr,
            )
            append_private_line(
                log_path,
                f"{dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')} "
                f"OUTPUT_VALIDATION status=failed detail={report_validation}",
            )
        else:
            append_private_line(
                log_path,
                f"{dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')} "
                f"OUTPUT_VALIDATION status=completed detail={report_validation}",
            )
    phase_status = "completed" if result == 0 else "failed"
    phase_results.append(f"{provider} consolidation — {phase_status} (exit {result})")
    append_private_line(
        log_path,
        f"{dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')} "
        f"PHASE_FINISH provider={provider} type=consolidation status={phase_status} "
        f"exit_code={result}",
    )
    emit_analysis_progress(
        phase="complete" if result == 0 else "consolidation",
        status="completed" if result == 0 else "failed", provider=provider,
        completed=plan["selected_count"] if result == 0 else completed_projects,
        total=plan["selected_count"],
        active_projects=0 if result == 0 else len(plan["groups"][provider]),
        message="Analysis completed" if result == 0 else "Consolidation failed",
    )
    return finish_run("completed" if result == 0 else "failed", result)


def launch_desktop() -> int:
    try:
        from desktop.app import run
    except ImportError as error:
        print(f"Desktop dependencies are unavailable: {error}", file=sys.stderr)
        print(
            "Run `./fairy-security-advisory --gui` from the project root and "
            "confirm dependency installation, or use `--yes`.",
            file=sys.stderr,
        )
        return 1
    return run()


def install_desktop_launcher(*, assume_yes: bool = False) -> int:
    if not assume_yes and not confirm(
        "Install the fAIry application-menu launcher and icon for the current Linux user?"
    ):
        print("Cancelled.")
        return 0
    try:
        desktop_path, icon_path = install_linux_desktop_entry()
    except OSError as error:
        print(f"Desktop integration failed: {error}", file=sys.stderr)
        return 1
    print(f"Application launcher installed: {desktop_path}")
    print(f"Application icon installed: {icon_path}")
    print("The application may take a few seconds to appear in the desktop menu.")
    return 0


def remove_desktop_launcher(*, assume_yes: bool = False) -> int:
    if not assume_yes and not confirm(
        "Remove the fAIry application-menu launcher and icon for the current Linux user?"
    ):
        print("Cancelled.")
        return 0
    try:
        desktop_path, icon_path = remove_linux_desktop_entry()
    except OSError as error:
        print(f"Unable to remove desktop integration: {error}", file=sys.stderr)
        return 1
    print(f"Removed application launcher: {desktop_path}")
    print(f"Removed application icon: {icon_path}")
    return 0


MENU: list[tuple[str, str, Callable[[], int]]] = [
    ("1", "Install/update the project environment", setup_project_environment),
    ("2", "Check requirements and installed AI agents", check_prerequisites),
    ("3", "Initialize local configuration", initialize_local_config),
    ("4", "Validate configuration and optional tools", validate_configuration),
    ("5", "Preview inventory without writing", preview_inventory),
    ("6", "Refresh local inventory", refresh_inventory),
    ("7", "Check advisory source reachability", check_sources),
    ("8", "Run automated tests", run_tests),
    ("9", "Run all pre-publication checks", prepublication_check),
    ("10", "Run the complete AI advisory check", run_ai_check),
    ("11", "Show complete AI check commands", show_skill_usage),
    (
        "12", "Start the desktop application",
        lambda: run_command([str(ROOT / "fairy-security-advisory"), "--gui"]),
    ),
    ("13", "Back up configuration files", backup_configuration),
    ("14", "Import a configuration backup", import_backup_configuration),
    ("15", "Archive closed follow-up activities", archive_followups),
    ("16", "Restore one configuration section to factory defaults", restore_factory_defaults),
    ("17", "Install the Linux application-menu launcher", install_desktop_launcher),
    ("18", "Remove the Linux application-menu launcher", remove_desktop_launcher),
]


def interactive_menu() -> int:
    print_cli_banner()
    while True:
        print("\nMain menu")
        for key, label, _action in MENU:
            print(f"  {key}. {label}")
        print("  0. Exit")
        choice = input("Select an option: ").strip()
        if choice == "0":
            return 0
        selected = next((action for key, _label, action in MENU if key == choice), None)
        if selected is None:
            print("Invalid option.")
            continue
        print()
        selected()


def main() -> int:
    action_names = (
        "menu", "setup", "prerequisites", "init", "validate", "preview",
        "refresh", "sources", "tests", "prepublish", "ai-check", "skill-help", "gui", "backup",
        "import-backup",
        "archive-followups",
        "restore-defaults",
        "desktop-install", "desktop-remove",
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=action_names, default="menu")
    parser.add_argument("--provider", choices=AI_PROMPTS)
    _default_profile, available_profiles = model_profiles()
    parser.add_argument("--profile", choices=available_profiles)
    _default_mode, available_modes = execution_modes()
    parser.add_argument("--mode", choices=available_modes)
    parser.add_argument("--yes", action="store_true", help="Confirm requested local writes or AI launch")
    parser.add_argument("--archive", help="Configuration backup ZIP used by --action import-backup")
    parser.add_argument(
        "--section", choices=RESTORE_SECTIONS,
        help="Configuration section used by --action restore-defaults",
    )
    parser.add_argument(
        "--non-interactive", action="store_true",
        help="Use non-interactive agent commands suitable for the desktop interface",
    )
    args = parser.parse_args()
    actions: dict[str, Callable[[], int]] = {
        "menu": interactive_menu,
        "setup": lambda: setup_project_environment(assume_yes=args.yes),
        "prerequisites": lambda: check_prerequisites(args.provider),
        "init": lambda: initialize_local_config(assume_yes=args.yes),
        "validate": validate_configuration,
        "preview": preview_inventory,
        "refresh": lambda: refresh_inventory(assume_yes=args.yes),
        "sources": lambda: check_sources(args.mode),
        "tests": run_tests,
        "prepublish": prepublication_check,
        "ai-check": lambda: run_ai_check(
            args.provider, args.profile, args.mode, assume_yes=args.yes,
            non_interactive=args.non_interactive,
        ),
        "skill-help": show_skill_usage,
        "backup": lambda: backup_configuration(assume_yes=args.yes),
        "import-backup": lambda: import_backup_configuration(args.archive, assume_yes=args.yes),
        "archive-followups": archive_followups,
        "restore-defaults": lambda: restore_factory_defaults(args.section, assume_yes=args.yes),
        "desktop-install": lambda: install_desktop_launcher(assume_yes=args.yes),
        "desktop-remove": lambda: remove_desktop_launcher(assume_yes=args.yes),
        "gui": launch_desktop,
    }
    return actions[args.action]()


if __name__ == "__main__":
    raise SystemExit(main())
