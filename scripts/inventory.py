#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Build a conservative, read-only technology inventory.

Read manifests and file names without opening secret files or executing project
code. The only permitted write is the selected local project configuration.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import yaml

try:
    from configuration import effective_config_path
except ImportError:
    from scripts.configuration import effective_config_path


SKIP_DIRS = {
    ".git", ".cache", ".idea", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".sub-worktrees", ".tox", ".venv", "__pycache__", "artifacts", "build",
    "bug_reports", "cache", "coverage", "dist", "node_modules", "runtime",
    "target", "third-party", "third_parties", "thirdparties", "tmp", "vendor",
    "venv", ".work-logs", "worklogs",
}
SECRET_NAMES = {
    ".env", ".env.local", "credentials", "credentials.json", "secrets.yaml",
    "secrets.yml", "dataSources.local.xml",
}
PROJECT_MARKERS = {
    "composer.json", "package.json", "pyproject.toml", "requirements.txt",
    "Pipfile", "poetry.lock", "uv.lock", "pom.xml", "build.gradle",
    "build.gradle.kts", "Gemfile", "go.mod", "Cargo.toml", "Vagrantfile",
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
}
SOURCE_EXTENSIONS = set(EXT for EXT in (
    ".php", ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".rb", ".pl",
    ".sh", ".go", ".rs", ".cs",
))
NON_PRODUCT_NAMES = re.compile(r"(^issue-|\.wiki$|^specs-|^worklogs?$)", re.I)
NESTED_PROJECT_AREAS = {"e2e-tests", "frontend", "subprojects", "tools"}
NESTED_NON_PROJECT_PARTS = {"config", "deploy", "library", "sass", "src", "terser", "jsbundler"}
MANIFEST_NAMES = PROJECT_MARKERS | {
    "composer.lock", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "Pipfile.lock", "Cargo.lock", "Gemfile.lock", "go.sum",
}

EXT_LANG = {
    ".php": "PHP", ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript/JSX",
    ".mjs": "JavaScript", ".cjs": "JavaScript", ".ts": "TypeScript",
    ".tsx": "TypeScript/TSX", ".java": "Java", ".kt": "Kotlin", ".rb": "Ruby",
    ".pl": "Perl", ".pm": "Perl", ".sh": "Shell", ".bash": "Bash",
    ".zsh": "Zsh", ".fish": "Fish", ".sql": "SQL", ".html": "HTML",
    ".htm": "HTML", ".xhtml": "XHTML", ".css": "CSS", ".scss": "SCSS",
    ".sass": "Sass", ".less": "Less", ".xml": "XML", ".xsl": "XSLT",
    ".xslt": "XSLT", ".wsdl": "WSDL", ".xsd": "XSD", ".twig": "Twig",
    ".smarty": "Smarty", ".dwoo": "Dwoo", ".ejs": "EJS", ".hbs": "Handlebars",
    ".tf": "HCL/Terraform", ".go": "Go", ".rs": "Rust", ".cs": "C#",
}

FRAMEWORK_PACKAGES = {
    "laravel/framework": "Laravel", "laravel/sanctum": "Laravel Sanctum",
    "laminas/laminas-mvc": "Laminas MVC", "zendframework/zendframework1": "Zend Framework 1",
    "shardj/zf1-future": "zf1-future", "symfony/framework-bundle": "Symfony",
    "react": "React", "redux": "Redux", "rxjs": "RxJS", "express": "Express",
    "socket.io": "Socket.IO", "jquery": "jQuery", "vite": "Vite",
    "webpack": "webpack", "esbuild": "esbuild", "grunt": "Grunt",
    "@babel/core": "Babel", "cypress": "Cypress", "vitest": "Vitest",
    "bootstrap": "Bootstrap", "tailwindcss": "Tailwind CSS", "ckeditor": "CKEditor",
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI", "pytest": "pytest",
    "onnxruntime": "ONNX Runtime", "sherpa-onnx": "Sherpa-ONNX", "vosk": "Vosk",
    "boto3": "AWS SDK", "google-cloud": "Google Cloud SDK",
}


def safe_load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Invalid configuration: {path}")
    return data


def atomic_write_yaml(path: Path, data: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=100),
        encoding="utf-8",
    )
    temporary.replace(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def is_skipped(path: Path) -> bool:
    lowered = {part.lower() for part in path.parts}
    return any(
        part in SKIP_DIRS or part.endswith(".worktrees")
        for part in path.parts
    ) or "htdocs" in lowered and "library" in lowered or "libs" in lowered and "thirdparties" in lowered


def matches_exclude(relative: Path, patterns: Iterable[str], *, directory: bool = False) -> bool:
    """Return whether a root-relative path matches a configured glob."""
    candidate = relative.as_posix().strip("/")
    if candidate in {"", "."}:
        return False
    for raw_pattern in patterns:
        pattern = str(raw_pattern).strip().replace("\\", "/")
        while pattern.startswith("./"):
            pattern = pattern[2:]
        pattern = pattern.lstrip("/")
        if not pattern:
            continue
        variants = {pattern}
        if pattern.startswith("**/"):
            variants.add(pattern[3:])
        for variant in variants:
            if fnmatch.fnmatchcase(candidate, variant):
                return True
            if directory and variant.endswith("/**"):
                directory_pattern = variant[:-3].rstrip("/")
                if fnmatch.fnmatchcase(candidate, directory_pattern):
                    return True
    return False


def discover_projects(
    root: Path, exclude_patterns: Iterable[str] = (), max_depth: int = 6,
) -> list[Path]:
    candidates: set[Path] = set()
    if not root.is_dir():
        return []
    root_depth = len(root.parts)
    for current, dirs, files in os.walk(root, topdown=True):
        current_path = Path(current)
        current_relative = current_path.relative_to(root)
        if matches_exclude(current_relative, exclude_patterns, directory=True):
            dirs[:] = []
            continue
        depth = len(current_path.parts) - root_depth
        names = set(files)
        git_marker = (current_path / ".git").exists()
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS and not d.endswith(".worktrees")
            and not matches_exclude(
                (current_path / d).relative_to(root), exclude_patterns, directory=True,
            )
        ]
        project_marker = bool(names & PROJECT_MARKERS)
        source_only_top_level = depth == 2 and any(Path(name).suffix.lower() in SOURCE_EXTENSIONS for name in names)
        duplicate_copy = current_path.name.endswith("_") and current_path.with_name(current_path.name.rstrip("_")).exists()
        non_product = bool(NON_PRODUCT_NAMES.search(current_path.name))
        if (git_marker or project_marker or source_only_top_level) and not duplicate_copy and not non_product and not is_skipped(current_relative):
            candidates.add(current_path)
        if depth >= max_depth:
            dirs[:] = []
    ordered = sorted(candidates, key=lambda p: (len(p.parts), str(p)))
    result: list[Path] = []
    for candidate in ordered:
        if not (candidate / ".git").exists():
            git_ancestors = [parent for parent in candidate.parents if parent in candidates and (parent / ".git").exists()]
            if git_ancestors:
                nearest = max(git_ancestors, key=lambda p: len(p.parts))
                relative_parts = candidate.relative_to(nearest).parts
                first = relative_parts[0].lower() if relative_parts else ""
                lower_parts = {part.lower() for part in relative_parts}
                allowed_nested = first in NESTED_PROJECT_AREAS and not (lower_parts & NESTED_NON_PROJECT_PARTS)
                if first == "tools" and len(relative_parts) > 1:
                    allowed_nested = False
                if not allowed_nested:
                    continue
        if any(parent in candidates and (candidate / ".git").exists() is False
               for parent in candidate.parents if parent != candidate):
            # Subprojects with their own manifests remain useful; discard only
            # generated directories or directories without an explicit marker.
            if not any((candidate / marker).exists() for marker in PROJECT_MARKERS):
                continue
        result.append(candidate)
    return result


def iter_project_files(
    project: Path, root: Path, exclude_patterns: Iterable[str], limit: int,
) -> tuple[list[Path], bool]:
    files: list[Path] = []
    truncated = False
    for current, dirs, names in os.walk(project, topdown=True):
        current_path = Path(current)
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS and not d.endswith(".worktrees")
            and not matches_exclude(
                (current_path / d).relative_to(root), exclude_patterns, directory=True,
            )
        ]
        for name in names:
            path = current_path / name
            if (
                name in SECRET_NAMES
                or name.startswith(".env")
                or is_skipped(path.relative_to(project))
                or matches_exclude(path.relative_to(root), exclude_patterns)
            ):
                continue
            files.append(path)
            if len(files) >= limit:
                truncated = True
                return files, truncated
    return files, truncated


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}


def dependency_map(project: Path, files: list[Path]) -> tuple[dict[str, str], list[str], dict[str, str]]:
    deps: dict[str, str] = {}
    frameworks: set[str] = set()
    declared_runtimes: dict[str, str] = {}
    rel_names = {str(p.relative_to(project)): p for p in files}

    for rel in ("composer.json", "package.json"):
        path = rel_names.get(rel)
        if not path:
            continue
        data = read_json(path)
        for section in ("require", "require-dev", "dependencies", "devDependencies"):
            values = data.get(section, {})
            if isinstance(values, dict):
                for name, version in values.items():
                    deps[str(name)] = str(version)
        if rel == "composer.json":
            php = data.get("config", {}).get("platform", {}).get("php") if isinstance(data.get("config"), dict) else None
            php = php or (data.get("require", {}).get("php") if isinstance(data.get("require"), dict) else None)
            if php:
                declared_runtimes["PHP"] = str(php)
        else:
            engines = data.get("engines", {})
            if isinstance(engines, dict):
                for name, version in engines.items():
                    declared_runtimes[str(name)] = str(version)

    pyproject = rel_names.get("pyproject.toml")
    if pyproject:
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            project_data = data.get("project", {})
            if project_data.get("requires-python"):
                declared_runtimes["Python"] = str(project_data["requires-python"])
            for item in project_data.get("dependencies", []):
                match = re.match(r"([A-Za-z0-9_.-]+)\s*(.*)", str(item))
                if match:
                    deps[match.group(1)] = match.group(2).strip() or "unconstrained"
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            pass

    requirements = rel_names.get("requirements.txt")
    if requirements:
        try:
            for raw in requirements.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith(("#", "-")) or " @ " in line:
                    continue
                match = re.match(r"([A-Za-z0-9_.-]+)\s*([^;]*)", line)
                if match:
                    deps[match.group(1)] = match.group(2).strip() or "unconstrained"
        except (OSError, UnicodeError):
            pass

    for candidate in (project / ".python-version", project / "runtime.txt"):
        if candidate.is_file() and candidate.name not in SECRET_NAMES:
            try:
                declared_runtimes["Python"] = candidate.read_text(encoding="utf-8").strip()[:80]
            except (OSError, UnicodeError):
                pass
    pyvenv = project / "venv" / "pyvenv.cfg"
    if pyvenv.is_file():
        try:
            match = re.search(r"(?m)^version\s*=\s*(.+)$", pyvenv.read_text(encoding="utf-8"))
            if match:
                declared_runtimes["Python installed (local venv)"] = match.group(1).strip()
        except (OSError, UnicodeError):
            pass

    lowered = {name.lower(): name for name in deps}
    for needle, framework in FRAMEWORK_PACKAGES.items():
        if needle in lowered or any(name.startswith(needle) for name in lowered):
            frameworks.add(framework)
    return dict(sorted(deps.items(), key=lambda item: item[0].lower())), sorted(frameworks), declared_runtimes


def docker_and_infra(project: Path, files: list[Path]) -> dict[str, list[str]]:
    containers: set[str] = set()
    databases: set[str] = set()
    web: set[str] = set()
    os_values: set[str] = set()
    cicd: set[str] = set()
    iac: set[str] = set()
    virtualization: set[str] = set()
    rels = [str(p.relative_to(project)) for p in files]

    for path, rel in zip(files, rels):
        lower = rel.lower()
        name = path.name.lower()
        if name.startswith("dockerfile"):
            try:
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    match = re.match(r"\s*FROM\s+([^\s]+)", line, re.I)
                    if match:
                        image = match.group(1)
                        containers.add(image)
                        base = image.lower()
                        if any(x in base for x in ("debian", "ubuntu", "alpine", "rockylinux", "centos")):
                            os_values.add(image)
                        if "apache" in base:
                            web.add("Apache HTTP Server")
                        if "nginx" in base:
                            web.add("nginx")
            except OSError:
                pass
        if ".github/workflows/" in lower:
            cicd.add("GitHub Actions")
        if name == ".gitlab-ci.yml":
            cicd.add("GitLab CI")
        if name == "jenkinsfile":
            cicd.add("Jenkins")
        if lower.endswith(".tf") or name in {"terragrunt.hcl"}:
            iac.add("Terraform")
        if "ansible" in lower or name in {"ansible.cfg", "playbook.yml", "playbook.yaml"}:
            iac.add("Ansible")
        if "k8s" in lower or "kubernetes" in lower or name == "chart.yaml":
            iac.add("Kubernetes/Helm")
        if name == "vagrantfile":
            virtualization.update(("Vagrant", "VirtualBox"))
        if name.endswith(".service"):
            virtualization.add("systemd")

    joined = " ".join(rels).lower()
    indicators = {
        "PostgreSQL": ("postgres", "psycopg"), "MySQL/MariaDB": ("mysql", "mariadb", "pdo_mysql"),
        "SQLite": ("sqlite",), "MongoDB": ("mongo", "pymongo"), "Redis": ("redis",),
    }
    for label, needles in indicators.items():
        if any(n in joined for n in needles):
            databases.add(label)
    for label, needles in {
        "Apache HTTP Server": ("apache", ".htaccess"), "nginx": ("nginx",),
        "Caddy": ("caddyfile",), "Traefik": ("traefik",), "PHP-FPM": ("php-fpm", "fpm.conf"),
    }.items():
        if any(n in joined for n in needles):
            web.add(label)
    return {
        "containers": sorted(containers), "databases": sorted(databases),
        "web_servers_and_proxies": sorted(web), "operating_systems": sorted(os_values),
        "ci_cd": sorted(cicd), "infrastructure_as_code": sorted(iac),
        "virtualization_and_services": sorted(virtualization),
    }


def analyze_project(
    project: Path, root: Path, exclude_patterns: Iterable[str], limit: int,
) -> dict[str, Any]:
    files, truncated = iter_project_files(project, root, exclude_patterns, limit)
    languages = Counter(EXT_LANG.get(p.suffix.lower()) for p in files)
    languages.pop(None, None)
    deps, frameworks, runtimes = dependency_map(project, files)
    manifests = sorted(str(p.relative_to(project)) for p in files if p.name in MANIFEST_NAMES)
    agents = sorted(str(p.relative_to(project)) for p in files if p.name == "AGENTS.md")
    infra = docker_and_infra(project, files)
    frontend = any(x in languages for x in ("JavaScript", "JavaScript/JSX", "TypeScript", "TypeScript/TSX", "CSS", "SCSS"))
    backend = any(x in languages for x in ("PHP", "Python", "Java", "Ruby", "Go", "C#"))
    return {
        "id": re.sub(r"[^a-z0-9]+", "-", project.name.lower()).strip("-") or "project",
        "path": str(project),
        "git_repository": (project / ".git").exists(),
        "agents_files": agents,
        "roles": [role for role, present in (("frontend", frontend), ("backend", backend)) if present],
        "languages": [{"name": name, "files": count} for name, count in languages.most_common()],
        "declared_or_local_runtime_versions": dict(sorted(runtimes.items())),
        "frameworks_and_tooling": frameworks,
        "manifests_and_lockfiles": manifests,
        "dependencies": deps,
        **infra,
        "scan": {"files_examined": len(files), "truncated": truncated, "read_only": True},
    }


def build_inventory(config: dict[str, Any]) -> list[dict[str, Any]]:
    limit = int(config.get("inventory", {}).get("max_files_per_project", 20000))
    previous_preferences: dict[str, dict[str, Any]] = {}
    for previous in config.get("inventory", {}).get("projects", []):
        if not isinstance(previous, dict) or not previous.get("path"):
            continue
        settings = previous.get("advisory_checks", {})
        if isinstance(settings, dict):
            previous_preferences[str(previous["path"])] = settings
    projects: dict[Path, tuple[Path, tuple[str, ...]]] = {}
    for item in config.get("project_roots", []):
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        root = Path(str(item.get("path", ""))).expanduser().resolve()
        raw_patterns = item.get("exclude", [])
        exclude_patterns = tuple(str(value) for value in raw_patterns) if isinstance(raw_patterns, list) else ()
        for project in discover_projects(root, exclude_patterns):
            existing = projects.get(project)
            if existing is None or len(root.parts) > len(existing[0].parts):
                projects[project] = (root, exclude_patterns)
    inventory: list[dict[str, Any]] = []
    for project, (root, exclude_patterns) in sorted(projects.items(), key=lambda item: str(item[0])):
        result = analyze_project(project, root, exclude_patterns, limit)
        previous = previous_preferences.get(str(project), {})
        preferred_ai = previous.get("preferred_ai")
        result["advisory_checks"] = {
            "enabled": bool(previous.get("enabled", True)),
            "preferred_ai": preferred_ai if preferred_ai in {"codex", "claude"} else None,
        }
        inventory.append(result)
    return inventory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config-dir", default="config",
        help="Directory containing factory configuration and the local/ override directory",
    )
    parser.add_argument("--output", help="Output path; defaults to config/local/projects.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Print the inventory without writing")
    args = parser.parse_args()

    config_directory = Path(args.config_dir).resolve()
    config_path = effective_config_path(config_directory, "projects.example.yaml")
    if not config_path.exists():
        print(f"Configuration not found: {config_path}", file=sys.stderr)
        return 2
    config = safe_load_yaml(config_path)
    projects = build_inventory(config)
    generated = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    inventory = config.setdefault("inventory", {})
    inventory["generated_at"] = generated
    inventory["projects"] = projects
    inventory["scanner"] = {
        "name": "scripts/inventory.py", "version": 1,
        "privacy": "manifest names, dependency constraints and technical indicators only",
    }

    if args.dry_run:
        print(yaml.safe_dump({"generated_at": generated, "projects": projects}, allow_unicode=True, sort_keys=False))
        return 0
    output = Path(args.output).resolve() if args.output else config_directory / "local/projects.yaml"
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_write_yaml(output, config)
    print(f"Inventory updated: {len(projects)} projects in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
