#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Move completed follow-up rows into private year/month Markdown archives."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import tempfile
from pathlib import Path

import yaml

try:
    from configuration import effective_config_path
except ImportError:
    from scripts.configuration import effective_config_path


CLOSED_MARKERS = ("closed", "completed", "resolved", "not applicable", "ignored")


def is_closed_status(status: str) -> bool:
    return any(marker in status.casefold() for marker in CLOSED_MARKERS)


def markdown_cells(line: str) -> list[str]:
    return [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text if text.endswith("\n") else f"{text}\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _existing_archive_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("|"):
            continue
        cells = markdown_cells(line)
        if cells and cells[0] not in {"ID", "---"} and not set(cells[0]) <= {"-", ":"}:
            rows[cells[0]] = line
    return rows


def archive_closed_followups(
    root: Path, *, followup_path: Path | None = None,
    archive_directory: Path | None = None, today: dt.date | None = None,
) -> dict[str, object]:
    """Archive closed rows first, then atomically remove them from follow-up."""
    if followup_path is None or archive_directory is None:
        reports_path = effective_config_path(root / "config", "reports.yaml")
        config = yaml.safe_load(reports_path.read_text(encoding="utf-8")) or {}
        reports = config.get("reports", {})
        followup_path = followup_path or root / str(
            reports.get("followup_file", "output/followup.md")
        )
        archive_directory = archive_directory or root / str(
            reports.get("followup_archive_directory", "output/followup-archive")
        )
    if not followup_path.is_file():
        return {"archived": 0, "archives": []}

    lines = followup_path.read_text(encoding="utf-8", errors="replace").splitlines()
    header: list[str] = []
    header_line = ""
    separator_line = ""
    closed: list[tuple[int, str, list[str], str]] = []
    for index, line in enumerate(lines):
        if not line.startswith("|"):
            continue
        cells = markdown_cells(line)
        if not header:
            header = cells
            header_line = line
            continue
        if all(cell and set(cell) <= {"-", ":"} for cell in cells):
            separator_line = line
            continue
        if len(cells) != len(header):
            continue
        row = dict(zip(header, cells))
        if is_closed_status(row.get("Status", "")):
            date_value = row.get("Last updated", "")
            match = re.match(r"^(\d{4})-(\d{2})", date_value)
            period = f"{match.group(1)}-{match.group(2)}" if match else (
                today or dt.datetime.now(dt.timezone.utc).date()
            ).strftime("%Y-%m")
            closed.append((index, period, cells, line))
    if not closed:
        return {"archived": 0, "archives": []}
    if not header_line or not separator_line:
        raise ValueError("Follow-up Markdown table header is incomplete.")

    archive_paths: list[Path] = []
    for period in sorted({item[1] for item in closed}):
        year, month = period.split("-", 1)
        archive = archive_directory / year / f"{month}.md"
        rows = _existing_archive_rows(archive)
        for _index, row_period, cells, line in closed:
            if row_period == period:
                rows[cells[0]] = line
        body = "\n".join(rows[key] for key in sorted(rows, key=str.casefold))
        content = (
            f"# Security advisory follow-up archive — {period}\n\n"
            "Closed activities retained for historical reference. Reopen work by creating "
            "a new follow-up activity linked to the archived ID and new evidence.\n\n"
            f"{header_line}\n{separator_line}\n{body}\n"
        )
        _atomic_write(archive, content)
        archive_paths.append(archive)

    closed_indices = {item[0] for item in closed}
    remaining = "\n".join(
        line for index, line in enumerate(lines) if index not in closed_indices
    ) + "\n"
    _atomic_write(followup_path, remaining)
    return {"archived": len(closed), "archives": archive_paths}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    args = parser.parse_args()
    root = Path(args.root).resolve()
    result = archive_closed_followups(root)
    print(f"Archived follow-up activities: {result['archived']}")
    for path in result["archives"]:
        print(path.relative_to(root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
