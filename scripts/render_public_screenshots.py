#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Render repository screenshots with synthetic data and no local environment content."""

from __future__ import annotations

import os
import sys
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PySide6.QtGui import QIcon  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from desktop import services  # noqa: E402
from desktop.main_window import MainWindow  # noqa: E402

ASSETS = ROOT / "docs/assets"


def demo_followup() -> str:
    return (
        "# Follow-up\n\n"
        "| ID | Advisory / CVE | Project | Description | Priority | Owner | Status | Opened | Last updated | Next action | Due date | Completion evidence | Source URL |\n"
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|\n"
        "| DEMO-001 | DEMO-ADV-001 | customer-portal | Example framework update | High | Application team | Open | 2026-11-16 | 2026-11-16 | Validate the fixed release in staging | 2026-11-20 | — | [Vendor advisory](https://example.com/security/advisories/demo-001) |\n"
        "| DEMO-002 | DEMO-ADV-002 | payments-api | Example runtime advisory | Medium | Platform team | Needs verification | 2026-11-16 | 2026-11-16 | Confirm the deployed runtime version | — | — | [Vendor advisory](https://example.com/security/advisories/demo-002) |\n"
        "| DEMO-003 | DEMO-ADV-003 | analytics-worker | Example transitive dependency | Low | Security team | Monitoring | 2026-11-15 | 2026-11-16 | Monitor upstream remediation | — | — | [Project advisory](https://example.com/security/advisories/demo-003) |\n"
    )


def demo_summary() -> str:
    return (
        "# Current security advisory status\n\n"
        "**Last check:** 2026-11-16 15:30 UTC\n\n"
        "- Three demonstration activities remain under review.\n"
        "- Primary-source verification is complete for two example advisories.\n"
        "- No scanned project was modified during analysis.\n"
    )


def demo_daily() -> str:
    return (
        "# Daily advisory check — demonstration\n\n"
        "This public screenshot uses synthetic projects and advisory identifiers.\n\n"
        "## Projects and technologies involved\n\n"
        "- customer-portal: TypeScript, React, Node.js.\n"
        "- payments-api: Python, FastAPI, PostgreSQL.\n"
        "- analytics-worker: Java, containers, CI/CD.\n"
    )


def render() -> tuple[Path, Path]:
    ASSETS.mkdir(parents=True, exist_ok=True)
    dashboard_path = ASSETS / "fairy-security-advisory-dashboard.png"
    followup_path = ASSETS / "fairy-security-advisory-followup.png"
    with TemporaryDirectory() as directory:
        demo = Path(directory)
        followup = demo / "followup.md"
        summary = demo / "check-summary.md"
        daily = demo / "daily-check.md"
        followup.write_text(demo_followup(), encoding="utf-8")
        summary.write_text(demo_summary(), encoding="utf-8")
        daily.write_text(demo_daily(), encoding="utf-8")
        report_entries = [
            ("Follow-up", followup),
            ("Current summary", summary),
            ("Daily · demonstration", daily),
        ]
        statistics = {
            "total": 8,
            "open": 3,
            "today": 2,
            "month": 8,
            "projects": {"customer-portal": 3, "payments-api": 3, "analytics-worker": 2},
            "priorities": {"Critical": 1, "High": 3, "Medium": 3, "Low": 1},
            "statuses": {"Open": 3, "Needs verification": 2, "Monitoring": 2, "Completed": 1},
            "languages": {"Python": 3, "TypeScript": 3, "Java": 2, "PHP": 1},
        }
        projects = [
            {"id": "customer-portal", "path": "/demo/customer-portal", "roles": ["frontend"],
             "languages": [{"name": "TypeScript"}], "frameworks_and_tooling": ["React"]},
            {"id": "payments-api", "path": "/demo/payments-api", "roles": ["backend"],
             "languages": [{"name": "Python"}], "frameworks_and_tooling": ["FastAPI"]},
        ]
        factory_effective = lambda path: services.factory_for_local(services.CONFIG_DIR, path)
        parse_followup = services.followup_activities
        parse_open_followup = services.open_followup_activities
        with ExitStack() as stack:
            stack.enter_context(patch.object(services, "developer_tools_enabled", return_value=False))
            stack.enter_context(patch.object(services, "effective_path_for_local", side_effect=factory_effective))
            stack.enter_context(patch.object(services, "inventory_projects", return_value=projects))
            stack.enter_context(patch.object(services, "inventory_age", return_value="demonstration data"))
            stack.enter_context(patch.object(services, "report_entries", return_value=report_entries))
            stack.enter_context(patch.object(
                services, "reports_config",
                return_value={"followup_file": str(followup)},
            ))
            stack.enter_context(patch.object(services, "security_statistics", return_value=statistics))
            stack.enter_context(patch.object(
                services, "ai_options",
                return_value=("economical", ["economical", "balanced", "thorough"],
                              "economical", ["economical", "balanced", "fast"]),
            ))
            stack.enter_context(patch.object(
                services, "followup_activities",
                side_effect=lambda path=None: parse_followup(path or followup),
            ))
            stack.enter_context(patch.object(
                services, "open_followup_activities",
                side_effect=lambda path=None: parse_open_followup(path or followup),
            ))
            stack.enter_context(patch.object(services, "component_status", return_value=[
                ("Local configuration", "Ready", "demonstration configuration"),
                ("Inventory", "Ready", "2 demonstration projects"),
            ]))
            stack.enter_context(patch.object(
                services, "agent_component_status",
                side_effect=lambda provider: (provider, "Missing", "not configured for screenshot"),
            ))
            application = QApplication.instance() or QApplication([])
            application.setApplicationName("fAIry Security Advisory")
            application.setStyle("Fusion")
            application.setWindowIcon(QIcon(str(ROOT / "desktop/assets/fairy-security-advisory-icon.png")))
            window = MainWindow()
            window.resize(1440, 900)
            window.show()
            application.processEvents()
            window.navigation.setCurrentRow(0)
            application.processEvents()
            if not window.grab().save(str(dashboard_path)):
                raise RuntimeError(f"Unable to save {dashboard_path}")
            window.navigation.setCurrentRow(3)
            window.report_list.setCurrentRow(0)
            application.processEvents()
            if not window.grab().save(str(followup_path)):
                raise RuntimeError(f"Unable to save {followup_path}")
            window.close()
            window.deleteLater()
            application.processEvents()
    return dashboard_path, followup_path


if __name__ == "__main__":
    for generated in render():
        print(generated.relative_to(ROOT))
