# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import stat
import datetime as dt
from types import SimpleNamespace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import yaml

from desktop.services import (
    ConfigurationError, accept_eula, agent_authentication, agent_usage_status, analysis_routing,
    archive_and_reset_reports,
    analysis_run_entries, analysis_run_files, assistant_command, delete_analysis_run,
    eula_accepted, extract_issue_update, project_metadata,
    followup_source_links, proposal_changes, security_statistics, update_followup_activity,
    read_analysis_run_file, restore_factory_configuration, validate_config_text,
    write_config_text, update_manual_technologies, technology_names,
    inventory_technology_labels,
    update_inventory_preferences,
)


class DesktopConfigurationServicesTest(unittest.TestCase):
    def test_manual_technology_is_saved_locally_and_labeled_distinctly(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "projects.yaml"
            path.write_text(
                "schema_version: 1\ninventory:\n  projects:\n"
                "    - id: workspace\n      path: /private/workspace\n"
                "      languages:\n        - name: Python\n",
                encoding="utf-8",
            )
            with patch("desktop.services.effective_config_path", return_value=path):
                project = update_manual_technologies("/private/workspace", [{
                    "name": "PostgreSQL", "category": "databases",
                    "note": "User-declared use; version unverified",
                }])
            self.assertIn("PostgreSQL", technology_names(project))
            self.assertIn("PostgreSQL [manual]", inventory_technology_labels(project))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            saved = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(
                saved["inventory"]["projects"][0]["manual_technologies"][0]["category"],
                "databases",
            )

    def test_report_reset_archives_current_files_and_preserves_logs(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            files = (
                output / "followup.md", output / "check-summary.md",
                output / "daily-advisory-check/2026-11-16.md",
                output / "followup-archive/2026/11.md",
            )
            for path in files:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(path.name, encoding="utf-8")
            log = output / "analysis-runs/2026/11/run/run.log"
            log.parent.mkdir(parents=True)
            log.write_text("previous run", encoding="utf-8")
            config = {
                "followup_file": "output/followup.md",
                "summary_file": "output/check-summary.md",
                "daily_directory": "output/daily-advisory-check",
                "followup_archive_directory": "output/followup-archive",
            }
            with patch("desktop.services.ROOT", root), patch(
                "desktop.services.reports_config", return_value=config,
            ):
                snapshot, count = archive_and_reset_reports()

            self.assertEqual(count, 4)
            self.assertTrue(snapshot.is_dir())
            for path in files:
                self.assertFalse(path.exists())
                self.assertEqual(
                    (snapshot / path.relative_to(output)).read_text(encoding="utf-8"),
                    path.name,
                )
            self.assertEqual(log.read_text(encoding="utf-8"), "previous run")

    def test_report_reset_rejects_a_file_outside_output(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "output").mkdir()
            outside = root / "sensitive.md"
            outside.write_text("keep", encoding="utf-8")
            with patch("desktop.services.ROOT", root), patch(
                "desktop.services.report_entries", return_value=[("Current summary", outside)],
            ):
                with self.assertRaises(ConfigurationError):
                    archive_and_reset_reports()
            self.assertEqual(outside.read_text(encoding="utf-8"), "keep")

    def test_report_reset_rolls_back_when_a_move_fails(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            first = output / "followup.md"
            second = output / "check-summary.md"
            first.write_text("open issue", encoding="utf-8")
            second.write_text("summary", encoding="utf-8")
            replace = os.replace

            def fail_second(source: Path, target: Path) -> None:
                if Path(source) == second:
                    raise OSError("simulated move failure")
                replace(source, target)

            with patch("desktop.services.ROOT", root), patch(
                "desktop.services.report_entries",
                return_value=[("Follow-up", first), ("Current summary", second)],
            ), patch("desktop.services.os.replace", side_effect=fail_second):
                with self.assertRaises(ConfigurationError):
                    archive_and_reset_reports()
            self.assertEqual(first.read_text(encoding="utf-8"), "open issue")
            self.assertEqual(second.read_text(encoding="utf-8"), "summary")

    def test_analysis_logs_are_archived_read_and_deleted_as_one_safe_run(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "analysis-runs"
            run = root / "2026/11/20261116T180000Z-42"
            run.mkdir(parents=True)
            (run / "run-summary.txt").write_text(
                "Run ID: 20261116T180000Z-42\nStatus: completed\n"
                "Started UTC: 2026-11-16T18:00:00Z\nCoordinator: codex\n",
                encoding="utf-8",
            )
            (run / "run.log").write_text("START\nFINISH\n", encoding="utf-8")
            with patch("desktop.services.ANALYSIS_RUNS_DIR", root):
                entries = analysis_run_entries()
                files = analysis_run_files(run)
                content = read_analysis_run_file(run / "run.log")
                removed = delete_analysis_run(run)

            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["year"], "2026")
            self.assertEqual(entries[0]["month"], "11")
            self.assertEqual(entries[0]["status"], "completed")
            self.assertEqual([path.name for path in files], ["run-summary.txt", "run.log"])
            self.assertEqual(content, "START\nFINISH\n")
            self.assertEqual(removed, "20261116T180000Z-42")
            self.assertFalse(run.exists())

    def test_analysis_log_deletion_rejects_directories_outside_archive(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "analysis-runs"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "run-summary.txt").write_text("Status: completed\n", encoding="utf-8")
            with patch("desktop.services.ANALYSIS_RUNS_DIR", root):
                with self.assertRaises(ConfigurationError):
                    delete_analysis_run(outside)

    def test_analysis_routing_returns_counts_without_local_paths(self) -> None:
        config = {"inventory": {"projects": [
            {"id": "api", "path": "/private/api"},
            {"id": "web", "path": "/private/web", "advisory_checks": {
                "enabled": True, "preferred_ai": "claude",
            }},
            {"id": "off", "path": "/private/off", "advisory_checks": {
                "enabled": False, "preferred_ai": None,
            }},
        ]}}
        with patch("desktop.services.effective_config_path"), patch(
            "desktop.services.load_yaml", return_value=config,
        ):
            routing = analysis_routing("codex")

        self.assertEqual(routing["groups"], {"codex": 1, "claude": 1})
        self.assertEqual(routing["excluded"], 1)
        self.assertEqual(routing["required_providers"], ["codex", "claude"])
        self.assertNotIn("/private", repr(routing))

    def test_inventory_preferences_are_written_only_to_local_configuration(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "projects.yaml"
            path.write_text(
                "schema_version: 1\ninventory:\n  projects:\n"
                "    - id: api\n      path: /private/api\n",
                encoding="utf-8",
            )
            with patch("desktop.services.effective_config_path", return_value=path):
                update_inventory_preferences({
                    "/private/api": {"enabled": False, "preferred_ai": "codex"},
                })

            updated = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(updated["inventory"]["projects"][0]["advisory_checks"], {
                "enabled": False, "preferred_ai": "codex",
            })
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_factory_restore_rejects_paths_outside_local_configuration(self) -> None:
        with self.assertRaises(ConfigurationError):
            restore_factory_configuration(Path("/tmp/reports.yaml"))

    @patch("desktop.services.codex_rate_limits")
    @patch("desktop.services.agent_authentication", return_value=True)
    @patch("desktop.services.resolve_agent_executable", return_value="/usr/bin/codex")
    @patch("desktop.services.summarize_usage")
    def test_codex_usage_combines_local_totals_and_remaining_allowance(
        self, summary, _which, _authenticated, limits,
    ) -> None:
        summary.return_value = {
            "runs": 2, "successful_runs": 2, "input_tokens": 12500,
            "output_tokens": 900, "cached_input_tokens": 4000, "cost_usd": 0,
        }
        limits.return_value = {
            "rateLimits": {"primary": {"usedPercent": 23, "resetsAt": 1794996213}},
        }

        local, allowance = agent_usage_status("codex")

        self.assertIn("Tracked full checks: 2", local)
        self.assertIn("input 12.5K", local)
        self.assertIn("77% remaining", allowance)

    def test_followup_sources_prefer_configured_primary_url(self) -> None:
        activity = {
            "Advisory / CVE": "CVE-2026-1234",
            "Source URL": "[Vendor advisory](https://vendor.example/advisory/1234)",
        }
        self.assertEqual(followup_source_links(activity), [
            ("Vendor advisory", "https://vendor.example/advisory/1234"),
        ])

    def test_followup_sources_fall_back_to_official_cve_records(self) -> None:
        self.assertEqual(followup_source_links({
            "Advisory / CVE": "CVE-2026-1234; CVE-2026-56789",
        }), [
            ("CVE-2026-1234", "https://www.cve.org/CVERecord?id=CVE-2026-1234"),
            ("CVE-2026-56789", "https://www.cve.org/CVERecord?id=CVE-2026-56789"),
        ])

    @patch("desktop.services.subprocess.run")
    def test_claude_authentication_reads_only_logged_in_flag(self, run) -> None:
        run.return_value = SimpleNamespace(
            returncode=0,
            stdout='{"loggedIn": true, "email": "private@example.invalid"}',
            stderr="",
        )
        self.assertTrue(agent_authentication("claude", "/usr/bin/claude"))
        self.assertEqual(run.call_args.args[0], ["/usr/bin/claude", "auth", "status"])

    @patch("desktop.services.agent_authentication", return_value=True)
    @patch("desktop.services.resolve_agent_executable", return_value="/usr/bin/codex")
    def test_issue_assistant_uses_read_only_codex_execution(self, _which, _authenticated) -> None:
        command = assistant_command("codex", "economical", "prompt")
        self.assertIn("read-only", command)
        self.assertIn("never", command)
        self.assertNotIn("--approve-for-me", command)
        self.assertLess(command.index("--ask-for-approval"), command.index("exec"))

    def test_project_metadata_is_loaded_from_the_version_file(self) -> None:
        metadata = project_metadata()
        self.assertEqual(metadata["name"], "fAIry Security Advisory")
        self.assertEqual(metadata["version"], "0.2.0")
        self.assertEqual(metadata["author"], "Graziano Ugenti <gucw@proton.me>")
        self.assertEqual(metadata["last_modified_year"], "2026")

    def test_eula_acceptance_is_written_only_to_private_local_configuration(self) -> None:
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            config.mkdir()
            (config / "application.yaml").write_text(
                "schema_version: 1\napplication:\n  developer_tools: false\n"
                "  eula:\n    required_version: 1\n    accepted_version: null\n"
                "    accepted_at_utc: null\n",
                encoding="utf-8",
            )
            local = config / "local/application.yaml"
            with patch("desktop.services.CONFIG_DIR", config), patch(
                "desktop.services.LOCAL_CONFIG_DIR", config / "local",
            ), patch("desktop.services.LOCAL_APPLICATION_CONFIG", local):
                self.assertFalse(eula_accepted())
                accept_eula()
                self.assertTrue(eula_accepted())

            stored = yaml.safe_load(local.read_text(encoding="utf-8"))
            self.assertEqual(stored["application"]["eula"]["accepted_version"], "1")
            self.assertTrue(stored["application"]["eula"]["accepted_at_utc"].endswith("Z"))
            self.assertEqual(stat.S_IMODE(local.stat().st_mode), 0o600)

    def test_configuration_requires_schema_version_one(self) -> None:
        with self.assertRaises(ConfigurationError):
            validate_config_text("schema_version: 2\n")

    def test_private_configuration_is_written_atomically_with_private_mode(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "projects.local.yaml"
            write_config_text(path, "schema_version: 1\nproject_roots: []\n", private=True)

            self.assertEqual(path.read_text(encoding="utf-8"), "schema_version: 1\nproject_roots: []\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(list(path.parent.glob(".*.tmp")), [])

    def test_security_statistics_are_derived_from_local_markdown(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            followup = root / "followup.md"
            followup.write_text(
                "| ID | Advisory / CVE | Project | Description | Priority | Owner | Status | Opened |\n"
                "|---|---|---|---|---|---|---|---|\n"
                "| A-1 | CVE-1 | api production | Upgrade PHP | High | Dev | Open | 2026-11-16 |\n"
                "| A-2 | CVE-2 | api | Upgrade Python | Medium | Dev | Completed | 2026-11-01 |\n",
                encoding="utf-8",
            )
            daily = root / "daily"
            daily.mkdir()
            (daily / "2026-11-16.md").write_text(
                "## Projects and technologies involved\n\n"
                "- api: PHP, JavaScript, and Apache.\n"
                "- worker: Python/CPython.\n\n"
                "## Relevant advisories\n",
                encoding="utf-8",
            )

            statistics = security_statistics(
                followup_path=followup, daily_directory=daily,
                today=dt.date(2026, 11, 16),
            )

            self.assertEqual(statistics["open"], 1)
            self.assertEqual(statistics["today"], 1)
            self.assertEqual(statistics["month"], 2)
            self.assertEqual(statistics["projects"], {"api": 2})
            self.assertEqual(statistics["priorities"], {"High": 1, "Medium": 1})
            self.assertEqual(statistics["languages"], {"JavaScript": 1, "PHP": 1, "Python": 1})

    def test_ai_proposal_is_separate_from_confirmed_followup_update(self) -> None:
        response, proposal = extract_issue_update(
            'I can record the assignment.\n<issue-update>{"action":"take_ownership",'
            '"owner":"Alice","next_action":"Verify the patched runtime"}</issue-update>'
        )
        self.assertEqual(response, "I can record the assignment.")
        self.assertEqual(proposal_changes(proposal), {
            "Owner": "Alice",
            "Status": "In progress",
            "Next action": "Verify the patched runtime",
        })

    def test_followup_update_targets_only_the_selected_issue_id(self) -> None:
        with TemporaryDirectory() as directory:
            followup = Path(directory) / "followup.md"
            followup.write_text(
                "# Follow-up\n\n"
                "| ID | Advisory / CVE | Project | Description | Priority | Owner | Status | Opened | Last updated | Next action | Due date | Completion evidence |\n"
                "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
                "| A-1 | CVE-1 | api | First | High | Dev | Open | 2026-11-01 | 2026-11-01 | Patch | — | — |\n"
                "| A-2 | CVE-1 | api | Second | High | Dev | Open | 2026-11-01 | 2026-11-01 | Review | — | — |\n",
                encoding="utf-8",
            )

            updated = update_followup_activity(
                "A-2", {"Status": "Completed", "Completion evidence": "Test suite passed"},
                path=followup, today=dt.date(2026, 11, 16),
            )

            text = followup.read_text(encoding="utf-8")
            self.assertEqual(updated["Project"], "api")
            self.assertIn("| A-1 | CVE-1 | api | First | High | Dev | Open |", text)
            self.assertIn(
                "| A-2 | CVE-1 | api | Second | High | Dev | Completed | "
                "2026-11-01 | 2026-11-16 | Review | — | Test suite passed |",
                text,
            )


if __name__ == "__main__":
    unittest.main()
