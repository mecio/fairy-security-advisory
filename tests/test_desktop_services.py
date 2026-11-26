# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import stat
import datetime as dt
import json
from types import SimpleNamespace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import yaml

from desktop.services import (
    ConfigurationError, accept_eula, agent_authentication, agent_usage_status, analysis_routing,
    archive_and_reset_reports, assistant_prompt,
    analysis_run_candidate_summary, analysis_run_entries, analysis_run_exclusions,
    analysis_run_files, assistant_command, delete_analysis_run,
    eula_accepted, extract_issue_update, project_metadata,
    followup_match_assessment, followup_project_names, followup_source_links,
    latest_candidate_assessments,
    proposal_changes, security_statistics,
    set_work_animation_mode,
    update_followup_activity,
    read_analysis_run_file, restore_factory_configuration, validate_config_text,
    write_config_text, update_manual_technologies, technology_names,
    inventory_technology_labels,
    technology_version_assistant_context, technology_version_assistant_prompt,
    update_project_technologies,
    update_inventory_preferences,
    write_technology_selection,
    work_animation_mode,
)


class DesktopConfigurationServicesTest(unittest.TestCase):
    def test_analysis_routing_only_requires_providers_in_selected_technology_projects(self) -> None:
        config = {"inventory": {"projects": [
            {"id": "php-app", "path": "/php-app", "advisory_checks": {
                "enabled": True, "preferred_ai": "codex",
            }, "manual_technologies": [{
                "category": "runtimes", "name": "PHP", "version": "8.3",
            }]},
            {"id": "node-app", "path": "/node-app", "advisory_checks": {
                "enabled": True, "preferred_ai": "claude",
            }, "manual_technologies": [{
                "category": "runtimes", "name": "Node.js", "version": "22",
            }]},
        ]}}
        from scripts.technology_state import collect_technology_scope
        php_key = next(item["key"] for item in collect_technology_scope(config)
                       if item["name"] == "PHP")
        with patch("desktop.services.load_yaml", return_value=config):
            selected = analysis_routing("codex", [php_key])
            all_projects = analysis_routing("codex")
            coordinated_by_claude = analysis_routing("claude", [php_key])
        self.assertEqual(selected["required_providers"], ["codex"])
        self.assertEqual(selected["groups"], {"codex": 1, "claude": 0})
        self.assertEqual(selected["selected"], 1)
        self.assertEqual(all_projects["required_providers"], ["codex", "claude"])
        self.assertEqual(coordinated_by_claude["required_providers"], ["claude", "codex"])

    def test_work_animation_mode_is_validated_and_saved_privately(self) -> None:
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            config.mkdir()
            (config / "application.yaml").write_text(
                "schema_version: 1\napplication:\n  work_animation_mode: full\n",
                encoding="utf-8",
            )
            local = config / "local/application.yaml"
            with patch("desktop.services.CONFIG_DIR", config), patch(
                "desktop.services.LOCAL_CONFIG_DIR", config / "local",
            ), patch("desktop.services.LOCAL_APPLICATION_CONFIG", local):
                self.assertEqual(work_animation_mode(), "full")
                set_work_animation_mode("reduced")
                self.assertEqual(work_animation_mode(), "reduced")
                with self.assertRaisesRegex(ConfigurationError, "Unsupported"):
                    set_work_animation_mode("dizzy")
            self.assertEqual(
                yaml.safe_load(local.read_text(encoding="utf-8"))["application"][
                    "work_animation_mode"
                ],
                "reduced",
            )

    def test_technology_version_assistant_uses_read_only_context(self) -> None:
        context = technology_version_assistant_context(
            {"id": "api", "path": "/projects/api"},
            {"name": "PostgreSQL", "category": "databases", "version": "",
             "source": "configuration"},
        )
        message = technology_version_assistant_prompt(context)
        prompt = assistant_prompt(context, message, [])

        self.assertEqual(context["Context type"], "technology-version")
        self.assertEqual(context["Current version"], "Missing")
        self.assertIn("determine the exact version of PostgreSQL", message)
        self.assertIn("read-only, evidence-based investigation", prompt)
        self.assertIn("Never emit an <issue-update> tag", prompt)

    def test_technology_selection_is_written_as_one_private_request_file(self) -> None:
        with TemporaryDirectory() as directory, patch(
            "desktop.services.ANALYSIS_REQUESTS_DIR", Path(directory),
        ):
            path = write_technology_selection(["php-1234567890abcdef"])
            payload = json.loads(path.read_text(encoding="utf-8"))
            mode = stat.S_IMODE(path.stat().st_mode)
        self.assertEqual(payload["technology_keys"], ["php-1234567890abcdef"])
        self.assertEqual(mode, 0o600)

    def test_technology_selection_rejects_symlinked_request_directory(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "outside"
            target.mkdir()
            request = root / "analysis-requests"
            request.symlink_to(target, target_is_directory=True)
            with patch("desktop.services.ANALYSIS_REQUESTS_DIR", request):
                with self.assertRaisesRegex(ConfigurationError, "must not be a symlink"):
                    write_technology_selection(["php-1234567890abcdef"])

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
            self.assertIn("● PostgreSQL version missing", inventory_technology_labels(project))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            saved = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(
                saved["inventory"]["projects"][0]["manual_technologies"][0]["category"],
                "databases",
            )

    def test_production_versions_are_saved_separately_from_inventory_versions(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "projects.yaml"
            path.write_text(
                "schema_version: 1\ninventory:\n  projects:\n"
                "    - id: workspace\n      path: /private/workspace\n"
                "      technology_inventory:\n"
                "        - {name: PostgreSQL, category: databases, version: '17.2'}\n",
                encoding="utf-8",
            )
            production = [{
                "name": "PostgreSQL", "category": "databases",
                "environment": "production", "version": "16.4",
                "evidence_type": "administrator-confirmed",
                "evidence": "Confirmed by system administrator",
                "verified_at": "2026-11-19T10:30:00Z",
            }]
            with patch("desktop.services.effective_config_path", return_value=path):
                project = update_project_technologies(
                    "/private/workspace", [], production,
                )
            self.assertEqual(project["production_technologies"], production)
            self.assertEqual(project["technology_inventory"][0]["version"], "17.2")
            self.assertIn(
                "prod production=16.4", inventory_technology_labels(project)[0],
            )

    def test_ambiguous_dependency_requires_ecosystem_before_saving(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "projects.yaml"
            path.write_text(
                "schema_version: 1\ninventory:\n  projects:\n    - path: /private/workspace\n"
                "      technology_inventory:\n"
                "        - {category: dependencies, name: shared, ecosystem: npm, version: 1.0.0}\n"
                "        - {category: dependencies, name: shared, ecosystem: pypi, version: 2.0.0}\n",
                encoding="utf-8",
            )
            with patch("desktop.services.effective_config_path", return_value=path):
                with self.assertRaisesRegex(ConfigurationError, "Select an ecosystem"):
                    update_manual_technologies("/private/workspace", [{
                        "name": "shared", "category": "dependencies", "version": "1.1.0",
                    }])
                updated = update_manual_technologies("/private/workspace", [{
                    "name": "shared", "category": "dependencies", "ecosystem": "npm",
                    "version": "1.1.0",
                }])
            self.assertEqual(updated["manual_technologies"][0]["ecosystem"], "npm")

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
            state = output / "advisory-state.json"
            state.write_text('{"schema_version":1}', encoding="utf-8")
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

            self.assertEqual(count, 5)
            self.assertTrue(snapshot.is_dir())
            for path in files:
                self.assertFalse(path.exists())
                self.assertEqual(
                    (snapshot / path.relative_to(output)).read_text(encoding="utf-8"),
                    path.name,
                )
            self.assertEqual(log.read_text(encoding="utf-8"), "previous run")
            self.assertFalse(state.exists())
            self.assertEqual(
                (snapshot / "advisory-state.json").read_text(encoding="utf-8"),
                '{"schema_version":1}',
            )

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
            (run / "correction-output.md").write_text(
                "Corrected rejected artifacts.\n", encoding="utf-8",
            )
            (run / "candidate-ledger.json").write_text(json.dumps({"schema_version": 1, "candidates": [{
                "advisory_id": "CVE-TEST-1", "project_id": "legacy", "declared_value": ">=7.2",
                "decision": "not-applicable", "decision_reason": "Confirmed absent prerequisite",
                "match_score": 42, "confidence": "weak",
            }]}), encoding="utf-8")
            (run / "candidate-intake.json").write_text(json.dumps({
                "schema_version": 1, "sources": [], "candidates": [{
                    "candidate_id": "source:CVE-TEST-1",
                }],
            }), encoding="utf-8")
            with patch("desktop.services.ANALYSIS_RUNS_DIR", root):
                entries = analysis_run_entries()
                files = analysis_run_files(run)
                exclusions = analysis_run_exclusions(run)
                candidate_summary = analysis_run_candidate_summary(run)
                content = read_analysis_run_file(run / "run.log")
                removed = delete_analysis_run(run)

            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["year"], "2026")
            self.assertEqual(entries[0]["month"], "11")
            self.assertEqual(entries[0]["status"], "completed")
            self.assertEqual([path.name for path in files], [
                "run-summary.txt", "run.log", "correction-output.md",
                "candidate-intake.json", "candidate-ledger.json",
            ])
            self.assertEqual(exclusions[0]["reason"], "Confirmed absent prerequisite")
            self.assertEqual(candidate_summary, {
                "intake": 1, "ledger": 1, "confirmed": 0, "review": 0,
                "weak": 1, "unscored": 0,
            })
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

    def test_followup_assessment_uses_project_aware_conservative_score_range(self) -> None:
        activity = {
            "Issue title": "PHP2Shell runtime verification",
            "Advisory / CVE": "AL07/261021/CSIRT-ITA; CVE-2026-109618",
            "Project": "legacy; portal",
        }
        assessment = followup_match_assessment(activity, [{
            "advisory_id": "AL07/261021/CSIRT-ITA",
            "identifiers": ["CVE-2026-109618"],
            "match_score": 62,
            "confidence": "review",
            "score_breakdown": {"version_relation": 20},
            "project_id": "legacy",
        }, {
            "advisory_id": "CVE-2026-109618",
            "match_score": 88,
            "confidence": "confirmed",
            "project_id": "portal",
        }, {
            "advisory_id": "CVE-2026-109618",
            "match_score": 99,
            "confidence": "confirmed",
            "project_id": "not-in-finding",
        }])
        self.assertEqual(assessment["score"], 62)
        self.assertEqual((assessment["score_min"], assessment["score_max"]), (62, 88))
        self.assertEqual(assessment["confidence"], "review")
        self.assertEqual(assessment["candidate_count"], 2)
        self.assertEqual(assessment["project_scores"], {"legacy": 62, "portal": 88})

    def test_latest_candidate_assessments_skips_non_terminal_run(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            running = root / "running"
            completed = root / "completed"
            running.mkdir()
            completed.mkdir()
            (running / "candidate-ledger.json").write_text(
                '{"candidates":[{"candidate_id":"new-but-running"}]}', encoding="utf-8",
            )
            (completed / "candidate-ledger.json").write_text(
                '{"candidates":[{"candidate_id":"published"}]}', encoding="utf-8",
            )
            with patch("desktop.services.analysis_run_entries", return_value=[
                {"path": running, "status": "running"},
                {"path": completed, "status": "completed"},
            ]):
                candidates = latest_candidate_assessments()
        self.assertEqual(candidates[0]["candidate_id"], "published")

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

    def test_issue_assistant_is_restricted_to_the_selected_finding(self) -> None:
        prompt = assistant_prompt(
            {"ID": "FA-1", "Advisory / CVE": "CVE-2026-1", "Project": "api"},
            "Parliamo dello spazio interstellare", [],
        )
        self.assertIn("complete topic boundary", prompt)
        self.assertIn("unrelated subject", prompt)
        self.assertIn("Do not invent a connection", prompt)

    def test_project_metadata_is_loaded_from_the_version_file(self) -> None:
        metadata = project_metadata()
        self.assertEqual(metadata["name"], "fAIry Security Advisory")
        self.assertEqual(metadata["version"], "0.2.1")
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

    def test_followup_projects_are_distinct(self) -> None:
        self.assertEqual(
            followup_project_names({"Project": "api; worker; API"}),
            ["api", "worker"],
        )

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
