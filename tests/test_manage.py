# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.manage import (
    ANALYSIS_PROGRESS_PREFIX, ROOT, ai_command, analysis_prompt, consolidation_prompt,
    candidate_intake_prompt, correction_prompt,
    check_prerequisites, consume_technology_selection, coverage_completion_status,
    emit_analysis_progress,
    missing_baseline_references,
    prepare_analysis_service, refresh_inventory,
    render_cli_banner, restrict_plan_to_technology_projects, run_ai_check,
    scoped_evidence_prompt, source_request, validate_canonical_report_updates,
    promote_staged_reports, staged_report_paths, validate_staged_analysis_artifacts,
)
from scripts.sandbox_preflight import claude_sandbox_settings


class AdvisorySourceRequestTest(unittest.TestCase):
    def test_explicit_technology_scope_filters_project_routing(self) -> None:
        plan = {
            "default_provider": "codex",
            "groups": {
                "codex": [{"id": "php-api", "path": "/php"}],
                "claude": [{"id": "node-web", "path": "/node"}],
            },
            "excluded": [], "selected_count": 2, "excluded_count": 0,
        }
        restrict_plan_to_technology_projects(
            plan, [{"key": "php-key", "projects": ["php-api"]}], enabled=True,
        )
        self.assertEqual(plan["groups"]["codex"], [{"id": "php-api", "path": "/php"}])
        self.assertEqual(plan["groups"]["claude"], [])
        self.assertEqual(plan["excluded"], [{"id": "node-web", "path": "/node"}])
        self.assertEqual((plan["selected_count"], plan["excluded_count"]), (1, 1))

    def test_missing_reference_requires_version_date_and_https_source(self) -> None:
        self.assertEqual(
            missing_baseline_references({
                "php-key": {
                    "baseline_version": "8.3.0", "since": None,
                    "release_source_url": None,
                },
            }),
            [("php-key", ["reference date", "reference source"])],
        )
        self.assertEqual(missing_baseline_references({
            "php-key": {
                "baseline_version": "8.3.0", "since": "2023-11-23T00:00:00Z",
                "release_source_url": "https://www.php.net/releases/8.3/en.php",
            },
        }), [])

    def test_selected_technology_without_reference_stops_before_sources_or_ai(self) -> None:
        config = {"inventory": {"projects": [{
            "id": "php-api", "path": "/projects/php-api",
            "advisory_checks": {"enabled": True},
            "manual_technologies": [{
                "category": "runtimes", "name": "PHP", "version": "8.3",
            }],
        }]}}
        from scripts.technology_state import collect_technology_scope
        key = collect_technology_scope(config)[0]["key"]

        def configuration(path: Path) -> dict:
            return config if "projects" in path.name else {}

        with patch(
            "scripts.manage.prepare_analysis_service", return_value=True,
        ), patch(
            "scripts.manage.configured_models",
            return_value=("balanced", {"codex": "codex-model", "claude": "claude-model"}),
        ), patch(
            "scripts.manage.configured_execution",
            return_value=("economical", {"use_subagents": False, "max_subagents": 0}),
        ), patch(
            "scripts.manage.safe_load_yaml", side_effect=configuration,
        ), patch(
            "scripts.manage.load_state_for_run",
            return_value={"schema_version": 1, "baselines": {}, "sources": {}},
        ), patch(
            "scripts.manage.resolve_release_metadata", return_value={},
        ), patch(
            "scripts.manage.check_sources", return_value=0,
        ) as sources, patch(
            "scripts.manage.ai_command",
        ) as ai, patch(
            "scripts.manage.confirm", return_value=True,
        ) as confirm:
            result = run_ai_check(
                "codex", "balanced", "economical", assume_yes=True,
                non_interactive=True, technology_keys=[key],
                technology_selection_explicit=True,
            )

        self.assertEqual(result, 1)
        sources.assert_not_called()
        ai.assert_not_called()
        confirm.assert_not_called()

    def test_staged_reports_are_not_published_until_promoted(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = {"daily report": root / "output/daily.md"}
            canonical["daily report"].parent.mkdir(parents=True)
            canonical["daily report"].write_text("old", encoding="utf-8")
            staged = staged_report_paths(root / "run", canonical)
            staged["daily report"].write_text("new", encoding="utf-8")
            self.assertEqual(canonical["daily report"].read_text(encoding="utf-8"), "old")
            promote_staged_reports(staged, canonical)
            self.assertEqual(canonical["daily report"].read_text(encoding="utf-8"), "new\n")

    def test_coverage_status_distinguishes_limitations_and_total_failure(self) -> None:
        self.assertEqual(
            coverage_completion_status({"one": "completed"}, ["one"], 2, 2),
            "completed",
        )
        self.assertEqual(
            coverage_completion_status({"one": "partial"}, ["one"], 2, 2),
            "completed-with-limitations",
        )
        self.assertEqual(
            coverage_completion_status({"one": "completed"}, ["one"], 1, 2),
            "completed-with-limitations",
        )
        self.assertEqual(
            coverage_completion_status({"one": "failed", "two": "failed"}, ["one", "two"], 2, 2),
            "failed",
        )

    def test_private_technology_selection_is_consumed_once(self) -> None:
        with TemporaryDirectory() as directory, patch("scripts.manage.ROOT", Path(directory)):
            request = Path(directory) / "output/analysis-requests/selection.json"
            request.parent.mkdir(parents=True)
            request.write_text(
                '{"schema_version":1,"technology_keys":["php-1234567890abcdef"]}',
                encoding="utf-8",
            )
            keys = consume_technology_selection(str(request))
            self.assertFalse(request.exists())
        self.assertEqual(keys, ["php-1234567890abcdef"])

    def test_private_technology_selection_rejects_symlinked_request_directory(self) -> None:
        with TemporaryDirectory() as directory, patch("scripts.manage.ROOT", Path(directory)):
            output = Path(directory) / "output"
            outside = Path(directory) / "outside"
            output.mkdir()
            outside.mkdir()
            request = outside / "selection.json"
            request.write_text(
                '{"schema_version":1,"technology_keys":[]}', encoding="utf-8",
            )
            (output / "analysis-requests").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "directory is unsafe"):
                consume_technology_selection(str(output / "analysis-requests/selection.json"))
            self.assertTrue(request.exists())

    def test_stale_inventory_is_never_refreshed_implicitly_before_analysis(self) -> None:
        with patch("scripts.manage.effective_config_path", return_value=Path("config/local/projects.yaml")), patch(
            "scripts.manage.safe_load_yaml", return_value={"project_roots": [{"path": "/tmp"}]},
        ), patch("scripts.manage.configured_roots_ready", return_value=True), patch(
            "scripts.manage.inventory_is_current", return_value=(False, "200 hours old"),
        ), patch("scripts.manage.refresh_inventory") as refresh, patch(
            "scripts.manage.validate_configuration", return_value=0,
        ), patch("scripts.manage.check_prerequisites", return_value=0), patch(
            "scripts.manage.check_sources", return_value=0,
        ):
            self.assertTrue(prepare_analysis_service("codex", assume_yes=True))
        refresh.assert_not_called()

    def test_stale_inventory_warns_without_failing_prerequisites(self) -> None:
        with patch(
            "scripts.manage.effective_config_path",
            return_value=Path("config/local/projects.yaml"),
        ), patch(
            "scripts.manage.safe_load_yaml",
            return_value={"project_roots": [{"path": "/tmp"}]},
        ), patch(
            "scripts.manage.configured_roots_ready", return_value=True,
        ), patch(
            "scripts.manage.inventory_is_current", return_value=(False, "200 hours old"),
        ), patch(
            "scripts.manage.agent_details", return_value=("1.0", True),
        ), patch(
            "scripts.manage.print_sandbox_preflight", return_value=True,
        ), patch(
            "scripts.manage.shutil.which", return_value="/usr/bin/tool",
        ), patch("builtins.print") as output:
            result = check_prerequisites("codex")

        self.assertEqual(result, 0)
        output.assert_any_call("WARN local inventory: 200 hours old")
        output.assert_any_call("Required prerequisites are ready.")

    def test_explicit_inventory_refresh_creates_backup_before_scanning(self) -> None:
        backup = {"archive": ROOT / "output/config-backups/safety.zip"}
        with patch("scripts.manage.effective_config_path", return_value=Path("config/local/projects.yaml")), patch(
            "scripts.manage.create_configuration_backup", return_value=backup,
        ) as create_backup, patch("scripts.manage.run_command", return_value=0) as run:
            self.assertEqual(refresh_inventory(assume_yes=True), 0)
        create_backup.assert_called_once()
        run.assert_called_once()

    def test_canonical_output_validation_rejects_unchanged_reports(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "daily report": root / "daily.md",
                "summary": root / "summary.md",
                "follow-up": root / "followup.md",
            }
            for path in paths.values():
                path.write_text("existing\n", encoding="utf-8")
            before = {
                name: "different" if name == "follow-up" else None
                for name in paths
            }
            # Daily and summary exist, but their signatures match the recorded state.
            from scripts.manage import report_signature
            before["daily report"] = report_signature(paths["daily report"])
            before["summary"] = report_signature(paths["summary"])

            valid, detail = validate_canonical_report_updates(paths, before)

        self.assertFalse(valid)
        self.assertIn("not updated: daily report, summary", detail)

    def test_canonical_output_validation_requires_every_selected_project(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "daily report": root / "daily.md",
                "summary": root / "summary.md",
                "follow-up": root / "followup.md",
            }
            prior = (
                "### Projects and technologies involved\n"
                "- Project: `worker` — previous check.\n"
            )
            paths["daily report"].write_text(
                prior + "\n### Projects and technologies involved\n"
                "- Project: `api` — evidence checked.\n",
                encoding="utf-8",
            )
            paths["summary"].write_text("updated summary\n", encoding="utf-8")
            paths["follow-up"].write_text("existing follow-up\n", encoding="utf-8")
            valid, detail = validate_canonical_report_updates(
                paths, {name: None for name in paths},
                expected_project_ids=["api", "worker"],
                prior_daily_text=prior,
            )
            self.assertFalse(valid)
            self.assertIn("missing project coverage: worker", detail)
            paths["daily report"].write_text(
                paths["daily report"].read_text(encoding="utf-8")
                + "- Project: `worker` — dossier reviewed.\n",
                encoding="utf-8",
            )
            valid, _detail = validate_canonical_report_updates(
                paths, {name: None for name in paths},
                expected_project_ids=["api", "worker"],
                prior_daily_text=prior,
            )
            self.assertTrue(valid)

    def test_canonical_output_validation_requires_every_selected_baseline_key(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "daily report": root / "daily.md", "summary": root / "summary.md",
                "follow-up": root / "followup.md",
            }
            paths["daily report"].write_text(
                "## Projects and technologies involved\n- Project: `api` — checked.\n",
                encoding="utf-8",
            )
            paths["summary"].write_text("updated", encoding="utf-8")
            paths["follow-up"].write_text("existing", encoding="utf-8")
            valid, detail = validate_canonical_report_updates(
                paths, {name: None for name in paths}, expected_project_ids=["api"],
                expected_technology_keys=["php-1234567890abcdef"],
            )
            self.assertFalse(valid)
            self.assertIn("missing technology baseline coverage", detail)
            paths["daily report"].write_text(
                paths["daily report"].read_text(encoding="utf-8")
                + "- Technology key: `php-1234567890abcdef` — completed.\n",
                encoding="utf-8",
            )
            valid, _detail = validate_canonical_report_updates(
                paths, {name: None for name in paths}, expected_project_ids=["api"],
                expected_technology_keys=["php-1234567890abcdef"],
            )
            self.assertTrue(valid)

    def test_artifact_validation_aggregates_staging_ledger_and_receipt_errors(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "daily report": root / "daily.md",
                "summary": root / "summary.md",
                "follow-up": root / "followup.md",
            }
            for path in paths.values():
                path.write_text("unchanged\n", encoding="utf-8")
            from scripts.manage import report_signature
            before = {name: report_signature(path) for name, path in paths.items()}

            valid, detail, baselines, sources = validate_staged_analysis_artifacts(
                paths, before, root / "missing-ledger.json",
                root / "missing-intake.json", root / "missing-receipt.json",
                [], [], [], {},
                expected_project_ids=[], prior_daily_text=None,
            )

        self.assertFalse(valid)
        self.assertIn("staging: not updated: daily report, summary", detail)
        self.assertIn("candidate ledger:", detail)
        self.assertIn("evidence receipt:", detail)
        self.assertEqual((baselines, sources), ({}, []))

    def test_artifact_validation_rejects_modified_immutable_intake(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            intake = root / "candidate-intake.json"
            intake.write_text(
                '{"schema_version":1,"sources":[],"candidates":[]}', encoding="utf-8",
            )
            from scripts.manage import report_signature
            frozen_signature = report_signature(intake)
            intake.write_text(
                '{"schema_version":1,"sources":[],"candidates":[],"changed":true}',
                encoding="utf-8",
            )
            paths = {
                "daily report": root / "daily.md", "summary": root / "summary.md",
                "follow-up": root / "followup.md",
            }
            for path in paths.values():
                path.write_text("staged\n", encoding="utf-8")
            valid, detail, _baselines, _sources = validate_staged_analysis_artifacts(
                paths, {name: None for name in paths}, root / "ledger.json", intake,
                root / "receipt.json", [], [], [], {}, expected_project_ids=[],
                prior_daily_text=None, expected_intake_signature=frozen_signature,
            )
        self.assertFalse(valid)
        self.assertIn("immutable intake changed", detail)

    def test_receipt_cannot_advance_source_that_intake_marks_partial(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "daily report": root / "daily.md", "summary": root / "summary.md",
                "follow-up": root / "followup.md",
            }
            paths["daily report"].write_text("# Updated daily\n", encoding="utf-8")
            paths["summary"].write_text("# Updated summary\n", encoding="utf-8")
            paths["follow-up"].write_text("# Follow-up\n", encoding="utf-8")
            source = {
                "id": "acn", "status": "partial", "candidate_ids": [],
                "records_checked": 1, "coverage_basis": "open-ended HTML index",
            }
            intake = root / "intake.json"
            ledger = root / "ledger.json"
            receipt = root / "receipt.json"
            intake.write_text(json.dumps({
                "schema_version": 1, "sources": [source], "candidates": [],
            }), encoding="utf-8")
            ledger.write_text(json.dumps({
                "schema_version": 1, "sources": [source], "candidates": [],
            }), encoding="utf-8")
            receipt.write_text(json.dumps({
                "schema_version": 1, "baselines": [],
                "sources": [{"id": "acn", "status": "complete"}],
            }), encoding="utf-8")
            valid, detail, _baselines, _sources = validate_staged_analysis_artifacts(
                paths, {name: None for name in paths}, ledger, intake, receipt,
                [], [], ["acn"], {}, expected_project_ids=[], prior_daily_text=None,
            )
        self.assertFalse(valid)
        self.assertIn("marks incomplete intake sources complete", detail)

    @patch.dict("os.environ", {"FAIRY_GUI_PROGRESS": "1"})
    @patch("builtins.print")
    def test_analysis_progress_event_is_machine_readable(self, output) -> None:
        emit_analysis_progress(
            phase="evidence", status="running", provider="claude",
            completed=2, total=5, active_projects=3,
            message="Collecting read-only evidence", detail="Provider dossier",
            attempt=1, max_attempts=2,
        )

        line = output.call_args.args[0]
        self.assertTrue(line.startswith(ANALYSIS_PROGRESS_PREFIX))
        event = json.loads(line[len(ANALYSIS_PROGRESS_PREFIX):])
        self.assertEqual(event["provider"], "claude")
        self.assertEqual(event["completed"], 2)
        self.assertEqual(event["active_projects"], 3)
        self.assertEqual(event["detail"], "Provider dossier")
        self.assertEqual((event["attempt"], event["max_attempts"]), (1, 2))
        self.assertTrue(output.call_args.kwargs["flush"])

    def test_cli_banner_is_plain_ascii_without_color(self) -> None:
        banner = render_cli_banner(color=False, width=100)
        self.assertIn("/ _|  / \\  |_ _| _ __  _   _", banner)
        self.assertIn("Security Advisory", banner)
        self.assertNotIn("\033", banner)
        self.assertTrue(all(ord(character) < 128 for character in banner))
        self.assertLessEqual(max(map(len, banner.splitlines())), 88)

    def test_cli_banner_has_a_compact_variant(self) -> None:
        banner = render_cli_banner(color=False, width=50)
        self.assertIn("/ _|  / \\  |_ _| _ __  _   _", banner)
        self.assertNotIn("AI-assisted security intelligence", banner)
        self.assertLessEqual(len(banner.splitlines()), 10)

    def test_osv_querybatch_uses_post_with_an_empty_query_list(self) -> None:
        request = source_request({
            "id": "osv",
            "type": "api",
            "url": "https://api.osv.dev/v1/querybatch",
        })

        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.data, b'{"queries": []}')
        self.assertEqual(request.headers["Content-type"], "application/json")

    def test_regular_source_uses_get(self) -> None:
        request = source_request({
            "id": "example",
            "type": "json",
            "url": "https://example.invalid/advisories.json",
        })

        self.assertEqual(request.get_method(), "GET")
        self.assertIsNone(request.data)

    @patch("scripts.manage.resolve_agent_executable", return_value="/usr/bin/codex")
    def test_codex_launch_enables_search(self, _which) -> None:
        self.assertEqual(
            ai_command("codex"),
            [
                "/usr/bin/codex", "--search", "--model", "gpt-5.6-luna",
                analysis_prompt("codex"),
            ],
        )

    @patch("scripts.manage.resolve_agent_executable", return_value="/usr/bin/claude")
    def test_claude_launch_uses_the_shared_skill_prompt(self, _which) -> None:
        self.assertEqual(
            ai_command("claude"),
            [
                "/usr/bin/claude", "--settings", claude_sandbox_settings(),
                "--model", "haiku", analysis_prompt("claude"),
            ],
        )

    @patch("scripts.manage.resolve_agent_executable", return_value="/usr/bin/codex")
    def test_balanced_profile_selects_terra(self, _which) -> None:
        self.assertEqual(
            ai_command("codex", "balanced")[3],
            "gpt-5.6-terra",
        )

    def test_economical_mode_disables_subagents(self) -> None:
        prompt = analysis_prompt("codex", "economical")
        self.assertIn("do not create sub-agents", prompt)

    def test_fast_mode_limits_subagents(self) -> None:
        prompt = analysis_prompt("codex", "fast")
        self.assertIn("at most 5", prompt)

    @patch("scripts.manage.resolve_agent_executable", return_value="/usr/bin/codex")
    def test_codex_non_interactive_command_uses_exec(self, _which) -> None:
        command = ai_command("codex", non_interactive=True)
        self.assertEqual(command[:2], ["/usr/bin/codex", "--search"])
        self.assertLess(command.index("--ask-for-approval"), command.index("exec"))
        self.assertNotIn("--approve-for-me", command)
        self.assertIn("workspace-write", command)
        self.assertIn("sandbox_workspace_write.network_access=true", command)
        self.assertIn("--json", command)

    @patch("scripts.manage.resolve_agent_executable", return_value="/usr/bin/codex")
    def test_codex_read_only_approval_option_precedes_exec(self, _which) -> None:
        command = ai_command("codex", non_interactive=True, read_only=True)
        self.assertLess(command.index("--ask-for-approval"), command.index("exec"))
        self.assertIn("read-only", command)
        self.assertNotIn("sandbox_workspace_write.network_access=true", command)
        self.assertNotIn("--approve-for-me", command)

    @patch("scripts.manage.resolve_agent_executable", return_value="/usr/bin/claude")
    def test_claude_non_interactive_command_uses_print_mode(self, _which) -> None:
        command = ai_command("claude", non_interactive=True)
        self.assertIn("--print", command)
        self.assertIn("stream-json", command)
        self.assertIn(claude_sandbox_settings(), command)

    def test_scoped_evidence_prompt_forbids_other_projects_and_writes(self) -> None:
        prompt = scoped_evidence_prompt(
            "claude", [{"id": "api", "path": "/projects/api"}], "economical",
        )
        self.assertIn("every and only", prompt)
        self.assertIn("Do not modify files", prompt)
        self.assertIn("do not run OSV-Scanner or Trivy", prompt)
        self.assertNotIn("run the complete security advisory check", prompt)

    def test_all_analysis_phases_ignore_report_reset_snapshots(self) -> None:
        prompts = (
            analysis_prompt("codex", "economical"),
            scoped_evidence_prompt("claude", [{"id": "api", "path": "/projects/api"}]),
            candidate_intake_prompt(
                "codex", Path("output/analysis-runs/plan.json"), [],
                Path("output/analysis-runs/candidate-intake.json"), [],
            ),
            consolidation_prompt("codex", Path("output/analysis-runs/plan.json"), []),
        )
        for prompt in prompts:
            with self.subTest(prompt=prompt[:40]):
                self.assertIn("Do not read output/report-resets/", prompt)
                self.assertIn("manual backups, not current evidence", prompt)

    def test_consolidation_prompt_requires_receipt_schema_field_names(self) -> None:
        prompt = consolidation_prompt("codex", Path("output/analysis-runs/plan.json"), [])
        self.assertIn('"key":"<technology key>"', prompt)
        self.assertIn("not `technology_key`", prompt)
        self.assertIn('"id":"<source ID>"', prompt)
        self.assertIn("not `source_id`", prompt)

    def test_candidate_intake_prompt_preserves_exact_php2shell_identity(self) -> None:
        prompt = candidate_intake_prompt(
            "codex", Path("run/plan.json"), [Path("run/claude-evidence.md")],
            Path("run/candidate-intake.json"), [{"id": "acn-alert-bollettini"}],
        )
        self.assertIn("CVE-2026-109618", prompt)
        self.assertIn("four or more digits", prompt)
        self.assertIn("Do not create generic replacements", prompt)
        self.assertIn("every CVE", prompt)
        self.assertIn("affected_constraints", prompt)
        self.assertIn("candidate_ids", prompt)
        self.assertIn("HTML search pages", prompt)

    def test_correction_prompt_is_single_attempt_and_path_scoped(self) -> None:
        prompt = correction_prompt(
            "codex", Path("run/plan.json"), Path("run/coordinator-output.md"),
            Path("run/candidate-ledger.json"), Path("run/evidence-state.json"),
            {"daily report": Path("run/staging/daily.md")},
            "evidence receipt: missing source acn", "economical",
        )
        self.assertIn("one and only controlled correction attempt", prompt)
        self.assertIn("evidence receipt: missing source acn", prompt)
        self.assertIn("run/staging/daily.md", prompt)
        self.assertIn("no further correction attempt", prompt)
        self.assertIn("Do not start a new analysis", prompt)

    def _run_receipt_correction_case(
        self, fix_on_retry: bool,
    ) -> tuple[int, int, str, str, str, list[dict[str, object]]]:
        config = {"inventory": {"projects": [{
            "id": "api", "path": "/projects/api",
            "advisory_checks": {"enabled": True, "preferred_ai": None},
        }]}}
        command_prompts: list[str] = []
        progress_events: list[dict[str, object]] = []
        invocations = 0

        def command(provider, *_args, **kwargs):
            command_prompts.append(str(kwargs.get("prompt", "")))
            return [provider, "run"]

        def tracked(_command, _provider, **kwargs):
            nonlocal invocations
            invocations += 1
            capture = kwargs["capture_path"]
            capture.parent.mkdir(parents=True, exist_ok=True)
            capture.write_text(f"AI output {invocations}\n", encoding="utf-8")
            if capture.name == "candidate-discovery-output.md":
                (capture.parent / "candidate-intake.json").write_text(
                    '{"schema_version":1,"sources":[],"candidates":[]}',
                    encoding="utf-8",
                )
                return 0
            staging = capture.parent / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "daily.md").write_text(
                "# Daily\n\n## Projects and technologies involved\n"
                "- Project: `api` — checked.\n", encoding="utf-8",
            )
            (staging / "summary.md").write_text("updated summary\n", encoding="utf-8")
            (staging / "followup.md").write_text("updated follow-up\n", encoding="utf-8")
            (capture.parent / "candidate-ledger.json").write_text(
                '{"schema_version":1,"sources":[],"candidates":[]}', encoding="utf-8",
            )
            receipt = (
                '{"schema_version":1,"baselines":[],"sources":[]}'
                if capture.name == "correction-output.md" and fix_on_retry
                else '{"schema_version":1,"baselines":[]}'
            )
            (capture.parent / "evidence-state.json").write_text(
                receipt, encoding="utf-8",
            )
            return 0

        with TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = {
                "daily report": root / "canonical/daily.md",
                "summary": root / "canonical/summary.md",
                "follow-up": root / "canonical/followup.md",
            }
            with patch("scripts.manage.ROOT", root), patch(
                "scripts.manage.prepare_analysis_service", return_value=True,
            ), patch(
                "scripts.manage.configured_models",
                return_value=("balanced", {"codex": "codex-model", "claude": "claude-model"}),
            ), patch(
                "scripts.manage.configured_execution",
                return_value=("economical", {"use_subagents": False, "max_subagents": 0}),
            ), patch(
                "scripts.manage.safe_load_yaml", return_value=config,
            ), patch(
                "scripts.manage.canonical_report_paths", return_value=canonical,
            ), patch(
                "scripts.manage.resolve_release_metadata", return_value={},
            ), patch(
                "scripts.manage.ai_command", side_effect=command,
            ), patch(
                "scripts.manage.run_tracked_command", side_effect=tracked,
            ), patch(
                "scripts.manage.emit_analysis_progress",
                side_effect=lambda **event: progress_events.append(event),
            ), patch(
                "scripts.manage.archive_closed_followups", return_value={"archived": 0},
            ):
                result = run_ai_check(
                    "codex", "balanced", "economical", assume_yes=True,
                    non_interactive=True,
                )
            summary_path = next((root / "output/analysis-runs").rglob("run-summary.txt"))
            summary = summary_path.read_text(encoding="utf-8")
            event_log = (summary_path.parent / "run.log").read_text(encoding="utf-8")
        return result, invocations, command_prompts[-1], summary, event_log, progress_events

    def test_invalid_receipt_gets_one_successful_controlled_correction(self) -> None:
        result, invocations, prompt, summary, event_log, events = (
            self._run_receipt_correction_case(True)
        )
        self.assertEqual((result, invocations), (0, 3))
        self.assertIn("evidence receipt:", prompt)
        self.assertIn("Phase: codex correction — completed (exit 0)", summary)
        self.assertIn("Correction output: correction-output.md", summary)
        self.assertIn("OUTPUT_VALIDATION status=failed attempt=1", event_log)
        self.assertIn("OUTPUT_VALIDATION status=completed attempt=2", event_log)
        phases = [str(event["phase"]) for event in events]
        self.assertIn("preflight", phases)
        self.assertLess(phases.index("validation"), phases.index("correction"))
        self.assertEqual(phases.count("validation"), 2)
        self.assertIn("candidate-intake", phases)
        self.assertIn("staging", phases)
        self.assertEqual(phases.count("report-staging"), 4)
        self.assertEqual(phases.count("candidate-ledger"), 4)
        self.assertEqual(phases.count("coverage-receipt"), 4)
        for phase in ("report-staging", "candidate-ledger", "coverage-receipt"):
            statuses = [event["status"] for event in events if event["phase"] == phase]
            self.assertEqual(statuses[0::2], ["running", "running"])
        self.assertIn("promotion", phases)
        self.assertIn("archive-followups", phases)
        self.assertIn("state-update", phases)
        self.assertLess(phases.index("state-update"), phases.index("complete"))
        correction = next(event for event in events if event["phase"] == "correction")
        self.assertEqual((correction["attempt"], correction["max_attempts"]), (1, 1))

    def test_invalid_receipt_is_not_retried_more_than_once(self) -> None:
        result, invocations, _prompt, summary, event_log, events = (
            self._run_receipt_correction_case(False)
        )
        self.assertEqual((result, invocations), (2, 3))
        self.assertIn("Status: failed", summary)
        self.assertEqual(event_log.count("type=correction attempt=1"), 2)
        self.assertNotIn("attempt=3", event_log)
        self.assertNotIn("promotion", [event["phase"] for event in events])
        failed = [event for event in events if event.get("status") == "failed"]
        self.assertEqual(failed[-1]["phase"], "validation")

    @patch("scripts.manage.prepare_analysis_service", return_value=True)
    @patch("scripts.manage.check_prerequisites", return_value=0)
    @patch("scripts.manage.configured_models", return_value=(
        "balanced", {"codex": "codex-model", "claude": "claude-model"},
    ))
    @patch("scripts.manage.configured_execution", return_value=(
        "economical", {"use_subagents": False, "max_subagents": 0},
    ))
    @patch("scripts.manage.ai_command")
    def test_routed_analysis_collects_other_provider_then_consolidates_once(
        self, command, _execution, _models, prerequisites, _prepare,
    ) -> None:
        config = {"inventory": {"projects": [
            {"id": "default", "path": "/projects/default", "advisory_checks": {
                "enabled": True, "preferred_ai": None,
            }},
            {"id": "claude", "path": "/projects/claude", "advisory_checks": {
                "enabled": True, "preferred_ai": "claude",
            }},
            {"id": "off", "path": "/projects/off", "advisory_checks": {
                "enabled": False, "preferred_ai": None,
            }},
        ]}}
        command.side_effect = lambda provider, *_args, **_kwargs: [provider, "run"]

        canonical_paths: dict[str, Path] = {}

        def tracked(_command, provider, **kwargs):
            capture = kwargs.get("capture_path")
            if capture:
                capture.parent.mkdir(parents=True, exist_ok=True)
                capture.write_text("# Evidence\n", encoding="utf-8")
            if capture and capture.name == "candidate-discovery-output.md":
                (capture.parent / "candidate-intake.json").write_text(
                    '{"schema_version":1,"sources":[],"candidates":[]}',
                    encoding="utf-8",
                )
                return 0
            if provider == "codex":
                staging = capture.parent / "staging"
                for name, canonical in canonical_paths.items():
                    path = staging / canonical.name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    content = (
                        "# Daily report\n\n### Projects and technologies involved\n"
                        "- Project: `default` — evidence checked.\n"
                        "- Project: `claude` — dossier checked.\n"
                        if name == "daily report" else f"# Updated {name}\n"
                    )
                    path.write_text(content, encoding="utf-8")
                (capture.parent / "evidence-state.json").write_text(
                    '{"schema_version":1,"baselines":[],"sources":[]}',
                    encoding="utf-8",
                )
                (capture.parent / "candidate-ledger.json").write_text(
                    '{"schema_version":1,"sources":[],"candidates":[]}', encoding="utf-8",
                )
            return 0

        with TemporaryDirectory() as directory:
            root = Path(directory)
            canonical_paths.update({
                "daily report": root / "output/daily-advisory-check/2026-11-16.md",
                "summary": root / "output/check-summary.md",
                "follow-up": root / "output/followup.md",
            })
            with patch(
                "scripts.manage.ROOT", root,
            ), patch(
                "scripts.manage.canonical_report_paths", return_value=canonical_paths,
            ), patch(
                "scripts.manage.safe_load_yaml", return_value=config,
            ), patch(
                "scripts.manage.run_tracked_command", side_effect=tracked,
            ) as run, patch(
                "scripts.manage.archive_closed_followups", return_value={"archived": 0},
            ):
                result = run_ai_check(
                    "codex", "balanced", "economical", assume_yes=True,
                    non_interactive=True,
                )
                summaries = list((root / "output/analysis-runs").rglob("run-summary.txt"))
                self.assertEqual(len(summaries), 1)
                run_directory = summaries[0].parent
                summary = summaries[0].read_text(encoding="utf-8")
                event_log = (run_directory / "run.log").read_text(encoding="utf-8")
                self.assertTrue((run_directory / "coordinator-output.md").is_file())

        self.assertEqual(result, 0)
        self.assertIn("Status: completed", summary)
        self.assertIn("Coordinator: codex", summary)
        self.assertIn("Codex model: codex-model", summary)
        self.assertIn("Claude model: claude-model", summary)
        self.assertIn("Phase: claude evidence — completed (exit 0)", summary)
        self.assertIn("Phase: codex candidate discovery — completed (exit 0)", summary)
        self.assertIn("Phase: codex consolidation — completed (exit 0)", summary)
        self.assertIn("type=evidence status=completed", event_log)
        self.assertIn("type=consolidation status=completed", event_log)
        self.assertIn("OUTPUT_VALIDATION status=completed", event_log)
        prerequisites.assert_called_once_with("claude")
        self.assertEqual(
            [call.args[1] for call in run.call_args_list], ["claude", "codex", "codex"],
        )
        self.assertTrue(command.call_args_list[0].kwargs["read_only"])
        self.assertNotIn("read_only", command.call_args_list[1].kwargs)
        self.assertNotIn("read_only", command.call_args_list[2].kwargs)

    @patch("builtins.print")
    @patch("scripts.manage.run_command")
    @patch("scripts.manage.confirm", return_value=False)
    @patch("scripts.manage.prepare_analysis_service", return_value=True)
    @patch("scripts.manage.ai_command", return_value=["/usr/bin/codex", "prompt"])
    def test_ai_launch_can_be_cancelled(
        self, _command, _prepare, _confirm, run_command, _print,
    ) -> None:
        plan = {
            "default_provider": "codex",
            "groups": {"codex": [{"id": "example", "path": "/example"}], "claude": []},
            "selected_count": 1, "excluded_count": 0,
        }
        with patch("scripts.manage.build_analysis_plan", return_value=plan), patch(
            "scripts.manage.collect_technology_scope", return_value=[],
        ), patch("scripts.manage.scan_rows", return_value=[]):
            self.assertEqual(run_ai_check("codex"), 0)
        run_command.assert_not_called()

    @patch("builtins.print")
    @patch("scripts.manage.confirm")
    @patch("scripts.manage.run_command")
    @patch("scripts.manage.prepare_analysis_service", return_value=False)
    @patch("scripts.manage.ai_command", return_value=["/usr/bin/codex", "prompt"])
    def test_ai_does_not_start_when_prerequisites_fail(
        self, _command, _prepare, run_command, confirm, _print,
    ) -> None:
        self.assertEqual(run_ai_check("codex"), 1)
        confirm.assert_not_called()
        run_command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
