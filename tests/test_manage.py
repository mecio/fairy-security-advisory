# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.manage import (
    ANALYSIS_PROGRESS_PREFIX, ai_command, analysis_prompt, emit_analysis_progress,
    render_cli_banner, run_ai_check,
    scoped_evidence_prompt, source_request, validate_canonical_report_updates,
)
from scripts.sandbox_preflight import claude_sandbox_settings


class AdvisorySourceRequestTest(unittest.TestCase):
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

    @patch.dict("os.environ", {"FAIRY_GUI_PROGRESS": "1"})
    @patch("builtins.print")
    def test_analysis_progress_event_is_machine_readable(self, output) -> None:
        emit_analysis_progress(
            phase="evidence", status="running", provider="claude",
            completed=2, total=5, active_projects=3,
            message="Collecting read-only evidence",
        )

        line = output.call_args.args[0]
        self.assertTrue(line.startswith(ANALYSIS_PROGRESS_PREFIX))
        event = json.loads(line[len(ANALYSIS_PROGRESS_PREFIX):])
        self.assertEqual(event["provider"], "claude")
        self.assertEqual(event["completed"], 2)
        self.assertEqual(event["active_projects"], 3)
        self.assertTrue(output.call_args.kwargs["flush"])

    def test_cli_banner_is_plain_ascii_without_color(self) -> None:
        banner = render_cli_banner(color=False, width=100)
        self.assertIn("fAIry Security Advisory", banner)
        self.assertNotIn("\033", banner)
        self.assertTrue(all(ord(character) < 128 for character in banner))
        self.assertLessEqual(max(map(len, banner.splitlines())), 88)

    def test_cli_banner_has_a_compact_variant(self) -> None:
        banner = render_cli_banner(color=False, width=50)
        self.assertIn("/AI\\", banner)
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
            if provider == "codex":
                for name, path in canonical_paths.items():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(f"# Updated {name}\n", encoding="utf-8")
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
            ) as run:
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
        self.assertIn("Phase: codex consolidation — completed (exit 0)", summary)
        self.assertIn("type=evidence status=completed", event_log)
        self.assertIn("type=consolidation status=completed", event_log)
        self.assertIn("OUTPUT_VALIDATION status=completed", event_log)
        prerequisites.assert_called_once_with("claude")
        self.assertEqual([call.args[1] for call in run.call_args_list], ["claude", "codex"])
        self.assertTrue(command.call_args_list[0].kwargs["read_only"])
        self.assertNotIn("read_only", command.call_args_list[1].kwargs)

    @patch("builtins.print")
    @patch("scripts.manage.run_command")
    @patch("scripts.manage.confirm", return_value=False)
    @patch("scripts.manage.prepare_analysis_service", return_value=True)
    @patch("scripts.manage.ai_command", return_value=["/usr/bin/codex", "prompt"])
    def test_ai_launch_can_be_cancelled(
        self, _command, _prepare, _confirm, run_command, _print,
    ) -> None:
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
