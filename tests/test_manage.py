# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest
from unittest.mock import patch

from scripts.manage import (
    ai_command, analysis_prompt, render_cli_banner, run_ai_check, source_request,
)


class AdvisorySourceRequestTest(unittest.TestCase):
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
            ["/usr/bin/claude", "--model", "haiku", analysis_prompt("claude")],
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
        self.assertEqual(command[:3], ["/usr/bin/codex", "--search", "exec"])
        self.assertIn("--approve-for-me", command)
        self.assertIn("--json", command)

    @patch("scripts.manage.resolve_agent_executable", return_value="/usr/bin/claude")
    def test_claude_non_interactive_command_uses_print_mode(self, _which) -> None:
        command = ai_command("claude", non_interactive=True)
        self.assertIn("--print", command)
        self.assertIn("stream-json", command)

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
