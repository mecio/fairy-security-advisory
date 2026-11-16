# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import os
import stat
import subprocess
from unittest.mock import patch

from scripts.ai_usage import (
    TRANSIENT_CODEX_ENV_VARS, append_cli_diagnostic, append_usage_record,
    load_usage_records, run_tracked_command, summarize_usage, usage_from_event,
)


class AIUsageTest(unittest.TestCase):
    @patch.dict("os.environ", {
        "CODEX_SESSION_ID": "parent-session",
        "CODEX_SANDBOX_NETWORK_DISABLED": "1",
        "FAIRY_TEST_ENV": "preserved",
    })
    @patch("scripts.ai_usage.append_usage_record")
    @patch("scripts.ai_usage.subprocess.Popen")
    def test_non_interactive_agent_receives_closed_stdin(self, popen, _usage) -> None:
        process = popen.return_value
        process.stdout = []
        process.wait.return_value = 0

        result = run_tracked_command(
            ["codex", "exec", "prompt"], "codex", model="model",
            profile="economical", execution_mode="economical",
        )

        self.assertEqual(result, 0)
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        child_environment = popen.call_args.kwargs["env"]
        self.assertEqual(child_environment["FAIRY_TEST_ENV"], "preserved")
        self.assertTrue(TRANSIENT_CODEX_ENV_VARS.isdisjoint(child_environment))

    def test_cli_diagnostic_is_retained_in_private_event_log(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "run.log"
            append_cli_diagnostic(path, "codex", "error: invalid option")

            self.assertIn("CLI codex: error: invalid option", path.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_claude_result_fields_are_normalized(self) -> None:
        usage = usage_from_event("claude", {
            "usage": {
                "input_tokens": 10,
                "output_tokens": 4,
                "cache_read_input_tokens": 7,
                "cache_creation_input_tokens": 2,
            },
            "total_cost_usd": 0.0125,
        })
        self.assertEqual(usage, {
            "input_tokens": 10,
            "output_tokens": 4,
            "cached_input_tokens": 7,
            "cache_creation_input_tokens": 2,
            "cost_usd": 0.0125,
        })

    def test_ignored_jsonl_history_is_aggregated_by_provider(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            append_usage_record({
                "provider": "codex", "exit_code": 0,
                "input_tokens": 100, "output_tokens": 20, "cost_usd": 0,
            }, path)
            append_usage_record({
                "provider": "claude", "exit_code": 1,
                "input_tokens": 50, "output_tokens": 5, "cost_usd": 0.01,
            }, path)

            records = load_usage_records(path)
            summary = summarize_usage("codex", records)

            self.assertEqual(summary["runs"], 1)
            self.assertEqual(summary["successful_runs"], 1)
            self.assertEqual(summary["input_tokens"], 100)
            self.assertEqual(summary["output_tokens"], 20)


if __name__ == "__main__":
    unittest.main()
