# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.ai_usage import append_usage_record, load_usage_records, summarize_usage, usage_from_event


class AIUsageTest(unittest.TestCase):
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
