# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.advisory_guardrails import validate_candidate_ledger


class CandidateLedgerGuardrailTest(unittest.TestCase):
    def test_fake_acn_php2shell_bulletin_retains_overlapping_php_constraint(self) -> None:
        """A local fixture exercises matching without fetching ACN during tests."""
        fake_bulletin = {
            "source": "acn-alert-bollettini",
            "title": "PHP2Shell critical PHP vulnerabilities",
            "advisories": [{
                "advisory_id": "CVE-2026-109618",
                "affected_range": "PHP before 8.5.12",
            }],
        }
        with TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = root / "candidate-ledger.json"
            daily = root / "daily.md"
            followup = root / "followup.md"
            daily.write_text("# Report\n\nCVE-2026-109618 retained for review.\n", encoding="utf-8")
            followup.write_text("| Advisory / CVE |\n|---|\n| CVE-2026-109618 |\n", encoding="utf-8")
            ledger.write_text(json.dumps({
                "schema_version": 1,
                "candidates": [{
                    **fake_bulletin["advisories"][0],
                    "source_id": fake_bulletin["source"],
                    "project_id": "legacy",
                    "technology_key": "php-72",
                    "declared_value": ">=7.2",
                    "range_relation": "overlaps",
                    "prerequisite_status": "unknown",
                    "decision": "follow-up",
                }],
            }), encoding="utf-8")
            validate_candidate_ledger(ledger, [{
                "key": "php-72", "version": ">=7.2", "projects": ["legacy"],
            }], daily, followup)

    def test_overlapping_candidate_cannot_be_silently_excluded(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = root / "candidate-ledger.json"
            daily = root / "daily.md"
            followup = root / "followup.md"
            daily.write_text("# Report\n", encoding="utf-8")
            followup.write_text("| Advisory / CVE |\n|---|\n", encoding="utf-8")
            ledger.write_text(json.dumps({"schema_version": 1, "candidates": [{
                "advisory_id": "CVE-2026-109618", "source_id": "acn-alert-bollettini",
                "project_id": "legacy", "technology_key": "php-72",
                "declared_value": ">=7.2", "affected_range": "before 8.5.12",
                "range_relation": "overlaps", "prerequisite_status": "unknown",
                "decision": "not-applicable",
            }]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "overlapping"):
                validate_candidate_ledger(ledger, [{
                    "key": "php-72", "version": ">=7.2", "projects": ["legacy"],
                }], daily, followup)
