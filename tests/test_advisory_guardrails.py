# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.advisory_guardrails import validate_candidate_ledger
from scripts.candidate_intake import (
    advisory_identifiers, score_candidate_ledger, validate_candidate_intake,
    validate_presentation_settings,
)


SOURCE = "acn-alert-bollettini"
BULLETIN = "AL07/261021/CSIRT-ITA"
CVES = ("CVE-2026-109618", "CVE-2026-109619")
SCOPE = [{"key": "php-72", "version": ">=7.2", "projects": ["legacy"]}]


def php2shell_intake() -> dict:
    """Local deterministic fixture: no live ACN request is made by regression tests."""
    return {
        "schema_version": 1,
        "sources": [{"id": SOURCE, "status": "complete"}],
        "candidates": [{
            "candidate_id": f"{SOURCE}:{BULLETIN}",
            "advisory_id": BULLETIN,
            "source_id": SOURCE,
            "source_record_id": BULLETIN,
            "title": "PHP2Shell: sanate vulnerabilità critiche in PHP",
            "url": "https://www.acn.gov.it/portale/w/php2shell-sanate-vulnerabilita-critiche-in-php",
            "identifiers": list(CVES),
            "technology_keys": ["php-72"],
            "project_ids": ["legacy"],
            "affected_range": "PHP before 8.5.12, 8.4.19, 8.3.26 and fixed branch releases",
            "identity_status": "confirmed",
            "source_quality": "official-aggregator",
            "extraction_status": "complete",
        }],
    }


def php2shell_ledger() -> dict:
    return {
        "schema_version": 1,
        "sources": [{"id": SOURCE, "status": "complete"}],
        "candidates": [{
            "candidate_id": f"{SOURCE}:{BULLETIN}",
            "advisory_id": BULLETIN,
            "source_id": SOURCE,
            "project_id": "legacy",
            "technology_key": "php-72",
            "declared_value": ">=7.2",
            "affected_range": "PHP before 8.5.12, 8.4.19, 8.3.26 and fixed branch releases",
            "range_relation": "overlaps",
            "prerequisite_status": "unknown",
            "decision_reason": "Declared PHP range overlaps; production prerequisites need verification.",
            "decision": "follow-up",
        }],
    }


class CandidateLedgerGuardrailTest(unittest.TestCase):
    def test_php2shell_fixture_retains_php_range_and_exact_identifiers_end_to_end(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            intake = root / "candidate-intake.json"
            ledger = root / "candidate-ledger.json"
            dossier = root / "provider-evidence.md"
            daily = root / "daily.md"
            followup = root / "followup.md"
            intake.write_text(json.dumps(php2shell_intake()), encoding="utf-8")
            ledger.write_text(json.dumps(php2shell_ledger()), encoding="utf-8")
            dossier.write_text(
                f"{BULLETIN}: {CVES[0]} and {CVES[1]} affect PHP.\n", encoding="utf-8",
            )
            markers = f"{BULLETIN}; {CVES[0]}; {CVES[1]}"
            daily.write_text(f"# Report\n\nPHP2Shell retained: {markers}.\n", encoding="utf-8")
            followup.write_text(
                f"| Advisory / CVE |\n|---|\n| {markers} |\n", encoding="utf-8",
            )

            validate_candidate_intake(intake, SCOPE, [SOURCE], [dossier])
            score_candidate_ledger(ledger, intake)
            validate_candidate_ledger(
                ledger, SCOPE, daily, followup, candidate_intake_path=intake,
            )
            scored = json.loads(ledger.read_text(encoding="utf-8"))["candidates"][0]

        self.assertEqual(scored["match_score"], 90)
        self.assertEqual(scored["confidence"], "confirmed")
        self.assertTrue(scored["notification_eligible"])
        self.assertEqual(scored["identifiers"], list(CVES))
        self.assertEqual(scored["declared_value"], ">=7.2")

    def test_long_cve_serials_are_valid_identifiers(self) -> None:
        self.assertEqual(
            advisory_identifiers(f"See {CVES[0]} and CVE-2026-9999."),
            {CVES[0], "CVE-2026-9999"},
        )

    def test_presentation_thresholds_require_ordered_percentages(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            validate_presentation_settings({
                "actionable_threshold": 40, "review_threshold": 60,
            })

    def test_configured_threshold_changes_band_but_not_candidate_or_decision(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            intake = root / "candidate-intake.json"
            ledger = root / "candidate-ledger.json"
            intake.write_text(json.dumps(php2shell_intake()), encoding="utf-8")
            ledger.write_text(json.dumps(php2shell_ledger()), encoding="utf-8")
            score_candidate_ledger(ledger, intake, {
                "actionable_threshold": 95,
                "review_threshold": 60,
            })
            scored = json.loads(ledger.read_text(encoding="utf-8"))["candidates"][0]
        self.assertEqual(scored["match_score"], 90)
        self.assertEqual(scored["confidence"], "review")
        self.assertEqual(scored["decision"], "follow-up")

    def test_notification_threshold_is_an_annotation_not_suppression(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            intake = root / "candidate-intake.json"
            ledger = root / "candidate-ledger.json"
            intake.write_text(json.dumps(php2shell_intake()), encoding="utf-8")
            weak = php2shell_ledger()
            weak["candidates"][0].update({
                "range_relation": "disjoint", "prerequisite_status": "confirmed-absent",
                "decision": "not-applicable",
            })
            ledger.write_text(json.dumps(weak), encoding="utf-8")
            score_candidate_ledger(ledger, intake, {
                "actionable_threshold": 95, "review_threshold": 60,
                "notify_below_threshold": False,
            })
            scored = json.loads(ledger.read_text(encoding="utf-8"))["candidates"][0]
        self.assertFalse(scored["notification_eligible"])
        self.assertEqual(scored["confidence"], "weak")
        self.assertEqual(scored["decision"], "not-applicable")

    def test_candidate_intake_cannot_disappear_from_ledger(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            intake = root / "candidate-intake.json"
            ledger = root / "candidate-ledger.json"
            daily = root / "daily.md"
            followup = root / "followup.md"
            intake.write_text(json.dumps(php2shell_intake()), encoding="utf-8")
            ledger.write_text(json.dumps({
                "schema_version": 1,
                "sources": [{"id": SOURCE, "status": "complete"}],
                "candidates": [],
            }), encoding="utf-8")
            daily.write_text("# Report\n", encoding="utf-8")
            followup.write_text("# Follow-up\n", encoding="utf-8")
            score_candidate_ledger(ledger, intake)
            with self.assertRaisesRegex(ValueError, "decisions missing"):
                validate_candidate_ledger(
                    ledger, SCOPE, daily, followup, candidate_intake_path=intake,
                )

    def test_provider_dossier_identifier_cannot_disappear_from_intake(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            intake = root / "candidate-intake.json"
            dossier = root / "provider-evidence.md"
            payload = php2shell_intake()
            payload["candidates"][0]["identifiers"] = [CVES[0]]
            intake.write_text(json.dumps(payload), encoding="utf-8")
            dossier.write_text(f"Found {CVES[0]} and {CVES[1]}.\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, CVES[1]):
                validate_candidate_intake(intake, SCOPE, [SOURCE], [dossier])

    def test_ledger_cannot_invent_candidate_when_intake_is_empty(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            intake = root / "candidate-intake.json"
            ledger = root / "candidate-ledger.json"
            daily = root / "daily.md"
            followup = root / "followup.md"
            intake.write_text(json.dumps({
                "schema_version": 1,
                "sources": [{"id": SOURCE, "status": "complete"}],
                "candidates": [],
            }), encoding="utf-8")
            ledger.write_text(json.dumps(php2shell_ledger()), encoding="utf-8")
            score_candidate_ledger(ledger, intake)
            daily.write_text(f"{BULLETIN}\n", encoding="utf-8")
            followup.write_text(f"{BULLETIN}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "absent from intake"):
                validate_candidate_ledger(
                    ledger, SCOPE, daily, followup, candidate_intake_path=intake,
                )

    def test_generic_replacement_cannot_overwrite_php2shell_identity(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            intake = root / "candidate-intake.json"
            ledger = root / "candidate-ledger.json"
            daily = root / "daily.md"
            followup = root / "followup.md"
            intake.write_text(json.dumps(php2shell_intake()), encoding="utf-8")
            replaced = php2shell_ledger()
            replaced["candidates"][0]["advisory_id"] = "Generic PHP advisories"
            ledger.write_text(json.dumps(replaced), encoding="utf-8")
            score_candidate_ledger(ledger, intake)
            daily.write_text("Generic PHP advisories\n", encoding="utf-8")
            followup.write_text("Generic PHP advisories\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "advisory ID disagrees"):
                validate_candidate_ledger(
                    ledger, SCOPE, daily, followup, candidate_intake_path=intake,
                )

    def test_all_exact_identifiers_must_reach_staged_reports(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            intake = root / "candidate-intake.json"
            ledger = root / "candidate-ledger.json"
            daily = root / "daily.md"
            followup = root / "followup.md"
            intake.write_text(json.dumps(php2shell_intake()), encoding="utf-8")
            ledger.write_text(json.dumps(php2shell_ledger()), encoding="utf-8")
            score_candidate_ledger(ledger, intake)
            daily.write_text(f"{BULLETIN}; {CVES[0]}\n", encoding="utf-8")
            followup.write_text(f"{BULLETIN}; {CVES[0]}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, CVES[1]):
                validate_candidate_ledger(
                    ledger, SCOPE, daily, followup, candidate_intake_path=intake,
                )

    def test_overlapping_candidate_cannot_be_silently_excluded(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = root / "candidate-ledger.json"
            daily = root / "daily.md"
            followup = root / "followup.md"
            daily.write_text(f"# Report\n{CVES[0]}\n", encoding="utf-8")
            followup.write_text("| Advisory / CVE |\n|---|\n", encoding="utf-8")
            excluded = php2shell_ledger()["candidates"][0]
            excluded.update({"advisory_id": CVES[0], "decision": "not-applicable"})
            ledger.write_text(json.dumps({
                "schema_version": 1, "candidates": [excluded],
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "overlapping"):
                validate_candidate_ledger(ledger, SCOPE, daily, followup)


if __name__ == "__main__":
    unittest.main()
