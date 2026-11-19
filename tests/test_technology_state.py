# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import datetime as dt
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.technology_state import (
    ambiguous_manual_dependencies, baseline_windows, collect_technology_scope,
    incremental_since, project_technology_records,
    load_state, load_state_for_run, record_completed_baselines, scan_rows, StateError,
    validate_evidence_state, version_quality,
)


class TechnologyStateTest(unittest.TestCase):
    def test_corrupt_or_symlinked_state_requires_human_review(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "output/advisory-state.json"
            state.parent.mkdir()
            state.write_text("not-json", encoding="utf-8")
            with self.assertRaises(StateError):
                load_state(root)
            state.unlink()
            outside = root / "outside.json"
            outside.write_text('{"schema_version":1,"baselines":{},"sources":{}}')
            state.symlink_to(outside)
            with self.assertRaisesRegex(StateError, "symlink"):
                load_state(root)

    def test_version_quality_distinguishes_exact_constraint_and_missing(self) -> None:
        self.assertEqual(version_quality("8.3.4"), "orange")
        self.assertEqual(version_quality("8.3.4", "resolved-lockfile"), "green")
        self.assertEqual(version_quality("^8.3"), "orange")
        self.assertEqual(version_quality(""), "red")
        self.assertEqual(version_quality("latest"), "red")
        self.assertEqual(
            version_quality("16.4", "production-administrator-confirmed"), "green",
        )
        self.assertEqual(
            version_quality("16.4", "production-reported-unverified"), "orange",
        )
        self.assertEqual(version_quality("16.4", "manual", "confirmed"), "green")
        self.assertEqual(version_quality("16.4", "verified-local", "hypothetical"), "orange")

    def test_user_version_status_does_not_change_advisory_version(self) -> None:
        base = {
            "id": "api",
            "manual_technologies": [{
                "category": "databases", "name": "PostgreSQL", "version": "17.2",
                "version_status": "hypothetical",
            }],
        }
        hypothetical = collect_technology_scope({"inventory": {"projects": [base]}})[0]
        base["manual_technologies"][0]["version_status"] = "confirmed"
        confirmed = collect_technology_scope({"inventory": {"projects": [base]}})[0]

        self.assertEqual(hypothetical["version"], "17.2")
        self.assertEqual(confirmed["version"], "17.2")
        self.assertEqual(hypothetical["key"], confirmed["key"])
        self.assertEqual((hypothetical["quality"], confirmed["quality"]), ("orange", "orange"))
        self.assertNotIn("version_status", hypothetical)
        self.assertNotIn("version_status", confirmed)

        for scoped in (hypothetical, confirmed):
            state = {"schema_version": 1, "baselines": {}, "sources": {}}
            record_completed_baselines(
                state, [scoped], {scoped["key"]: "completed"},
                dt.datetime(2026, 11, 19, tzinfo=dt.timezone.utc),
            )
            self.assertEqual(state["baselines"][scoped["key"]]["status"], "completed")

        displayed = project_technology_records(base)[0]
        self.assertEqual(displayed["version_status"], "confirmed")
        self.assertEqual(displayed["quality"], "green")

    def test_production_versions_are_separate_advisory_scope_with_environments(self) -> None:
        config = {"inventory": {"projects": [{
            "id": "api",
            "technology_inventory": [{
                "category": "databases", "name": "PostgreSQL", "version": "17.2",
                "source": "verified-local",
            }],
            "production_technologies": [
                {"category": "databases", "name": "PostgreSQL",
                 "environment": "production-eu", "version": "16.4",
                 "evidence_type": "administrator-confirmed", "evidence": "Admin evidence",
                 "verified_at": "2026-11-19T10:30:00Z"},
                {"category": "databases", "name": "PostgreSQL",
                 "environment": "production-us", "version": "17.2",
                 "evidence_type": "authorized-check", "evidence": "Read-only check",
                 "verified_at": "2026-11-19T10:35:00Z"},
            ],
        }]}}
        scope = collect_technology_scope(config)
        self.assertEqual({item["version"] for item in scope}, {"16.4", "17.2"})
        by_version = {item["version"]: item for item in scope}
        self.assertEqual(
            by_version["16.4"]["production_deployments"][0]["environment"],
            "production-eu",
        )
        self.assertEqual(by_version["16.4"]["quality"], "green")
        self.assertEqual(by_version["17.2"]["inventory_projects"], ["api"])
        self.assertEqual(
            by_version["17.2"]["production_deployments"][0]["environment"],
            "production-us",
        )

    def test_aggregate_scope_keeps_production_metadata_only_per_deployment(self) -> None:
        config = {"inventory": {"projects": [{
            "id": "api",
            "production_technologies": [
                {"category": "databases", "name": "PostgreSQL",
                 "environment": "production-eu", "version": "16.4",
                 "evidence_type": "reported-unverified", "evidence": "Operator report",
                 "verified_at": "2026-11-19T10:30:00Z"},
                {"category": "databases", "name": "PostgreSQL",
                 "environment": "production-us", "version": "16.4",
                 "evidence_type": "administrator-confirmed", "evidence": "Admin evidence",
                 "verified_at": "2026-11-19T10:35:00Z"},
            ],
        }]}}

        scope = collect_technology_scope(config)[0]
        self.assertEqual(scope["version"], "16.4")
        self.assertEqual(scope["quality"], "green")
        self.assertEqual(len(scope["production_deployments"]), 2)
        for singular in ("environment", "evidence_type", "evidence", "verified_at"):
            self.assertNotIn(singular, scope)

    def test_production_scope_survives_a_local_dependency_exclusion(self) -> None:
        config = {"inventory": {"projects": [{
            "id": "api",
            "technology_inventory": [{
                "category": "dependencies", "ecosystem": "npm",
                "name": "legacy-package", "version": "1.0.0",
            }],
            "manual_technologies": [{
                "category": "dependencies", "ecosystem": "npm",
                "name": "legacy-package", "exclude": True,
            }],
            "production_technologies": [{
                "category": "dependencies", "ecosystem": "npm",
                "name": "legacy-package", "environment": "production",
                "version": "0.9.0", "evidence_type": "administrator-confirmed",
                "evidence": "Legacy deployment confirmed", "verified_at": "2026-11-19T10:30:00Z",
            }],
        }]}}
        scope = collect_technology_scope(config)
        self.assertEqual([(item["version"], item["source"]) for item in scope], [
            ("0.9.0", "production-administrator-confirmed"),
        ])

    def test_manual_value_overrides_matching_detected_technology(self) -> None:
        records = project_technology_records({
            "technology_inventory": [{
                "category": "databases", "name": "PostgreSQL",
                "version": "16.4", "source": "detected",
            }],
            "manual_technologies": [{
                "category": "databases", "name": "PostgreSQL", "version": "17.2",
            }],
        })
        self.assertEqual(records, [{
            "category": "databases", "name": "PostgreSQL", "version": "17.2",
            "quality": "orange", "source": "manual",
        }])

    def test_manual_override_preserves_two_explicit_versions(self) -> None:
        records = project_technology_records({
            "technology_inventory": [{
                "category": "dependencies", "name": "shared", "version": "0.9.0",
                "source": "resolved-lockfile",
            }],
            "manual_technologies": [
                {"category": "dependencies", "name": "shared", "version": "1.0.0"},
                {"category": "dependencies", "name": "shared", "version": "2.0.0"},
            ],
        })
        self.assertEqual([record["version"] for record in records], ["1.0.0", "2.0.0"])
        self.assertTrue(all(record["quality"] == "orange" for record in records))

    def test_targeted_version_edit_preserves_other_detected_version(self) -> None:
        records = project_technology_records({
            "technology_inventory": [
                {"category": "dependencies", "name": "shared", "ecosystem": "npm",
                 "version": "1.0.0", "source": "resolved-lockfile"},
                {"category": "dependencies", "name": "shared", "ecosystem": "npm",
                 "version": "2.0.0", "source": "resolved-lockfile"},
            ],
            "manual_technologies": [{
                "category": "dependencies", "name": "shared", "ecosystem": "npm",
                "version": "1.1.0", "replaces_version": "1.0.0",
            }],
        })
        self.assertEqual([(item["version"], item["source"]) for item in records],
                         [("1.1.0", "manual"), ("2.0.0", "resolved-lockfile")])

    def test_manual_package_override_replaces_detected_ecosystem_record(self) -> None:
        records = project_technology_records({
            "technology_inventory": [{"category": "dependencies", "ecosystem": "npm",
                "name": "shared", "version": "1.0.0"}],
            "manual_technologies": [{"category": "dependencies", "name": "shared",
                "version": "2.0.0"}],
        })
        self.assertEqual([item["version"] for item in records], ["2.0.0"])
        self.assertEqual(records[0]["ecosystem"], "npm")

    def test_manual_go_version_restores_exact_package_baseline(self) -> None:
        project = {"technology_inventory": [{"category": "dependencies", "ecosystem": "go",
            "name": "example.test/lib", "version": "v1.2.3", "source": "go-minimum"}],
            "manual_technologies": [{"category": "dependencies", "name": "example.test/lib",
                "version": "v1.3.0"}]}
        records = project_technology_records(project)
        self.assertEqual([(item["ecosystem"], item["version"], item["source"])
                          for item in records], [("go", "v1.3.0", "manual")])
        scope = collect_technology_scope({"inventory": {"projects": [{"id": "app", **project}]}})
        windows = baseline_windows(scope, [scope[0]["key"]],
            dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc))
        self.assertEqual(windows[scope[0]["key"]]["anchor_policy"], "package-exact")

    def test_ecosystem_specific_override_preserves_other_package_and_rejects_ambiguity(self) -> None:
        project = {"technology_inventory": [
            {"category": "dependencies", "name": "shared", "ecosystem": "npm", "version": "1.0.0"},
            {"category": "dependencies", "name": "shared", "ecosystem": "pypi", "version": "2.0.0"},
        ], "manual_technologies": [
            {"category": "dependencies", "name": "shared", "ecosystem": "npm", "version": "1.1.0"},
        ]}
        self.assertEqual({(item["ecosystem"], item["version"])
                          for item in project_technology_records(project)},
                         {("npm", "1.1.0"), ("pypi", "2.0.0")})
        project["manual_technologies"] = [
            {"category": "dependencies", "name": "shared", "version": "1.1.0"},
        ]
        self.assertEqual(ambiguous_manual_dependencies(project, project["manual_technologies"]),
                         ["shared"])
        self.assertEqual({(item["ecosystem"], item["version"])
                          for item in project_technology_records(project)},
                         {("npm", "1.0.0"), ("pypi", "2.0.0")})

    def test_human_can_exclude_replaced_go_original_and_confirm_fork(self) -> None:
        project = {"technology_inventory": [
            {"category": "dependencies", "name": "example.test/old", "ecosystem": "go",
             "version": "", "source": "go-replaced"},
            {"category": "dependencies", "name": "example.test/fork", "ecosystem": "go",
             "version": "v2.1.0", "source": "go-replacement-candidate"},
        ], "manual_technologies": [
            {"category": "dependencies", "name": "example.test/old", "ecosystem": "go",
             "exclude": True},
            {"category": "dependencies", "name": "example.test/fork", "ecosystem": "go",
             "version": "v2.1.0"},
        ]}
        records = project_technology_records(project)
        self.assertEqual([(item["name"], item["version"], item["source"])
                          for item in records], [("example.test/fork", "v2.1.0", "manual")])

    def test_manual_override_replaces_detected_product_alias(self) -> None:
        records = project_technology_records({
            "technology_inventory": [{
                "category": "databases", "name": "Postgres", "version": "16.4",
                "source": "resolved-lockfile",
            }],
            "manual_technologies": [{
                "category": "databases", "name": "PostgreSQL", "version": "17.2",
            }],
        })
        self.assertEqual([(item["name"], item["version"]) for item in records], [
            ("PostgreSQL", "17.2"),
        ])

    def test_package_ecosystems_and_product_with_same_name_remain_distinct(self) -> None:
        config = {"inventory": {"projects": [{"id": "app", "technology_inventory": [
            {"category": "dependencies", "ecosystem": "npm", "name": "redis", "version": "4.7.0"},
            {"category": "dependencies", "ecosystem": "pypi", "name": "redis", "version": "4.7.0"},
            {"category": "containers", "name": "redis", "version": "7.4.0"},
        ], "manual_technologies": [
            {"category": "databases", "name": "Redis", "version": "7.4.1"},
        ]}]}}
        scope = collect_technology_scope(config)
        self.assertEqual({(item.get("ecosystem", "platform"), item["version"]) for item in scope},
            {("npm", "4.7.0"), ("pypi", "4.7.0"), ("platform", "7.4.1")})

    def test_known_version_in_one_ecosystem_does_not_hide_unknown_in_another(self) -> None:
        config = {"inventory": {"projects": [{"id": "app", "technology_inventory": [
            {"category": "dependencies", "ecosystem": "npm", "name": "shared", "version": "1.0.0"},
            {"category": "dependencies", "ecosystem": "pypi", "name": "shared", "version": ""},
        ]}]}}
        scope = collect_technology_scope(config)
        self.assertEqual({(item.get("ecosystem"), item["version"]) for item in scope},
                         {("npm", "1.0.0"), ("pypi", "")})

    def test_missing_daily_reports_invalidate_saved_baselines_and_checkpoints(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "output/advisory-state.json"
            state_path.parent.mkdir()
            state_path.write_text(json.dumps({"schema_version": 1,
                "baselines": {"package": {"status": "completed"}},
                "sources": {"osv": {"last_success_at": "2026-11-17T00:00:00Z"}}}),
                encoding="utf-8")
            daily = root / "output/daily-advisory-check"
            self.assertEqual(load_state_for_run(root, daily)["baselines"], {})
            self.assertEqual(load_state_for_run(root, daily)["sources"], {})
            daily.mkdir()
            (daily / "2026-11-17.md").write_text("report", encoding="utf-8")
            self.assertIn("package", load_state_for_run(root, daily)["baselines"])

    def test_scope_is_deduplicated_and_mapped_to_every_selected_project(self) -> None:
        config = {"inventory": {"projects": [
            {"id": "one", "technology_inventory": [{
                "category": "runtimes", "name": "PHP", "version": "8.3.4",
            }]},
            {"id": "two", "technology_inventory": [{
                "category": "runtimes", "name": "PHP", "version": "8.3.4",
            }]},
            {"id": "off", "advisory_checks": {"enabled": False},
             "technology_inventory": [{
                 "category": "runtimes", "name": "PHP", "version": "7.4.0",
             }]},
        ]}}
        scope = collect_technology_scope(config)
        self.assertEqual(len(scope), 1)
        self.assertEqual(scope[0]["projects"], ["one", "two"])

    def test_versioned_product_suppresses_unknown_language_or_service_alias(self) -> None:
        config = {"inventory": {"projects": [{
            "id": "one", "technology_inventory": [
                {"category": "languages", "name": "PHP", "version": ""},
                {"category": "containers", "name": "php", "version": "8.5.12"},
                {"category": "runtimes", "name": "PHP", "version": "8.5.12"},
            ],
        }]}}
        scope = collect_technology_scope(config)
        self.assertEqual(len(scope), 1)
        self.assertEqual(scope[0]["version"], "8.5.12")

    def test_missing_baseline_is_selected_and_unknown_version_completes_partially(self) -> None:
        config = {"inventory": {"projects": [{
            "id": "one", "technology_inventory": [{
                "category": "databases", "name": "PostgreSQL", "version": "",
            }],
        }]}}
        state = {"schema_version": 1, "baselines": {}, "sources": {}}
        rows = scan_rows(config, state)
        self.assertTrue(rows[0]["selected"])
        record_completed_baselines(
            state, rows, {rows[0]["key"]: "partial"},
            dt.datetime(2026, 11, 17, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(state["baselines"][rows[0]["key"]]["status"], "partial")
        self.assertFalse(scan_rows(config, state)[0]["selected"])

    def test_incremental_window_uses_per_source_success_minus_overlap(self) -> None:
        state = {"sources": {"osv": {"last_success_at": "2026-11-17T12:00:00Z"}}}
        since = incremental_since(
            state, "osv", 10, dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(since, "2026-11-07T12:00:00Z")
        self.assertIsNone(incremental_since(state, "acn", 10, dt.datetime.now(dt.timezone.utc)))

    def test_baseline_window_is_independent_from_incremental_checkpoint(self) -> None:
        now = dt.datetime(2026, 11, 20, 12, tzinfo=dt.timezone.utc)
        scope = [{"key": "php-123", "name": "PHP", "version": "8.3.4"}]
        windows = baseline_windows(scope, ["php-123"], now)
        self.assertIsNone(windows["php-123"]["since"])
        self.assertEqual(
            windows["php-123"]["since_basis"], "official-version-release-date-to-resolve",
        )
        self.assertEqual(windows["php-123"]["until"], "2026-11-20T12:00:00Z")

    def test_unverified_go_requirement_cannot_complete_exact_version_baseline(self) -> None:
        now = dt.datetime(2026, 11, 20, 12, tzinfo=dt.timezone.utc)
        scope = [{"key": "go-123", "category": "dependencies",
                  "name": "example.test/lib", "version": "v1.2.3",
                  "ecosystem": "go", "source": "go-minimum", "quality": "orange"}]
        windows = baseline_windows(scope, ["go-123"], now)
        self.assertEqual(windows["go-123"]["anchor_policy"], "go-declaration-to-verify")
        self.assertIsNone(windows["go-123"]["baseline_version"])
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evidence-state.json"
            path.write_text(json.dumps({"schema_version": 1, "baselines": [{
                "key": "go-123", "status": "completed", "baseline_version": "v1.2.3",
                "release_date": "2024-01-01", "searched_since": "2024-01-01",
                "searched_until": "2026-11-20", "release_source_url": "https://go.dev/example",
            }], "sources": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unresolved Go"):
                validate_evidence_state(path, ["go-123"], [], windows)
        state = {"baselines": {}, "sources": {}}
        record_completed_baselines(state, scope, {"go-123": "completed"}, now)
        self.assertEqual(state["baselines"]["go-123"]["status"], "partial")

    def test_structured_receipt_advances_only_complete_sources(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evidence-state.json"
            path.write_text(json.dumps({
                "schema_version": 1,
                "baselines": [{
                    "key": "php-123", "status": "completed",
                    "baseline_version": "8.3.0",
                    "release_date": "2024-03-14", "searched_since": "2024-03-14",
                    "searched_until": "2026-11-20",
                    "release_source_url": "https://www.php.net/releases/8.3/en.php",
                }],
                "sources": [
                    {"id": "osv", "status": "complete"},
                    {"id": "acn", "status": "partial"},
                ],
            }), encoding="utf-8")
            baselines, sources = validate_evidence_state(
                path, ["php-123"], ["osv", "acn"], {
                    "php-123": {
                        "version": "8.3.4", "until": "2026-11-20T12:00:00Z",
                        "anchor_policy": "platform-release-line-to-resolve",
                    },
                },
            )
        self.assertEqual(baselines, {"php-123": "completed"})
        self.assertEqual(sources, ["osv"])

    def test_completed_baseline_cannot_start_after_release_date(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evidence-state.json"
            path.write_text(json.dumps({
                "schema_version": 1,
                "baselines": [{
                    "key": "php-123", "status": "completed",
                    "baseline_version": "8.3.0",
                    "release_date": "2024-03-14", "searched_since": "2025-01-01",
                    "searched_until": "2026-11-20",
                    "release_source_url": "https://www.php.net/releases/8.3/en.php",
                }],
                "sources": [],
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "starts after"):
                validate_evidence_state(
                    path, ["php-123"], [], {
                        "php-123": {
                            "version": "8.3.4", "until": "2026-11-20",
                            "anchor_policy": "platform-release-line-to-resolve",
                        },
                    },
                )

    def test_structured_receipt_must_account_for_every_selected_baseline(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evidence-state.json"
            path.write_text(json.dumps({
                "schema_version": 1, "baselines": [], "sources": [],
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "every selected baseline"):
                validate_evidence_state(path, ["php-123"], [])


if __name__ == "__main__":
    unittest.main()
