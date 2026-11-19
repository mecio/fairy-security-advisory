# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts.inventory import (
    analyze_project, build_inventory, discover_projects, iter_project_files, matches_exclude,
    normalize_manual_technologies, normalize_production_technologies,
)


class ProjectRootExclusionsTest(unittest.TestCase):
    def test_composer_php_constraint_is_only_a_runtime_technology(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            project = Path(temporary_directory) / "app"
            project.mkdir()
            (project / "composer.json").write_text(
                '{"require":{"php":">=7.2","vendor/package":"^1.0"}}',
                encoding="utf-8",
            )
            result = analyze_project(project, project, (), 100)

        php = [
            item for item in result["technology_inventory"]
            if item["name"].casefold() == "php" and item.get("version") == ">=7.2"
        ]
        self.assertEqual(len(php), 1)
        self.assertEqual((php[0]["category"], php[0]["name"]), ("runtimes", "PHP"))

    def test_project_analysis_builds_versioned_technology_inventory_from_lockfile(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            project = Path(temporary_directory) / "app"
            project.mkdir()
            (project / "composer.json").write_text(
                '{"require":{"vendor/package":"^1.0"}}', encoding="utf-8",
            )
            (project / "composer.lock").write_text(
                '{"packages":[{"name":"vendor/package","version":"v1.2.3"}]}',
                encoding="utf-8",
            )
            result = analyze_project(project, project, (), 100)

        package = next(
            item for item in result["technology_inventory"]
            if item["name"] == "vendor/package"
        )
        self.assertEqual(package["version"], "1.2.3")
        self.assertEqual(package["quality"], "green")

    def test_project_analysis_preserves_multiple_versions_of_same_package(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            project = Path(temporary_directory) / "app"
            project.mkdir()
            (project / "package.json").write_text(
                '{"dependencies":{"shared":"^1"}}', encoding="utf-8",
            )
            (project / "package-lock.json").write_text(
                '{"packages":{'
                '"node_modules/shared":{"name":"shared","version":"1.0.0"},'
                '"node_modules/parent/node_modules/shared":{"name":"shared","version":"2.0.0"}'
                '}}', encoding="utf-8",
            )
            result = analyze_project(project, project, (), 100)

        versions = sorted(
            item["version"] for item in result["technology_inventory"]
            if item["name"] == "shared"
        )
        self.assertEqual(versions, ["1.0.0", "2.0.0"])

    def test_project_analysis_reads_lockfiles_and_go_requirements(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            project = Path(temporary_directory) / "app"
            project.mkdir()
            (project / "pyproject.toml").write_text('[project]\nname="app"\n', encoding="utf-8")
            (project / "poetry.lock").write_text(
                '[[package]]\nname="python-lib"\nversion="1.2.3"\n', encoding="utf-8",
            )
            (project / "Cargo.lock").write_text(
                '[[package]]\nname="rust-lib"\nversion="2.3.4"\n', encoding="utf-8",
            )
            (project / "Gemfile.lock").write_text(
                "GEM\n  specs:\n    ruby-lib (3.4.5)\n", encoding="utf-8",
            )
            (project / "go.sum").write_text(
                "example.test/go-lib v4.5.5 h1:old\n"
                "example.test/go-lib v4.5.6 h1:current\n", encoding="utf-8",
            )
            (project / "go.mod").write_text(
                "module example.test/app\nrequire (\n"
                "  example.test/go-lib v4.5.6 // indirect\n)\n", encoding="utf-8",
            )
            (project / "pnpm-lock.yaml").write_text(
                "lockfileVersion: '9.0'\npackages:\n  pnpm-lib@5.6.7: {}\n",
                encoding="utf-8",
            )
            result = analyze_project(project, project, (), 100)

        versions = {
            (item["name"], item["version"])
            for item in result["technology_inventory"]
        }
        self.assertTrue({
            ("python-lib", "1.2.3"), ("rust-lib", "2.3.4"),
            ("ruby-lib", "3.4.5"), ("example.test/go-lib", "v4.5.6"),
            ("pnpm-lib", "5.6.7"),
        }.issubset(versions))
        go_records = [item for item in result["technology_inventory"]
                      if item["name"] == "example.test/go-lib"]
        self.assertEqual([(item["version"], item["quality"]) for item in go_records],
                         [("v4.5.6", "orange")])
        self.assertEqual(go_records[0]["source"], "go-minimum")

    def test_go_replacement_does_not_claim_the_original_module_version_is_used(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            project = Path(temporary_directory)
            (project / "go.mod").write_text(
                "module example.test/app\n"
                "require (\nexample.test/local v1.2.3\nexample.test/forked v2.0.0\n)\n"
                "replace example.test/local => ./localfork\n"
                "replace (\nexample.test/forked => example.test/fork v2.1.0\n)\n",
                encoding="utf-8",
            )
            result = analyze_project(project, project, (), 100)
        go_records = {(item["name"], item["version"], item["source"])
                      for item in result["technology_inventory"]
                      if item.get("ecosystem") == "go"}
        self.assertEqual(go_records, {
            ("example.test/local", "", "go-replaced"),
            ("example.test/forked", "", "go-replaced"),
            ("example.test/fork", "v2.1.0", "go-replacement-candidate"),
        })

    def test_go_workspace_replacements_and_multiple_candidates_are_collected(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            project = Path(temporary_directory)
            module = project / "service"
            module.mkdir()
            (module / "go.mod").write_text(
                "module example.test/service\nrequire example.test/lib v1.0.0\n"
                "replace example.test/lib v1.0.0 => example.test/obsolete v1.0.0\n",
                encoding="utf-8",
            )
            (project / "go.work").write_text(
                "go 1.22\nuse (\n./service\n)\n"
                "replace (\n"
                "example.test/lib v1.0.0 => example.test/fork-a v1.0.0\n"
                "example.test/lib v2.0.0 => example.test/fork-b v2.0.0\n"
                ")\n", encoding="utf-8",
            )
            result = analyze_project(project, project, (), 100)
        go_records = {(item["name"], item["version"], item["source"])
                      for item in result["technology_inventory"] if item.get("ecosystem") == "go"}
        self.assertIn("go.work", result["manifests_and_lockfiles"])
        self.assertIn(("example.test/lib", "", "go-replaced"), go_records)
        self.assertIn(("example.test/fork-a", "v1.0.0", "go-replacement-candidate"), go_records)
        self.assertIn(("example.test/fork-b", "v2.0.0", "go-replacement-candidate"), go_records)
        self.assertNotIn(("example.test/obsolete", "v1.0.0", "go-replacement-candidate"), go_records)

    def test_go_workspace_external_module_requests_human_review_without_reading_it(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            project = base / "app"
            external = base / "external"
            project.mkdir()
            external.mkdir()
            (project / "go.work").write_text("go 1.22\nuse ../external\n", encoding="utf-8")
            (external / "go.mod").write_text(
                "module example.test/private\nrequire example.test/secret v1.0.0\n",
                encoding="utf-8",
            )
            result = analyze_project(project, project, (), 100)
        records = [item for item in result["technology_inventory"] if item.get("ecosystem") == "go"]
        self.assertEqual([(item["name"], item["quality"]) for item in records],
                         [("Go workspace module (unresolved)", "red")])

    def test_go_sum_alone_does_not_claim_an_active_dependency(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            project = Path(temporary_directory)
            (project / "go.sum").write_text(
                "example.test/old v1.0.0 h1:historical\n", encoding="utf-8",
            )
            result = analyze_project(project, project, (), 100)
        self.assertFalse(any(item["name"] == "example.test/old"
                             for item in result["technology_inventory"]))

    def test_yarn_berry_and_legacy_pnpm_versions_are_read(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            project = Path(temporary_directory) / "app"
            project.mkdir()
            (project / "package.json").write_text("{}", encoding="utf-8")
            (project / "yarn.lock").write_text(
                '"modern@npm:^1.0.0":\n  version: 1.2.3\n', encoding="utf-8",
            )
            (project / "pnpm-lock.yaml").write_text(
                "lockfileVersion: 5.4\npackages:\n  /legacy/2.3.4: {}\n",
                encoding="utf-8",
            )
            result = analyze_project(project, project, (), 100)
        versions = {
            (item["name"], item["version"])
            for item in result["technology_inventory"]
        }
        self.assertIn(("modern", "1.2.3"), versions)
        self.assertIn(("legacy", "2.3.4"), versions)

    def test_exclusions_apply_to_discovery_and_file_inventory(self) -> None:
        patterns = ("**/excluded-project/**", "**/generated/**", "**/*.secret")

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            included = root / "included-project"
            excluded = root / "excluded-project"
            generated = included / "generated"

            generated.mkdir(parents=True)
            excluded.mkdir()
            (included / "package.json").write_text("{}", encoding="utf-8")
            (included / "notes.secret").write_text("not a real secret", encoding="utf-8")
            (generated / "package.json").write_text("{}", encoding="utf-8")
            (excluded / "package.json").write_text("{}", encoding="utf-8")

            discovered = discover_projects(root, patterns)
            self.assertEqual(discovered, [included])

            files, truncated = iter_project_files(included, root, patterns, 100)
            relative_files = {path.relative_to(root).as_posix() for path in files}
            self.assertFalse(truncated)
            self.assertEqual(relative_files, {"included-project/package.json"})

    def test_double_star_pattern_also_matches_at_root_level(self) -> None:
        self.assertTrue(
            matches_exclude(Path("vendor"), ("**/vendor/**",), directory=True)
        )

    def test_inventory_refresh_preserves_preferences_and_replaces_manual_technology_edits(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            existing = root / "existing"
            new = root / "new"
            existing.mkdir()
            new.mkdir()
            config = {
                "project_roots": [{"path": str(root), "enabled": True, "exclude": []}],
                "inventory": {
                    "max_files_per_project": 100,
                    "projects": [{
                        "path": str(existing),
                        "advisory_checks": {"enabled": False, "preferred_ai": "claude"},
                        "manual_technologies": [{
                            "name": "PostgreSQL", "category": "databases",
                            "note": "User-declared database",
                        }],
                        "production_technologies": [{
                            "name": "PostgreSQL", "category": "databases",
                            "environment": "production-eu", "version": "16.4",
                            "evidence_type": "administrator-confirmed",
                            "evidence": "Confirmed by the system administrator",
                            "verified_at": "2026-11-19T10:30:00Z",
                        }],
                    }],
                },
            }

            def analyzed(path, _root, _exclude, _limit):
                return {"id": path.name, "path": str(path)}

            with patch(
                "scripts.inventory.discover_projects", return_value=[existing, new],
            ), patch("scripts.inventory.analyze_project", side_effect=analyzed):
                projects = build_inventory(config)

            by_id = {project["id"]: project for project in projects}
            self.assertEqual(by_id["existing"]["advisory_checks"], {
                "enabled": False, "preferred_ai": "claude",
            })
            self.assertEqual(by_id["new"]["advisory_checks"], {
                "enabled": True, "preferred_ai": None,
            })
            self.assertEqual(by_id["existing"]["manual_technologies"], [])
            self.assertEqual(by_id["new"]["manual_technologies"], [])
            self.assertEqual(
                by_id["existing"]["production_technologies"][0]["version"], "16.4",
            )
            self.assertEqual(by_id["new"]["production_technologies"], [])

    def test_production_technologies_require_evidence_and_support_environments(self) -> None:
        values = normalize_production_technologies([
            {"name": "PostgreSQL", "category": "databases",
             "environment": "production-eu", "version": "16.4",
             "evidence_type": "administrator-confirmed",
             "evidence": "Confirmed by system administrator",
             "verified_at": "2026-11-19T11:30:00+01:00"},
            {"name": "PostgreSQL", "category": "databases",
             "environment": "production-us", "version": "16.6",
             "evidence_type": "authorized-check", "evidence": "Read-only version command",
             "verified_at": "2026-11-19T10:35:00Z"},
        ])
        self.assertEqual([item["environment"] for item in values], [
            "production-eu", "production-us",
        ])
        self.assertEqual(values[0]["verified_at"], "2026-11-19T10:30:00Z")
        with self.assertRaisesRegex(ValueError, "duplicate production environment"):
            normalize_production_technologies([values[0], {**values[0], "version": "16.5"}])
        with self.assertRaisesRegex(ValueError, "needs evidence"):
            normalize_production_technologies([{**values[0], "evidence": ""}])

    def test_manual_technologies_reject_duplicates_and_control_characters(self) -> None:
        with self.assertRaises(ValueError):
            normalize_manual_technologies([
                {"name": "PostgreSQL", "category": "databases"},
                {"name": "postgresql", "category": "databases"},
            ])
        with self.assertRaises(ValueError):
            normalize_manual_technologies([
                {"name": "PostgreSQL\nsecret", "category": "databases"},
            ])
        values = normalize_manual_technologies([
            {"name": "shared", "category": "dependencies", "version": "1.0.0"},
            {"name": "shared", "category": "dependencies", "version": "2.0.0"},
        ])
        self.assertEqual(len(values), 2)
        ecosystems = normalize_manual_technologies([
            {"name": "shared", "category": "dependencies", "ecosystem": "npm", "version": "1.0.0"},
            {"name": "shared", "category": "dependencies", "ecosystem": "pypi", "version": "1.0.0"},
        ])
        self.assertEqual({item["ecosystem"] for item in ecosystems}, {"npm", "pypi"})
        excluded = normalize_manual_technologies([
            {"name": "example.test/old", "category": "dependencies",
             "ecosystem": "go", "exclude": True},
        ])
        self.assertTrue(excluded[0]["exclude"])
        targeted = normalize_manual_technologies([
            {"name": "shared", "category": "dependencies", "ecosystem": "npm",
             "version": "1.1.0", "replaces_version": "1.0.0"},
        ])
        self.assertEqual(targeted[0]["replaces_version"], "1.0.0")

        assessed = normalize_manual_technologies([{
            "name": "PostgreSQL", "category": "databases", "version": "17.2",
            "version_status": "hypothetical",
        }])
        self.assertEqual(assessed[0]["version_status"], "hypothetical")
        with self.assertRaisesRegex(ValueError, "unsupported version status"):
            normalize_manual_technologies([{
                "name": "PostgreSQL", "category": "databases", "version": "17.2",
                "version_status": "trusted-by-magic",
            }])
        with self.assertRaisesRegex(ValueError, "both excluded and versioned"):
            normalize_manual_technologies([
                {"name": "example.test/old", "category": "dependencies",
                 "ecosystem": "go", "exclude": True},
                {"name": "example.test/old", "category": "dependencies",
                 "ecosystem": "go", "version": "v1.0.0"},
            ])


if __name__ == "__main__":
    unittest.main()
