# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts.inventory import build_inventory, discover_projects, iter_project_files, matches_exclude


class ProjectRootExclusionsTest(unittest.TestCase):
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

    def test_inventory_refresh_preserves_local_advisory_preferences(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
