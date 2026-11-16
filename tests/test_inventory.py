# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.inventory import discover_projects, iter_project_files, matches_exclude


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


if __name__ == "__main__":
    unittest.main()
